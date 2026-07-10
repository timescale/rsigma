use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Method, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::auth::AuthIdentity;
use super::metrics::Metrics;
use super::store::SqliteStateStore;
use rsigma_runtime::Sink;

pub const DEFAULT_MAX_ENTRIES: u64 = 10_000;
pub const DEFAULT_MAX_AGE: &str = "720h";
pub const DEFAULT_MAX_BODY_BYTES: usize = 65_536;

/// Effective audit-trail settings resolved from config and `--state-db`.
#[derive(Debug, Clone)]
pub struct AuditSettings {
    pub enabled: bool,
    pub max_entries: u64,
    pub max_age: Duration,
    pub max_body_bytes: usize,
    pub sink: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditConfig {
    pub max_entries: u64,
    pub max_age: Duration,
    pub max_body_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub ts: i64,
    pub method: String,
    pub endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_digest: Option<String>,
    pub status: u16,
}

#[derive(Clone)]
pub struct AuditLog {
    store: Arc<SqliteStateStore>,
    config: AuditConfig,
    metrics: Arc<Metrics>,
    sink: Option<Arc<tokio::sync::Mutex<Sink>>>,
}

impl AuditLog {
    pub fn new(
        store: Arc<SqliteStateStore>,
        config: AuditConfig,
        metrics: Arc<Metrics>,
        sink: Option<Arc<tokio::sync::Mutex<Sink>>>,
    ) -> Self {
        Self {
            store,
            config,
            metrics,
            sink,
        }
    }

    pub fn max_body_bytes(&self) -> usize {
        self.config.max_body_bytes
    }

    /// Persist (and optionally emit) an audit record without blocking the
    /// caller. Each call spawns its own task, so concurrent mutations may reach
    /// the optional sink out of timestamp order; the SQLite table remains the
    /// authoritative, id-ordered record.
    pub fn record(&self, rec: AuditRecord) {
        let store = self.store.clone();
        let metrics = self.metrics.clone();
        let sink = self.sink.clone();
        tokio::spawn(async move {
            match store.insert_audit(&rec).await {
                Ok(()) => {
                    metrics.audit_records_total.inc();
                    if let Some(sink) = sink {
                        if let Ok(json) = serde_json::to_string(&rec) {
                            let mut s = sink.lock().await;
                            if let Err(e) = s.send_raw(&json).await {
                                tracing::warn!(error = %e, "audit sink emission failed");
                                metrics.audit_write_errors_total.inc();
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "audit log insert failed");
                    metrics.audit_write_errors_total.inc();
                }
            }
        });
    }

    pub async fn query(
        &self,
        limit: u64,
        offset: u64,
        since: Option<i64>,
        until: Option<i64>,
    ) -> Result<(u64, Vec<AuditRecord>), String> {
        self.store.query_audit(limit, offset, since, until).await
    }

    pub async fn prune(&self) {
        let age_cutoff = now_ts() - self.config.max_age.as_secs() as i64;
        if let Err(e) = self
            .store
            .prune_audit(self.config.max_entries, age_cutoff)
            .await
        {
            tracing::warn!(error = %e, "audit log prune failed");
            self.metrics.audit_write_errors_total.inc();
        }
    }
}

/// Append `on_full=drop` to a sink spec when absent so audit emission never
/// blocks on a slow downstream.
pub fn audit_sink_spec(spec: &str) -> String {
    let (_, params) = super::server::split_query(spec);
    if params.iter().any(|(k, _)| *k == "on_full") {
        spec.to_string()
    } else if spec.contains('?') {
        format!("{spec}&on_full=drop")
    } else {
        format!("{spec}?on_full=drop")
    }
}

pub fn is_audited(method: &Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&Method::POST, "/api/v1/silences")
            | (&Method::DELETE, "/api/v1/silences/{id}")
            | (&Method::POST, "/api/v1/dispositions")
            | (&Method::POST, "/api/v1/reload")
            | (&Method::POST, "/api/v1/sources/resolve")
            | (&Method::POST, "/api/v1/sources/resolve/{source_id}")
            | (&Method::DELETE, "/api/v1/sources/cache/{source_id}")
            | (&Method::DELETE, "/api/v1/fields/observer")
            | (&Method::DELETE, "/api/v1/schemas")
    )
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn digest_hex(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(body);
    Some(
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    )
}

fn skip_body_buffer(method: &Method, headers: &HeaderMap) -> bool {
    if *method == Method::DELETE {
        return true;
    }
    match headers.get(header::CONTENT_LENGTH) {
        Some(v) => v.as_bytes() == b"0",
        None => !headers.contains_key(header::TRANSFER_ENCODING),
    }
}

/// Read the declared body length from `Content-Length`, if present and valid.
fn declared_len(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<usize>().ok())
}

fn payload_too_large(max: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        axum::Json(serde_json::json!({
            "error": "request body exceeds audit max_body_bytes",
            "max_body_bytes": max
        })),
    )
        .into_response()
}

pub async fn audit_middleware(
    State(log): State<Arc<AuditLog>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    use axum::extract::MatchedPath;

    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| request.uri().path().to_owned());

    if !is_audited(request.method(), &path) {
        return next.run(request).await;
    }

    let method = request.method().clone();
    let token = request
        .extensions()
        .get::<AuthIdentity>()
        .map(|id| id.token.clone())
        .unwrap_or(None);

    // Records the outcome once we know the status. Digest is `None` for
    // bodyless or rejected requests.
    let emit = |log: &AuditLog, status: u16, payload_digest: Option<String>| {
        log.record(AuditRecord {
            id: None,
            ts: now_ts(),
            method: method.to_string(),
            endpoint: path.clone(),
            token: token.clone(),
            payload_digest,
            status,
        });
    };

    let max = log.max_body_bytes();
    let (parts, body) = request.into_parts();
    let body_bytes = if skip_body_buffer(&method, &parts.headers) {
        Bytes::new()
    } else {
        // A declared `Content-Length` over the cap is a definitive reject
        // before reading the stream.
        if declared_len(&parts.headers).is_some_and(|len| len > max) {
            emit(&log, StatusCode::PAYLOAD_TOO_LARGE.as_u16(), None);
            return payload_too_large(max);
        }
        // `to_bytes` errors when the streamed body exceeds the limit; past the
        // `Content-Length` precheck the dominant cause of a limit hit is an
        // oversized chunked body, so we treat the error as too-large. A rare
        // mid-stream read error maps here too, which is acceptable.
        match axum::body::to_bytes(body, max).await {
            Ok(bytes) => bytes,
            Err(_) => {
                emit(&log, StatusCode::PAYLOAD_TOO_LARGE.as_u16(), None);
                return payload_too_large(max);
            }
        }
    };

    let payload_digest = digest_hex(&body_bytes);
    let request = Request::from_parts(parts, Body::from(body_bytes));
    let response = next.run(request).await;
    let status = response.status().as_u16();

    emit(&log, status, payload_digest);

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn is_audited_truth_table() {
        assert!(is_audited(&Method::POST, "/api/v1/silences"));
        assert!(is_audited(&Method::DELETE, "/api/v1/silences/{id}"));
        assert!(is_audited(&Method::POST, "/api/v1/reload"));
        assert!(!is_audited(&Method::GET, "/api/v1/silences"));
        assert!(!is_audited(&Method::GET, "/api/v1/audit"));
        assert!(!is_audited(&Method::POST, "/api/v1/events"));
        assert!(!is_audited(&Method::POST, "/v1/logs"));
        assert!(!is_audited(&Method::GET, "/metrics"));
    }

    #[test]
    fn digest_empty_body_is_none() {
        assert_eq!(digest_hex(b""), None);
    }

    #[test]
    fn digest_nonempty_body_is_sha256_hex() {
        let digest = digest_hex(b"hello").unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn audit_sink_spec_appends_drop_policy() {
        assert_eq!(audit_sink_spec("stdout"), "stdout?on_full=drop");
        assert_eq!(
            audit_sink_spec("file:///tmp/audit.jsonl?pretty=true"),
            "file:///tmp/audit.jsonl?pretty=true&on_full=drop"
        );
        assert_eq!(
            audit_sink_spec("stdout?on_full=block"),
            "stdout?on_full=block"
        );
    }
}
