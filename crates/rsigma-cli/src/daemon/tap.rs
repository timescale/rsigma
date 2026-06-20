//! Live event-tap HTTP streaming: session management, server-side redaction,
//! and the chunked-NDJSON producer behind `GET /api/v1/tap`.
//!
//! The runtime ([`rsigma_runtime::tap`]) captures raw lines and decoded events
//! into bounded per-session channels off the engine hot path. This module owns
//! everything CLI-side: query-param validation, the per-session salted
//! redactor, and the async task that drains a session, redacts, serializes to
//! NDJSON, enforces the duration / limit bounds, and appends a summary record.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{StatusCode, header};
use axum::response::Response;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use rsigma_runtime::{TapPayload, TapRegistry, TapSessionHandle, TapStage};

use super::metrics::Metrics;

/// Default capture window when the client omits `duration`.
const DEFAULT_DURATION: Duration = Duration::from_secs(30);

/// Live event-tap state shared with the HTTP handler. Present in `AppState`
/// only when the tap is enabled.
#[derive(Clone)]
pub(crate) struct TapState {
    pub registry: Arc<TapRegistry>,
    pub metrics: Arc<Metrics>,
}

impl TapState {
    pub(crate) fn new(registry: Arc<TapRegistry>, metrics: Arc<Metrics>) -> Self {
        Self { registry, metrics }
    }
}

/// Raw query string for `GET /api/v1/tap`, validated into [`ParsedParams`].
#[derive(Debug, Default, Deserialize)]
pub(crate) struct TapQuery {
    duration: Option<String>,
    limit: Option<u64>,
    stage: Option<String>,
    redact: Option<String>,
}

/// Validated capture parameters.
#[derive(Debug)]
pub(crate) struct ParsedParams {
    pub stage: TapStage,
    pub duration: Duration,
    pub limit: Option<u64>,
    pub redact_paths: Vec<String>,
}

/// Validate the query params against the daemon's `max_duration`. Returns a
/// human-readable message on failure, which the handler maps to a `400`.
pub(crate) fn parse_params(
    query: &TapQuery,
    max_duration: Duration,
) -> Result<ParsedParams, String> {
    let stage = match query.stage.as_deref() {
        None | Some("decoded") => TapStage::Decoded,
        Some("raw") => TapStage::Raw,
        Some(other) => {
            return Err(format!(
                "invalid stage '{other}' (expected 'decoded' or 'raw')"
            ));
        }
    };

    let duration = match query.duration.as_deref() {
        None => DEFAULT_DURATION,
        Some(s) => {
            humantime::parse_duration(s).map_err(|e| format!("invalid duration '{s}': {e}"))?
        }
    };
    if duration > max_duration {
        return Err(format!(
            "duration {} exceeds the daemon's tap max_duration {}",
            humantime::format_duration(duration),
            humantime::format_duration(max_duration),
        ));
    }

    let redact_paths = query
        .redact
        .as_deref()
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    Ok(ParsedParams {
        stage,
        duration,
        limit: query.limit,
        redact_paths,
    })
}

/// Build the streaming `200` response: register the metrics, spawn the
/// producer task, and return a chunked-NDJSON body. The caller has already
/// registered the session (so the `409` cap is enforced before this runs).
pub(crate) fn stream_response(
    handle: TapSessionHandle,
    params: ParsedParams,
    metrics: Arc<Metrics>,
) -> Response {
    let redactor = (!params.redact_paths.is_empty())
        .then(|| Redactor::new(&params.redact_paths, random_salt()));

    metrics.tap_sessions_total.inc();
    metrics.tap_active_sessions.inc();

    // A small bounded body channel: when the client reads slowly the producer
    // blocks here, which lets the per-session capture channel fill and drop
    // (lossy by design) rather than ever stalling the engine.
    let (body_tx, body_rx) = mpsc::channel::<Result<String, std::io::Error>>(64);
    let producer = Producer {
        handle,
        stage: params.stage,
        duration: params.duration,
        limit: params.limit,
        redactor,
        metrics,
        body_tx,
    };
    tokio::spawn(producer.run());

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .body(Body::from_stream(ReceiverStream::new(body_rx)))
        .expect("static tap response builds")
}

/// The async task draining one capture session into the HTTP body.
struct Producer {
    handle: TapSessionHandle,
    stage: TapStage,
    duration: Duration,
    limit: Option<u64>,
    redactor: Option<Redactor>,
    metrics: Arc<Metrics>,
    body_tx: mpsc::Sender<Result<String, std::io::Error>>,
}

impl Producer {
    async fn run(mut self) {
        let start = Instant::now();
        let deadline = tokio::time::Instant::now() + self.duration;
        let mut streamed: u64 = 0;
        let mut redaction_dropped: u64 = 0;

        loop {
            if self.limit.is_some_and(|limit| streamed >= limit) {
                break;
            }

            let payload = tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => break,
                // Detect a dropped client connection promptly, even while idle,
                // so the session (and its slot against `max_sessions`) is freed
                // without waiting for the duration to elapse.
                _ = self.body_tx.closed() => break,
                next = self.handle.rx.recv() => match next {
                    Some(p) => p,
                    None => break,
                },
            };

            let line = match render_line(payload, self.redactor.as_ref()) {
                Some(line) => line,
                None => {
                    // Redacting raw stage: an unparseable line is dropped
                    // rather than emitted unredacted (the redaction contract).
                    redaction_dropped += 1;
                    continue;
                }
            };

            if self.body_tx.send(Ok(line)).await.is_err() {
                break; // client disconnected mid-send
            }
            streamed += 1;
            self.metrics.tap_events_streamed_total.inc();
        }

        // Summary record: `captured` is what the client received; `dropped`
        // sums hot-path channel-full drops and redaction parse-failures, so a
        // consumer can detect gaps in the fixture.
        let hot_dropped = self.handle.dropped.load(Ordering::Relaxed);
        let total_dropped = hot_dropped + redaction_dropped;
        if total_dropped > 0 {
            self.metrics.tap_events_dropped_total.inc_by(total_dropped);
        }
        let summary = serde_json::json!({
            "rsigma_tap_summary": {
                "captured": streamed,
                "dropped": total_dropped,
                "duration_ms": start.elapsed().as_millis() as u64,
                "stage": stage_str(self.stage),
            }
        });
        let _ = self.body_tx.send(Ok(format!("{summary}\n"))).await;

        self.metrics.tap_active_sessions.dec();
        // `self.handle` drops here, deregistering the session from the registry.
    }
}

fn stage_str(stage: TapStage) -> &'static str {
    match stage {
        TapStage::Raw => "raw",
        TapStage::Decoded => "decoded",
    }
}

/// Render one captured payload into an NDJSON line (trailing newline included),
/// or `None` when a redacting raw capture hits an unparseable line.
fn render_line(payload: TapPayload, redactor: Option<&Redactor>) -> Option<String> {
    match payload {
        TapPayload::Decoded(value) => {
            let mut value = *value;
            if let Some(r) = redactor {
                r.redact(&mut value);
            }
            Some(serialize_line(&value))
        }
        TapPayload::Raw(mut line) => match redactor {
            // Non-redacting raw: emit the line verbatim, reusing its buffer.
            None => {
                line.push('\n');
                Some(line)
            }
            // Redacting raw: only JSON-parseable lines can be redacted; an
            // unparseable line is dropped (signalled with `None`) rather than
            // emitted unredacted.
            Some(r) => {
                let mut value: serde_json::Value = serde_json::from_str(&line).ok()?;
                r.redact(&mut value);
                Some(serialize_line(&value))
            }
        },
    }
}

/// Serialize a JSON value to a single NDJSON line (with trailing newline).
fn serialize_line(value: &serde_json::Value) -> String {
    let mut line = serde_json::to_string(value).unwrap_or_default();
    line.push('\n');
    line
}

/// Generate a random per-session salt for the redactor.
fn random_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).expect("OS RNG available for tap session salt");
    salt
}

/// Deterministic, salted field redactor.
///
/// Each configured dotted path is navigated with the same object-key /
/// numeric-index semantics as the enrichment template engine, with one
/// deliberate divergence: when a non-numeric segment meets an array, the path
/// fans out to every element (fail-closed, so a fixture never leaks one array
/// element). Each matched leaf is replaced with
/// `rsigma:redacted:<16 hex chars of SHA-256(salt || canonical value)>`, so
/// equal inputs map to equal tokens within a session (preserving correlation
/// cardinality on replay) while the per-session salt blocks dictionary
/// reversal and cross-fixture linkage.
pub(crate) struct Redactor {
    paths: Vec<Vec<String>>,
    salt: [u8; 16],
}

impl Redactor {
    pub(crate) fn new(paths: &[String], salt: [u8; 16]) -> Self {
        let paths = paths
            .iter()
            .map(|p| p.split('.').map(str::to_string).collect())
            .collect();
        Self { paths, salt }
    }

    pub(crate) fn redact(&self, value: &mut serde_json::Value) {
        for path in &self.paths {
            redact_at(value, path, &self.salt);
        }
    }
}

fn redact_at(value: &mut serde_json::Value, segments: &[String], salt: &[u8; 16]) {
    use serde_json::Value;
    match segments.split_first() {
        // Path fully consumed: this is the leaf to redact.
        None => *value = token(value, salt),
        Some((seg, rest)) => match value {
            Value::Object(map) => {
                if let Some(child) = map.get_mut(seg.as_str()) {
                    redact_at(child, rest, salt);
                }
                // A path that resolves to nothing is a no-op.
            }
            Value::Array(arr) => {
                if let Ok(idx) = seg.parse::<usize>() {
                    if let Some(child) = arr.get_mut(idx) {
                        redact_at(child, rest, salt);
                    }
                } else {
                    // Non-numeric segment meets an array: fan out to every
                    // element and apply the same segment to each (fail-closed).
                    for elem in arr.iter_mut() {
                        redact_at(elem, segments, salt);
                    }
                }
            }
            _ => {}
        },
    }
}

/// Build the redaction token for `value`, hashing its canonical JSON form so
/// non-string leaves redact deterministically too.
fn token(value: &serde_json::Value, salt: &[u8; 16]) -> serde_json::Value {
    use std::fmt::Write;

    let canonical = match value {
        serde_json::Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    };
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(16);
    for b in &digest[..8] {
        let _ = write!(hex, "{b:02x}");
    }
    serde_json::Value::String(format!("rsigma:redacted:{hex}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SALT: [u8; 16] = [7u8; 16];

    fn redact(paths: &[&str], mut value: serde_json::Value) -> serde_json::Value {
        let owned: Vec<String> = paths.iter().map(|s| s.to_string()).collect();
        Redactor::new(&owned, SALT).redact(&mut value);
        value
    }

    fn tok(s: &str) -> String {
        match token(&serde_json::Value::String(s.to_string()), &SALT) {
            serde_json::Value::String(s) => s,
            _ => unreachable!(),
        }
    }

    #[test]
    fn redacts_top_level_field() {
        let out = redact(&["src_ip"], json!({"src_ip": "1.2.3.4", "user": "alice"}));
        assert_eq!(out["src_ip"], serde_json::Value::String(tok("1.2.3.4")));
        assert_eq!(out["user"], "alice");
    }

    #[test]
    fn redacts_nested_dotted_path() {
        let out = redact(
            &["user.email"],
            json!({"user": {"email": "a@b.c", "id": 1}}),
        );
        assert_eq!(
            out["user"]["email"],
            serde_json::Value::String(tok("a@b.c"))
        );
        assert_eq!(out["user"]["id"], 1);
    }

    #[test]
    fn numeric_segment_indexes_array() {
        let out = redact(&["ips.0"], json!({"ips": ["1.1.1.1", "2.2.2.2"]}));
        assert_eq!(out["ips"][0], serde_json::Value::String(tok("1.1.1.1")));
        assert_eq!(out["ips"][1], "2.2.2.2");
    }

    #[test]
    fn non_numeric_segment_fans_out_over_array() {
        let out = redact(
            &["users.email"],
            json!({"users": [{"email": "a@x"}, {"email": "b@x"}]}),
        );
        assert_eq!(
            out["users"][0]["email"],
            serde_json::Value::String(tok("a@x"))
        );
        assert_eq!(
            out["users"][1]["email"],
            serde_json::Value::String(tok("b@x"))
        );
    }

    #[test]
    fn missing_path_is_noop() {
        let out = redact(&["nope.here"], json!({"src_ip": "1.2.3.4"}));
        assert_eq!(out, json!({"src_ip": "1.2.3.4"}));
    }

    #[test]
    fn non_string_leaf_redacted_via_canonical_json() {
        let out = redact(&["port"], json!({"port": 8080}));
        let expected = match token(&json!(8080), &SALT) {
            serde_json::Value::String(s) => s,
            _ => unreachable!(),
        };
        assert_eq!(out["port"], serde_json::Value::String(expected));
    }

    #[test]
    fn determinism_within_one_salt() {
        let out = redact(&["a", "b"], json!({"a": "same", "b": "same", "c": "same"}));
        // Equal inputs hash to equal tokens (preserves correlation cardinality).
        assert_eq!(out["a"], out["b"]);
        // Un-redacted field keeps its value.
        assert_eq!(out["c"], "same");
    }

    #[test]
    fn divergence_across_salts() {
        let a = {
            let mut v = json!({"x": "secret"});
            Redactor::new(&["x".into()], [1u8; 16]).redact(&mut v);
            v
        };
        let b = {
            let mut v = json!({"x": "secret"});
            Redactor::new(&["x".into()], [2u8; 16]).redact(&mut v);
            v
        };
        assert_ne!(a["x"], b["x"]);
    }

    #[test]
    fn token_has_expected_shape() {
        let t = tok("anything");
        assert!(t.starts_with("rsigma:redacted:"));
        let hex = t.strip_prefix("rsigma:redacted:").unwrap();
        assert_eq!(hex.len(), 16);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn parse_params_defaults_to_decoded_30s() {
        let p = parse_params(&TapQuery::default(), Duration::from_secs(300)).unwrap();
        assert_eq!(p.stage, TapStage::Decoded);
        assert_eq!(p.duration, Duration::from_secs(30));
        assert!(p.limit.is_none());
        assert!(p.redact_paths.is_empty());
    }

    #[test]
    fn parse_params_rejects_over_max_duration() {
        let q = TapQuery {
            duration: Some("10m".into()),
            ..Default::default()
        };
        let err = parse_params(&q, Duration::from_secs(300)).unwrap_err();
        assert!(err.contains("exceeds"), "{err}");
    }

    #[test]
    fn parse_params_rejects_bad_stage() {
        let q = TapQuery {
            stage: Some("bogus".into()),
            ..Default::default()
        };
        assert!(parse_params(&q, Duration::from_secs(300)).is_err());
    }

    #[test]
    fn parse_params_splits_redact_list() {
        let q = TapQuery {
            redact: Some("user.email, src_ip ,".into()),
            stage: Some("raw".into()),
            ..Default::default()
        };
        let p = parse_params(&q, Duration::from_secs(300)).unwrap();
        assert_eq!(p.stage, TapStage::Raw);
        assert_eq!(p.redact_paths, vec!["user.email", "src_ip"]);
    }

    /// Recursively sort object keys so a snapshot is stable whether or not the
    /// `serde_json/preserve_order` feature is unified into the build (it is
    /// under `--all-features`, which flips object output from sorted to
    /// insertion order). Production fixtures stay order-agnostic NDJSON; this
    /// only canonicalizes the golden text.
    fn canonical_json(value: &serde_json::Value) -> serde_json::Value {
        use serde_json::Value;
        match value {
            Value::Object(map) => {
                let mut entries: Vec<(String, Value)> = map
                    .iter()
                    .map(|(k, v)| (k.clone(), canonical_json(v)))
                    .collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                Value::Object(entries.into_iter().collect())
            }
            Value::Array(arr) => Value::Array(arr.iter().map(canonical_json).collect()),
            other => other.clone(),
        }
    }

    /// Golden output for a redacted decoded fixture line plus the summary
    /// record, pinned with the fixed test salt so the tokens are stable.
    #[test]
    fn golden_redacted_decoded_fixture() {
        let event = json!({
            "CommandLine": "whoami",
            "user": {"email": "alice@example.com"},
            "src_ip": "10.0.0.1",
        });
        let redactor = Redactor::new(&["user.email".into(), "src_ip".into()], SALT);
        let line =
            render_line(super::TapPayload::Decoded(Box::new(event)), Some(&redactor)).unwrap();
        let event_value: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        let summary = serde_json::json!({
            "rsigma_tap_summary": {
                "captured": 1,
                "dropped": 0,
                "duration_ms": 0,
                "stage": "decoded",
            }
        });
        let golden = format!(
            "{}\n{}\n",
            serde_json::to_string(&canonical_json(&event_value)).unwrap(),
            serde_json::to_string(&canonical_json(&summary)).unwrap(),
        );
        insta::assert_snapshot!("redacted_decoded_fixture", golden);
    }
}
