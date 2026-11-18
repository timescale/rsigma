//! HTTP push, replace, delete, and list for `type: watchlist` sources.
//!
//! A successful change updates the in-memory registry, then asks the refresh
//! scheduler to rebuild rules. The response returns before that rebuild
//! finishes. A full trigger channel is logged and still a success.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRef, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, SecondsFormat, Utc};
use rsigma_eval::pipeline::sources::SourceType;
use rsigma_runtime::sources::refresh::RefreshTrigger;
use rsigma_runtime::sources::registry::DaemonSourceRegistry;
use rsigma_runtime::sources::{WatchlistError, WatchlistItem, WatchlistRegistry, WatchlistRow};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::metrics::Metrics;

/// Largest accepted indicator request body.
pub(crate) const BODY_LIMIT: usize = 4 * 1024 * 1024;

const LIST_DEFAULT_LIMIT: usize = 1000;
const LIST_MAX_LIMIT: usize = 10_000;

pub(crate) type PersistFn = Arc<
    dyn Fn(String, Vec<WatchlistRow>) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
        + Send
        + Sync,
>;

/// Shared state for the indicator routes and the expiry sweeper.
#[derive(Clone)]
pub(crate) struct WatchlistApi {
    registry: Arc<WatchlistRegistry>,
    sources: Arc<DaemonSourceRegistry>,
    trigger: Option<mpsc::Sender<RefreshTrigger>>,
    metrics: Arc<Metrics>,
    persist: Option<PersistFn>,
}

impl WatchlistApi {
    pub(crate) fn new(
        registry: Arc<WatchlistRegistry>,
        sources: Arc<DaemonSourceRegistry>,
        trigger: Option<mpsc::Sender<RefreshTrigger>>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            registry,
            sources,
            trigger,
            metrics,
            persist: None,
        }
    }

    /// Write each accepted change through before the response. A failure
    /// restores the previous in-memory set.
    pub(crate) fn set_persist(&mut self, persist: PersistFn) {
        self.persist = Some(persist);
    }

    async fn post(&self, source_id: &str, body: &[u8]) -> Response {
        let now = Utc::now();
        if let Err(response) = self.require_watchlist(source_id) {
            return *response;
        }
        let request = match parse_push(body) {
            Ok(request) => request,
            Err(response) => return *response,
        };
        let writes = self.registry.write_lock();
        let _guard = writes.lock().await;
        let before = self.before_rows(source_id);
        let summary = match self
            .registry
            .add(source_id, &request.items, request.ttl, now)
        {
            Ok(summary) => summary,
            Err(error) => return watchlist_error(error),
        };
        if let Err(response) = self.commit(source_id, &before, now).await {
            return *response;
        }
        self.count(source_id, "add", summary.added);
        self.count(source_id, "update", summary.updated);
        self.gauge(source_id, summary.total);
        self.publish(source_id);
        (
            StatusCode::OK,
            Json(json!({
                "source_id": source_id,
                "added": summary.added,
                "updated": summary.updated,
                "total": summary.total,
            })),
        )
            .into_response()
    }

    async fn put(&self, source_id: &str, body: &[u8]) -> Response {
        let now = Utc::now();
        if let Err(response) = self.require_watchlist(source_id) {
            return *response;
        }
        let request = match parse_push(body) {
            Ok(request) => request,
            Err(response) => return *response,
        };
        let writes = self.registry.write_lock();
        let _guard = writes.lock().await;
        let before_values = self.live_values(source_id, now);
        let before = self.before_rows(source_id);
        let summary = match self
            .registry
            .replace(source_id, &request.items, request.ttl, now)
        {
            Ok(summary) => summary,
            Err(error) => return watchlist_error(error),
        };
        if let Err(response) = self.commit(source_id, &before, now).await {
            return *response;
        }
        let after: HashSet<String> = self.live_values(source_id, now);
        self.count(
            source_id,
            "remove",
            before_values.difference(&after).count(),
        );
        self.count(source_id, "add", after.difference(&before_values).count());
        self.count(
            source_id,
            "update",
            before_values.intersection(&after).count(),
        );
        self.gauge(source_id, summary.total);
        self.publish(source_id);
        (
            StatusCode::OK,
            Json(json!({
                "source_id": source_id,
                "total": summary.total,
                "removed": summary.removed,
            })),
        )
            .into_response()
    }

    async fn delete(&self, source_id: &str, body: &[u8]) -> Response {
        let now = Utc::now();
        if let Err(response) = self.require_watchlist(source_id) {
            return *response;
        }
        let request = match parse_delete(body) {
            Ok(request) => request,
            Err(response) => return *response,
        };
        let writes = self.registry.write_lock();
        let _guard = writes.lock().await;
        let before = self.before_rows(source_id);
        let summary = match self.registry.remove(source_id, &request.indicators, now) {
            Ok(summary) => summary,
            Err(error) => return watchlist_error(error),
        };
        if let Err(response) = self.commit(source_id, &before, now).await {
            return *response;
        }
        self.count(source_id, "remove", summary.removed);
        self.gauge(source_id, summary.total);
        self.publish(source_id);
        (
            StatusCode::OK,
            Json(json!({
                "source_id": source_id,
                "removed": summary.removed,
                "not_found": summary.not_found,
                "total": summary.total,
            })),
        )
            .into_response()
    }

    fn get(&self, source_id: &str, limit: usize, offset: usize) -> Response {
        let now = Utc::now();
        if let Err(response) = self.require_watchlist(source_id) {
            return *response;
        }
        let limit = limit.min(LIST_MAX_LIMIT);
        match self.registry.list(source_id, now, limit, offset) {
            Ok((total, page)) => {
                let indicators: Vec<Value> = page
                    .into_iter()
                    .map(|(value, entry)| {
                        json!({
                            "value": value,
                            "added_at": stamp(entry.added_at),
                            "expires_at": entry.expires_at.map(stamp),
                        })
                    })
                    .collect();
                (
                    StatusCode::OK,
                    Json(json!({
                        "source_id": source_id,
                        "total": total,
                        "indicators": indicators,
                    })),
                )
                    .into_response()
            }
            Err(error) => watchlist_error(error),
        }
    }

    fn require_watchlist(&self, source_id: &str) -> Result<(), Box<Response>> {
        match self.sources.get(source_id) {
            None => Err(api_error(StatusCode::NOT_FOUND, "unknown source")),
            Some(entry) => match entry.source.source_type {
                SourceType::Watchlist { .. } => Ok(()),
                _ => Err(api_error(StatusCode::CONFLICT, "source is not a watchlist")),
            },
        }
    }

    fn before_rows(&self, source_id: &str) -> Vec<WatchlistRow> {
        if self.persist.is_some() {
            self.registry
                .snapshot()
                .into_iter()
                .filter(|row| row.source_id == source_id)
                .collect()
        } else {
            Vec::new()
        }
    }

    async fn commit(
        &self,
        source_id: &str,
        before: &[WatchlistRow],
        now: DateTime<Utc>,
    ) -> Result<(), Box<Response>> {
        let Some(persist) = &self.persist else {
            return Ok(());
        };
        let rows: Vec<WatchlistRow> = self
            .registry
            .snapshot()
            .into_iter()
            .filter(|row| row.source_id == source_id)
            .collect();
        if let Err(message) = persist(source_id.to_string(), rows).await {
            self.registry.restore_source(source_id, before, now);
            return Err(api_error(StatusCode::INTERNAL_SERVER_ERROR, message));
        }
        Ok(())
    }

    fn live_values(&self, source_id: &str, now: DateTime<Utc>) -> HashSet<String> {
        self.registry
            .values(source_id, now)
            .unwrap_or_default()
            .into_iter()
            .collect()
    }

    fn count(&self, source_id: &str, op: &str, n: usize) {
        if n == 0 {
            return;
        }
        self.metrics
            .watchlist_changes_total
            .with_label_values(&[source_id, op])
            .inc_by(n as u64);
    }

    fn gauge(&self, source_id: &str, total: usize) {
        self.metrics
            .watchlist_indicators
            .with_label_values(&[source_id])
            .set(total as i64);
    }

    fn publish(&self, source_id: &str) {
        let Some(tx) = &self.trigger else {
            return;
        };
        if tx
            .try_send(RefreshTrigger::Single(source_id.to_string()))
            .is_err()
        {
            tracing::debug!(source_id, "watchlist refresh trigger was not queued");
        }
    }
}

struct PushRequest {
    ttl: Option<Duration>,
    items: Vec<WatchlistItem>,
}

#[derive(Deserialize)]
struct PushBody {
    #[serde(default)]
    ttl: Option<String>,
    indicators: Vec<WatchlistItem>,
}

#[derive(Deserialize)]
struct DeleteBody {
    indicators: Vec<String>,
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

fn default_limit() -> usize {
    LIST_DEFAULT_LIMIT
}

fn parse_push(body: &[u8]) -> Result<PushRequest, Box<Response>> {
    let parsed: PushBody = serde_json::from_slice(body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "malformed indicator request"))?;
    let ttl = match parsed.ttl.as_deref() {
        None => None,
        Some(text) => Some(
            humantime::parse_duration(text)
                .map_err(|_| api_error(StatusCode::BAD_REQUEST, "ttl is not a duration"))?,
        ),
    };
    Ok(PushRequest {
        ttl,
        items: parsed.indicators,
    })
}

fn parse_delete(body: &[u8]) -> Result<DeleteBody, Box<Response>> {
    serde_json::from_slice(body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "malformed indicator request"))
}

fn watchlist_error(error: WatchlistError) -> Response {
    let status = match error {
        WatchlistError::UnknownSource => StatusCode::NOT_FOUND,
        WatchlistError::NotAWatchlist => StatusCode::CONFLICT,
        WatchlistError::InvalidValue { .. } => StatusCode::BAD_REQUEST,
        WatchlistError::TooManyItems => StatusCode::PAYLOAD_TOO_LARGE,
        WatchlistError::LimitExceeded { .. } => StatusCode::UNPROCESSABLE_ENTITY,
    };
    error_response(status, error.to_string())
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

fn api_error(status: StatusCode, message: impl Into<String>) -> Box<Response> {
    Box::new(error_response(status, message))
}

fn stamp(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Create the zero-valued series for every declared watchlist.
pub(crate) fn preregister_metrics(metrics: &Metrics, ids: &[String]) {
    for id in ids {
        metrics
            .watchlist_indicators
            .with_label_values(&[id.as_str()])
            .set(0);
        for op in ["add", "update", "remove", "expire"] {
            let _ = metrics
                .watchlist_changes_total
                .with_label_values(&[id.as_str(), op]);
        }
    }
}

/// Drop expired indicators every 10 seconds and ask for a rebuild of each
/// watchlist that lost one.
pub(crate) fn spawn_sweeper(
    registry: Arc<WatchlistRegistry>,
    trigger: Option<mpsc::Sender<RefreshTrigger>>,
    metrics: Arc<Metrics>,
    store: Option<Arc<super::store::SqliteStateStore>>,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await;
        loop {
            tick.tick().await;
            let now = Utc::now();
            let writes = registry.write_lock();
            let _guard = writes.lock().await;
            let api = WatchlistApi {
                registry: registry.clone(),
                sources: Arc::new(DaemonSourceRegistry::empty()),
                trigger: trigger.clone(),
                metrics: metrics.clone(),
                persist: None,
            };
            let removed = registry.sweep(now);
            if !removed.is_empty()
                && let Some(store) = &store
                && let Err(error) = store.delete_expired_watchlist_rows(now).await
            {
                tracing::warn!(error = %error, "failed to delete expired watchlist indicators");
            }
            for (id, count) in removed {
                api.count(&id, "expire", count);
                if let Ok(values) = registry.values(&id, now) {
                    api.gauge(&id, values.len());
                }
                api.publish(&id);
            }
        }
    });
}

/// Load indicators saved for the declared watchlists. Rows for any other
/// source id stay in the database and are not loaded. `--clear-state`
/// deletes the table instead.
pub(crate) async fn restore_from_store(
    store: &super::store::SqliteStateStore,
    registry: &WatchlistRegistry,
    ids: &[String],
    metrics: &Metrics,
    clear: bool,
) {
    if clear {
        match store.clear_watchlist_indicators().await {
            Ok(()) => tracing::info!("Watchlist indicators cleared"),
            Err(error) => {
                tracing::warn!(error = %error, "failed to clear watchlist indicators")
            }
        }
        return;
    }
    let rows = match store.load_watchlist_rows().await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(error = %error, "failed to load watchlist indicators, starting empty");
            return;
        }
    };
    let known: HashSet<&str> = ids.iter().map(String::as_str).collect();
    let skipped = rows
        .iter()
        .filter(|row| !known.contains(row.source_id.as_str()))
        .count();
    if skipped > 0 {
        tracing::warn!(
            skipped,
            "watchlist indicators for undeclared sources were left in the state database"
        );
    }
    let now = Utc::now();
    let restored = registry.restore(&rows, now);
    if restored.expired > 0
        && let Err(error) = store.delete_expired_watchlist_rows(now).await
    {
        tracing::warn!(error = %error, "failed to delete expired watchlist indicators");
    }
    if restored.over_cap > 0 {
        tracing::warn!(
            indicators = restored.over_cap,
            "watchlist indicators above the source cap were left in the state database"
        );
    }
    for id in ids {
        if let Ok(values) = registry.values(id, now) {
            metrics
                .watchlist_indicators
                .with_label_values(&[id.as_str()])
                .set(values.len() as i64);
        }
    }
    tracing::info!(
        indicators = rows
            .len()
            .saturating_sub(skipped + restored.expired + restored.over_cap),
        "watchlist indicators restored"
    );
}

/// Indicator routes with a 4 MiB body limit. Callers merge this into the
/// daemon router before the auth layer. `WatchlistApi` is taken from the
/// router state with [`FromRef`].
pub(crate) fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    WatchlistApi: FromRef<S>,
{
    Router::new()
        .route(
            "/api/v1/sources/{source_id}/indicators",
            get(get_indicators)
                .post(post_indicators)
                .put(put_indicators)
                .delete(delete_indicators),
        )
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
}

async fn get_indicators(
    State(api): State<WatchlistApi>,
    Path(source_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Response {
    api.get(&source_id, query.limit, query.offset)
}

async fn post_indicators(
    State(api): State<WatchlistApi>,
    Path(source_id): Path<String>,
    body: Bytes,
) -> Response {
    api.post(&source_id, &body).await
}

async fn put_indicators(
    State(api): State<WatchlistApi>,
    Path(source_id): Path<String>,
    body: Bytes,
) -> Response {
    api.put(&source_id, &body).await
}

async fn delete_indicators(
    State(api): State<WatchlistApi>,
    Path(source_id): Path<String>,
    body: Bytes,
) -> Response {
    api.delete(&source_id, &body).await
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use rsigma_eval::pipeline::sources::{
        DataFormat, DynamicSource, ErrorPolicy, RefreshPolicy, SourceType,
    };
    use rsigma_runtime::sources::registry::DaemonSourceRegistry;
    use tower::ServiceExt;

    fn watch(id: &str, max: usize) -> DynamicSource {
        DynamicSource {
            id: id.into(),
            source_type: SourceType::Watchlist {
                max_indicators: max,
                max_value_length: 64,
                default_ttl: None,
            },
            refresh: RefreshPolicy::Once,
            timeout: None,
            on_error: ErrorPolicy::UseCached,
            required: true,
            default: None,
        }
    }

    fn file_source(id: &str) -> DynamicSource {
        DynamicSource {
            id: id.into(),
            source_type: SourceType::File {
                path: PathBuf::from("list.txt"),
                format: DataFormat::Lines,
                extract: None,
                stix: None,
            },
            refresh: RefreshPolicy::Once,
            timeout: None,
            on_error: ErrorPolicy::UseCached,
            required: true,
            default: None,
        }
    }

    fn api_for(sources: Vec<DynamicSource>) -> WatchlistApi {
        let owned = sources.clone();
        let external = sources
            .into_iter()
            .map(|source| (source, PathBuf::from("sources.yml")))
            .collect();
        WatchlistApi::new(
            Arc::new(WatchlistRegistry::from_sources(&owned)),
            Arc::new(DaemonSourceRegistry::from_external(external).unwrap()),
            None,
            Arc::new(Metrics::new()),
        )
    }

    async fn call(api: WatchlistApi, method: &str, uri: &str, body: &str) -> (StatusCode, Value) {
        let response = routes()
            .with_state(api)
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        (status, value)
    }

    #[tokio::test]
    async fn post_get_put_delete_round_trip() {
        let (tx, mut rx) = mpsc::channel(4);
        let mut api = api_for(vec![watch("c2_ips", 10)]);
        api.trigger = Some(tx);
        let (status, body) = call(
            api.clone(),
            "POST",
            "/api/v1/sources/c2_ips/indicators",
            r#"{"ttl":"7d","indicators":["198.51.100.7",{"value":"203.0.113.9","ttl":"24h"}]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["added"], 2);
        assert_eq!(body["updated"], 0);
        assert_eq!(body["total"], 2);
        assert!(matches!(
            rx.try_recv().unwrap(),
            RefreshTrigger::Single(id) if id == "c2_ips"
        ));

        let (status, listed) = call(
            api.clone(),
            "GET",
            "/api/v1/sources/c2_ips/indicators?limit=1&offset=1",
            "",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed["total"], 2);
        assert_eq!(listed["indicators"].as_array().unwrap().len(), 1);
        assert_eq!(listed["indicators"][0]["value"], "203.0.113.9");
        assert!(listed["indicators"][0]["expires_at"].is_string());

        let (status, replaced) = call(
            api.clone(),
            "PUT",
            "/api/v1/sources/c2_ips/indicators",
            r#"{"indicators":["203.0.113.9","198.51.100.8"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replaced["total"], 2);
        assert_eq!(replaced["removed"], 1);

        let (status, deleted) = call(
            api.clone(),
            "DELETE",
            "/api/v1/sources/c2_ips/indicators",
            r#"{"indicators":["203.0.113.9","missing.example"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(deleted["removed"], 1);
        assert_eq!(deleted["not_found"], 1);
        assert_eq!(deleted["total"], 1);

        let rendered = api.metrics.registry.gather();
        let text = prometheus::TextEncoder::new()
            .encode_to_string(&rendered)
            .unwrap();
        assert!(text.contains("rsigma_watchlist_indicators{source_id=\"c2_ips\"} 1"));
        assert!(text.contains("rsigma_watchlist_changes_total{op=\"add\",source_id=\"c2_ips\"}"));
    }

    #[tokio::test]
    async fn status_codes() {
        let api = api_for(vec![watch("c2_ips", 1), file_source("feeds")]);

        let (status, body) = call(
            api.clone(),
            "POST",
            "/api/v1/sources/missing/indicators",
            r#"{"indicators":["a"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "unknown source");

        let (status, _) = call(
            api.clone(),
            "POST",
            "/api/v1/sources/feeds/indicators",
            r#"{"indicators":["a"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, body) = call(
            api.clone(),
            "POST",
            "/api/v1/sources/c2_ips/indicators",
            r#"{"indicators":["  "]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "indicator 0: value is empty");

        let (status, _) = call(
            api.clone(),
            "POST",
            "/api/v1/sources/c2_ips/indicators",
            "not-json",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = call(
            api.clone(),
            "POST",
            "/api/v1/sources/c2_ips/indicators",
            r#"{"indicators":[{"value":"a","expires_at":"yesterday"}]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = call(
            api.clone(),
            "POST",
            "/api/v1/sources/c2_ips/indicators",
            r#"{"ttl":"soon","indicators":["a"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let too_many = format!(
            "{{\"indicators\":[{}]}}",
            (0..10_001)
                .map(|i| format!("\"v{i}\""))
                .collect::<Vec<_>>()
                .join(",")
        );
        let (status, _) = call(
            api.clone(),
            "POST",
            "/api/v1/sources/c2_ips/indicators",
            &too_many,
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

        let (status, _) = call(
            api.clone(),
            "POST",
            "/api/v1/sources/c2_ips/indicators",
            r#"{"indicators":["a","b"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, listed) =
            call(api.clone(), "GET", "/api/v1/sources/c2_ips/indicators", "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed["total"], 0);
    }

    #[tokio::test]
    async fn persist_failure_is_500_and_keeps_memory() {
        let mut api = api_for(vec![watch("c2_ips", 10)]);
        let (status, _) = call(
            api.clone(),
            "POST",
            "/api/v1/sources/c2_ips/indicators",
            r#"{"indicators":["198.51.100.7"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        api.persist = Some(Arc::new(|_, _| {
            Box::pin(async { Err("state database write failed".into()) })
        }));
        let (status, body) = call(
            api.clone(),
            "POST",
            "/api/v1/sources/c2_ips/indicators",
            r#"{"indicators":["203.0.113.9"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], "state database write failed");
        let values = api.registry.values("c2_ips", Utc::now()).unwrap();
        assert_eq!(values, vec!["198.51.100.7".to_string()]);
    }

    #[tokio::test]
    async fn oversized_body_is_413() {
        let api = api_for(vec![watch("c2_ips", 10)]);
        let response = routes()
            .with_state(api)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/sources/c2_ips/indicators")
                    .body(Body::from(vec![b'a'; BODY_LIMIT + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn indicator_route_does_not_capture_resolve() {
        let app = Router::new()
            .route(
                "/api/v1/sources/resolve/{source_id}",
                post(|| async { "resolve" }),
            )
            .route(
                "/api/v1/sources/{source_id}/indicators",
                post(|| async { "indicators" }),
            );
        let resolve = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/sources/resolve/c2_ips")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let indicators = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/sources/c2_ips/indicators")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let resolve_body = axum::body::to_bytes(resolve.into_body(), 64).await.unwrap();
        let indicator_body = axum::body::to_bytes(indicators.into_body(), 64)
            .await
            .unwrap();
        assert_eq!(resolve_body.as_ref(), b"resolve");
        assert_eq!(indicator_body.as_ref(), b"indicators");
    }

    #[test]
    fn declared_watchlists_start_at_zero() {
        let metrics = Metrics::new();
        preregister_metrics(&metrics, &["c2_ips".into()]);
        let text = prometheus::TextEncoder::new()
            .encode_to_string(&metrics.registry.gather())
            .unwrap();
        assert!(text.contains("rsigma_watchlist_indicators{source_id=\"c2_ips\"} 0"));
        assert!(text.contains("op=\"expire\""));
    }

    async fn wait_until(flag: &AtomicUsize, value: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while flag.load(Ordering::SeqCst) != value {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {value} persist calls"
            );
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn a_failed_write_does_not_roll_back_another_source() {
        let mut api = api_for(vec![watch("a", 10), watch("b", 10)]);
        let gate = Arc::new(tokio::sync::Notify::new());
        let entered = Arc::new(AtomicUsize::new(0));
        let gate_persist = Arc::clone(&gate);
        let entered_persist = Arc::clone(&entered);
        api.set_persist(Arc::new(move |source_id, _| {
            let gate = Arc::clone(&gate_persist);
            let entered = Arc::clone(&entered_persist);
            Box::pin(async move {
                entered.fetch_add(1, Ordering::SeqCst);
                if source_id == "a" {
                    gate.notified().await;
                    return Err("state database write failed".into());
                }
                Ok(())
            })
        }));

        let first = tokio::spawn(call(
            api.clone(),
            "POST",
            "/api/v1/sources/a/indicators",
            r#"{"indicators":["1.1.1.1"]}"#,
        ));
        wait_until(&entered, 1).await;
        let second = tokio::spawn(call(
            api.clone(),
            "POST",
            "/api/v1/sources/b/indicators",
            r#"{"indicators":["2.2.2.2"]}"#,
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            entered.load(Ordering::SeqCst),
            1,
            "the second write overlapped the first"
        );
        gate.notify_one();

        let (status_a, _) = first.await.unwrap();
        let (status_b, _) = second.await.unwrap();
        assert_eq!(status_a, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status_b, StatusCode::OK);
        let now = Utc::now();
        assert!(api.registry.values("a", now).unwrap().is_empty());
        assert_eq!(api.registry.values("b", now).unwrap(), vec!["2.2.2.2"]);
    }

    #[tokio::test]
    async fn overlapping_writes_persist_the_set_memory_keeps() {
        let mut api = api_for(vec![watch("c2_ips", 10)]);
        let gate = Arc::new(tokio::sync::Notify::new());
        let entered = Arc::new(AtomicUsize::new(0));
        let stored = Arc::new(std::sync::Mutex::new(Vec::<Vec<String>>::new()));
        let gate_persist = Arc::clone(&gate);
        let entered_persist = Arc::clone(&entered);
        let stored_persist = Arc::clone(&stored);
        api.set_persist(Arc::new(move |_source_id, rows| {
            let gate = Arc::clone(&gate_persist);
            let entered = Arc::clone(&entered_persist);
            let stored = Arc::clone(&stored_persist);
            Box::pin(async move {
                let n = entered.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    gate.notified().await;
                }
                stored
                    .lock()
                    .unwrap()
                    .push(rows.iter().map(|row| row.value.clone()).collect::<Vec<_>>());
                Ok(())
            })
        }));

        let first = tokio::spawn(call(
            api.clone(),
            "POST",
            "/api/v1/sources/c2_ips/indicators",
            r#"{"indicators":["1.1.1.1"]}"#,
        ));
        wait_until(&entered, 1).await;
        let second = tokio::spawn(call(
            api.clone(),
            "POST",
            "/api/v1/sources/c2_ips/indicators",
            r#"{"indicators":["2.2.2.2"]}"#,
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            entered.load(Ordering::SeqCst),
            1,
            "the second write overlapped the first"
        );
        gate.notify_one();

        let (status_a, _) = first.await.unwrap();
        let (status_b, _) = second.await.unwrap();
        assert_eq!(status_a, StatusCode::OK);
        assert_eq!(status_b, StatusCode::OK);
        let memory = api.registry.values("c2_ips", Utc::now()).unwrap();
        let stored = stored.lock().unwrap();
        assert_eq!(stored.last().unwrap(), &memory);
    }

    #[tokio::test]
    async fn restore_leaves_out_rows_above_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let store = super::super::store::SqliteStateStore::open(&dir.path().join("state.db"))
            .expect("state db");
        let now = Utc::now();
        let rows: Vec<WatchlistRow> = ["a", "b", "c"]
            .into_iter()
            .map(|value| WatchlistRow {
                source_id: "c2".into(),
                value: value.into(),
                added_at: now,
                expires_at: None,
            })
            .collect();
        store
            .replace_watchlist_rows("c2", &rows)
            .await
            .expect("store rows");
        let registry = WatchlistRegistry::from_sources(&[watch("c2", 100)]);
        let mut ids = HashSet::new();
        ids.insert("c2".into());
        registry.apply_reference_limits(&ids, 2);
        let metrics = Metrics::new();
        preregister_metrics(&metrics, &["c2".into()]);
        restore_from_store(&store, &registry, &["c2".into()], &metrics, false).await;
        assert_eq!(registry.values("c2", Utc::now()).unwrap(), vec!["a", "b"]);
    }
}
