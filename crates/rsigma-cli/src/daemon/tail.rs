//! Live detection tail: session management and the chunked-NDJSON producer
//! behind `GET /api/v1/detections/stream`.
//!
//! This mirrors the [event tap](super::tap) design on the output side. The
//! daemon's sink task feeds every post-enrichment result entry to active tail
//! sessions through bounded per-session channels with non-blocking `try_send`,
//! so a slow tail client can never backpressure the sink task or stall the
//! at-least-once ack-join. Optional `level` / `rule` filters are applied at the
//! sink (server-side) so a noisy daemon's tail stays readable.

use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{StatusCode, header};
use axum::response::Response;
use rsigma_eval::EvaluationResult;
use rsigma_parser::Level;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::metrics::Metrics;

/// Live detection-tail state shared with the HTTP handler. Present in
/// `AppState` only when the tail is enabled.
#[derive(Clone)]
pub(crate) struct TailState {
    pub registry: Arc<TailRegistry>,
    pub metrics: Arc<Metrics>,
}

impl TailState {
    pub(crate) fn new(registry: Arc<TailRegistry>, metrics: Arc<Metrics>) -> Self {
        Self { registry, metrics }
    }
}

/// Severity rank for `level` filtering. `Level` is not `Ord`, so map the
/// variants to their natural severity order.
fn level_rank(level: Level) -> u8 {
    match level {
        Level::Informational => 0,
        Level::Low => 1,
        Level::Medium => 2,
        Level::High => 3,
        Level::Critical => 4,
    }
}

/// Server-side filter applied to each result before it reaches a tail session.
#[derive(Debug, Clone, Default)]
pub(crate) struct TailFilter {
    /// Minimum severity; a result below it (or without a level) is dropped.
    min_level: Option<Level>,
    /// Case-insensitive substring matched against the rule title or id.
    rule: Option<String>,
}

impl TailFilter {
    fn matches(&self, result: &EvaluationResult) -> bool {
        if let Some(min) = self.min_level {
            match result.header.level {
                Some(level) if level_rank(level) >= level_rank(min) => {}
                _ => return false,
            }
        }
        if let Some(needle) = &self.rule {
            let title = result.header.rule_title.to_lowercase();
            let id = result
                .header
                .rule_id
                .as_deref()
                .unwrap_or_default()
                .to_lowercase();
            if !title.contains(needle) && !id.contains(needle) {
                return false;
            }
        }
        true
    }
}

/// A single active tail session: a filter plus a bounded channel into the
/// streaming task, with a drop counter shared with the session handle.
pub(crate) struct TailSession {
    id: u64,
    filter: TailFilter,
    tx: mpsc::Sender<Arc<EvaluationResult>>,
    dropped: Arc<AtomicU64>,
}

impl TailSession {
    /// Offer one result without ever blocking. On a full or closed channel the
    /// result is dropped and counted, so the sink task never waits on a slow
    /// tail client.
    fn offer(&self, result: Arc<EvaluationResult>) {
        if self.tx.try_send(result).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Handle returned to the streaming task on a successful
/// [`TailRegistry::register`]. Deregisters the session on drop, so a dropped
/// client connection frees its slot automatically.
pub(crate) struct TailSessionHandle {
    id: u64,
    registry: Arc<TailRegistry>,
    rx: mpsc::Receiver<Arc<EvaluationResult>>,
    dropped: Arc<AtomicU64>,
}

impl Drop for TailSessionHandle {
    fn drop(&mut self) {
        self.registry.deregister(self.id);
    }
}

/// The set of active tail sessions plus the daemon-wide tail limits.
pub struct TailRegistry {
    buffer_events: usize,
    max_sessions: usize,
    next_id: AtomicU64,
    sessions: Mutex<Vec<Arc<TailSession>>>,
    snapshot: ArcSwap<Vec<Arc<TailSession>>>,
}

impl TailRegistry {
    pub fn new(buffer_events: usize, max_sessions: usize) -> Arc<Self> {
        Arc::new(Self {
            buffer_events: buffer_events.max(1),
            max_sessions,
            next_id: AtomicU64::new(0),
            sessions: Mutex::new(Vec::new()),
            snapshot: ArcSwap::from_pointee(Vec::new()),
        })
    }

    fn register(self: &Arc<Self>, filter: TailFilter) -> Option<TailSessionHandle> {
        let mut sessions = self.sessions.lock().expect("tail sessions mutex");
        if sessions.len() >= self.max_sessions {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(self.buffer_events);
        let dropped = Arc::new(AtomicU64::new(0));
        sessions.push(Arc::new(TailSession {
            id,
            filter,
            tx,
            dropped: dropped.clone(),
        }));
        self.publish(&sessions);
        Some(TailSessionHandle {
            id,
            registry: self.clone(),
            rx,
            dropped,
        })
    }

    fn deregister(&self, id: u64) {
        let mut sessions = self.sessions.lock().expect("tail sessions mutex");
        let before = sessions.len();
        sessions.retain(|s| s.id != id);
        if sessions.len() != before {
            self.publish(&sessions);
        }
    }

    fn publish(&self, sessions: &[Arc<TailSession>]) {
        self.snapshot.store(Arc::new(sessions.to_vec()));
    }

    /// Fan one batch of post-enrichment results out to active tail sessions.
    /// Called from the sink task; cheap when no session is active (one
    /// `ArcSwap` load plus an empty check). An entry is cloned once into an
    /// `Arc` only if at least one session's filter matches it.
    pub fn capture(&self, results: &[EvaluationResult]) {
        let snapshot = self.snapshot.load();
        if snapshot.is_empty() {
            return;
        }
        for entry in results {
            let mut shared: Option<Arc<EvaluationResult>> = None;
            for session in snapshot.iter() {
                if session.filter.matches(entry) {
                    let arc = shared.get_or_insert_with(|| Arc::new(entry.clone()));
                    session.offer(arc.clone());
                }
            }
        }
    }
}

/// Raw query string for `GET /api/v1/detections/stream`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct TailQuery {
    duration: Option<String>,
    limit: Option<u64>,
    level: Option<String>,
    rule: Option<String>,
}

/// Validated tail parameters.
#[derive(Debug)]
pub(crate) struct ParsedParams {
    /// Capture window; `None` streams until the client disconnects or `limit`.
    pub duration: Option<Duration>,
    pub limit: Option<u64>,
    pub filter: TailFilter,
}

/// Validate the query params. Returns a human-readable message on failure,
/// which the handler maps to a `400`.
pub(crate) fn parse_params(query: &TailQuery) -> Result<ParsedParams, String> {
    let duration = match query.duration.as_deref() {
        None => None,
        Some(s) => {
            Some(humantime::parse_duration(s).map_err(|e| format!("invalid duration '{s}': {e}"))?)
        }
    };

    let min_level = match query.level.as_deref() {
        None => None,
        Some(s) => Some(Level::from_str(s).map_err(|_| {
            format!("invalid level '{s}' (expected informational, low, medium, high, or critical)")
        })?),
    };

    let rule = query
        .rule
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase);

    Ok(ParsedParams {
        duration,
        limit: query.limit,
        filter: TailFilter { min_level, rule },
    })
}

/// Register a session and build the streaming `200` response. Returns `None`
/// when the concurrent-session cap is reached (the caller maps this to `409`).
pub(crate) fn stream_response(
    registry: &Arc<TailRegistry>,
    params: ParsedParams,
    metrics: Arc<Metrics>,
) -> Option<Response> {
    let handle = registry.register(params.filter)?;

    metrics.tail_active_sessions.inc();

    let (body_tx, body_rx) = mpsc::channel::<Result<String, std::io::Error>>(64);
    let producer = Producer {
        handle,
        duration: params.duration,
        limit: params.limit,
        metrics,
        body_tx,
    };
    tokio::spawn(producer.run());

    Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/x-ndjson")
            .body(Body::from_stream(ReceiverStream::new(body_rx)))
            .expect("static tail response builds"),
    )
}

/// The async task draining one tail session into the HTTP body.
struct Producer {
    handle: TailSessionHandle,
    duration: Option<Duration>,
    limit: Option<u64>,
    metrics: Arc<Metrics>,
    body_tx: mpsc::Sender<Result<String, std::io::Error>>,
}

impl Producer {
    async fn run(mut self) {
        let deadline = self.duration.map(|d| tokio::time::Instant::now() + d);
        let mut streamed: u64 = 0;

        loop {
            if self.limit.is_some_and(|limit| streamed >= limit) {
                break;
            }

            let timeout = async {
                match deadline {
                    Some(dl) => tokio::time::sleep_until(dl).await,
                    // No duration bound: stream until disconnect or limit.
                    None => std::future::pending::<()>().await,
                }
            };

            let result = tokio::select! {
                biased;
                _ = timeout => break,
                // Tear the session down promptly when the client disconnects,
                // even while idle, so its slot is freed without a deadline.
                _ = self.body_tx.closed() => break,
                next = self.handle.rx.recv() => match next {
                    Some(result) => result,
                    None => break,
                },
            };

            let mut line = serde_json::to_string(&*result).unwrap_or_default();
            line.push('\n');
            if self.body_tx.send(Ok(line)).await.is_err() {
                break; // client disconnected mid-send
            }
            streamed += 1;
        }

        let dropped = self.handle.dropped.load(Ordering::Relaxed);
        if dropped > 0 {
            self.metrics.tail_detections_dropped_total.inc_by(dropped);
        }
        let summary = serde_json::json!({
            "rsigma_tail_summary": { "streamed": streamed, "dropped": dropped }
        });
        let _ = self.body_tx.send(Ok(format!("{summary}\n"))).await;

        self.metrics.tail_active_sessions.dec();
        // `self.handle` drops here, deregistering the session.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::{DetectionBody, ResultBody, RuleHeader};
    use std::collections::HashMap;

    fn detection(title: &str, level: Option<Level>) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: title.to_string(),
                rule_id: None,
                level,
                tags: Vec::new(),
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec!["selection".to_string()],
                matched_fields: Vec::new(),
                event: None,
            }),
        }
    }

    #[test]
    fn filter_matches_everything_when_empty() {
        let f = TailFilter::default();
        assert!(f.matches(&detection("anything", None)));
        assert!(f.matches(&detection("anything", Some(Level::Low))));
    }

    #[test]
    fn level_filter_excludes_below_and_unleveled() {
        let f = TailFilter {
            min_level: Some(Level::High),
            rule: None,
        };
        assert!(f.matches(&detection("a", Some(Level::High))));
        assert!(f.matches(&detection("a", Some(Level::Critical))));
        assert!(!f.matches(&detection("a", Some(Level::Medium))));
        assert!(!f.matches(&detection("a", None)));
    }

    #[test]
    fn rule_filter_is_case_insensitive_substring() {
        let f = TailFilter {
            min_level: None,
            rule: Some("whoami".to_string()),
        };
        assert!(f.matches(&detection("Detect WHOAMI usage", None)));
        assert!(!f.matches(&detection("Detect netcat", None)));
    }

    #[tokio::test]
    async fn register_respects_cap_and_deregisters_on_drop() {
        let reg = TailRegistry::new(8, 2);
        let a = reg.register(TailFilter::default());
        let b = reg.register(TailFilter::default());
        assert!(a.is_some() && b.is_some());
        // Third session is over the cap.
        assert!(reg.register(TailFilter::default()).is_none());
        // Dropping a handle frees its slot.
        drop(a);
        assert!(reg.register(TailFilter::default()).is_some());
    }

    #[tokio::test]
    async fn capture_applies_filter_and_counts_drops() {
        let reg = TailRegistry::new(1, 1);
        let handle = reg
            .register(TailFilter {
                min_level: Some(Level::High),
                rule: None,
            })
            .expect("registered");

        // Below the level filter: never delivered.
        reg.capture(&[detection("low", Some(Level::Low))]);
        // At/above: first fills the capacity-1 channel, second is dropped.
        reg.capture(&[detection("hi1", Some(Level::High))]);
        reg.capture(&[detection("hi2", Some(Level::Critical))]);

        assert_eq!(handle.dropped.load(Ordering::Relaxed), 1);
    }
}
