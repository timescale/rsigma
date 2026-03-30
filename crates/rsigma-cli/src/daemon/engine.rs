use std::sync::{Arc, Mutex};
use std::time::Instant;

use rsigma_eval::{Event, ProcessResult};

use super::metrics::Metrics;
use super::state::DaemonEngine;

/// Shared daemon engine behind a std::sync::Mutex.
///
/// std::sync::Mutex is preferred over tokio::sync::Mutex here because the lock
/// is never held across .await points — process_event and load_rules are both
/// synchronous operations.
pub type SharedEngine = Arc<Mutex<DaemonEngine>>;

/// Process a single JSON line through the engine and return matches.
///
/// Parses the JSON, applies the event filter (which may produce multiple
/// payloads from a single line), evaluates each payload against the engine,
/// and returns a merged `ProcessResult` containing all detections and
/// correlations. Updates metrics counters as a side-effect.
pub fn process_line(
    engine: &mut DaemonEngine,
    line: &str,
    metrics: &Metrics,
    event_filter: &crate::EventFilter,
) -> ProcessResult {
    let value: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            metrics.events_parse_errors.inc();
            tracing::debug!(error = %e, "Invalid JSON on input");
            return ProcessResult {
                detections: vec![],
                correlations: vec![],
            };
        }
    };

    let payloads = crate::apply_event_filter(&value, event_filter);

    let mut merged = ProcessResult {
        detections: Vec::new(),
        correlations: Vec::new(),
    };

    for payload in payloads {
        let event = Event::from_value(&payload);

        let start = Instant::now();
        let result = engine.process_event(&event);
        let elapsed = start.elapsed().as_secs_f64();

        metrics.events_processed.inc();
        metrics.processing_latency.observe(elapsed);

        metrics
            .detection_matches
            .inc_by(result.detections.len() as u64);
        metrics
            .correlation_matches
            .inc_by(result.correlations.len() as u64);

        merged.detections.extend(result.detections);
        merged.correlations.extend(result.correlations);
    }

    merged
}
