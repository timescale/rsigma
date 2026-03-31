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

/// Process a batch of JSON lines using parallel batch evaluation.
///
/// Parses each line, applies the event filter, then evaluates all resulting
/// events together via `DaemonEngine::process_batch()` (which uses parallel
/// detection + sequential correlation). Returns one `ProcessResult` per
/// input line, with multi-payload lines merged.
pub fn process_batch_lines(
    engine: &mut DaemonEngine,
    batch: &[String],
    metrics: &Metrics,
    event_filter: &crate::EventFilter,
) -> Vec<ProcessResult> {
    // Phase 1: Parse JSON and apply event filters, tracking line origin.
    // Payloads are owned here so Events can borrow them during evaluation.
    let mut parsed: Vec<(usize, Vec<serde_json::Value>)> = Vec::with_capacity(batch.len());
    for (line_idx, line) in batch.iter().enumerate() {
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(value) => {
                let payloads = crate::apply_event_filter(&value, event_filter);
                if !payloads.is_empty() {
                    parsed.push((line_idx, payloads));
                }
            }
            Err(e) => {
                metrics.events_parse_errors.inc();
                tracing::debug!(error = %e, "Invalid JSON on input");
            }
        }
    }

    // Flatten: (line_idx, &Value) for each payload across all lines
    let mut flat: Vec<(usize, &serde_json::Value)> = Vec::new();
    for (line_idx, payloads) in &parsed {
        for payload in payloads {
            flat.push((*line_idx, payload));
        }
    }

    if flat.is_empty() {
        return (0..batch.len())
            .map(|_| ProcessResult {
                detections: vec![],
                correlations: vec![],
            })
            .collect();
    }

    // Phase 2: Batch evaluation — parallel detection + sequential correlation
    let events: Vec<Event> = flat.iter().map(|(_, v)| Event::from_value(v)).collect();
    let event_refs: Vec<&Event> = events.iter().collect();

    let start = Instant::now();
    let batch_results = engine.process_batch(&event_refs);
    let elapsed = start.elapsed().as_secs_f64();
    let per_event_latency = elapsed / event_refs.len() as f64;

    // Phase 3: Merge results per input line and update metrics
    let mut line_results: Vec<ProcessResult> = (0..batch.len())
        .map(|_| ProcessResult {
            detections: vec![],
            correlations: vec![],
        })
        .collect();

    for ((line_idx, _), result) in flat.iter().zip(batch_results) {
        metrics.events_processed.inc();
        metrics.processing_latency.observe(per_event_latency);
        metrics
            .detection_matches
            .inc_by(result.detections.len() as u64);
        metrics
            .correlation_matches
            .inc_by(result.correlations.len() as u64);

        line_results[*line_idx].detections.extend(result.detections);
        line_results[*line_idx]
            .correlations
            .extend(result.correlations);
    }

    line_results
}
