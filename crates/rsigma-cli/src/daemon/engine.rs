use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rsigma_eval::Event;

use super::metrics::Metrics;
use super::state::DaemonEngine;

/// Shared daemon engine behind a std::sync::Mutex.
///
/// std::sync::Mutex is preferred over tokio::sync::Mutex here because the lock
/// is never held across .await points — process_event and load_rules are both
/// synchronous operations.
pub type SharedEngine = Arc<Mutex<DaemonEngine>>;

/// Process a single JSON line through the engine and write matches to stdout.
pub fn process_line(
    engine: &mut DaemonEngine,
    line: &str,
    metrics: &Metrics,
    pretty: bool,
    event_filter: &crate::EventFilter,
) {
    let value: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            metrics.events_parse_errors.inc();
            tracing::debug!(error = %e, "Invalid JSON on input");
            return;
        }
    };

    let payloads = crate::apply_event_filter(&value, event_filter);

    for payload in payloads {
        let event = Event::from_value(&payload);

        let start = Instant::now();
        let result = engine.process_event(&event);
        let elapsed = start.elapsed().as_secs_f64();

        metrics.events_processed.inc();
        metrics.processing_latency.observe(elapsed);

        let stdout = std::io::stdout();
        let mut out = stdout.lock();

        for m in &result.detections {
            metrics.detection_matches.inc();
            let json = if pretty {
                serde_json::to_string_pretty(m)
            } else {
                serde_json::to_string(m)
            };
            if let Ok(j) = json {
                let _ = writeln!(out, "{j}");
            }
        }

        for m in &result.correlations {
            metrics.correlation_matches.inc();
            let json = if pretty {
                serde_json::to_string_pretty(m)
            } else {
                serde_json::to_string(m)
            };
            if let Ok(j) = json {
                let _ = writeln!(out, "{j}");
            }
        }
    }
}
