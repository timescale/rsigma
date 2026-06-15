//! Shared, format-aware event stream loop.
//!
//! Both `engine eval` and `rule backtest` read a corpus (NDJSON, syslog,
//! plain, logfmt, CEF, or EVTX), parse each record into an [`Event`], apply
//! the optional jq/JSONPath filter, optionally feed the field observer, and
//! evaluate the result through an engine. The only thing that differs between
//! the two commands is what happens with each [`EvaluationResult`]: eval
//! renders it, backtest accumulates per-rule counters.
//!
//! This module owns the parsing/filtering/observation half so the two
//! commands cannot drift on input handling. The per-result half is supplied
//! by the caller as a `FnMut(&EvaluationResult)` callback, and the choice of
//! engine is abstracted behind [`EventProcessor`].

use std::io::BufRead;

use rsigma_eval::{CorrelationEngine, Engine, EvaluationResult, Event, FieldObserver, JsonEvent};

use crate::EventFilter;

/// Drives a single decoded event through one of the two engine kinds.
///
/// The stateful [`CorrelationEngine`] and the stateless [`Engine`] expose
/// different evaluation methods (`process_event` vs `evaluate`); this trait
/// hides that difference so the stream loop is engine-agnostic. Each produced
/// [`EvaluationResult`] is forwarded to `on_result` in evaluation order.
pub(crate) trait EventProcessor {
    fn process<E: Event>(&mut self, event: &E, on_result: &mut dyn FnMut(&EvaluationResult));
}

/// [`EventProcessor`] backed by a stateful correlation engine.
pub(crate) struct CorrelationProcessor<'a> {
    pub engine: &'a mut CorrelationEngine,
}

impl EventProcessor for CorrelationProcessor<'_> {
    fn process<E: Event>(&mut self, event: &E, on_result: &mut dyn FnMut(&EvaluationResult)) {
        for m in &self.engine.process_event(event) {
            on_result(m);
        }
    }
}

/// [`EventProcessor`] backed by a stateless detection engine.
pub(crate) struct DetectionProcessor<'a> {
    pub engine: &'a Engine,
}

impl EventProcessor for DetectionProcessor<'_> {
    fn process<E: Event>(&mut self, event: &E, on_result: &mut dyn FnMut(&EvaluationResult)) {
        for m in &self.engine.evaluate(event) {
            on_result(m);
        }
    }
}

/// Feed one event to the observer if one is configured; no-op otherwise.
/// Inlined to keep the disabled path a single null-pointer check.
#[inline]
fn observe_event<E: Event + ?Sized>(observer: Option<&FieldObserver>, event: &E) {
    if let Some(observer) = observer {
        observer.observe(event);
    }
}

/// Stream lines from `reader` through `processor` with format-aware parsing,
/// invoking `on_result` for each evaluation result.
///
/// Returns the number of lines read (events), matching the historical eval
/// "Processed N events" semantics: blank and unreadable lines are counted but
/// skipped before evaluation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn stream_events<P: EventProcessor>(
    reader: impl BufRead,
    event_filter: &EventFilter,
    input_format_str: &str,
    syslog_tz_str: &str,
    syslog_strip_bom: bool,
    observe: Option<&FieldObserver>,
    processor: &mut P,
    on_result: &mut dyn FnMut(&EvaluationResult),
) -> u64 {
    let mut line_num = 0u64;

    #[cfg(feature = "daemon")]
    let format =
        crate::commands::parse_input_format(input_format_str, syslog_tz_str, syslog_strip_bom);
    #[cfg(not(feature = "daemon"))]
    let _ = (input_format_str, syslog_tz_str, syslog_strip_bom);

    for line in reader.lines() {
        line_num += 1;
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Error reading line {line_num}: {e}");
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        // Format-aware parsing: use rsigma-runtime's input adapters when
        // available (the `daemon` feature), JSON-only otherwise.
        #[cfg(feature = "daemon")]
        process_line(processor, &line, &format, event_filter, observe, on_result);
        #[cfg(not(feature = "daemon"))]
        process_line_json(processor, &line, event_filter, observe, on_result);
    }

    line_num
}

/// Parse one line with the configured format adapter and evaluate it.
#[cfg(feature = "daemon")]
fn process_line<P: EventProcessor>(
    processor: &mut P,
    line: &str,
    format: &rsigma_runtime::InputFormat,
    event_filter: &EventFilter,
    observe: Option<&FieldObserver>,
    on_result: &mut dyn FnMut(&EvaluationResult),
) {
    let Some(decoded) = rsigma_runtime::parse_line(line, format) else {
        return;
    };
    // For JSON events, apply the event filter (which may produce multiple
    // payloads). Non-JSON events evaluate directly (no event filter).
    if matches!(decoded, rsigma_runtime::EventInputDecoded::Json(_)) {
        let json_value = decoded.to_json();
        for payload in crate::apply_event_filter(&json_value, event_filter) {
            let event = JsonEvent::borrow(&payload);
            observe_event(observe, &event);
            processor.process(&event, on_result);
        }
    } else {
        observe_event(observe, &decoded);
        processor.process(&decoded, on_result);
    }
}

/// Parse one line as JSON and evaluate it (the no-`daemon` fallback).
#[cfg(not(feature = "daemon"))]
fn process_line_json<P: EventProcessor>(
    processor: &mut P,
    line: &str,
    event_filter: &EventFilter,
    observe: Option<&FieldObserver>,
    on_result: &mut dyn FnMut(&EvaluationResult),
) {
    let value: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Invalid JSON: {e}");
            return;
        }
    };

    for payload in crate::apply_event_filter(&value, event_filter) {
        let event = JsonEvent::borrow(&payload);
        observe_event(observe, &event);
        processor.process(&event, on_result);
    }
}

/// Stream every record from an EVTX file through `processor`, invoking
/// `on_result` for each evaluation result. Returns the number of records read.
///
/// Exits with [`crate::exit_code::RULE_ERROR`] if the file cannot be opened,
/// matching the historical eval behavior.
#[cfg(feature = "evtx")]
pub(crate) fn stream_evtx_events<P: EventProcessor>(
    path: &std::path::Path,
    event_filter: &EventFilter,
    observe: Option<&FieldObserver>,
    processor: &mut P,
    on_result: &mut dyn FnMut(&EvaluationResult),
) -> u64 {
    let mut reader = rsigma_runtime::EvtxFileReader::open(path).unwrap_or_else(|e| {
        eprintln!("Error opening EVTX file '{}': {e}", path.display());
        std::process::exit(crate::exit_code::RULE_ERROR);
    });

    let mut rec_count = 0u64;
    for record in reader.records() {
        rec_count += 1;
        let value = match record {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error reading EVTX record {rec_count}: {e}");
                continue;
            }
        };

        for payload in crate::apply_event_filter(&value, event_filter) {
            let event = JsonEvent::borrow(&payload);
            observe_event(observe, &event);
            processor.process(&event, on_result);
        }
    }

    rec_count
}
