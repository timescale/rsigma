use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use std::process;

use rsigma_eval::{CorrelationEngine, Engine, JsonEvent, Pipeline};
use rsigma_parser::SigmaCollection;

use crate::EventFilter;

/// Resolved event source from the `--event` flag.
enum EventSource {
    /// Inline JSON string (e.g. `-e '{"key":"value"}'`).
    SingleJson(String),
    /// NDJSON from a file (e.g. `-e @events.ndjson`).
    NdjsonFile(PathBuf),
    /// NDJSON from stdin (no `--event` flag).
    Stdin,
}

/// Resolve the `--event` argument into an `EventSource`.
/// Detects `@path` prefix for file-based input.
fn resolve_event_source(event_json: Option<String>) -> EventSource {
    match event_json {
        Some(s) if s.starts_with('@') => {
            let path = PathBuf::from(&s[1..]);
            if !path.exists() {
                eprintln!("Event file not found: {}", path.display());
                process::exit(1);
            }
            EventSource::NdjsonFile(path)
        }
        Some(s) => EventSource::SingleJson(s),
        None => EventSource::Stdin,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_eval(
    rules_path: PathBuf,
    event_json: Option<String>,
    pretty: bool,
    pipeline_paths: Vec<PathBuf>,
    jq: Option<String>,
    jsonpath: Option<String>,
    suppress: Option<String>,
    action: Option<String>,
    no_detections: bool,
    include_event: bool,
    correlation_event_mode: String,
    max_correlation_events: usize,
    timestamp_fields: Vec<String>,
    input_format: String,
    syslog_tz: String,
) {
    let collection = crate::load_collection(&rules_path);
    let pipelines = crate::load_pipelines(&pipeline_paths);
    let has_correlations = !collection.correlations.is_empty();

    let event_filter = crate::build_event_filter(jq, jsonpath);

    let event_source = resolve_event_source(event_json);

    let corr_config = crate::build_correlation_config(
        suppress,
        action,
        no_detections,
        correlation_event_mode,
        max_correlation_events,
        timestamp_fields,
    );

    if has_correlations {
        cmd_eval_with_correlations(
            collection,
            &rules_path,
            event_source,
            pretty,
            &pipelines,
            &event_filter,
            corr_config,
            include_event,
            &input_format,
            &syslog_tz,
        );
    } else {
        cmd_eval_detection_only(
            collection,
            &rules_path,
            event_source,
            pretty,
            &pipelines,
            &event_filter,
            include_event,
            &input_format,
            &syslog_tz,
        );
    }
}

/// Evaluation with correlations (stateful).
#[allow(clippy::too_many_arguments)]
fn cmd_eval_with_correlations(
    collection: SigmaCollection,
    rules_path: &std::path::Path,
    event_source: EventSource,
    pretty: bool,
    pipelines: &[Pipeline],
    event_filter: &EventFilter,
    config: rsigma_eval::CorrelationConfig,
    include_event: bool,
    input_format_str: &str,
    syslog_tz_str: &str,
) {
    let mut engine = CorrelationEngine::new(config);
    engine.set_include_event(include_event);
    for p in pipelines {
        engine.add_pipeline(p.clone());
    }
    if let Err(e) = engine.add_collection(&collection) {
        eprintln!("Error compiling rules: {e}");
        process::exit(1);
    }

    eprintln!(
        "Loaded {} detection rules + {} correlation rules from {}",
        engine.detection_rule_count(),
        engine.correlation_rule_count(),
        rules_path.display(),
    );

    match event_source {
        EventSource::SingleJson(json_str) => {
            let value: serde_json::Value = match serde_json::from_str(&json_str) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Invalid JSON event: {e}");
                    process::exit(1);
                }
            };

            for payload in crate::apply_event_filter(&value, event_filter) {
                let event = JsonEvent::borrow(&payload);
                let result = engine.process_event(&event);

                let total = result.detections.len() + result.correlations.len();
                if total == 0 {
                    eprintln!("No matches.");
                } else {
                    for m in &result.detections {
                        crate::print_json(m, pretty);
                    }
                    for m in &result.correlations {
                        crate::print_json(m, pretty);
                    }
                }
            }
        }
        EventSource::NdjsonFile(path) => {
            let file = File::open(&path).unwrap_or_else(|e| {
                eprintln!("Error opening event file '{}': {e}", path.display());
                process::exit(1);
            });
            let reader = BufReader::new(file);
            let (det_count, corr_count, line_num) = eval_stream_corr(
                &mut engine,
                reader,
                event_filter,
                pretty,
                input_format_str,
                syslog_tz_str,
            );
            eprintln!(
                "Processed {line_num} events, {det_count} detection matches, {corr_count} correlation matches."
            );
        }
        EventSource::Stdin => {
            let stdin = io::stdin();
            let (det_count, corr_count, line_num) = eval_stream_corr(
                &mut engine,
                stdin.lock(),
                event_filter,
                pretty,
                input_format_str,
                syslog_tz_str,
            );
            eprintln!(
                "Processed {line_num} events, {det_count} detection matches, {corr_count} correlation matches."
            );
        }
    }
}

/// Stream lines through the correlation engine with format-aware parsing.
/// Returns (det_count, corr_count, line_count).
#[allow(clippy::too_many_arguments)]
fn eval_stream_corr(
    engine: &mut CorrelationEngine,
    reader: impl BufRead,
    event_filter: &EventFilter,
    pretty: bool,
    input_format_str: &str,
    syslog_tz_str: &str,
) -> (u64, u64, u64) {
    let mut line_num = 0u64;
    let mut det_count = 0u64;
    let mut corr_count = 0u64;

    #[cfg(feature = "daemon")]
    let format = crate::parse_input_format(input_format_str, syslog_tz_str);
    #[cfg(not(feature = "daemon"))]
    let _ = (input_format_str, syslog_tz_str);

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

        // Format-aware parsing: use rsigma-runtime's input adapters when available.
        #[cfg(feature = "daemon")]
        {
            eval_line_corr(
                engine,
                &line,
                &format,
                event_filter,
                pretty,
                &mut det_count,
                &mut corr_count,
            );
        }
        #[cfg(not(feature = "daemon"))]
        {
            eval_line_corr_json(
                engine,
                &line,
                event_filter,
                pretty,
                &mut det_count,
                &mut corr_count,
            );
        }
    }

    (det_count, corr_count, line_num)
}

/// Evaluate a single line through the correlation engine using format-aware parsing.
#[cfg(feature = "daemon")]
fn eval_line_corr(
    engine: &mut CorrelationEngine,
    line: &str,
    format: &rsigma_runtime::InputFormat,
    event_filter: &EventFilter,
    pretty: bool,
    det_count: &mut u64,
    corr_count: &mut u64,
) {
    use rsigma_eval::Event;

    if let Some(decoded) = rsigma_runtime::parse_line(line, format) {
        // For JSON events, apply the event filter (which may produce multiple payloads).
        if matches!(decoded, rsigma_runtime::EventInputDecoded::Json(_)) {
            let json_value = decoded.to_json();
            for payload in crate::apply_event_filter(&json_value, event_filter) {
                let event = JsonEvent::borrow(&payload);
                let result = engine.process_event(&event);
                for m in &result.detections {
                    *det_count += 1;
                    crate::print_json(m, pretty);
                }
                for m in &result.correlations {
                    *corr_count += 1;
                    crate::print_json(m, pretty);
                }
            }
        } else {
            // Non-JSON events: evaluate directly (no event filter).
            let result = engine.process_event(&decoded);
            for m in &result.detections {
                *det_count += 1;
                crate::print_json(m, pretty);
            }
            for m in &result.correlations {
                *corr_count += 1;
                crate::print_json(m, pretty);
            }
        }
    }
}

/// Evaluate a single line through the correlation engine (JSON-only fallback).
#[cfg(not(feature = "daemon"))]
fn eval_line_corr_json(
    engine: &mut CorrelationEngine,
    line: &str,
    event_filter: &EventFilter,
    pretty: bool,
    det_count: &mut u64,
    corr_count: &mut u64,
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
        let result = engine.process_event(&event);
        for m in &result.detections {
            *det_count += 1;
            crate::print_json(m, pretty);
        }
        for m in &result.correlations {
            *corr_count += 1;
            crate::print_json(m, pretty);
        }
    }
}

/// Evaluation without correlations (stateless, original behavior).
#[allow(clippy::too_many_arguments)]
fn cmd_eval_detection_only(
    collection: SigmaCollection,
    rules_path: &std::path::Path,
    event_source: EventSource,
    pretty: bool,
    pipelines: &[Pipeline],
    event_filter: &EventFilter,
    include_event: bool,
    input_format_str: &str,
    syslog_tz_str: &str,
) {
    let mut engine = Engine::new();
    engine.set_include_event(include_event);
    for p in pipelines {
        engine.add_pipeline(p.clone());
    }
    if let Err(e) = engine.add_collection(&collection) {
        eprintln!("Error compiling rules: {e}");
        process::exit(1);
    }

    eprintln!(
        "Loaded {} rules from {}",
        engine.rule_count(),
        rules_path.display()
    );

    match event_source {
        EventSource::SingleJson(json_str) => {
            let value: serde_json::Value = match serde_json::from_str(&json_str) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Invalid JSON event: {e}");
                    process::exit(1);
                }
            };

            let payloads = crate::apply_event_filter(&value, event_filter);
            if payloads.is_empty() {
                eprintln!("No matches.");
            } else {
                for payload in &payloads {
                    let event = JsonEvent::borrow(payload);
                    let matches = engine.evaluate(&event);

                    if matches.is_empty() {
                        eprintln!("No matches.");
                    } else {
                        for m in &matches {
                            crate::print_json(m, pretty);
                        }
                    }
                }
            }
        }
        EventSource::NdjsonFile(path) => {
            let file = File::open(&path).unwrap_or_else(|e| {
                eprintln!("Error opening event file '{}': {e}", path.display());
                process::exit(1);
            });
            let reader = BufReader::new(file);
            let (match_count, line_num) = eval_stream_detect(
                &engine,
                reader,
                event_filter,
                pretty,
                input_format_str,
                syslog_tz_str,
            );
            eprintln!("Processed {line_num} events, {match_count} matches.");
        }
        EventSource::Stdin => {
            let stdin = io::stdin();
            let (match_count, line_num) = eval_stream_detect(
                &engine,
                stdin.lock(),
                event_filter,
                pretty,
                input_format_str,
                syslog_tz_str,
            );
            eprintln!("Processed {line_num} events, {match_count} matches.");
        }
    }
}

/// Stream lines through the detection engine with format-aware parsing.
/// Returns (match_count, line_count).
#[allow(clippy::too_many_arguments)]
fn eval_stream_detect(
    engine: &Engine,
    reader: impl BufRead,
    event_filter: &EventFilter,
    pretty: bool,
    input_format_str: &str,
    syslog_tz_str: &str,
) -> (u64, u64) {
    let mut line_num = 0u64;
    let mut match_count = 0u64;

    #[cfg(feature = "daemon")]
    let format = crate::parse_input_format(input_format_str, syslog_tz_str);
    #[cfg(not(feature = "daemon"))]
    let _ = (input_format_str, syslog_tz_str);

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

        #[cfg(feature = "daemon")]
        {
            eval_line_detect(
                engine,
                &line,
                &format,
                event_filter,
                pretty,
                &mut match_count,
            );
        }
        #[cfg(not(feature = "daemon"))]
        {
            eval_line_detect_json(engine, &line, event_filter, pretty, &mut match_count);
        }
    }

    (match_count, line_num)
}

/// Evaluate a single line through the detection engine using format-aware parsing.
#[cfg(feature = "daemon")]
fn eval_line_detect(
    engine: &Engine,
    line: &str,
    format: &rsigma_runtime::InputFormat,
    event_filter: &EventFilter,
    pretty: bool,
    match_count: &mut u64,
) {
    use rsigma_eval::Event;

    if let Some(decoded) = rsigma_runtime::parse_line(line, format) {
        if matches!(decoded, rsigma_runtime::EventInputDecoded::Json(_)) {
            let json_value = decoded.to_json();
            for payload in crate::apply_event_filter(&json_value, event_filter) {
                let event = JsonEvent::borrow(&payload);
                for m in &engine.evaluate(&event) {
                    *match_count += 1;
                    crate::print_json(m, pretty);
                }
            }
        } else {
            for m in &engine.evaluate(&decoded) {
                *match_count += 1;
                crate::print_json(m, pretty);
            }
        }
    }
}

/// Evaluate a single line through the detection engine (JSON-only fallback).
#[cfg(not(feature = "daemon"))]
fn eval_line_detect_json(
    engine: &Engine,
    line: &str,
    event_filter: &EventFilter,
    pretty: bool,
    match_count: &mut u64,
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
        for m in &engine.evaluate(&event) {
            *match_count += 1;
            crate::print_json(m, pretty);
        }
    }
}
