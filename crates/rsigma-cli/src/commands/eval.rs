use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use std::process;

use clap::Args;
use rsigma_eval::{CorrelationEngine, Engine, JsonEvent, Pipeline};
use rsigma_parser::SigmaCollection;

use crate::EventFilter;

/// Arguments for `rsigma engine eval` (and the deprecated `rsigma eval`).
#[derive(Args, Debug)]
pub(crate) struct EvalArgs {
    /// Path to a Sigma rule file or directory of rules
    #[arg(short, long)]
    pub rules: PathBuf,

    /// A single event as a JSON string, or @path to read from a file.
    /// Supports NDJSON files and .evtx (Windows Event Log) files.
    /// If omitted, reads NDJSON from stdin.
    #[arg(short, long)]
    pub event: Option<String>,

    /// Pretty-print JSON output
    #[arg(long)]
    pub pretty: bool,

    /// Processing pipeline(s) to apply. Accepts builtin names (ecs_windows, sysmon) or YAML file paths
    #[arg(short = 'p', long = "pipeline")]
    pub pipelines: Vec<PathBuf>,

    /// jq filter to extract the event payload from each JSON object.
    /// Example: --jq '.event' or --jq '.records[]'
    #[arg(long = "jq", conflicts_with = "jsonpath")]
    pub jq: Option<String>,

    /// JSONPath (RFC 9535) query to extract the event payload.
    /// Example: --jsonpath '$.event' or --jsonpath '$.records[*]'
    #[arg(long = "jsonpath", conflicts_with = "jq")]
    pub jsonpath: Option<String>,

    /// Suppression window for correlation alerts.
    /// After a correlation fires for a group key, suppress re-alerts
    /// for this duration. Examples: 5m, 1h, 30s.
    #[arg(long = "suppress")]
    pub suppress: Option<String>,

    /// Action to take after a correlation fires.
    /// 'alert' (default): keep state, re-alert on next match.
    /// 'reset': clear window state, require threshold from scratch.
    #[arg(long = "action", value_parser = ["alert", "reset"])]
    pub action: Option<String>,

    /// Suppress detection-level output for rules that are only
    /// referenced by correlations (where generate=false).
    #[arg(long = "no-detections")]
    pub no_detections: bool,

    /// Include the full event JSON in each detection match output.
    /// Equivalent to the `rsigma.include_event` custom attribute.
    #[arg(long = "include-event")]
    pub include_event: bool,

    /// Correlation event inclusion mode:
    ///   none  — don't include events (default, zero overhead)
    ///   full  — include full event bodies (deflate compressed in memory)
    ///   refs  — include lightweight references (timestamp + event ID)
    /// Use --max-correlation-events to cap storage per window.
    #[arg(long = "correlation-event-mode", default_value = "none")]
    pub correlation_event_mode: String,

    /// Maximum events to store per correlation window group when
    /// --correlation-event-mode is not 'none'. Oldest events are
    /// evicted when the cap is reached.
    #[arg(long = "max-correlation-events", default_value = "10")]
    pub max_correlation_events: usize,

    /// Event field name(s) to use for timestamp extraction in correlations.
    /// Can be specified multiple times; tried in order before built-in
    /// defaults (@timestamp, timestamp, EventTime, …).
    /// Equivalent to the `rsigma.timestamp_field` custom attribute.
    #[arg(long = "timestamp-field")]
    pub timestamp_fields: Vec<String>,

    /// Input log format for event parsing.
    /// auto: try JSON → syslog → plain (default).
    /// Explicit: json, syslog, plain, logfmt (requires logfmt feature),
    /// cef (requires cef feature).
    #[arg(long = "input-format", default_value = "auto")]
    pub input_format: String,

    /// Default timezone offset for RFC 3164 syslog (e.g. +05:00, -08:00).
    /// Only used when --input-format is syslog or auto. Defaults to UTC.
    #[arg(long = "syslog-tz", default_value = "+00:00")]
    pub syslog_tz: String,

    /// Exit with code 1 when any detection or correlation fires.
    /// Useful in CI/CD pipelines to fail a build on detection.
    #[arg(long = "fail-on-detection")]
    pub fail_on_detection: bool,

    /// Enable bloom-filter pre-filtering of positive substring matchers.
    /// See `rsigma engine daemon --help` for the trade-off.
    #[arg(long = "bloom-prefilter")]
    pub bloom_prefilter: bool,

    /// Memory budget (in bytes) for the bloom index. Defaults to 1 MB.
    /// No effect unless `--bloom-prefilter` is set.
    #[arg(long = "bloom-max-bytes")]
    pub bloom_max_bytes: Option<usize>,

    /// Enable the cross-rule Aho-Corasick pre-filter (daachorse-index).
    /// See `rsigma engine daemon --help` for the trade-off. Available when
    /// compiled with the `daachorse-index` Cargo feature.
    #[cfg(feature = "daachorse-index")]
    #[arg(long = "cross-rule-ac")]
    pub cross_rule_ac: bool,
}

/// Resolved event source from the `--event` flag.
enum EventSource {
    /// Inline JSON string (e.g. `-e '{"key":"value"}'`).
    SingleJson(String),
    /// NDJSON from a file (e.g. `-e @events.ndjson`).
    NdjsonFile(PathBuf),
    /// EVTX binary file (e.g. `-e @security.evtx`).
    #[cfg(feature = "evtx")]
    EvtxFile(PathBuf),
    /// NDJSON from stdin (no `--event` flag).
    Stdin,
}

/// Resolve the `--event` argument into an `EventSource`.
/// Detects `@path` prefix for file-based input. Files with a `.evtx`
/// extension are routed to the EVTX adapter (requires the `evtx` feature).
fn resolve_event_source(event_json: Option<String>) -> EventSource {
    match event_json {
        Some(s) if s.starts_with('@') => {
            let path = PathBuf::from(&s[1..]);
            if !path.exists() {
                eprintln!("Event file not found: {}", path.display());
                process::exit(crate::exit_code::RULE_ERROR);
            }
            #[cfg(feature = "evtx")]
            if path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("evtx"))
            {
                return EventSource::EvtxFile(path);
            }
            EventSource::NdjsonFile(path)
        }
        Some(s) => EventSource::SingleJson(s),
        None => EventSource::Stdin,
    }
}

/// Returns `true` if any detection or correlation matched.
pub(crate) fn cmd_eval(args: EvalArgs) -> bool {
    let EvalArgs {
        rules: rules_path,
        event: event_json,
        pretty,
        pipelines: pipeline_paths,
        jq,
        jsonpath,
        suppress,
        action,
        no_detections,
        include_event,
        correlation_event_mode,
        max_correlation_events,
        timestamp_fields,
        input_format,
        syslog_tz,
        fail_on_detection: _,
        bloom_prefilter,
        bloom_max_bytes,
        #[cfg(feature = "daachorse-index")]
        cross_rule_ac,
    } = args;

    let collection = crate::load_collection(&rules_path);
    let pipelines = crate::load_pipelines(&pipeline_paths);

    if pipelines.iter().any(|p| p.is_dynamic()) {
        eprintln!(
            "  note: dynamic sources are not resolved by `rsigma engine eval`. \
             Use `rsigma pipeline resolve` to inspect sources or `rsigma engine daemon` to evaluate \
             events with dynamic pipelines."
        );
    }

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
        "wallclock",
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
            bloom_prefilter,
            bloom_max_bytes,
            #[cfg(feature = "daachorse-index")]
            cross_rule_ac,
        )
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
            bloom_prefilter,
            bloom_max_bytes,
            #[cfg(feature = "daachorse-index")]
            cross_rule_ac,
        )
    }
}

/// Evaluation with correlations (stateful). Returns `true` if any match fired.
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
    bloom_prefilter: bool,
    bloom_max_bytes: Option<usize>,
    #[cfg(feature = "daachorse-index")] cross_rule_ac: bool,
) -> bool {
    let mut engine = CorrelationEngine::new(config);
    engine.set_include_event(include_event);
    if let Some(budget) = bloom_max_bytes {
        engine.set_bloom_max_bytes(budget);
    }
    engine.set_bloom_prefilter(bloom_prefilter);
    #[cfg(feature = "daachorse-index")]
    engine.set_cross_rule_ac(cross_rule_ac);
    for p in pipelines {
        engine.add_pipeline(p.clone());
    }
    if let Err(e) = engine.add_collection(&collection) {
        eprintln!("Error compiling rules: {e}");
        process::exit(crate::exit_code::RULE_ERROR);
    }

    eprintln!(
        "Loaded {} detection rules + {} correlation rules from {}",
        engine.detection_rule_count(),
        engine.correlation_rule_count(),
        rules_path.display(),
    );
    tracing::info!(
        detection_rules = engine.detection_rule_count(),
        correlation_rules = engine.correlation_rule_count(),
        rules_path = %rules_path.display(),
        "Rules loaded",
    );

    match event_source {
        EventSource::SingleJson(json_str) => {
            let value: serde_json::Value = match serde_json::from_str(&json_str) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Invalid JSON event: {e}");
                    process::exit(crate::exit_code::RULE_ERROR);
                }
            };

            let mut had_matches = false;
            for payload in crate::apply_event_filter(&value, event_filter) {
                let event = JsonEvent::borrow(&payload);
                let result = engine.process_event(&event);

                let total = result.detections.len() + result.correlations.len();
                if total == 0 {
                    eprintln!("No matches.");
                } else {
                    had_matches = true;
                    for m in &result.detections {
                        crate::print_json(m, pretty);
                    }
                    for m in &result.correlations {
                        crate::print_json(m, pretty);
                    }
                }
            }
            had_matches
        }
        EventSource::NdjsonFile(path) => {
            let file = File::open(&path).unwrap_or_else(|e| {
                eprintln!("Error opening event file '{}': {e}", path.display());
                process::exit(crate::exit_code::RULE_ERROR);
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
            det_count > 0 || corr_count > 0
        }
        #[cfg(feature = "evtx")]
        EventSource::EvtxFile(path) => {
            let (det_count, corr_count, rec_count) =
                eval_evtx_corr(&mut engine, &path, event_filter, pretty);
            eprintln!(
                "Processed {rec_count} EVTX records, {det_count} detection matches, {corr_count} correlation matches."
            );
            det_count > 0 || corr_count > 0
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
            det_count > 0 || corr_count > 0
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
    let format = crate::commands::parse_input_format(input_format_str, syslog_tz_str);
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

/// Evaluation without correlations (stateless). Returns `true` if any match fired.
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
    bloom_prefilter: bool,
    bloom_max_bytes: Option<usize>,
    #[cfg(feature = "daachorse-index")] cross_rule_ac: bool,
) -> bool {
    let mut engine = Engine::new();
    engine.set_include_event(include_event);
    if let Some(budget) = bloom_max_bytes {
        engine.set_bloom_max_bytes(budget);
    }
    engine.set_bloom_prefilter(bloom_prefilter);
    #[cfg(feature = "daachorse-index")]
    engine.set_cross_rule_ac(cross_rule_ac);
    for p in pipelines {
        engine.add_pipeline(p.clone());
    }
    if let Err(e) = engine.add_collection(&collection) {
        eprintln!("Error compiling rules: {e}");
        process::exit(crate::exit_code::RULE_ERROR);
    }

    eprintln!(
        "Loaded {} rules from {}",
        engine.rule_count(),
        rules_path.display()
    );
    tracing::info!(
        detection_rules = engine.rule_count(),
        correlation_rules = 0,
        rules_path = %rules_path.display(),
        "Rules loaded",
    );

    match event_source {
        EventSource::SingleJson(json_str) => {
            let value: serde_json::Value = match serde_json::from_str(&json_str) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Invalid JSON event: {e}");
                    process::exit(crate::exit_code::RULE_ERROR);
                }
            };

            let mut had_matches = false;
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
                        had_matches = true;
                        for m in &matches {
                            crate::print_json(m, pretty);
                        }
                    }
                }
            }
            had_matches
        }
        EventSource::NdjsonFile(path) => {
            let file = File::open(&path).unwrap_or_else(|e| {
                eprintln!("Error opening event file '{}': {e}", path.display());
                process::exit(crate::exit_code::RULE_ERROR);
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
            match_count > 0
        }
        #[cfg(feature = "evtx")]
        EventSource::EvtxFile(path) => {
            let (match_count, rec_count) = eval_evtx_detect(&engine, &path, event_filter, pretty);
            eprintln!("Processed {rec_count} EVTX records, {match_count} matches.");
            match_count > 0
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
            match_count > 0
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
    let format = crate::commands::parse_input_format(input_format_str, syslog_tz_str);
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

// ---------------------------------------------------------------------------
// EVTX file evaluation
// ---------------------------------------------------------------------------

/// Evaluate all records from an EVTX file through the correlation engine.
/// Returns (det_count, corr_count, record_count).
#[cfg(feature = "evtx")]
fn eval_evtx_corr(
    engine: &mut CorrelationEngine,
    path: &std::path::Path,
    event_filter: &EventFilter,
    pretty: bool,
) -> (u64, u64, u64) {
    let mut reader = rsigma_runtime::EvtxFileReader::open(path).unwrap_or_else(|e| {
        eprintln!("Error opening EVTX file '{}': {e}", path.display());
        process::exit(crate::exit_code::RULE_ERROR);
    });

    let mut rec_count = 0u64;
    let mut det_count = 0u64;
    let mut corr_count = 0u64;

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
            let result = engine.process_event(&event);
            for m in &result.detections {
                det_count += 1;
                crate::print_json(m, pretty);
            }
            for m in &result.correlations {
                corr_count += 1;
                crate::print_json(m, pretty);
            }
        }
    }

    (det_count, corr_count, rec_count)
}

/// Evaluate all records from an EVTX file through the detection engine.
/// Returns (match_count, record_count).
#[cfg(feature = "evtx")]
fn eval_evtx_detect(
    engine: &Engine,
    path: &std::path::Path,
    event_filter: &EventFilter,
    pretty: bool,
) -> (u64, u64) {
    let mut reader = rsigma_runtime::EvtxFileReader::open(path).unwrap_or_else(|e| {
        eprintln!("Error opening EVTX file '{}': {e}", path.display());
        process::exit(crate::exit_code::RULE_ERROR);
    });

    let mut rec_count = 0u64;
    let mut match_count = 0u64;

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
            for m in &engine.evaluate(&event) {
                match_count += 1;
                crate::print_json(m, pretty);
            }
        }
    }

    (match_count, rec_count)
}
