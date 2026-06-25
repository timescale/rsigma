use std::fs::File;
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;

use clap::parser::ValueSource;
use clap::{ArgMatches, Args};
use rsigma_eval::{
    CorrelationConfig, CorrelationEngine, Engine, EvaluationResult, FieldObserver, JsonEvent,
    LogSourceExtractor, MatchDetailLevel, OnUnknown, Pipeline, ResultBody, RouteOutcome,
    RoutingPlan, RuleFieldSet, SchemaClassifier, SchemaRouter, load_schema_config,
};
use rsigma_parser::SigmaCollection;

#[cfg(feature = "evtx")]
use super::eval_stream::stream_evtx_events;
use super::eval_stream::{
    CorrelationProcessor, DetectionProcessor, RoutingProcessor, stream_events,
};
use crate::EventFilter;
use crate::config;
use crate::exit_code;
use crate::output::{DelimitedWriter, OutputCtx, OutputFormat, Tabular};

/// Arguments for `rsigma engine eval` (and the deprecated `rsigma eval`).
#[derive(Args, Debug)]
pub(crate) struct EvalArgs {
    /// Path to a YAML config file. Overrides config-file discovery.
    /// CLI flags still take precedence over config-file values.
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Print the effective config (defaults < file < env) and exit.
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Path to a Sigma rule file or directory of rules.
    /// Required unless supplied via `eval.rules` in the config file.
    #[arg(short, long)]
    pub rules: Option<PathBuf>,

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
    /// Example: `--jsonpath '$.event'` or `--jsonpath '$.records[*]'`.
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

    /// Match-detail verbosity for detection output.
    ///   off     — field + value only (default; historical shape)
    ///   summary — adds the matcher kind, selection, and case sensitivity,
    ///             and reports keyword and absence matches
    ///   full    — also records the matched pattern
    #[arg(long = "match-detail", value_parser = ["off", "summary", "full"], default_value = "off")]
    pub match_detail: String,

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

    /// Hard cap on correlation state entries across all correlations and
    /// group keys. When reached, the stalest entries are evicted down to
    /// 90% capacity and a warning is logged.
    #[arg(long = "max-state-entries", default_value_t = crate::config::defaults::MAX_STATE_ENTRIES, value_parser = clap::value_parser!(usize))]
    pub max_state_entries: usize,

    /// Cap on retained entries within a single correlation group's window
    /// state (timestamps, value pairs, or per-rule hits). Bounds the
    /// within-window growth of chatty groups; oldest entries are dropped
    /// (session windows keep their span anchor). Unset = unbounded.
    /// Equivalent to the `rsigma.max_group_entries` custom attribute.
    #[arg(long = "max-group-entries")]
    pub max_group_entries: Option<usize>,

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

    /// Strip a leading UTF-8 BOM from RFC 5424 syslog messages. On by
    /// default (RFC 5424 treats the BOM as an encoding marker, not content);
    /// pass `--syslog-strip-bom false` to keep it. Only relevant for
    /// syslog/auto input.
    #[arg(long = "syslog-strip-bom", default_value_t = true, action = clap::ArgAction::Set)]
    pub syslog_strip_bom: bool,

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

    /// Record the field keys of every evaluated event and emit a
    /// coverage report at the end of the run.
    ///
    /// The report joins observed event fields against the field names
    /// referenced by the loaded rules and surfaces two halves of
    /// detection coverage:
    ///
    /// - **gap signal:** event fields no rule references.
    /// - **broken-coverage signal:** rule fields that never appeared
    ///   in an event during the run.
    ///
    /// Off by default. Same JSON shape as the daemon's
    /// `GET /api/v1/fields` endpoint so the same `jq` query works
    /// against either runtime (e.g. for a CI gate).
    #[arg(long = "observe-fields")]
    pub observe_fields: bool,

    /// Hard ceiling on the number of distinct field names tracked.
    /// Once the ceiling is reached, new keys are dropped (and counted
    /// via `overflow_dropped` in the report); existing keys keep
    /// incrementing. Default: 10000. Has no effect unless
    /// `--observe-fields` is set.
    #[arg(
        long = "observe-fields-max-keys",
        default_value_t = std::num::NonZeroUsize::new(10_000).unwrap(),
    )]
    pub observe_fields_max_keys: std::num::NonZeroUsize,

    /// Path to write the field-observation JSON report to. When
    /// omitted (and `--observe-fields` is set) the report is written
    /// to stderr so detections on stdout stay machine-consumable.
    #[arg(
        long = "observe-fields-report",
        value_name = "PATH",
        requires = "observe_fields"
    )]
    pub observe_fields_report: Option<PathBuf>,

    /// Recognize each event's schema and route it to the pipeline-set bound to
    /// that schema (instead of applying one pipeline set to every event).
    /// Bindings come from the `routing:` section of `--schema-config`.
    #[arg(long = "schema-routing")]
    pub schema_routing: bool,

    /// Path to a YAML file of schema signatures and routing bindings (the
    /// `schemas:` and `routing:` sections). Used with `--schema-routing`.
    #[arg(long = "schema-config", value_name = "PATH")]
    pub schema_config: Option<PathBuf>,

    /// Override the `on_unknown` policy for events that match no schema:
    /// `warn`, `drop`, `passthrough`, or `error`. Defaults to the config value
    /// (or `warn`). Used with `--schema-routing`.
    #[arg(long = "on-unknown", value_name = "POLICY")]
    pub on_unknown: Option<String>,

    /// Enable conflict-based logsource pruning: skip rules whose
    /// product/service/category cannot apply to the event's logsource. Opt-in
    /// and fail-open; an event with no logsource is evaluated against every
    /// rule.
    #[arg(long = "logsource-routing")]
    pub logsource_routing: bool,

    /// Event field names each logsource dimension is read from, as
    /// `product=...,service=...,category=...` (defaults to the literal field
    /// names). Used with `--logsource-routing`.
    #[arg(long = "logsource-field-map", value_name = "MAP")]
    pub logsource_field_map: Option<String>,

    /// Static event logsource applied when the field is absent, as
    /// `product=windows,service=...,category=...`, for a single-source
    /// pipeline. Used with `--logsource-routing`.
    #[arg(long = "event-logsource", value_name = "LOGSOURCE")]
    pub event_logsource: Option<String>,
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

/// Overlay the `eval` config section (defaults < file < env) onto `args` for
/// any flag the operator did not set explicitly. Handles `--dry-run` by
/// printing the effective config and exiting. Called before `cmd_eval` so the
/// resolved `fail_on_detection` drives the exit code.
pub(crate) fn apply_eval_config(args: &mut EvalArgs, matches: &ArgMatches) {
    let base = config::load_and_merge(args.config.as_deref());
    if args.dry_run {
        config::print_dry_run("eval", &base);
        process::exit(exit_code::SUCCESS);
    }
    overlay_eval_config(args, matches, base);
}

/// Pure overlay of the resolved `eval` section onto `args` (no disk access),
/// split out from [`apply_eval_config`] so it can be unit-tested.
fn overlay_eval_config(
    args: &mut EvalArgs,
    matches: &ArgMatches,
    base: config::RsigmaConfigPartial,
) {
    let explicit = |id: &str| {
        matches!(
            matches.value_source(id),
            Some(ValueSource::CommandLine | ValueSource::EnvVariable)
        )
    };

    if let Some(eval) = base.eval {
        if !explicit("rules")
            && let Some(v) = eval.rules
        {
            args.rules = Some(v);
        }
        if !explicit("pipelines")
            && let Some(v) = eval.pipelines
        {
            args.pipelines = v;
        }
        if !explicit("input_format")
            && let Some(v) = eval.input_format
        {
            args.input_format = v;
        }
        if !explicit("syslog_tz")
            && let Some(v) = eval.syslog_tz
        {
            args.syslog_tz = v;
        }
        if !explicit("syslog_strip_bom")
            && let Some(v) = eval.syslog_strip_bom
        {
            args.syslog_strip_bom = v;
        }
        if !explicit("fail_on_detection")
            && let Some(v) = eval.fail_on_detection
        {
            args.fail_on_detection = v;
        }
        if let Some(schema) = eval.schema {
            if !explicit("schema_routing")
                && let Some(v) = schema.routing
            {
                args.schema_routing = v;
            }
            if !explicit("schema_config")
                && let Some(v) = schema.config
            {
                args.schema_config = Some(v);
            }
            if !explicit("on_unknown")
                && let Some(v) = schema.on_unknown
            {
                args.on_unknown = Some(v);
            }
        }
        if let Some(ls) = eval.logsource_routing {
            if !explicit("logsource_routing")
                && let Some(v) = ls.enabled
            {
                args.logsource_routing = v;
            }
            if !explicit("logsource_field_map")
                && let Some(fm) = ls.field_map
                && let Some(s) = crate::logsource_opts::dims_to_kv(
                    fm.product.as_deref(),
                    fm.service.as_deref(),
                    fm.category.as_deref(),
                )
            {
                args.logsource_field_map = Some(s);
            }
            if !explicit("event_logsource")
                && let Some(el) = ls.event_logsource
                && let Some(s) = crate::logsource_opts::dims_to_kv(
                    el.product.as_deref(),
                    el.service.as_deref(),
                    el.category.as_deref(),
                )
            {
                args.event_logsource = Some(s);
            }
        }
    }
}

/// Returns `true` if any detection or correlation matched.
pub(crate) fn cmd_eval(args: EvalArgs, ctx: OutputCtx) -> bool {
    let EvalArgs {
        config: _,
        dry_run: _,
        rules: rules_opt,
        event: event_json,
        pretty,
        pipelines: pipeline_paths,
        jq,
        jsonpath,
        suppress,
        action,
        no_detections,
        include_event,
        match_detail,
        correlation_event_mode,
        max_correlation_events,
        max_state_entries,
        max_group_entries,
        timestamp_fields,
        input_format,
        syslog_tz,
        syslog_strip_bom,
        fail_on_detection: _,
        bloom_prefilter,
        bloom_max_bytes,
        #[cfg(feature = "daachorse-index")]
        cross_rule_ac,
        observe_fields,
        observe_fields_max_keys,
        observe_fields_report,
        schema_routing,
        schema_config,
        on_unknown,
        logsource_routing,
        logsource_field_map,
        event_logsource,
    } = args;

    let rules_path = rules_opt.unwrap_or_else(|| {
        eprintln!("error: no rules path; set --rules or eval.rules in the config file");
        process::exit(exit_code::CONFIG_ERROR);
    });

    let collection = crate::load_collection(&rules_path);
    let pipelines = crate::load_pipelines(&pipeline_paths);

    if pipelines.iter().any(|p| p.is_dynamic()) && ctx.show_progress() {
        eprintln!(
            "  note: dynamic sources are not resolved by `rsigma engine eval`. \
             Use `rsigma pipeline resolve` to inspect sources or `rsigma engine daemon` to evaluate \
             events with dynamic pipelines."
        );
    }

    let has_correlations = !collection.correlations.is_empty();

    // `value_parser` restricts this to off/summary/full, so parsing cannot fail.
    let match_detail = match_detail
        .parse::<MatchDetailLevel>()
        .unwrap_or(MatchDetailLevel::Off);

    let event_filter = crate::build_event_filter(jq, jsonpath);

    let event_source = resolve_event_source(event_json);

    // EVTX-only format-derived default: a `.evtx` input implies `product:
    // windows` when no explicit or static product is configured.
    let evtx_input = {
        #[cfg(feature = "evtx")]
        {
            matches!(event_source, EventSource::EvtxFile(_))
        }
        #[cfg(not(feature = "evtx"))]
        {
            false
        }
    };
    let logsource_extractor = match crate::logsource_opts::build_logsource_extractor(
        logsource_routing,
        logsource_field_map.as_deref(),
        event_logsource.as_deref(),
        evtx_input,
    ) {
        Ok(extractor) => extractor,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(exit_code::CONFIG_ERROR);
        }
    };

    let corr_config = crate::build_correlation_config(
        suppress,
        action,
        no_detections,
        correlation_event_mode,
        max_correlation_events,
        max_state_entries,
        max_group_entries,
        timestamp_fields,
        "wallclock",
    );

    // Field observability context, built once before evaluation and
    // shared across the eval helpers. None unless `--observe-fields`
    // is set. The rule field set is computed from the collection +
    // pipelines so the report matches what the engine evaluates
    // against; ownership of the collection is preserved because
    // `add_collection` borrows it.
    let observe_ctx: Option<ObserveContext> = if observe_fields {
        Some(ObserveContext {
            observer: Arc::new(FieldObserver::new(observe_fields_max_keys.get())),
            rule_field_set: RuleFieldSet::collect(&collection, &pipelines, true),
            report_path: observe_fields_report,
        })
    } else {
        None
    };
    let observe_ref = observe_ctx.as_ref();

    // The match renderer encapsulates the selected output format. `--pretty`
    // is honoured for backwards compatibility: it implies the JSON branch and
    // turns pretty-printing on even when stdout is not a TTY.
    let mut renderer = MatchRenderer::new(ctx, pretty);

    if schema_routing {
        let mut router = build_schema_router(
            &collection,
            schema_config.as_deref(),
            on_unknown.as_deref(),
            corr_config,
            include_event,
            match_detail,
            logsource_extractor,
        );
        let had_matches = cmd_eval_routed(
            event_source,
            &mut renderer,
            &mut router,
            &event_filter,
            &input_format,
            &syslog_tz,
            syslog_strip_bom,
            observe_ref,
        );
        renderer.flush();
        if let Some(octx) = observe_ref {
            render_field_report(octx);
        }
        return had_matches;
    }

    let had_matches = if has_correlations {
        cmd_eval_with_correlations(
            collection,
            &rules_path,
            event_source,
            &mut renderer,
            &pipelines,
            &event_filter,
            corr_config,
            include_event,
            match_detail,
            &input_format,
            &syslog_tz,
            syslog_strip_bom,
            bloom_prefilter,
            bloom_max_bytes,
            #[cfg(feature = "daachorse-index")]
            cross_rule_ac,
            logsource_extractor,
            observe_ref,
        )
    } else {
        cmd_eval_detection_only(
            collection,
            &rules_path,
            event_source,
            &mut renderer,
            &pipelines,
            &event_filter,
            include_event,
            match_detail,
            &input_format,
            &syslog_tz,
            syslog_strip_bom,
            bloom_prefilter,
            bloom_max_bytes,
            #[cfg(feature = "daachorse-index")]
            cross_rule_ac,
            logsource_extractor,
            observe_ref,
        )
    };

    renderer.flush();

    if let Some(octx) = observe_ref {
        render_field_report(octx);
    }

    had_matches
}

/// Parse the `--on-unknown` policy string.
fn parse_on_unknown(s: &str) -> OnUnknown {
    match s.to_ascii_lowercase().as_str() {
        "warn" => OnUnknown::Warn,
        "drop" => OnUnknown::Drop,
        "passthrough" => OnUnknown::Passthrough,
        "error" => OnUnknown::Error,
        other => {
            eprintln!(
                "Invalid --on-unknown policy '{other}' (expected warn, drop, passthrough, or error)"
            );
            process::exit(exit_code::CONFIG_ERROR);
        }
    }
}

/// Build a [`SchemaRouter`] from the schema config (signatures + routing
/// bindings) and the resolved pipeline-sets.
fn build_schema_router(
    collection: &SigmaCollection,
    schema_config: Option<&Path>,
    on_unknown_override: Option<&str>,
    corr_config: CorrelationConfig,
    include_event: bool,
    match_detail: MatchDetailLevel,
    logsource_extractor: Option<LogSourceExtractor>,
) -> SchemaRouter {
    let (signatures, routing) = match schema_config {
        Some(path) => match load_schema_config(path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error loading schema config: {e}");
                process::exit(exit_code::CONFIG_ERROR);
            }
        },
        None => (Vec::new(), None),
    };

    let classifier = if signatures.is_empty() {
        SchemaClassifier::builtin()
    } else {
        SchemaClassifier::with_user_signatures(signatures)
    };

    let mut routing = routing.unwrap_or_default();
    if let Some(policy) = on_unknown_override {
        routing.on_unknown = parse_on_unknown(policy);
    }
    if routing.bindings.is_empty() {
        eprintln!(
            "  note: --schema-routing is on but no routing bindings are configured; \
             every event routes to the default pipeline-set. Add a routing section to --schema-config."
        );
    }

    let plan = RoutingPlan::from_config(&routing);
    let pipeline_sets: Vec<Vec<Pipeline>> = plan
        .pipeline_sets()
        .iter()
        .map(|names| {
            let paths: Vec<PathBuf> = names.iter().map(PathBuf::from).collect();
            crate::load_pipelines(&paths)
        })
        .collect();

    match SchemaRouter::build(
        collection,
        classifier,
        plan,
        pipeline_sets,
        corr_config,
        include_event,
        match_detail,
        logsource_extractor,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error building schema router: {e}");
            process::exit(exit_code::RULE_ERROR);
        }
    }
}

/// Routed evaluation: classify each event and dispatch to the per-schema
/// engine, feeding detections into the shared correlation store. Returns
/// `true` if any match fired.
#[allow(clippy::too_many_arguments)]
fn cmd_eval_routed(
    event_source: EventSource,
    renderer: &mut MatchRenderer,
    router: &mut SchemaRouter,
    event_filter: &EventFilter,
    input_format_str: &str,
    syslog_tz_str: &str,
    syslog_strip_bom: bool,
    observe: Option<&ObserveContext>,
) -> bool {
    let mut det_count = 0u64;
    let mut corr_count = 0u64;
    let mut unknown = 0u64;
    let mut dropped = 0u64;
    let events: u64;

    match event_source {
        EventSource::SingleJson(json_str) => {
            events = 1;
            let value: serde_json::Value = match serde_json::from_str(&json_str) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Invalid JSON event: {e}");
                    process::exit(crate::exit_code::RULE_ERROR);
                }
            };
            for payload in crate::apply_event_filter(&value, event_filter) {
                let event = JsonEvent::borrow(&payload);
                if let Some(octx) = observe {
                    octx.observer.observe(&event);
                }
                let routed = router.route(&event);
                match routed.outcome {
                    RouteOutcome::EvaluatedUnknown => unknown += 1,
                    RouteOutcome::Dropped | RouteOutcome::Errored => dropped += 1,
                    RouteOutcome::Evaluated => {}
                }
                for m in &routed.results {
                    if m.is_correlation() {
                        corr_count += 1;
                    } else {
                        det_count += 1;
                    }
                    renderer.emit(m);
                }
            }
        }
        EventSource::NdjsonFile(path) => {
            let file = File::open(&path).unwrap_or_else(|e| {
                eprintln!("Error opening event file '{}': {e}", path.display());
                process::exit(crate::exit_code::RULE_ERROR);
            });
            let observer = observe.map(|c| c.observer.as_ref());
            let mut processor = RoutingProcessor::new(router);
            events = stream_events(
                BufReader::new(file),
                event_filter,
                input_format_str,
                syslog_tz_str,
                syslog_strip_bom,
                observer,
                &mut processor,
                &mut |m| {
                    if m.is_correlation() {
                        corr_count += 1;
                    } else {
                        det_count += 1;
                    }
                    renderer.emit(m);
                },
            );
            unknown = processor.unknown;
            dropped = processor.dropped + processor.errored;
        }
        #[cfg(feature = "evtx")]
        EventSource::EvtxFile(path) => {
            let observer = observe.map(|c| c.observer.as_ref());
            let mut processor = RoutingProcessor::new(router);
            events = stream_evtx_events(&path, event_filter, observer, &mut processor, &mut |m| {
                if m.is_correlation() {
                    corr_count += 1;
                } else {
                    det_count += 1;
                }
                renderer.emit(m);
            });
            unknown = processor.unknown;
            dropped = processor.dropped + processor.errored;
        }
        EventSource::Stdin => {
            let stdin = io::stdin();
            let observer = observe.map(|c| c.observer.as_ref());
            let mut processor = RoutingProcessor::new(router);
            events = stream_events(
                stdin.lock(),
                event_filter,
                input_format_str,
                syslog_tz_str,
                syslog_strip_bom,
                observer,
                &mut processor,
                &mut |m| {
                    if m.is_correlation() {
                        corr_count += 1;
                    } else {
                        det_count += 1;
                    }
                    renderer.emit(m);
                },
            );
            unknown = processor.unknown;
            dropped = processor.dropped + processor.errored;
        }
    }

    if renderer.ctx().show_stats() {
        eprintln!(
            "Processed {events} events, {det_count} detection matches, {corr_count} correlation matches, {unknown} unknown schema, {dropped} dropped."
        );
    }
    det_count > 0 || corr_count > 0
}

/// Evaluation with correlations (stateful). Returns `true` if any match fired.
#[allow(clippy::too_many_arguments)]
fn cmd_eval_with_correlations(
    collection: SigmaCollection,
    rules_path: &std::path::Path,
    event_source: EventSource,
    renderer: &mut MatchRenderer,
    pipelines: &[Pipeline],
    event_filter: &EventFilter,
    config: rsigma_eval::CorrelationConfig,
    include_event: bool,
    match_detail: MatchDetailLevel,
    input_format_str: &str,
    syslog_tz_str: &str,
    syslog_strip_bom: bool,
    bloom_prefilter: bool,
    bloom_max_bytes: Option<usize>,
    #[cfg(feature = "daachorse-index")] cross_rule_ac: bool,
    logsource_extractor: Option<LogSourceExtractor>,
    observe: Option<&ObserveContext>,
) -> bool {
    let mut engine = CorrelationEngine::new(config);
    engine.set_include_event(include_event);
    engine.set_match_detail(match_detail);
    if let Some(budget) = bloom_max_bytes {
        engine.set_bloom_max_bytes(budget);
    }
    engine.set_bloom_prefilter(bloom_prefilter);
    #[cfg(feature = "daachorse-index")]
    engine.set_cross_rule_ac(cross_rule_ac);
    engine.set_logsource_extractor(logsource_extractor);
    for p in pipelines {
        engine.add_pipeline(p.clone());
    }
    if let Err(e) = engine.add_collection(&collection) {
        eprintln!("Error compiling rules: {e}");
        process::exit(crate::exit_code::RULE_ERROR);
    }

    if renderer.ctx().show_progress() {
        eprintln!(
            "Loaded {} detection rules + {} correlation rules from {}",
            engine.detection_rule_count(),
            engine.correlation_rule_count(),
            rules_path.display(),
        );
    }
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
                if let Some(octx) = observe {
                    octx.observer.observe(&event);
                }
                let result = engine.process_event(&event);

                if result.is_empty() {
                    if renderer.ctx().show_progress() {
                        eprintln!("No matches.");
                    }
                } else {
                    had_matches = true;
                    for m in &result {
                        renderer.emit(m);
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
            let mut det_count = 0u64;
            let mut corr_count = 0u64;
            let line_num = {
                let observer = observe.map(|c| c.observer.as_ref());
                let mut processor = CorrelationProcessor {
                    engine: &mut engine,
                };
                stream_events(
                    reader,
                    event_filter,
                    input_format_str,
                    syslog_tz_str,
                    syslog_strip_bom,
                    observer,
                    &mut processor,
                    &mut |m| {
                        if m.is_detection() {
                            det_count += 1;
                        } else {
                            corr_count += 1;
                        }
                        renderer.emit(m);
                    },
                )
            };
            if renderer.ctx().show_stats() {
                eprintln!(
                    "Processed {line_num} events, {det_count} detection matches, {corr_count} correlation matches."
                );
            }
            det_count > 0 || corr_count > 0
        }
        #[cfg(feature = "evtx")]
        EventSource::EvtxFile(path) => {
            let mut det_count = 0u64;
            let mut corr_count = 0u64;
            let rec_count = {
                let observer = observe.map(|c| c.observer.as_ref());
                let mut processor = CorrelationProcessor {
                    engine: &mut engine,
                };
                stream_evtx_events(&path, event_filter, observer, &mut processor, &mut |m| {
                    if m.is_detection() {
                        det_count += 1;
                    } else {
                        corr_count += 1;
                    }
                    renderer.emit(m);
                })
            };
            if renderer.ctx().show_stats() {
                eprintln!(
                    "Processed {rec_count} EVTX records, {det_count} detection matches, {corr_count} correlation matches."
                );
            }
            det_count > 0 || corr_count > 0
        }
        EventSource::Stdin => {
            let stdin = io::stdin();
            let mut det_count = 0u64;
            let mut corr_count = 0u64;
            let line_num = {
                let observer = observe.map(|c| c.observer.as_ref());
                let mut processor = CorrelationProcessor {
                    engine: &mut engine,
                };
                stream_events(
                    stdin.lock(),
                    event_filter,
                    input_format_str,
                    syslog_tz_str,
                    syslog_strip_bom,
                    observer,
                    &mut processor,
                    &mut |m| {
                        if m.is_detection() {
                            det_count += 1;
                        } else {
                            corr_count += 1;
                        }
                        renderer.emit(m);
                    },
                )
            };
            if renderer.ctx().show_stats() {
                eprintln!(
                    "Processed {line_num} events, {det_count} detection matches, {corr_count} correlation matches."
                );
            }
            det_count > 0 || corr_count > 0
        }
    }
}

/// Evaluation without correlations (stateless). Returns `true` if any match fired.
#[allow(clippy::too_many_arguments)]
fn cmd_eval_detection_only(
    collection: SigmaCollection,
    rules_path: &std::path::Path,
    event_source: EventSource,
    renderer: &mut MatchRenderer,
    pipelines: &[Pipeline],
    event_filter: &EventFilter,
    include_event: bool,
    match_detail: MatchDetailLevel,
    input_format_str: &str,
    syslog_tz_str: &str,
    syslog_strip_bom: bool,
    bloom_prefilter: bool,
    bloom_max_bytes: Option<usize>,
    #[cfg(feature = "daachorse-index")] cross_rule_ac: bool,
    logsource_extractor: Option<LogSourceExtractor>,
    observe: Option<&ObserveContext>,
) -> bool {
    let mut engine = Engine::new();
    engine.set_include_event(include_event);
    engine.set_match_detail(match_detail);
    if let Some(budget) = bloom_max_bytes {
        engine.set_bloom_max_bytes(budget);
    }
    engine.set_bloom_prefilter(bloom_prefilter);
    #[cfg(feature = "daachorse-index")]
    engine.set_cross_rule_ac(cross_rule_ac);
    engine.set_logsource_extractor(logsource_extractor);
    for p in pipelines {
        engine.add_pipeline(p.clone());
    }
    if let Err(e) = engine.add_collection(&collection) {
        eprintln!("Error compiling rules: {e}");
        process::exit(crate::exit_code::RULE_ERROR);
    }

    if renderer.ctx().show_progress() {
        eprintln!(
            "Loaded {} rules from {}",
            engine.rule_count(),
            rules_path.display()
        );
    }
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
                if renderer.ctx().show_progress() {
                    eprintln!("No matches.");
                }
            } else {
                for payload in &payloads {
                    let event = JsonEvent::borrow(payload);
                    if let Some(octx) = observe {
                        octx.observer.observe(&event);
                    }
                    let matches = engine.evaluate(&event);

                    if matches.is_empty() {
                        if renderer.ctx().show_progress() {
                            eprintln!("No matches.");
                        }
                    } else {
                        had_matches = true;
                        for m in &matches {
                            renderer.emit(m);
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
            let mut match_count = 0u64;
            let line_num = {
                let observer = observe.map(|c| c.observer.as_ref());
                let mut processor = DetectionProcessor { engine: &engine };
                stream_events(
                    reader,
                    event_filter,
                    input_format_str,
                    syslog_tz_str,
                    syslog_strip_bom,
                    observer,
                    &mut processor,
                    &mut |m| {
                        match_count += 1;
                        renderer.emit(m);
                    },
                )
            };
            if renderer.ctx().show_stats() {
                eprintln!("Processed {line_num} events, {match_count} matches.");
            }
            match_count > 0
        }
        #[cfg(feature = "evtx")]
        EventSource::EvtxFile(path) => {
            let mut match_count = 0u64;
            let rec_count = {
                let observer = observe.map(|c| c.observer.as_ref());
                let mut processor = DetectionProcessor { engine: &engine };
                stream_evtx_events(&path, event_filter, observer, &mut processor, &mut |m| {
                    match_count += 1;
                    renderer.emit(m);
                })
            };
            if renderer.ctx().show_stats() {
                eprintln!("Processed {rec_count} EVTX records, {match_count} matches.");
            }
            match_count > 0
        }
        EventSource::Stdin => {
            let stdin = io::stdin();
            let mut match_count = 0u64;
            let line_num = {
                let observer = observe.map(|c| c.observer.as_ref());
                let mut processor = DetectionProcessor { engine: &engine };
                stream_events(
                    stdin.lock(),
                    event_filter,
                    input_format_str,
                    syslog_tz_str,
                    syslog_strip_bom,
                    observer,
                    &mut processor,
                    &mut |m| {
                        match_count += 1;
                        renderer.emit(m);
                    },
                )
            };
            if renderer.ctx().show_stats() {
                eprintln!("Processed {line_num} events, {match_count} matches.");
            }
            match_count > 0
        }
    }
}

// ---------------------------------------------------------------------------
// Field observability for `engine eval`
// ---------------------------------------------------------------------------

/// Shared context for the eval-time field observer. Built once before
/// the event loop. The observer itself is handed to the shared stream loop
/// as an `Option<&FieldObserver>`; the rest of the context is consumed by
/// [`render_field_report`] at end-of-run.
struct ObserveContext {
    observer: Arc<FieldObserver>,
    rule_field_set: RuleFieldSet,
    /// When `None`, the report is written to stderr at end-of-run.
    /// When `Some(path)`, it is written to that file (created or
    /// truncated). Stdout is intentionally not a destination: the
    /// detection NDJSON stream lives there.
    report_path: Option<PathBuf>,
}

/// Maximum number of rule titles surfaced per missing-field entry in
/// the eval report (matches the daemon's `/api/v1/fields/missing`
/// behaviour). A `truncated: true` flag accompanies any field that
/// touches more rules than this cap.
const EVAL_MISSING_RULE_TITLES_CAP: usize = 10;

/// Render the end-of-run field coverage report and write it to the
/// configured destination (file or stderr). The JSON shape matches
/// the daemon's `GET /api/v1/fields` payload so CI pipelines can
/// share a single `jq` query across runtimes.
fn render_field_report(ctx: &ObserveContext) {
    let snapshot = ctx.observer.snapshot();
    let coverage = snapshot.coverage(&ctx.rule_field_set);

    let unknown_entries: Vec<serde_json::Value> = coverage
        .unknown
        .iter()
        .map(|e| {
            let field: &str = &e.field;
            serde_json::json!({ "field": field, "count": e.count })
        })
        .collect();
    let missing_entries: Vec<serde_json::Value> = coverage
        .missing
        .iter()
        .map(|(name, origin)| {
            let total = origin.rule_titles.len();
            let truncated = total > EVAL_MISSING_RULE_TITLES_CAP;
            let rule_titles: Vec<&str> = origin
                .rule_titles
                .iter()
                .map(String::as_str)
                .take(EVAL_MISSING_RULE_TITLES_CAP)
                .collect();
            let sources: Vec<&str> = origin.sources.iter().map(|s| s.as_str()).collect();
            serde_json::json!({
                "field": name,
                "rule_count": total,
                "sources": sources,
                "rule_titles": rule_titles,
                "truncated": truncated,
            })
        })
        .collect();

    let report = serde_json::json!({
        "summary": {
            "events_observed": snapshot.events_observed,
            "unique_keys_observed": snapshot.unique_keys,
            "rule_fields_loaded": ctx.rule_field_set.len(),
            "overflow_dropped": snapshot.overflow_dropped,
            "max_keys": snapshot.max_keys,
            "uptime_seconds": snapshot.uptime_seconds,
            "intersection_count": coverage.intersection_count,
            "unknown_count": unknown_entries.len(),
            "missing_count": missing_entries.len(),
        },
        "unknown": unknown_entries,
        "missing": missing_entries,
    });

    let serialized = serde_json::to_string_pretty(&report).unwrap_or_else(|_| report.to_string());

    match ctx.report_path.as_deref() {
        Some(path) => {
            if let Err(e) = write_report_to_file(path, &serialized) {
                eprintln!(
                    "Failed to write field observation report to {}: {e}",
                    path.display()
                );
            }
        }
        None => {
            // Write to stderr so detections on stdout stay
            // machine-consumable. A best-effort write: failures here
            // do not change the exit code because the run already
            // produced the NDJSON results the operator cares about.
            let _ = writeln!(io::stderr(), "{serialized}");
        }
    }
}

fn write_report_to_file(path: &Path, serialized: &str) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(serialized.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()
}

// ---------------------------------------------------------------------------
// MatchRenderer: format-aware streaming output for evaluation results
// ---------------------------------------------------------------------------

/// Format-aware streaming sink for [`EvaluationResult`] records.
///
/// Built once per `cmd_eval` call from the resolved [`OutputCtx`]. JSON and
/// the delimited formats stream per match; `table` buffers and renders in
/// [`MatchRenderer::flush`].
///
/// The legacy `--pretty` flag flips the JSON branch to pretty-print even
/// when stdout is piped, so callers can still get pretty JSON in CI logs.
struct MatchRenderer {
    ctx: OutputCtx,
    state: RenderState,
}

enum RenderState {
    /// Plain JSON (one object per line, pretty if requested).
    Json { pretty: bool },
    /// Streaming delimited writer (`csv` or `tsv`).
    Delimited(DelimitedWriter),
    /// Buffer of rows for the width-aligning table renderer.
    Table(Vec<EvalRow>),
}

impl MatchRenderer {
    fn new(ctx: OutputCtx, pretty_flag: bool) -> Self {
        // `--pretty` was the historical way to opt into pretty-printed JSON.
        // The operator explicitly asked for that, so honour it regardless of
        // the resolved format (it would be confusing if `--pretty` silently
        // turned into compact NDJSON when piped).
        let state = if pretty_flag && !ctx.explicit_format {
            RenderState::Json { pretty: true }
        } else {
            match ctx.format {
                OutputFormat::Json => RenderState::Json {
                    pretty: pretty_flag || ctx.pretty_json(),
                },
                OutputFormat::Ndjson => RenderState::Json { pretty: false },
                OutputFormat::Csv => {
                    RenderState::Delimited(DelimitedWriter::new(',', EvalRow::headers()))
                }
                OutputFormat::Tsv => {
                    RenderState::Delimited(DelimitedWriter::new('\t', EvalRow::headers()))
                }
                OutputFormat::Table => RenderState::Table(Vec::new()),
            }
        };
        Self { ctx, state }
    }

    fn ctx(&self) -> &OutputCtx {
        &self.ctx
    }

    /// Emit one match in the configured format.
    fn emit(&mut self, m: &EvaluationResult) {
        match &mut self.state {
            RenderState::Json { pretty } => crate::output::render_json(m, *pretty),
            RenderState::Delimited(writer) => {
                let row = EvalRow::from_result(m).row();
                writer.push(&row);
            }
            RenderState::Table(rows) => rows.push(EvalRow::from_result(m)),
        }
    }

    /// Render any buffered output. No-op for the streaming formats.
    fn flush(&mut self) {
        if let RenderState::Table(rows) = &self.state {
            crate::output::render_table(rows);
        }
    }
}

/// Tabular row projection of an [`EvaluationResult`] for `--output-format
/// table|csv|tsv`. Four columns by design:
///
/// * `LEVEL`: rule level (`info`, `low`, `medium`, `high`, `critical`) or
///   `-` when the rule did not set one.
/// * `RULE`: rule title.
/// * `TYPE`: `detection` for plain matches, the correlation type name
///   (`event_count`, `temporal`, …) for correlation firings.
/// * `DETAIL`: a one-line summary -- matched fields for detections,
///   `group_key` plus the aggregated value for correlations.
///
/// JSON / NDJSON output preserves the full record; the projection here is
/// for the human / spreadsheet views.
#[derive(Clone)]
struct EvalRow {
    level: String,
    rule: String,
    kind: String,
    detail: String,
}

const ROW_HEADERS: &[&str] = &["LEVEL", "RULE", "TYPE", "DETAIL"];

const DETAIL_MAX: usize = 200;

impl EvalRow {
    fn from_result(m: &EvaluationResult) -> Self {
        let level = m
            .header
            .level
            .as_ref()
            .map(|l| l.as_str().to_string())
            .unwrap_or_else(|| "-".to_string());
        let rule = m.header.rule_title.clone();
        let (kind, detail) = match &m.body {
            ResultBody::Detection(d) => {
                let detail = d
                    .matched_fields
                    .iter()
                    .map(|fm| format!("{}={}", fm.field, summarize_value(&fm.value)))
                    .collect::<Vec<_>>()
                    .join(", ");
                ("detection".to_string(), truncate(detail))
            }
            ResultBody::Correlation(c) => {
                let group = c
                    .group_key
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let detail = if group.is_empty() {
                    format!("agg={}", c.aggregated_value)
                } else {
                    format!("{group} | agg={}", c.aggregated_value)
                };
                (c.correlation_type.as_str().to_string(), truncate(detail))
            }
        };
        Self {
            level,
            rule,
            kind,
            detail,
        }
    }
}

impl Tabular for EvalRow {
    fn headers() -> &'static [&'static str] {
        ROW_HEADERS
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.level.clone(),
            self.rule.clone(),
            self.kind.clone(),
            self.detail.clone(),
        ]
    }
}

/// Render a matched-field value as a compact one-line string. The full
/// payload is always available via `--output-format ndjson` if needed.
fn summarize_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        // Compact JSON for arrays/objects keeps the table on one line.
        other => other.to_string(),
    }
}

/// Cap a detail cell at [`DETAIL_MAX`] characters. Long values get a `…`
/// suffix so a single wide field cannot derail the table layout.
fn truncate(mut s: String) -> String {
    if s.chars().count() <= DETAIL_MAX {
        return s;
    }
    let truncated: String = s.chars().take(DETAIL_MAX - 1).collect();
    s.clear();
    s.push_str(&truncated);
    s.push('…');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Command, FromArgMatches};

    fn parse(argv: &[&str]) -> (EvalArgs, ArgMatches) {
        let cmd = EvalArgs::augment_args(Command::new("eval"));
        let matches = cmd.get_matches_from(argv);
        let args = EvalArgs::from_arg_matches(&matches).expect("valid args");
        (args, matches)
    }

    fn partial(yaml: &str) -> config::RsigmaConfigPartial {
        yaml_serde::from_str(yaml).expect("valid partial")
    }

    #[test]
    fn cli_flag_beats_config_file() {
        let (mut args, matches) = parse(&["eval", "--rules", "/cli/rules"]);
        let base = partial("eval:\n  rules: /file/rules\n  fail_on_detection: true\n");
        overlay_eval_config(&mut args, &matches, base);
        // CLI flag wins for rules; the file fills fail_on_detection.
        assert_eq!(args.rules.as_deref(), Some(Path::new("/cli/rules")));
        assert!(args.fail_on_detection);
    }

    #[test]
    fn config_fills_unset_rules() {
        let (mut args, matches) = parse(&["eval"]);
        let base = partial("eval:\n  rules: /file/rules\n");
        overlay_eval_config(&mut args, &matches, base);
        assert_eq!(args.rules.as_deref(), Some(Path::new("/file/rules")));
    }

    #[test]
    fn syslog_strip_bom_default_on_config_off_flag_wins() {
        // Default: stripping is on.
        let (args, _) = parse(&["eval", "--rules", "/r"]);
        assert!(args.syslog_strip_bom);

        // File disables it and the flag is unset: file applies.
        let (mut args, matches) = parse(&["eval", "--rules", "/r"]);
        let base = partial("eval:\n  syslog_strip_bom: false\n");
        overlay_eval_config(&mut args, &matches, base);
        assert!(!args.syslog_strip_bom);

        // Explicit CLI flag wins over the file.
        let (mut args, matches) = parse(&["eval", "--rules", "/r", "--syslog-strip-bom", "true"]);
        let base = partial("eval:\n  syslog_strip_bom: false\n");
        overlay_eval_config(&mut args, &matches, base);
        assert!(args.syslog_strip_bom);
    }

    #[test]
    fn schema_routing_from_config_file() {
        let (mut args, matches) = parse(&["eval", "--rules", "/r"]);
        let base = partial(
            "eval:\n  schema:\n    routing: true\n    config: /file/schema.yml\n    on_unknown: drop\n",
        );
        overlay_eval_config(&mut args, &matches, base);
        assert!(args.schema_routing);
        assert_eq!(
            args.schema_config.as_deref(),
            Some(Path::new("/file/schema.yml"))
        );
        assert_eq!(args.on_unknown.as_deref(), Some("drop"));
    }

    #[test]
    fn schema_routing_flag_beats_config_file() {
        let (mut args, matches) = parse(&["eval", "--rules", "/r", "--on-unknown", "error"]);
        let base = partial("eval:\n  schema:\n    routing: true\n    on_unknown: drop\n");
        overlay_eval_config(&mut args, &matches, base);
        // Routing comes from the file; the explicit flag wins for on_unknown.
        assert!(args.schema_routing);
        assert_eq!(args.on_unknown.as_deref(), Some("error"));
    }
}
