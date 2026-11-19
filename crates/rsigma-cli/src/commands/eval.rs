use std::collections::HashMap;
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
    RoutingPlan, RuleFieldSet, RulesetEngines, RulesetUnit, SchemaClassifier, SchemaRouter,
    UnitEngine, load_schema_config,
};
use rsigma_parser::SigmaCollection;

#[cfg(feature = "evtx")]
use super::eval_stream::stream_evtx_events;
use super::eval_stream::{
    CorrelationProcessor, DetectionProcessor, RoutingProcessor, RulesetsProcessor, stream_events,
};
use crate::EventFilter;
use crate::config;
use crate::exit_code;
use crate::output::{
    DelimitedWriter, OutputCtx, OutputFile, OutputFormat, Tabular, same_output_path,
};

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

    /// Named rulesets from the configuration to evaluate side by side.
    #[arg(
        long = "ruleset",
        value_name = "NAME",
        conflicts_with = "rules",
        action = clap::ArgAction::Append
    )]
    pub rulesets: Vec<String>,

    /// Effective ruleset entries, including config-file schema bindings.
    #[arg(skip)]
    pub ruleset_entries: Vec<crate::config::RulesetEntryPartial>,

    /// Pipeline fallback from `eval.pipelines`, used by multi-ruleset mode.
    #[arg(skip)]
    pub config_pipelines: Vec<PathBuf>,

    /// A single event as a JSON string, or @path to read from a file.
    /// Supports NDJSON files and .evtx (Windows Event Log) files.
    /// If omitted, reads NDJSON from stdin.
    #[arg(short, long)]
    pub event: Option<String>,

    /// Pretty-print JSON output
    #[arg(long)]
    pub pretty: bool,

    /// Write detection and correlation results to this file instead of
    /// stdout. The file is created or truncated. Defaults to NDJSON unless
    /// --output-format is set; the summary and diagnostics stay on stderr.
    #[arg(short = 'o', long = "output", value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Finding wire shape for each fire: `native` (default) or `ocsf`.
    /// OCSF composes with `--output-format json` or `ndjson`. `table`, `csv`,
    /// and `tsv` are rejected.
    #[arg(long = "finding-format", value_parser = ["native", "ocsf"])]
    pub finding_format: Option<String>,

    /// OCSF schema version (`1.1.0` or `1.3.0`). Requires `--finding-format ocsf`.
    #[arg(long = "ocsf-version")]
    pub ocsf_version: Option<String>,

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

    /// Emit output for rules referenced by correlations, including
    /// correlations that feed another correlation.
    #[arg(long = "emit-detections")]
    pub emit_detections: bool,

    /// Deprecated: correlation-only detection output is suppressed by default.
    #[arg(long = "no-detections", conflicts_with = "emit_detections")]
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

    /// Opt-in, gated per-schema rule partitioning (with `--schema-routing`):
    /// compile each platform-locked per-schema engine with only the rules whose
    /// product can apply. Off by default.
    #[arg(long = "schema-partition-rules")]
    pub schema_partition_rules: bool,

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

    /// After replaying all events, print the final correlation window state
    /// (per correlation and group: current aggregate vs threshold, window
    /// entries, last alert, seconds to eviction) to stderr as JSON. Useful for
    /// offline "why didn't it fire?" diagnosis. Correlation mode only.
    #[arg(long = "dump-correlation-state")]
    pub dump_correlation_state: bool,
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
        let cli_rules = explicit("rules");
        let cli_rulesets = explicit("rulesets");
        let config_list = eval
            .rulesets
            .as_ref()
            .is_some_and(|entries| !entries.is_empty());
        let config_single = eval.ruleset.is_some();

        if !cli_rules && !cli_rulesets {
            if eval.rules.is_some() && (config_list || config_single) {
                eprintln!("error: set either eval.rules or eval.ruleset/eval.rulesets, not both");
                process::exit(exit_code::CONFIG_ERROR);
            }
            if config_single && config_list {
                eprintln!("error: set either eval.ruleset or eval.rulesets, not both");
                process::exit(exit_code::CONFIG_ERROR);
            }
        }

        if !cli_rules
            && !cli_rulesets
            && let Some(v) = eval.rules
        {
            args.rules = Some(v);
        }
        if !cli_rules && !cli_rulesets {
            if let Some(entries) = eval.rulesets.filter(|entries| !entries.is_empty()) {
                args.ruleset_entries = entries;
            } else if let Some(name) = eval.ruleset {
                args.ruleset_entries = vec![crate::config::RulesetEntryPartial::Name(name)];
            }
        }

        if !explicit("pipelines") {
            args.config_pipelines = eval.pipelines.unwrap_or_default();
            args.pipelines = if args.ruleset_entries.is_empty() {
                args.config_pipelines.clone()
            } else {
                Vec::new()
            };
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
        if !explicit("output")
            && let Some(v) = eval.output
        {
            args.output = Some(v);
        }
        if !explicit("finding_format")
            && let Some(v) = eval.finding_format
        {
            args.finding_format = Some(v);
        }
        if !explicit("ocsf_version")
            && let Some(v) = eval.ocsf_version
        {
            args.ocsf_version = Some(v);
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
            if !explicit("schema_partition_rules")
                && let Some(v) = schema.partition_rules
            {
                args.schema_partition_rules = v;
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
                    fm.custom.as_ref(),
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
                    el.custom.as_ref(),
                )
            {
                args.event_logsource = Some(s);
            }
        }
    }

    if !args.rulesets.is_empty() {
        args.ruleset_entries = args
            .rulesets
            .iter()
            .cloned()
            .map(crate::config::RulesetEntryPartial::Name)
            .collect();
    }
}

/// Returns `true` if any detection or correlation matched.
pub(crate) fn cmd_eval(args: EvalArgs, ctx: OutputCtx) -> bool {
    if !args.ruleset_entries.is_empty() {
        return cmd_eval_rulesets(args, ctx);
    }

    let EvalArgs {
        config,
        dry_run: _,
        rules: rules_opt,
        rulesets: _,
        ruleset_entries: _,
        config_pipelines: _,
        event: event_json,
        pretty,
        output,
        finding_format,
        ocsf_version,
        pipelines: pipeline_paths,
        jq,
        jsonpath,
        suppress,
        action,
        emit_detections,
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
        schema_partition_rules,
        schema_config,
        on_unknown,
        logsource_routing,
        logsource_field_map,
        event_logsource,
        dump_correlation_state,
    } = args;

    let rules_path: Vec<PathBuf> = rules_opt.into_iter().collect();
    let input = crate::ruleset::RuleInput {
        rules: &rules_path,
        ruleset: None,
        config: config.as_deref(),
    };
    if input.rules.is_empty() {
        eprintln!(
            "error: no rules path; set --rules, --ruleset, eval.rules, eval.ruleset, or eval.rulesets in the config file"
        );
        process::exit(exit_code::CONFIG_ERROR);
    }

    let rules_label = input.label();
    let collection = input.single_path_collection(&ctx);
    let pipelines = crate::load_pipelines(&pipeline_paths);

    if pipelines.iter().any(|p| p.is_dynamic()) && ctx.show_progress() {
        eprintln!("{DYNAMIC_SOURCES_NOTE}");
    }

    let has_correlations = !collection.correlations.is_empty();

    if dump_correlation_state && (schema_routing || !has_correlations) {
        eprintln!(
            "warning: --dump-correlation-state needs correlation rules and is not supported with \
             --schema-routing; ignoring"
        );
    }

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

    if no_detections {
        eprintln!(
            "warning: --no-detections is deprecated; correlation-only detections are suppressed by default"
        );
    }
    let corr_config = crate::build_correlation_config(
        suppress,
        action,
        emit_detections,
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
    let finding_ocsf = finding_format.as_deref() == Some("ocsf");
    if finding_ocsf
        && matches!(
            ctx.format,
            OutputFormat::Csv | OutputFormat::Tsv | OutputFormat::Table
        )
    {
        eprintln!("error: --finding-format ocsf requires --output-format json or ndjson");
        std::process::exit(crate::exit_code::CONFIG_ERROR);
    }
    ctx.ensure_finding_ocsf_available("engine eval", finding_ocsf);
    if let Some(version) = &ocsf_version {
        if !finding_ocsf {
            eprintln!("error: --ocsf-version requires --finding-format ocsf");
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        }
        #[cfg(feature = "ocsf")]
        if version
            .parse::<rsigma_runtime::ocsf::OcsfVersion>()
            .is_err()
        {
            eprintln!("error: --ocsf-version must be 1.1.0 or 1.3.0");
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        }
        #[cfg(not(feature = "ocsf"))]
        let _ = version;
    }
    let output = output.map(|path| {
        ensure_output_is_not_input(&path, &event_source);
        OutputFile::create(path)
    });
    let mut renderer = MatchRenderer::new(
        ctx,
        pretty,
        output,
        finding_ocsf,
        ocsf_version.as_deref(),
        false,
    );

    if schema_routing {
        let mut router = build_schema_router(
            &collection,
            schema_config.as_deref(),
            on_unknown.as_deref(),
            corr_config,
            include_event,
            match_detail,
            logsource_extractor,
            schema_partition_rules,
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

    let engine_options = EngineOptions {
        include_event,
        match_detail,
        bloom_prefilter,
        bloom_max_bytes,
        #[cfg(feature = "daachorse-index")]
        cross_rule_ac,
        logsource_extractor,
    };

    let had_matches = if has_correlations {
        cmd_eval_with_correlations(
            collection,
            &rules_label,
            event_source,
            &mut renderer,
            &pipelines,
            &event_filter,
            corr_config,
            &engine_options,
            &input_format,
            &syslog_tz,
            syslog_strip_bom,
            observe_ref,
            dump_correlation_state,
        )
    } else {
        cmd_eval_detection_only(
            collection,
            &rules_label,
            event_source,
            &mut renderer,
            &pipelines,
            &event_filter,
            &engine_options,
            &input_format,
            &syslog_tz,
            syslog_strip_bom,
            observe_ref,
        )
    };

    renderer.flush();

    if let Some(octx) = observe_ref {
        render_field_report(octx);
    }

    had_matches
}

/// Evaluate several named rulesets side by side.
fn cmd_eval_rulesets(args: EvalArgs, ctx: OutputCtx) -> bool {
    let EvalArgs {
        config,
        dry_run: _,
        rules: _,
        rulesets: _,
        ruleset_entries,
        config_pipelines,
        event: event_json,
        pretty,
        output,
        finding_format,
        ocsf_version,
        pipelines: pipeline_paths,
        jq,
        jsonpath,
        suppress,
        action,
        emit_detections,
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
        schema_partition_rules,
        schema_config,
        on_unknown,
        logsource_routing,
        logsource_field_map,
        event_logsource,
        dump_correlation_state,
    } = args;

    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::new();
    for entry in ruleset_entries {
        let (name, when_schemas) = match entry {
            crate::config::RulesetEntryPartial::Name(name) => (name, Vec::new()),
            crate::config::RulesetEntryPartial::Bound {
                name,
                when,
                tenants,
                unknown,
            } => {
                if tenants.as_ref().is_some_and(|t| !t.is_empty()) {
                    eprintln!(
                        "error: ruleset '{name}' sets `tenants`, which is only valid under daemon.rulesets"
                    );
                    process::exit(exit_code::CONFIG_ERROR);
                }
                if !unknown.is_empty() {
                    eprintln!(
                        "error: ruleset '{name}' has unknown keys: {}",
                        unknown.keys().cloned().collect::<Vec<_>>().join(", ")
                    );
                    process::exit(exit_code::CONFIG_ERROR);
                }
                let when = when.unwrap_or(crate::config::WhenPartial {
                    schemas: Vec::new(),
                    unknown: Default::default(),
                });
                if !when.unknown.is_empty() {
                    eprintln!(
                        "error: ruleset '{name}' has unknown `when` keys: {}",
                        when.unknown.keys().cloned().collect::<Vec<_>>().join(", ")
                    );
                    process::exit(exit_code::CONFIG_ERROR);
                }
                (name, when.schemas)
            }
        };
        if !seen.insert(name.clone()) {
            eprintln!("error: duplicate ruleset name '{name}'");
            process::exit(exit_code::CONFIG_ERROR);
        }
        entries.push((name, when_schemas));
    }

    if no_detections {
        eprintln!(
            "warning: --no-detections is deprecated; correlation-only detections are suppressed by default"
        );
    }

    // `value_parser` restricts this to off/summary/full, so parsing cannot fail.
    let match_detail = match_detail
        .parse::<MatchDetailLevel>()
        .unwrap_or(MatchDetailLevel::Off);
    let event_filter = crate::build_event_filter(jq, jsonpath);
    let event_source = resolve_event_source(event_json);
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
        emit_detections,
        correlation_event_mode,
        max_correlation_events,
        max_state_entries,
        max_group_entries,
        timestamp_fields,
        "wallclock",
    );
    let finding_ocsf = finding_format.as_deref() == Some("ocsf");
    if finding_ocsf
        && matches!(
            ctx.format,
            OutputFormat::Csv | OutputFormat::Tsv | OutputFormat::Table
        )
    {
        eprintln!("error: --finding-format ocsf requires --output-format json or ndjson");
        std::process::exit(crate::exit_code::CONFIG_ERROR);
    }
    ctx.ensure_finding_ocsf_available("engine eval", finding_ocsf);
    if let Some(version) = &ocsf_version {
        if !finding_ocsf {
            eprintln!("error: --ocsf-version requires --finding-format ocsf");
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        }
        #[cfg(feature = "ocsf")]
        if version
            .parse::<rsigma_runtime::ocsf::OcsfVersion>()
            .is_err()
        {
            eprintln!("error: --ocsf-version must be 1.1.0 or 1.3.0");
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        }
        #[cfg(not(feature = "ocsf"))]
        let _ = version;
    }
    let output = output.map(|path| {
        ensure_output_is_not_input(&path, &event_source);
        OutputFile::create(path)
    });
    let mut renderer = MatchRenderer::new(
        ctx,
        pretty,
        output,
        finding_ocsf,
        ocsf_version.as_deref(),
        true,
    );

    let engine_options = EngineOptions {
        include_event,
        match_detail,
        bloom_prefilter,
        bloom_max_bytes,
        #[cfg(feature = "daachorse-index")]
        cross_rule_ac,
        logsource_extractor,
    };

    let mut units = Vec::new();
    let mut observe_field_set = RuleFieldSet::default();
    let mut dynamic_pipelines = false;

    if schema_routing {
        if entries.len() != 1 {
            eprintln!("error: --schema-routing supports exactly one --ruleset");
            process::exit(exit_code::CONFIG_ERROR);
        }
        let (name, when_schemas) = &entries[0];
        if !when_schemas.is_empty() {
            eprintln!("error: ruleset '{name}' cannot use `when` with --schema-routing");
            process::exit(exit_code::CONFIG_ERROR);
        }
        let (_, spec) = crate::ruleset::load_named(name, config.as_deref());
        if !spec.pipelines.is_empty() {
            eprintln!(
                "error: ruleset '{name}' has pipelines, which conflict with --schema-routing"
            );
            process::exit(exit_code::CONFIG_ERROR);
        }
        let resolved = crate::ruleset::resolve_or_exit(name, &spec, renderer.ctx());
        let collection = resolved.collection;
        let router = build_schema_router(
            &collection,
            schema_config.as_deref(),
            on_unknown.as_deref(),
            corr_config,
            include_event,
            match_detail,
            engine_options.logsource_extractor.clone(),
            schema_partition_rules,
        );
        let field_set = RuleFieldSet::collect(&collection, &[], true);
        observe_field_set.extend(field_set.clone());
        units.push(RulesetUnit {
            name: Arc::from(name.as_str()),
            when_schemas: Vec::new(),
            tenants: Vec::new(),
            engine: UnitEngine::Routed(Box::new(router)),
            field_set,
        });
    } else {
        for (name, when_schemas) in entries {
            let (name, spec) = crate::ruleset::load_named(&name, config.as_deref());
            let resolved = crate::ruleset::resolve_or_exit(&name, &spec, renderer.ctx());
            let collection = resolved.collection;

            let pipeline_paths = if !pipeline_paths.is_empty() {
                pipeline_paths.clone()
            } else if !spec.pipelines.is_empty() {
                crate::ruleset::ruleset_pipelines(&spec)
            } else {
                config_pipelines.clone()
            };
            let pipelines = crate::load_pipelines(&pipeline_paths);
            dynamic_pipelines |= pipelines.iter().any(|p| p.is_dynamic());
            let field_set = RuleFieldSet::collect(&collection, &pipelines, true);
            observe_field_set.extend(field_set.clone());

            let engine = if !collection.correlations.is_empty() || dump_correlation_state {
                let mut engine = CorrelationEngine::new(corr_config.clone());
                engine_options.apply_to_correlation(&mut engine);
                for pipeline in &pipelines {
                    engine.add_pipeline(pipeline.clone());
                }
                if let Err(e) = engine.add_collection(&collection) {
                    eprintln!("Error compiling rules for ruleset '{name}': {e}");
                    process::exit(exit_code::RULE_ERROR);
                }
                UnitEngine::Correlation(Box::new(engine))
            } else {
                let mut engine = Engine::new();
                engine_options.apply_to_engine(&mut engine);
                for pipeline in &pipelines {
                    engine.add_pipeline(pipeline.clone());
                }
                if let Err(e) = engine.add_collection(&collection) {
                    eprintln!("Error compiling rules for ruleset '{name}': {e}");
                    process::exit(exit_code::RULE_ERROR);
                }
                UnitEngine::Detection(Box::new(engine))
            };

            units.push(RulesetUnit {
                name: Arc::from(name.as_str()),
                when_schemas,
                tenants: Vec::new(),
                engine,
                field_set,
            });
        }
    }

    let classifier = if units.iter().any(|unit| !unit.when_schemas.is_empty()) {
        Some(Arc::new(load_schema_classifier(schema_config.as_deref())))
    } else {
        None
    };
    let mut engines = match RulesetEngines::new(units, classifier) {
        Ok(engines) => engines,
        Err(error) => {
            eprintln!("error: {error}");
            process::exit(exit_code::CONFIG_ERROR);
        }
    };

    if dynamic_pipelines && renderer.ctx().show_progress() {
        eprintln!("{DYNAMIC_SOURCES_NOTE}");
    }
    if renderer.ctx().show_progress() {
        for stats in engines.ruleset_stats() {
            eprintln!(
                "Loaded {} detection rules + {} correlation rules from ruleset {}",
                stats.detection_rules, stats.correlation_rules, stats.name
            );
        }
    }

    let observe_ctx: Option<ObserveContext> = if observe_fields {
        Some(ObserveContext {
            observer: Arc::new(FieldObserver::new(observe_fields_max_keys.get())),
            rule_field_set: observe_field_set,
            report_path: observe_fields_report,
        })
    } else {
        None
    };
    let observe_ref = observe_ctx.as_ref();

    let unit_names: Vec<Arc<str>> = engines.units().iter().map(|u| u.name.clone()).collect();
    let name_to_index: HashMap<Arc<str>, usize> = unit_names
        .iter()
        .enumerate()
        .map(|(index, name)| (name.clone(), index))
        .collect();
    let mut counts: Vec<(u64, u64)> = vec![(0, 0); unit_names.len()];
    let mut events = 0u64;
    let mut had_matches = false;

    match event_source {
        EventSource::SingleJson(json_str) => {
            let value: serde_json::Value = match serde_json::from_str(&json_str) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Invalid JSON event: {e}");
                    process::exit(crate::exit_code::RULE_ERROR);
                }
            };
            for payload in crate::apply_event_filter(value, &event_filter) {
                events += 1;
                let event = JsonEvent::borrow(&payload);
                if let Some(octx) = observe_ref {
                    octx.observer.observe(&event);
                }
                let results = engines.process_event(&event);
                if results.is_empty() && renderer.ctx().show_progress() {
                    eprintln!("No matches.");
                }
                for m in &results {
                    had_matches = true;
                    count_ruleset_match(&mut counts, &name_to_index, m);
                    renderer.emit(m);
                }
            }
        }
        EventSource::NdjsonFile(path) => {
            let file = File::open(&path).unwrap_or_else(|e| {
                eprintln!("Error opening event file '{}': {e}", path.display());
                process::exit(crate::exit_code::RULE_ERROR);
            });
            let observer = observe_ref.map(|c| c.observer.as_ref());
            let mut processor = RulesetsProcessor {
                engines: &mut engines,
            };
            events = stream_events(
                BufReader::new(file),
                &event_filter,
                &input_format,
                &syslog_tz,
                syslog_strip_bom,
                observer,
                &mut processor,
                &mut |m| {
                    had_matches = true;
                    count_ruleset_match(&mut counts, &name_to_index, m);
                    renderer.emit(m);
                },
            );
        }
        #[cfg(feature = "evtx")]
        EventSource::EvtxFile(path) => {
            let observer = observe_ref.map(|c| c.observer.as_ref());
            let mut processor = RulesetsProcessor {
                engines: &mut engines,
            };
            events = stream_evtx_events(&path, &event_filter, observer, &mut processor, &mut |m| {
                had_matches = true;
                count_ruleset_match(&mut counts, &name_to_index, m);
                renderer.emit(m);
            });
        }
        EventSource::Stdin => {
            let stdin = io::stdin();
            let observer = observe_ref.map(|c| c.observer.as_ref());
            let mut processor = RulesetsProcessor {
                engines: &mut engines,
            };
            events = stream_events(
                stdin.lock(),
                &event_filter,
                &input_format,
                &syslog_tz,
                syslog_strip_bom,
                observer,
                &mut processor,
                &mut |m| {
                    had_matches = true;
                    count_ruleset_match(&mut counts, &name_to_index, m);
                    renderer.emit(m);
                },
            );
        }
    }

    if dump_correlation_state {
        match serde_json::to_string_pretty(&engines.introspect()) {
            Ok(json) => eprintln!("--- correlation state snapshot ---\n{json}"),
            Err(e) => eprintln!("failed to serialize correlation state snapshot: {e}"),
        }
    }

    let total_det: u64 = counts.iter().map(|(det, _)| det).sum();
    let total_corr: u64 = counts.iter().map(|(_, corr)| corr).sum();
    let route_counts = engines.route_counts();
    if renderer.ctx().show_stats() {
        eprintln!(
            "Processed {events} events, {total_det} detection matches, {total_corr} correlation matches, {} unknown schema, {} dropped.",
            route_counts.unknown,
            route_counts.dropped + route_counts.errored
        );
        let skipped = engines.skipped_totals();
        for (index, (name, (det, corr))) in unit_names.iter().zip(counts.iter()).enumerate() {
            let skipped = skipped
                .iter()
                .find(|(unit, _)| unit == name)
                .map(|(_, count)| *count)
                .unwrap_or(0);
            if engines.units()[index].when_schemas.is_empty() {
                eprintln!("ruleset {name}: {det} detection matches, {corr} correlation matches");
            } else {
                eprintln!(
                    "ruleset {name}: {det} detection matches, {corr} correlation matches, {skipped} events skipped by when"
                );
            }
        }
        print_schema_pruning(&engines.schema_pruning_summary());
    }

    renderer.flush();
    if let Some(octx) = observe_ref {
        render_field_report(octx);
    }
    had_matches
}

fn load_schema_classifier(schema_config: Option<&Path>) -> SchemaClassifier {
    let (signatures, _) = match schema_config {
        Some(path) => match load_schema_config(path) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("Error loading schema config: {error}");
                process::exit(exit_code::CONFIG_ERROR);
            }
        },
        None => (Vec::new(), None),
    };
    if signatures.is_empty() {
        SchemaClassifier::builtin()
    } else {
        SchemaClassifier::with_user_signatures(signatures)
    }
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
#[allow(clippy::too_many_arguments)]
fn build_schema_router(
    collection: &SigmaCollection,
    schema_config: Option<&Path>,
    on_unknown_override: Option<&str>,
    corr_config: CorrelationConfig,
    include_event: bool,
    match_detail: MatchDetailLevel,
    logsource_extractor: Option<LogSourceExtractor>,
    partition_rules: bool,
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
        partition_rules,
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
            for payload in crate::apply_event_filter(value, event_filter) {
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
        print_schema_pruning(&router.schema_pruning_summary());
    }
    det_count > 0 || corr_count > 0
}

const DYNAMIC_SOURCES_NOTE: &str = "  note: dynamic sources are not resolved by `rsigma engine eval`. \
     Use `rsigma pipeline resolve` to inspect sources or `rsigma engine daemon` to evaluate \
     events with dynamic pipelines.";

fn print_schema_pruning(pruning: &[rsigma_eval::SchemaPruning]) {
    if pruning.is_empty() {
        return;
    }
    eprintln!("Logsource pruning by schema (eligible/pruned rules):");
    for entry in pruning {
        eprintln!(
            "  {}: {} eligible, {} pruned",
            entry.schema, entry.eligible, entry.pruned
        );
    }
}

/// Count one match against its ruleset's detection or correlation total.
fn count_ruleset_match(
    counts: &mut [(u64, u64)],
    name_to_index: &HashMap<Arc<str>, usize>,
    result: &EvaluationResult,
) {
    if let Some(name) = &result.header.ruleset
        && let Some(index) = name_to_index.get(name)
    {
        if result.is_correlation() {
            counts[*index].1 += 1;
        } else {
            counts[*index].0 += 1;
        }
    }
}

/// Engine tuning shared by every evaluation path.
#[derive(Clone)]
struct EngineOptions {
    include_event: bool,
    match_detail: MatchDetailLevel,
    bloom_prefilter: bool,
    bloom_max_bytes: Option<usize>,
    #[cfg(feature = "daachorse-index")]
    cross_rule_ac: bool,
    logsource_extractor: Option<LogSourceExtractor>,
}

impl EngineOptions {
    fn apply_to_engine(&self, engine: &mut Engine) {
        engine.set_include_event(self.include_event);
        engine.set_match_detail(self.match_detail);
        if let Some(budget) = self.bloom_max_bytes {
            engine.set_bloom_max_bytes(budget);
        }
        engine.set_bloom_prefilter(self.bloom_prefilter);
        #[cfg(feature = "daachorse-index")]
        engine.set_cross_rule_ac(self.cross_rule_ac);
        engine.set_logsource_extractor(self.logsource_extractor.clone());
    }

    fn apply_to_correlation(&self, engine: &mut CorrelationEngine) {
        engine.set_include_event(self.include_event);
        engine.set_match_detail(self.match_detail);
        if let Some(budget) = self.bloom_max_bytes {
            engine.set_bloom_max_bytes(budget);
        }
        engine.set_bloom_prefilter(self.bloom_prefilter);
        #[cfg(feature = "daachorse-index")]
        engine.set_cross_rule_ac(self.cross_rule_ac);
        engine.set_logsource_extractor(self.logsource_extractor.clone());
    }
}

/// Evaluation with correlations (stateful). Returns `true` if any match fired.
#[allow(clippy::too_many_arguments)]
fn cmd_eval_with_correlations(
    collection: SigmaCollection,
    rules_label: &str,
    event_source: EventSource,
    renderer: &mut MatchRenderer,
    pipelines: &[Pipeline],
    event_filter: &EventFilter,
    config: rsigma_eval::CorrelationConfig,
    options: &EngineOptions,
    input_format_str: &str,
    syslog_tz_str: &str,
    syslog_strip_bom: bool,
    observe: Option<&ObserveContext>,
    dump_correlation_state: bool,
) -> bool {
    let mut engine = CorrelationEngine::new(config);
    options.apply_to_correlation(&mut engine);
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
            rules_label,
        );
    }
    tracing::info!(
        detection_rules = engine.detection_rule_count(),
        correlation_rules = engine.correlation_rule_count(),
        rules_label = %rules_label,
        "Rules loaded",
    );

    let had_matches = match event_source {
        EventSource::SingleJson(json_str) => {
            let value: serde_json::Value = match serde_json::from_str(&json_str) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Invalid JSON event: {e}");
                    process::exit(crate::exit_code::RULE_ERROR);
                }
            };

            let mut had_matches = false;
            for payload in crate::apply_event_filter(value, event_filter) {
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
    };

    if dump_correlation_state {
        dump_correlation_snapshot(&engine);
    }
    had_matches
}

/// Print the final correlation window snapshot to stderr as pretty JSON, so a
/// user can replay an NDJSON file and see why a correlation did or did not
/// fire. Goes to stderr to keep detection output on stdout machine-consumable.
fn dump_correlation_snapshot(engine: &CorrelationEngine) {
    let snapshot = engine.introspect();
    match serde_json::to_string_pretty(&snapshot) {
        Ok(json) => eprintln!("--- correlation state snapshot ---\n{json}"),
        Err(e) => eprintln!("failed to serialize correlation state snapshot: {e}"),
    }
}

/// Evaluation without correlations (stateless). Returns `true` if any match fired.
#[allow(clippy::too_many_arguments)]
fn cmd_eval_detection_only(
    collection: SigmaCollection,
    rules_label: &str,
    event_source: EventSource,
    renderer: &mut MatchRenderer,
    pipelines: &[Pipeline],
    event_filter: &EventFilter,
    options: &EngineOptions,
    input_format_str: &str,
    syslog_tz_str: &str,
    syslog_strip_bom: bool,
    observe: Option<&ObserveContext>,
) -> bool {
    let mut engine = Engine::new();
    options.apply_to_engine(&mut engine);
    for p in pipelines {
        engine.add_pipeline(p.clone());
    }
    if let Err(e) = engine.add_collection(&collection) {
        eprintln!("Error compiling rules: {e}");
        process::exit(crate::exit_code::RULE_ERROR);
    }

    if renderer.ctx().show_progress() {
        eprintln!("Loaded {} rules from {}", engine.rule_count(), rules_label);
    }
    tracing::info!(
        detection_rules = engine.rule_count(),
        correlation_rules = 0,
        rules_label = %rules_label,
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
            let payloads = crate::apply_event_filter(value, event_filter);
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
///
/// With `--output`, results go to an [`OutputFile`] instead of stdout.
struct MatchRenderer {
    ctx: OutputCtx,
    state: RenderState,
    /// `--output` destination for the JSON and table formats. The delimited
    /// formats move the file into their [`DelimitedWriter`] instead.
    file: Option<OutputFile>,
    /// Prefix tabular rows with the ruleset name.
    ruleset_column: bool,
}

/// Refuse an `--output` path that names the `--event` input file, which
/// would otherwise be truncated before it is read. `./x` and `x` are the
/// same file.
fn ensure_output_is_not_input(output: &Path, source: &EventSource) {
    let input = match source {
        EventSource::NdjsonFile(p) => p,
        #[cfg(feature = "evtx")]
        EventSource::EvtxFile(p) => p,
        EventSource::SingleJson(_) | EventSource::Stdin => return,
    };
    if same_output_path(output, input) {
        eprintln!(
            "error: --output '{}' is the --event input file",
            output.display()
        );
        process::exit(exit_code::CONFIG_ERROR);
    }
}

enum RenderState {
    /// Plain JSON (one object per line, pretty if requested).
    Json { pretty: bool },
    /// OCSF Detection Finding (class 2004), one object per line.
    #[cfg(feature = "ocsf")]
    Ocsf {
        pretty: bool,
        version: rsigma_runtime::ocsf::OcsfVersion,
    },
    /// Streaming delimited writer (`csv` or `tsv`).
    Delimited(Box<DelimitedWriter>),
    /// Buffer of rows for the width-aligning table renderer.
    Table(TableRows),
}

enum TableRows {
    Path(Vec<EvalRow>),
    Ruleset(Vec<RulesetEvalRow>),
}

impl MatchRenderer {
    fn new(
        mut ctx: OutputCtx,
        pretty_flag: bool,
        mut file: Option<OutputFile>,
        finding_ocsf: bool,
        ocsf_version: Option<&str>,
        ruleset_column: bool,
    ) -> Self {
        // A file is never a terminal, and without an explicit format it gets
        // NDJSON so it can be consumed line by line.
        if file.is_some() {
            ctx.stdout_is_tty = false;
            if !ctx.explicit_format {
                ctx.format = OutputFormat::Ndjson;
            }
        }
        // `--pretty` was the historical way to opt into pretty-printed JSON.
        // The operator explicitly asked for that, so honour it regardless of
        // the resolved format (it would be confusing if `--pretty` silently
        // turned into compact NDJSON when piped).
        #[cfg(not(feature = "ocsf"))]
        let _ = ocsf_version;
        let state = if finding_ocsf {
            #[cfg(feature = "ocsf")]
            {
                RenderState::Ocsf {
                    pretty: pretty_flag || ctx.pretty_json(),
                    version: ocsf_version
                        .and_then(|v| v.parse().ok())
                        .unwrap_or_default(),
                }
            }
            #[cfg(not(feature = "ocsf"))]
            {
                unreachable!("--finding-format ocsf exits before the renderer is built");
            }
        } else if pretty_flag && !ctx.explicit_format {
            RenderState::Json { pretty: true }
        } else {
            match ctx.format {
                OutputFormat::Json => RenderState::Json {
                    pretty: pretty_flag || ctx.pretty_json(),
                },
                OutputFormat::Ndjson => RenderState::Json { pretty: false },
                OutputFormat::Csv => {
                    RenderState::Delimited(Box::new(delimited(',', &mut file, ruleset_column)))
                }
                OutputFormat::Tsv => {
                    RenderState::Delimited(Box::new(delimited('\t', &mut file, ruleset_column)))
                }
                OutputFormat::Table => RenderState::Table(if ruleset_column {
                    TableRows::Ruleset(Vec::new())
                } else {
                    TableRows::Path(Vec::new())
                }),
            }
        };
        Self {
            ctx,
            state,
            file,
            ruleset_column,
        }
    }

    fn ctx(&self) -> &OutputCtx {
        &self.ctx
    }

    /// Emit one match in the configured format.
    fn emit(&mut self, m: &EvaluationResult) {
        match &mut self.state {
            RenderState::Json { pretty } => match &mut self.file {
                Some(file) => {
                    let result = crate::output::write_json(&mut file.writer, m, *pretty);
                    file.check(result);
                }
                None => crate::output::render_json(m, *pretty),
            },
            #[cfg(feature = "ocsf")]
            RenderState::Ocsf { pretty, version } => match &mut self.file {
                Some(file) => {
                    let result =
                        crate::output::write_ocsf_finding(&mut file.writer, m, *pretty, *version);
                    file.check(result);
                }
                None => crate::output::render_ocsf_finding(m, *pretty, *version),
            },
            RenderState::Delimited(writer) => {
                let row = if self.ruleset_column {
                    RulesetEvalRow::from_result(m).row()
                } else {
                    EvalRow::from_result(m).row()
                };
                writer.push(&row);
            }
            RenderState::Table(rows) => match rows {
                TableRows::Path(rows) => rows.push(EvalRow::from_result(m)),
                TableRows::Ruleset(rows) => rows.push(RulesetEvalRow::from_result(m)),
            },
        }
    }

    /// Render any buffered output and flush the `--output` file.
    fn flush(&mut self) {
        match &mut self.state {
            RenderState::Table(rows) => match rows {
                TableRows::Path(rows) => match &mut self.file {
                    Some(file) => {
                        let result = crate::output::write_table(&mut file.writer, rows);
                        file.check(result);
                    }
                    None => crate::output::render_table(rows),
                },
                TableRows::Ruleset(rows) => match &mut self.file {
                    Some(file) => {
                        let result = crate::output::write_table(&mut file.writer, rows);
                        file.check(result);
                    }
                    None => crate::output::render_table(rows),
                },
            },
            RenderState::Delimited(writer) => writer.finish(),
            RenderState::Json { .. } => {}
            #[cfg(feature = "ocsf")]
            RenderState::Ocsf { .. } => {}
        }
        if let Some(file) = &mut self.file {
            let result = file.writer.flush();
            file.check(result);
        }
    }
}

/// Build the `csv`/`tsv` writer, moving the `--output` file into it when set.
fn delimited(sep: char, file: &mut Option<OutputFile>, ruleset_column: bool) -> DelimitedWriter {
    let headers = if ruleset_column {
        RulesetEvalRow::headers()
    } else {
        EvalRow::headers()
    };
    match file.take() {
        Some(file) => DelimitedWriter::with_writer(sep, headers, Box::new(file.writer)),
        None => DelimitedWriter::new(sep, headers),
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

/// Tabular row projection with the ruleset name as a leading column.
#[derive(Clone)]
struct RulesetEvalRow {
    ruleset: String,
    level: String,
    rule: String,
    kind: String,
    detail: String,
}

impl RulesetEvalRow {
    fn from_result(m: &EvaluationResult) -> Self {
        let base = EvalRow::from_result(m);
        Self {
            ruleset: m.header.ruleset.as_deref().unwrap_or("-").to_string(),
            level: base.level,
            rule: base.rule,
            kind: base.kind,
            detail: base.detail,
        }
    }
}

impl Tabular for RulesetEvalRow {
    fn headers() -> &'static [&'static str] {
        &["RULESET", "LEVEL", "RULE", "TYPE", "DETAIL"]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.ruleset.clone(),
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
    fn output_fills_from_config_file() {
        let (mut args, matches) = parse(&["eval"]);
        overlay_eval_config(
            &mut args,
            &matches,
            partial("eval:\n  output: /file/out.ndjson\n"),
        );
        assert_eq!(args.output.as_deref(), Some(Path::new("/file/out.ndjson")));
    }

    #[test]
    fn output_flag_beats_config_file() {
        let (mut args, matches) = parse(&["eval", "-o", "/cli/out.ndjson"]);
        overlay_eval_config(
            &mut args,
            &matches,
            partial("eval:\n  output: /file/out.ndjson\n"),
        );
        assert_eq!(args.output.as_deref(), Some(Path::new("/cli/out.ndjson")));
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

    #[test]
    fn ruleset_flags_parse_repeatable() {
        let (args, _) = parse(&["eval", "--ruleset", "a", "--ruleset", "b"]);
        assert_eq!(args.rulesets, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn config_rulesets_fill_entries_with_when() {
        let (mut args, matches) = parse(&["eval"]);
        overlay_eval_config(
            &mut args,
            &matches,
            partial(
                "eval:\n  rulesets:\n    - a\n    - name: b\n      when:\n        schemas: [aws_cloudtrail]\n",
            ),
        );
        assert_eq!(args.ruleset_entries.len(), 2);
        match &args.ruleset_entries[1] {
            crate::config::RulesetEntryPartial::Bound { name, when, .. } => {
                assert_eq!(name, "b");
                assert_eq!(when.as_ref().unwrap().schemas, vec!["aws_cloudtrail"]);
            }
            other => panic!("expected a bound entry, got {other:?}"),
        }
    }

    #[test]
    fn cli_rulesets_replace_the_config_list() {
        let (mut args, matches) = parse(&["eval", "--ruleset", "cli"]);
        overlay_eval_config(
            &mut args,
            &matches,
            partial(
                "eval:\n  rulesets:\n    - name: configured\n      when:\n        schemas: [aws_cloudtrail]\n",
            ),
        );
        assert_eq!(args.ruleset_entries.len(), 1);
        assert!(matches!(
            &args.ruleset_entries[0],
            crate::config::RulesetEntryPartial::Name(name) if name == "cli"
        ));
    }

    #[test]
    fn ruleset_entries_deserialize_both_shapes() {
        let bare: crate::config::RulesetEntryPartial =
            yaml_serde::from_str("a").expect("bare name");
        assert!(matches!(bare, crate::config::RulesetEntryPartial::Name(name) if name == "a"));

        let bound: crate::config::RulesetEntryPartial =
            yaml_serde::from_str("name: a\nwhen:\n  schemas: [aws_cloudtrail]\n")
                .expect("bound entry");
        match bound {
            crate::config::RulesetEntryPartial::Bound {
                name,
                when,
                tenants: _,
                unknown,
            } => {
                assert_eq!(name, "a");
                assert_eq!(when.unwrap().schemas, vec!["aws_cloudtrail"]);
                assert!(unknown.is_empty());
            }
            other => panic!("expected a bound entry, got {other:?}"),
        }

        assert!(
            yaml_serde::from_str::<crate::config::RulesetEntryPartial>(
                "name: a\nwhen:\n  schemas: [x]\n  bogus: true\n"
            )
            .is_ok(),
            "unknown when keys are captured, not rejected"
        );
        let entry: crate::config::RulesetEntryPartial =
            yaml_serde::from_str("name: a\nwhen:\n  schemas: [x]\n  bogus: true\n").unwrap();
        match entry {
            crate::config::RulesetEntryPartial::Bound { when, .. } => {
                assert!(when.unwrap().unknown.contains_key("bogus"));
            }
            _ => panic!("expected a bound entry"),
        }
    }
}
