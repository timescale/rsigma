mod commands;
#[cfg(feature = "daemon")]
mod daemon;
pub(crate) mod exit_code;
mod fix;

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use commands::{
    ConditionArgs, ConvertArgs, EvalArgs, FieldsArgs, LintArgs, LintCounts, ListFormatsArgs,
    ParseArgs, ResolveArgs, StdinArgs, ValidateArgs,
};
#[cfg(feature = "daemon")]
use commands::{DaemonArgs, cmd_daemon};
use jaq_interpret::{Ctx, FilterT, ParseCtx, RcIter, Val};
use rsigma_eval::{
    CorrelationAction, CorrelationConfig, CorrelationEventMode, Pipeline, parse_pipeline_file,
    resolve_builtin_pipeline,
};
use rsigma_parser::{SigmaCollection, parse_sigma_directory, parse_sigma_file};
use serde_json_path::JsonPath;

#[derive(Parser)]
#[command(name = "rsigma")]
#[command(about = "Parse, validate, and evaluate Sigma detection rules")]
#[command(version)]
struct Cli {
    /// Emit structured diagnostic logs to stderr (for CI / log aggregation).
    ///
    /// When set, initializes a tracing-subscriber on stderr using the chosen
    /// format. Verbosity is controlled via the RUST_LOG environment variable
    /// (default: info). Human-readable stdout/stderr output is unchanged;
    /// this flag only adds machine-readable diagnostic logs alongside it.
    ///
    /// Has no effect on the `engine daemon` subcommand, which always logs JSON.
    #[arg(long = "log-format", value_enum, global = true)]
    log_format: Option<LogFormat>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum LogFormat {
    /// Structured JSON (one object per line).
    Json,
    /// Human-readable text with ANSI colors when stderr is a TTY.
    Text,
}

// The new noun-led command groups (`engine`, `rule`, `backend`, `pipeline`,
// `attack`) are the source of truth. The flat top-level variants that follow
// are deprecated aliases kept for one release; each carries `[deprecated]` in
// its `about` text and prints a stderr warning before forwarding to the same
// `cmd_*` helper.
//
// We deliberately use a `//` comment (not `///`) so clap does not promote it
// to the top-level `--help` `about` text and override the explicit
// `#[command(about = ...)]` on `Cli`.
#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Run rules against events (eval / daemon)
    Engine {
        #[command(subcommand)]
        cmd: EngineCommands,
    },

    /// Inspect and operate on Sigma rule files
    Rule {
        #[command(subcommand)]
        cmd: RuleCommands,
    },

    /// Convert Sigma rules to backend-native queries
    Backend {
        #[command(subcommand)]
        cmd: BackendCommands,
    },

    /// Pipeline tooling (resolve dynamic sources, …)
    Pipeline {
        #[command(subcommand)]
        cmd: PipelineCommands,
    },

    /// MITRE ATT&CK tooling (reserved; populated by the ATT&CK contributor PR)
    Attack {
        #[command(subcommand)]
        cmd: AttackCommands,
    },

    // ---- Deprecated flat aliases (visible this release, hidden next) ----
    /// [deprecated] Use `rsigma engine eval` instead
    Eval(EvalArgs),

    /// [deprecated] Use `rsigma engine daemon` instead
    #[cfg(feature = "daemon")]
    Daemon(DaemonArgs),

    /// [deprecated] Use `rsigma rule parse` instead
    Parse(ParseArgs),

    /// [deprecated] Use `rsigma rule validate` instead
    Validate(ValidateArgs),

    /// [deprecated] Use `rsigma rule lint` instead
    Lint(LintArgs),

    /// [deprecated] Use `rsigma rule fields` instead
    Fields(FieldsArgs),

    /// [deprecated] Use `rsigma rule condition` instead
    Condition(ConditionArgs),

    /// [deprecated] Use `rsigma rule stdin` instead
    Stdin(StdinArgs),

    /// [deprecated] Use `rsigma backend convert` instead
    Convert(ConvertArgs),

    /// [deprecated] Use `rsigma backend targets` instead
    #[command(name = "list-targets")]
    ListTargets,

    /// [deprecated] Use `rsigma backend formats` instead
    #[command(name = "list-formats")]
    ListFormats(ListFormatsArgs),

    /// [deprecated] Use `rsigma pipeline resolve` instead
    Resolve(ResolveArgs),
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum EngineCommands {
    /// Evaluate events against Sigma rules
    Eval(EvalArgs),

    /// Run as a long-running daemon with hot-reload, health checks, and metrics
    #[cfg(feature = "daemon")]
    Daemon(DaemonArgs),
}

#[derive(Subcommand)]
enum RuleCommands {
    /// Parse a single Sigma YAML file and print the AST as JSON
    Parse(ParseArgs),

    /// Parse all Sigma rules in a directory (recursive) and report results
    Validate(ValidateArgs),

    /// Lint Sigma rules against the specification
    Lint(LintArgs),

    /// List all fields referenced by Sigma rules
    Fields(FieldsArgs),

    /// Parse a condition expression and print the AST
    Condition(ConditionArgs),

    /// Read Sigma YAML from stdin and print parsed AST as JSON
    Stdin(StdinArgs),
}

#[derive(Subcommand)]
enum BackendCommands {
    /// Convert Sigma rules to backend-native queries
    Convert(ConvertArgs),

    /// List available conversion targets (backends)
    Targets,

    /// List available output formats for a target
    Formats(ListFormatsArgs),
}

#[derive(Subcommand)]
enum PipelineCommands {
    /// Resolve dynamic pipeline sources and display their data
    Resolve(ResolveArgs),
}

/// Reserved for the MITRE ATT&CK contributor work in
/// [post-evaluation_enrichment_f3efb7b4.plan.md].
///
/// Concrete variants (`Coverage`, `Update`) land in that PR behind
/// `#[cfg(feature = "attack-mapping")]`. Until then this enum is empty and
/// `rsigma attack` reports "no available subcommands" via clap.
#[derive(Subcommand)]
enum AttackCommands {}

fn main() {
    let cli = Cli::parse();

    // Daemon installs its own JSON subscriber unconditionally; only init for
    // other subcommands when the user opts in via --log-format.
    #[cfg(feature = "daemon")]
    let is_daemon = matches!(
        cli.command,
        Commands::Engine {
            cmd: EngineCommands::Daemon(_),
            ..
        } | Commands::Daemon(_)
    );
    #[cfg(not(feature = "daemon"))]
    let is_daemon = false;
    if !is_daemon && let Some(format) = cli.log_format {
        init_cli_log_subscriber(format);
    }

    dispatch(cli.command);
}

/// Forward a deprecated flat invocation to its new home and print a stderr
/// migration hint. The warning text follows a single template so operators
/// see a consistent message regardless of which alias they hit.
fn deprecation_warn(old: &str, new: &str) {
    eprintln!(
        "warning: `rsigma {old}` is deprecated; use `rsigma {new}` instead. \
         This alias will be hidden in the next release and removed in v1.0."
    );
}

fn dispatch(command: Commands) {
    match command {
        // -- Grouped commands ------------------------------------------------
        Commands::Engine { cmd } => dispatch_engine(cmd),
        Commands::Rule { cmd } => dispatch_rule(cmd),
        Commands::Backend { cmd } => dispatch_backend(cmd),
        Commands::Pipeline { cmd } => dispatch_pipeline(cmd),
        Commands::Attack { cmd } => dispatch_attack(cmd),

        // -- Deprecated flat aliases ----------------------------------------
        Commands::Eval(args) => {
            deprecation_warn("eval", "engine eval");
            run_eval(args);
        }
        #[cfg(feature = "daemon")]
        Commands::Daemon(args) => {
            deprecation_warn("daemon", "engine daemon");
            cmd_daemon(args);
        }
        Commands::Parse(args) => {
            deprecation_warn("parse", "rule parse");
            commands::cmd_parse(args);
        }
        Commands::Validate(args) => {
            deprecation_warn("validate", "rule validate");
            commands::cmd_validate(args);
        }
        Commands::Lint(args) => {
            deprecation_warn("lint", "rule lint");
            run_lint(args);
        }
        Commands::Fields(args) => {
            deprecation_warn("fields", "rule fields");
            commands::cmd_fields(args);
        }
        Commands::Condition(args) => {
            deprecation_warn("condition", "rule condition");
            commands::cmd_condition(args);
        }
        Commands::Stdin(args) => {
            deprecation_warn("stdin", "rule stdin");
            commands::cmd_stdin(args);
        }
        Commands::Convert(args) => {
            deprecation_warn("convert", "backend convert");
            commands::cmd_convert(args);
        }
        Commands::ListTargets => {
            deprecation_warn("list-targets", "backend targets");
            commands::cmd_list_targets();
        }
        Commands::ListFormats(ListFormatsArgs { target }) => {
            deprecation_warn("list-formats", "backend formats");
            commands::cmd_list_formats(target);
        }
        Commands::Resolve(args) => {
            deprecation_warn("resolve", "pipeline resolve");
            commands::cmd_resolve(args);
        }
    }
}

fn dispatch_engine(cmd: EngineCommands) {
    match cmd {
        EngineCommands::Eval(args) => run_eval(args),
        #[cfg(feature = "daemon")]
        EngineCommands::Daemon(args) => cmd_daemon(args),
    }
}

fn dispatch_rule(cmd: RuleCommands) {
    match cmd {
        RuleCommands::Parse(args) => commands::cmd_parse(args),
        RuleCommands::Validate(args) => commands::cmd_validate(args),
        RuleCommands::Lint(args) => run_lint(args),
        RuleCommands::Fields(args) => commands::cmd_fields(args),
        RuleCommands::Condition(args) => commands::cmd_condition(args),
        RuleCommands::Stdin(args) => commands::cmd_stdin(args),
    }
}

fn dispatch_backend(cmd: BackendCommands) {
    match cmd {
        BackendCommands::Convert(args) => commands::cmd_convert(args),
        BackendCommands::Targets => commands::cmd_list_targets(),
        BackendCommands::Formats(ListFormatsArgs { target }) => commands::cmd_list_formats(target),
    }
}

fn dispatch_pipeline(cmd: PipelineCommands) {
    match cmd {
        PipelineCommands::Resolve(args) => commands::cmd_resolve(args),
    }
}

fn dispatch_attack(cmd: AttackCommands) {
    // `AttackCommands` is intentionally empty until the ATT&CK contributor PR
    // populates it. The exhaustive `match` keeps it impossible to add a
    // variant without wiring a handler. Once `Coverage` and `Update` land,
    // they slot in here.
    match cmd {}
}

/// Shared eval entry point used by both `engine eval` and the deprecated
/// `eval` alias. Centralizes the `--fail-on-detection` exit-code handling.
fn run_eval(args: EvalArgs) {
    let fail_on_detection = args.fail_on_detection;
    let had_matches = commands::cmd_eval(args);
    if fail_on_detection && had_matches {
        process::exit(exit_code::FINDINGS);
    }
}

/// Shared lint entry point used by both `rule lint` and the deprecated `lint`
/// alias. Centralizes the `--fail-level` exit-code handling.
fn run_lint(args: LintArgs) {
    let fail_level = args.fail_level.clone();
    let LintCounts {
        errors,
        warnings,
        infos,
    } = commands::cmd_lint(args);
    let should_fail = match fail_level.as_str() {
        "info" => errors > 0 || warnings > 0 || infos > 0,
        "warning" => errors > 0 || warnings > 0,
        _ => errors > 0,
    };
    if should_fail {
        process::exit(exit_code::FINDINGS);
    }
}

/// Initialize a stderr tracing subscriber for non-daemon subcommands.
///
/// Verbosity follows `RUST_LOG` and defaults to `info`. Errors during global
/// subscriber registration are ignored so the CLI keeps working even if the
/// flag is passed twice or another consumer of the process already installed
/// a subscriber.
fn init_cli_log_subscriber(format: LogFormat) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    match format {
        LogFormat::Json => {
            let _ = builder.json().try_init();
        }
        LogFormat::Text => {
            let _ = builder.try_init();
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers (used across commands)
// ---------------------------------------------------------------------------

pub(crate) fn load_pipelines(paths: &[PathBuf]) -> Vec<Pipeline> {
    let mut pipelines = Vec::new();
    for path in paths {
        let name = path.to_str().unwrap_or("");
        if let Some(result) = resolve_builtin_pipeline(name) {
            match result {
                Ok(p) => {
                    eprintln!(
                        "Loaded builtin pipeline: {} (priority {})",
                        p.name, p.priority
                    );
                    pipelines.push(p);
                }
                Err(e) => {
                    eprintln!("Error parsing builtin pipeline '{name}': {e}");
                    process::exit(exit_code::CONFIG_ERROR);
                }
            }
        } else {
            match parse_pipeline_file(path) {
                Ok(p) => {
                    eprintln!("Loaded pipeline: {} (priority {})", p.name, p.priority);
                    if p.is_dynamic() {
                        let source_ids: Vec<&str> =
                            p.sources.iter().map(|s| s.id.as_str()).collect();
                        eprintln!("  dynamic source(s): {}", source_ids.join(", "));
                    }
                    pipelines.push(p);
                }
                Err(e) => {
                    eprintln!("Error loading pipeline {}: {e}", path.display());
                    process::exit(exit_code::CONFIG_ERROR);
                }
            }
        }
    }
    pipelines.sort_by_key(|p| p.priority);
    pipelines
}

pub(crate) fn load_collection(path: &std::path::Path) -> SigmaCollection {
    let collection = if path.is_dir() {
        match parse_sigma_directory(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error loading rules from {}: {e}", path.display());
                process::exit(exit_code::RULE_ERROR);
            }
        }
    } else {
        match parse_sigma_file(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error loading rule {}: {e}", path.display());
                process::exit(exit_code::RULE_ERROR);
            }
        }
    };

    if !collection.errors.is_empty() {
        eprintln!(
            "Warning: {} parse errors while loading rules",
            collection.errors.len()
        );
    }

    collection
}

pub(crate) fn print_warnings(errors: &[String]) {
    if !errors.is_empty() {
        eprintln!("Warnings:");
        for err in errors {
            eprintln!("  - {err}");
        }
    }
}

pub(crate) fn print_json(value: &impl serde::Serialize, pretty: bool) {
    let json = if pretty {
        serde_json::to_string_pretty(value)
    } else {
        serde_json::to_string(value)
    };
    match json {
        Ok(j) => println!("{j}"),
        Err(e) => {
            eprintln!("JSON serialization error: {e}");
            process::exit(exit_code::CONFIG_ERROR);
        }
    }
}

// ---------------------------------------------------------------------------
// Event filtering (jq / JSONPath)
// ---------------------------------------------------------------------------

/// Pre-compiled event filter -- either a jq filter or a JSONPath query.
pub(crate) enum EventFilter {
    /// No filter -- pass through the entire event.
    None,
    /// A compiled jq filter.
    Jq(jaq_interpret::Filter),
    /// A compiled JSONPath query.
    JsonPath(JsonPath),
}

/// Build an `EventFilter` from CLI arguments. Exits on parse errors.
pub(crate) fn build_event_filter(jq: Option<String>, jsonpath: Option<String>) -> EventFilter {
    if let Some(jq_expr) = jq {
        eprintln!("Event filter: jq '{jq_expr}'");
        let mut defs = ParseCtx::new(Vec::new());
        let (parsed, errs) = jaq_parse::parse(&jq_expr, jaq_parse::main());
        if !errs.is_empty() {
            eprintln!("Invalid jq filter: {:?}", errs);
            process::exit(exit_code::CONFIG_ERROR);
        }
        let Some(parsed) = parsed else {
            eprintln!("Invalid jq filter: failed to parse '{jq_expr}'");
            process::exit(exit_code::CONFIG_ERROR);
        };
        let filter = defs.compile(parsed);
        if !defs.errs.is_empty() {
            eprintln!("jq compilation errors ({} error(s))", defs.errs.len());
            process::exit(exit_code::CONFIG_ERROR);
        }
        EventFilter::Jq(filter)
    } else if let Some(jp_expr) = jsonpath {
        eprintln!("Event filter: jsonpath '{jp_expr}'");
        match JsonPath::parse(&jp_expr) {
            Ok(path) => EventFilter::JsonPath(path),
            Err(e) => {
                eprintln!("Invalid JSONPath: {e}");
                process::exit(exit_code::CONFIG_ERROR);
            }
        }
    } else {
        EventFilter::None
    }
}

/// Build a `CorrelationConfig` from CLI arguments. Exits on parse errors.
pub(crate) fn build_correlation_config(
    suppress: Option<String>,
    action: Option<String>,
    no_detections: bool,
    correlation_event_mode: String,
    max_correlation_events: usize,
    extra_timestamp_fields: Vec<String>,
    timestamp_fallback: &str,
) -> CorrelationConfig {
    let suppress_secs = suppress.map(|s| match rsigma_parser::Timespan::parse(&s) {
        Ok(ts) => ts.seconds,
        Err(e) => {
            eprintln!("Invalid suppress duration '{s}': {e}");
            process::exit(exit_code::CONFIG_ERROR);
        }
    });

    let action_on_match = action
        .map(|s| {
            s.parse::<CorrelationAction>().unwrap_or_else(|e| {
                eprintln!("{e}");
                process::exit(exit_code::CONFIG_ERROR);
            })
        })
        .unwrap_or_default();

    let event_mode = correlation_event_mode
        .parse::<CorrelationEventMode>()
        .unwrap_or_else(|e| {
            eprintln!("{e}");
            process::exit(exit_code::CONFIG_ERROR);
        });

    let ts_fallback = match timestamp_fallback {
        "skip" => rsigma_eval::TimestampFallback::Skip,
        _ => rsigma_eval::TimestampFallback::WallClock,
    };

    let mut config = CorrelationConfig {
        suppress: suppress_secs,
        action_on_match,
        emit_detections: !no_detections,
        correlation_event_mode: event_mode,
        max_correlation_events,
        timestamp_fallback: ts_fallback,
        ..Default::default()
    };

    if !extra_timestamp_fields.is_empty() {
        let mut fields = extra_timestamp_fields;
        fields.extend(config.timestamp_fields);
        config.timestamp_fields = fields;
    }

    config
}

/// Apply the event filter, returning one or more extracted JSON values.
///
/// - `EventFilter::None`: returns the input as-is (single element).
/// - `EventFilter::Jq`: runs the jq filter, which may yield multiple values
///   (e.g., `.records[]`).
/// - `EventFilter::JsonPath`: queries the input, returning all matched nodes.
pub(crate) fn apply_event_filter(
    value: &serde_json::Value,
    filter: &EventFilter,
) -> Vec<serde_json::Value> {
    match filter {
        EventFilter::None => vec![value.clone()],

        EventFilter::Jq(f) => {
            let inputs = RcIter::new(core::iter::empty());
            let out = f.run((Ctx::new([], &inputs), Val::from(value.clone())));
            out.filter_map(|r| match r {
                Ok(val) => val_to_json(val),
                Err(e) => {
                    eprintln!("jq runtime error: {e}");
                    None
                }
            })
            .collect()
        }

        EventFilter::JsonPath(path) => {
            let nodes = path.query(value);
            nodes.all().into_iter().cloned().collect()
        }
    }
}

/// Convert a jaq `Val` to a `serde_json::Value`.
fn val_to_json(val: Val) -> Option<serde_json::Value> {
    match val {
        Val::Null => Some(serde_json::Value::Null),
        Val::Bool(b) => Some(serde_json::Value::Bool(b)),
        Val::Int(n) => Some(serde_json::Value::Number(n.into())),
        Val::Float(f) => serde_json::Number::from_f64(f).map(serde_json::Value::Number),
        Val::Num(n) => {
            if let Ok(i) = n.parse::<i64>() {
                Some(serde_json::Value::Number(i.into()))
            } else if let Ok(f) = n.parse::<f64>() {
                serde_json::Number::from_f64(f).map(serde_json::Value::Number)
            } else {
                Some(serde_json::Value::String(n.to_string()))
            }
        }
        Val::Str(s) => Some(serde_json::Value::String(s.to_string())),
        Val::Arr(arr) => {
            let items: Vec<serde_json::Value> =
                arr.iter().filter_map(|v| val_to_json(v.clone())).collect();
            Some(serde_json::Value::Array(items))
        }
        Val::Obj(obj) => {
            let map: serde_json::Map<String, serde_json::Value> = obj
                .iter()
                .filter_map(|(k, v)| val_to_json(v.clone()).map(|jv| (k.to_string(), jv)))
                .collect();
            Some(serde_json::Value::Object(map))
        }
    }
}
