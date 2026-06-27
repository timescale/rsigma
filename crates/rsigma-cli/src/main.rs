mod commands;
mod config;
#[cfg(feature = "daemon")]
mod daemon;
pub(crate) mod exit_code;
mod fix;
pub(crate) mod logsource_opts;
pub(crate) mod output;
pub(crate) mod rule_meta;

use std::path::PathBuf;
use std::process;

use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser, Subcommand};
use commands::{
    BacktestArgs, ClassifyArgs, ConditionArgs, ConvertArgs, CoverageArgs, DocArgs, EvalArgs,
    FieldsArgs, LintArgs, LintCounts, ListFormatsArgs, MigrateSourcesArgs, ParseArgs,
    ScorecardArgs, StatusArgs, StdinArgs, TailArgs, TapArgs, ValidateArgs, VisibilityArgs,
};
// `pipeline resolve` resolves dynamic sources, which needs the async runtime
// (tokio) and the source resolver from rsigma-runtime. Both ship with the
// `daemon` feature, so the command is gated on it.
#[cfg(feature = "daemon")]
use commands::ResolveArgs;
#[cfg(feature = "daemon")]
use commands::{DaemonArgs, cmd_daemon};
#[cfg(feature = "mcp")]
use commands::{McpCommands, dispatch_mcp};
use jaq_core::load::{Arena, File, Loader};
use jaq_core::{Compiler, Ctx, Vars, data, unwrap_valr};
use jaq_json::Val;
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

    /// Output format for structured CLI data (matches, fields, lint findings).
    ///
    /// Values: `json` (default on a TTY), `ndjson` (default when piped),
    /// `table`, `csv`, `tsv`. Resolution: flag > `RSIGMA_GLOBAL__OUTPUT_FORMAT`
    /// > `global.output_format` in the config file > TTY-aware default.
    ///
    /// `convert` keeps its own `-f/--format` for the backend query format and
    /// only honors `json` for this flag (wraps queries); other values fall
    /// back to raw text.
    #[arg(long = "output-format", value_enum, global = true)]
    output_format: Option<output::OutputFormat>,

    /// Color policy for human-friendly output (lint findings, summaries).
    ///
    /// Values: `auto` (color on a TTY when `NO_COLOR` is unset, the default),
    /// `always`, `never`. Resolution: flag > `RSIGMA_GLOBAL__COLOR` >
    /// `global.color` in the config file > `auto`.
    #[arg(long = "color", value_enum, global = true)]
    color: Option<output::ColorChoice>,

    /// Suppress all non-data output (progress + stats). Errors still go to
    /// stderr. Useful in CI when only the matched results matter.
    #[arg(long = "quiet", short = 'q', global = true)]
    quiet: bool,

    /// Suppress only the trailing summary / stats line. Progress messages
    /// stay on stderr. Useful when piping to a tool that does not expect a
    /// summary footer but the operator still wants to see what happened.
    #[arg(long = "no-stats", global = true)]
    no_stats: bool,

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

// The new noun-led command groups (`engine`, `rule`, `backend`, `pipeline`)
// are the source of truth. The flat top-level variants that follow are
// deprecated aliases kept around for one more release as undocumented
// forwarders. Each is marked `#[command(hide = true)]` so it no longer
// appears in `rsigma --help`, but the dispatch arms below still accept the
// invocation and print a stderr warning before delegating to the same
// `cmd_*` helper. These variants are removed entirely at v1.0 (issue #126).
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
    #[cfg(feature = "daemon")]
    Pipeline {
        #[command(subcommand)]
        cmd: PipelineCommands,
    },

    /// Run the Model Context Protocol (MCP) server for AI agents
    #[cfg(feature = "mcp")]
    Mcp {
        #[command(subcommand)]
        cmd: McpCommands,
    },

    /// Manage rsigma configuration files (init, validate, schema, path)
    Config {
        #[command(subcommand)]
        cmd: config::commands::ConfigCommands,
    },

    // ---- Deprecated flat aliases (hidden from `--help`, still functional) ----
    /// \[deprecated\] Use `rsigma engine eval` instead
    #[command(hide = true)]
    Eval(EvalArgs),

    /// \[deprecated\] Use `rsigma engine daemon` instead
    #[cfg(feature = "daemon")]
    #[command(hide = true)]
    Daemon(DaemonArgs),

    /// \[deprecated\] Use `rsigma rule parse` instead
    #[command(hide = true)]
    Parse(ParseArgs),

    /// \[deprecated\] Use `rsigma rule validate` instead
    #[command(hide = true)]
    Validate(ValidateArgs),

    /// \[deprecated\] Use `rsigma rule lint` instead
    #[command(hide = true)]
    Lint(LintArgs),

    /// \[deprecated\] Use `rsigma rule fields` instead
    #[command(hide = true)]
    Fields(FieldsArgs),

    /// \[deprecated\] Use `rsigma rule condition` instead
    #[command(hide = true)]
    Condition(ConditionArgs),

    /// \[deprecated\] Use `rsigma rule stdin` instead
    #[command(hide = true)]
    Stdin(StdinArgs),

    /// \[deprecated\] Use `rsigma backend convert` instead
    #[command(hide = true)]
    Convert(ConvertArgs),

    /// \[deprecated\] Use `rsigma backend targets` instead
    #[command(name = "list-targets", hide = true)]
    ListTargets,

    /// \[deprecated\] Use `rsigma backend formats` instead
    #[command(name = "list-formats", hide = true)]
    ListFormats(ListFormatsArgs),

    /// \[deprecated\] Use `rsigma pipeline resolve` instead
    #[cfg(feature = "daemon")]
    #[command(hide = true)]
    Resolve(ResolveArgs),
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum EngineCommands {
    /// Evaluate events against Sigma rules
    Eval(EvalArgs),

    /// Report which schema each event matches (content-based recognition)
    Classify(ClassifyArgs),

    /// Query a running daemon's status (GET /api/v1/status)
    Status(StatusArgs),

    /// Record a running daemon's live event stream to a replayable fixture
    /// (GET /api/v1/tap)
    Tap(TapArgs),

    /// Stream a running daemon's live detections to the terminal
    /// (GET /api/v1/detections/stream)
    Tail(TailArgs),

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

    /// Report or scaffold the ADS detection-strategy document for rules
    Doc(DocArgs),

    /// Replay an event corpus and diff per-rule fires against expectations
    Backtest(BacktestArgs),

    /// Map rules onto MITRE ATT&CK: Navigator layer export + coverage gaps
    Coverage(CoverageArgs),

    /// Fuse backtest + coverage (+ metrics, triage) into keep/tune/retire verdicts
    Scorecard(ScorecardArgs),

    /// Score telemetry visibility: DeTT&CT export + visibility Navigator layer
    Visibility(VisibilityArgs),

    /// Parse a condition expression and print the AST
    Condition(ConditionArgs),

    /// Read Sigma YAML from stdin and print parsed AST as JSON
    Stdin(StdinArgs),

    /// Extract pipeline-embedded sources: into standalone source files
    MigrateSources(MigrateSourcesArgs),
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

#[cfg(feature = "daemon")]
#[derive(Subcommand)]
enum PipelineCommands {
    /// Resolve dynamic pipeline sources and display their data
    Resolve(ResolveArgs),
}

fn main() {
    // Parse into `ArgMatches` (not just the typed `Cli`) so commands can ask
    // clap which flags were set explicitly on the command line. That drives
    // the config precedence (CLI flag > env > file > default).
    let matches = Cli::command().get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    };

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
    // The --log-format flag wins; otherwise honor global.log_format from a
    // discovered config file (or an explicit --config path) or
    // RSIGMA_GLOBAL__LOG_FORMAT.
    let cfg_override = scan_config_flag();
    let log_format = cli.log_format.or_else(|| {
        config::discovered_log_format(cfg_override.as_deref()).and_then(|s| parse_log_format(&s))
    });
    if !is_daemon && let Some(format) = log_format {
        init_cli_log_subscriber(format);
    }

    // Build the global output context once, after the config layer is loaded
    // but before any command runs. The same precedence model that drives
    // --log-format applies here: flag > env > file > default.
    let (cfg_format, cfg_color) = config::discovered_global_output(cfg_override.as_deref());
    let (cfg_format, cfg_color) = output::warn_invalid_global_output(cfg_format, cfg_color);
    let stdout_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let ctx = output::OutputCtx::resolve(
        cli.output_format,
        cfg_format.as_deref(),
        cli.color,
        cfg_color.as_deref(),
        cli.quiet,
        cli.no_stats,
        stdout_is_tty,
    );

    dispatch(cli.command, &matches, ctx);
}

/// Pre-scan argv for an explicit `--config <PATH>` / `--config=<PATH>` so the
/// early log-format resolution honors the same file the subcommand will load.
/// Only the long form is scanned; the short `-c` belongs to the `config`
/// subcommands, where `global.log_format` is irrelevant.
fn scan_config_flag() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            return args.next().map(PathBuf::from);
        }
        if let Some(value) = arg.strip_prefix("--config=") {
            return Some(PathBuf::from(value));
        }
    }
    None
}

/// Parse a `global.log_format` config string into a `LogFormat`.
fn parse_log_format(s: &str) -> Option<LogFormat> {
    match s {
        "json" => Some(LogFormat::Json),
        "text" => Some(LogFormat::Text),
        _ => None,
    }
}

/// Forward a deprecated flat invocation to its new home and print a stderr
/// migration hint. The warning text follows a single template so operators
/// see a consistent message regardless of which alias they hit.
fn deprecation_warn(old: &str, new: &str) {
    eprintln!(
        "warning: `rsigma {old}` is deprecated; use `rsigma {new}` instead. \
         This alias is hidden from `--help` and will be removed in v1.0."
    );
}

fn dispatch(command: Commands, matches: &ArgMatches, ctx: output::OutputCtx) {
    match command {
        // -- Grouped commands ------------------------------------------------
        Commands::Engine { cmd } => dispatch_engine(cmd, matches, ctx),
        Commands::Rule { cmd } => dispatch_rule(cmd, matches, ctx),
        Commands::Backend { cmd } => dispatch_backend(cmd, ctx),
        #[cfg(feature = "daemon")]
        Commands::Pipeline { cmd } => dispatch_pipeline(cmd),
        #[cfg(feature = "mcp")]
        Commands::Mcp { cmd } => dispatch_mcp(cmd),
        Commands::Config { cmd } => config::commands::dispatch(cmd),

        // -- Deprecated flat aliases ----------------------------------------
        Commands::Eval(args) => {
            deprecation_warn("eval", "engine eval");
            let em = matches
                .subcommand_matches("eval")
                .expect("eval submatches present");
            run_eval(args, em, ctx);
        }
        #[cfg(feature = "daemon")]
        Commands::Daemon(args) => {
            deprecation_warn("daemon", "engine daemon");
            let dm = matches
                .subcommand_matches("daemon")
                .expect("daemon submatches present");
            cmd_daemon(args, dm);
        }
        Commands::Parse(args) => {
            deprecation_warn("parse", "rule parse");
            commands::cmd_parse(args, ctx);
        }
        Commands::Validate(args) => {
            deprecation_warn("validate", "rule validate");
            commands::cmd_validate(args);
        }
        Commands::Lint(args) => {
            deprecation_warn("lint", "rule lint");
            run_lint(args, ctx);
        }
        Commands::Fields(args) => {
            deprecation_warn("fields", "rule fields");
            commands::cmd_fields(args, ctx);
        }
        Commands::Condition(args) => {
            deprecation_warn("condition", "rule condition");
            commands::cmd_condition(args, ctx);
        }
        Commands::Stdin(args) => {
            deprecation_warn("stdin", "rule stdin");
            commands::cmd_stdin(args, ctx);
        }
        Commands::Convert(args) => {
            deprecation_warn("convert", "backend convert");
            commands::cmd_convert(args, ctx);
        }
        Commands::ListTargets => {
            deprecation_warn("list-targets", "backend targets");
            commands::cmd_list_targets();
        }
        Commands::ListFormats(ListFormatsArgs { target }) => {
            deprecation_warn("list-formats", "backend formats");
            commands::cmd_list_formats(target);
        }
        #[cfg(feature = "daemon")]
        Commands::Resolve(args) => {
            deprecation_warn("resolve", "pipeline resolve");
            commands::cmd_resolve(args);
        }
    }
}

fn dispatch_engine(cmd: EngineCommands, matches: &ArgMatches, ctx: output::OutputCtx) {
    match cmd {
        EngineCommands::Eval(args) => {
            let em = matches
                .subcommand_matches("engine")
                .and_then(|m| m.subcommand_matches("eval"))
                .expect("engine eval submatches present");
            run_eval(args, em, ctx);
        }
        EngineCommands::Classify(args) => commands::cmd_classify(args, ctx),
        EngineCommands::Status(args) => commands::cmd_status(args, ctx),
        EngineCommands::Tap(args) => commands::cmd_tap(args, ctx),
        EngineCommands::Tail(args) => commands::cmd_tail(args, ctx),
        #[cfg(feature = "daemon")]
        EngineCommands::Daemon(args) => {
            let dm = matches
                .subcommand_matches("engine")
                .and_then(|m| m.subcommand_matches("daemon"))
                .expect("engine daemon submatches present");
            cmd_daemon(args, dm);
        }
    }
}

fn dispatch_rule(cmd: RuleCommands, matches: &ArgMatches, ctx: output::OutputCtx) {
    match cmd {
        RuleCommands::Parse(args) => commands::cmd_parse(args, ctx),
        RuleCommands::Validate(args) => commands::cmd_validate(args),
        RuleCommands::Lint(args) => run_lint(args, ctx),
        RuleCommands::Fields(args) => commands::cmd_fields(args, ctx),
        RuleCommands::Doc(args) => {
            let dm = matches
                .subcommand_matches("rule")
                .and_then(|m| m.subcommand_matches("doc"))
                .expect("rule doc submatches present");
            run_doc(args, dm, ctx);
        }
        RuleCommands::Backtest(args) => {
            let bm = matches
                .subcommand_matches("rule")
                .and_then(|m| m.subcommand_matches("backtest"))
                .expect("rule backtest submatches present");
            run_backtest(args, bm, ctx);
        }
        RuleCommands::Coverage(args) => {
            let cm = matches
                .subcommand_matches("rule")
                .and_then(|m| m.subcommand_matches("coverage"))
                .expect("rule coverage submatches present");
            run_coverage(args, cm, ctx);
        }
        RuleCommands::Scorecard(args) => {
            let sm = matches
                .subcommand_matches("rule")
                .and_then(|m| m.subcommand_matches("scorecard"))
                .expect("rule scorecard submatches present");
            run_scorecard(args, sm, ctx);
        }
        RuleCommands::Visibility(args) => {
            let vm = matches
                .subcommand_matches("rule")
                .and_then(|m| m.subcommand_matches("visibility"))
                .expect("rule visibility submatches present");
            run_visibility(args, vm, ctx);
        }
        RuleCommands::Condition(args) => commands::cmd_condition(args, ctx),
        RuleCommands::Stdin(args) => commands::cmd_stdin(args, ctx),
        RuleCommands::MigrateSources(args) => commands::cmd_migrate_sources(args),
    }
}

fn dispatch_backend(cmd: BackendCommands, ctx: output::OutputCtx) {
    match cmd {
        BackendCommands::Convert(args) => commands::cmd_convert(args, ctx),
        BackendCommands::Targets => commands::cmd_list_targets(),
        BackendCommands::Formats(ListFormatsArgs { target }) => commands::cmd_list_formats(target),
    }
}

#[cfg(feature = "daemon")]
fn dispatch_pipeline(cmd: PipelineCommands) {
    match cmd {
        PipelineCommands::Resolve(args) => commands::cmd_resolve(args),
    }
}

/// Shared eval entry point used by both `engine eval` and the deprecated
/// `eval` alias. Applies config (CLI flag > env > file > default) before
/// reading `fail_on_detection`, then centralizes the exit-code handling.
fn run_eval(mut args: EvalArgs, matches: &ArgMatches, ctx: output::OutputCtx) {
    commands::apply_eval_config(&mut args, matches);
    let fail_on_detection = args.fail_on_detection;
    let had_matches = commands::cmd_eval(args, ctx);
    if fail_on_detection && had_matches {
        process::exit(exit_code::FINDINGS);
    }
}

/// Entry point for `rule backtest`. Applies config (CLI flag > env > file >
/// default) before running, then exits with the report's house exit code
/// (0 pass, 1 findings, 2 rule error, 3 config error).
fn run_backtest(mut args: BacktestArgs, matches: &ArgMatches, ctx: output::OutputCtx) {
    commands::apply_backtest_config(&mut args, matches);
    let code = commands::cmd_backtest(args, ctx);
    process::exit(code);
}

/// Entry point for `rule coverage`. Applies config (CLI flag > env > file >
/// default) before running, then exits with the report's house exit code
/// (0 success, 1 gaps under --fail-on-gaps, 2 rule error, 3 config error).
fn run_coverage(mut args: CoverageArgs, matches: &ArgMatches, ctx: output::OutputCtx) {
    commands::apply_coverage_config(&mut args, matches);
    let code = commands::cmd_coverage(args, ctx);
    process::exit(code);
}

/// Entry point for `rule scorecard`. Applies config (CLI flag > env > file >
/// default) before running, then exits with the report's house exit code
/// (0 success or under --fail-on, 1 verdicts hit --fail-on, 2 input unreadable,
/// 3 bad flags or a malformed/version-mismatched report).
fn run_scorecard(mut args: ScorecardArgs, matches: &ArgMatches, ctx: output::OutputCtx) {
    commands::apply_scorecard_config(&mut args, matches);
    let code = commands::cmd_scorecard(args, ctx);
    process::exit(code);
}

/// Entry point for `rule doc`. Applies the `doc` config section (CLI flag >
/// env > file > default) before running, then exits with the house exit code
/// (0 success or plain render, 1 when --fail-on-missing finds rules below the
/// ADS bar, 2 unreadable rule, 3 bad flags).
fn run_doc(mut args: DocArgs, matches: &ArgMatches, ctx: output::OutputCtx) {
    commands::apply_doc_config(&mut args, matches);
    let code = commands::cmd_doc(args, ctx);
    process::exit(code);
}

/// Entry point for `rule visibility`. Applies config (CLI flag > env > file >
/// default) before running, then exits with the report's house exit code
/// (0 success, 1 blind spots under --fail-on-blind-spots, 2 rule error, 3
/// config error).
fn run_visibility(mut args: VisibilityArgs, matches: &ArgMatches, ctx: output::OutputCtx) {
    commands::apply_visibility_config(&mut args, matches);
    let code = commands::cmd_visibility(args, ctx);
    process::exit(code);
}

/// Shared lint entry point used by both `rule lint` and the deprecated `lint`
/// alias. Centralizes the `--fail-level` exit-code handling.
fn run_lint(args: LintArgs, ctx: output::OutputCtx) {
    let fail_level = args.fail_level.clone();
    let LintCounts {
        errors,
        warnings,
        infos,
    } = commands::cmd_lint(args, ctx);
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
                    // The inline-sources deprecation warning lives in
                    // rsigma-runtime, which is only linked with the `daemon`
                    // feature. Builds without it cannot resolve sources anyway.
                    #[cfg(feature = "daemon")]
                    if !p.sources.is_empty() {
                        rsigma_runtime::warn_pipeline_inline_sources(path, &p.name);
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

/// Load and merge a Sigma collection from one or more file/directory paths.
///
/// Directories are parsed recursively; each path's rules, correlations,
/// filters, and per-rule parse errors are concatenated. Exits with
/// `RULE_ERROR` if any path is missing or unreadable, or if no rules were
/// found across all paths. Accumulated per-rule parse errors are reported as a
/// stderr warning (matching [`load_collection`]) rather than aborting, so a
/// single malformed rule in a large directory does not silently vanish. Shared
/// by `backend convert` and `rule coverage`.
pub(crate) fn load_collection_multi(paths: &[PathBuf]) -> SigmaCollection {
    let mut collection = SigmaCollection::new();
    for path in paths {
        if path.is_dir() {
            match parse_sigma_directory(path) {
                Ok(dir_collection) => {
                    collection.rules.extend(dir_collection.rules);
                    collection.correlations.extend(dir_collection.correlations);
                    collection.filters.extend(dir_collection.filters);
                    collection.errors.extend(dir_collection.errors);
                }
                Err(e) => {
                    eprintln!("Error parsing directory {}: {e}", path.display());
                    process::exit(exit_code::RULE_ERROR);
                }
            }
        } else if path.is_file() {
            match parse_sigma_file(path) {
                Ok(file_collection) => {
                    collection.rules.extend(file_collection.rules);
                    collection.correlations.extend(file_collection.correlations);
                    collection.filters.extend(file_collection.filters);
                    collection.errors.extend(file_collection.errors);
                }
                Err(e) => {
                    eprintln!("Error parsing {}: {e}", path.display());
                    process::exit(exit_code::RULE_ERROR);
                }
            }
        } else {
            eprintln!("Path not found: {}", path.display());
            process::exit(exit_code::RULE_ERROR);
        }
    }
    if !collection.errors.is_empty() {
        eprintln!(
            "Warning: {} parse errors while loading rules",
            collection.errors.len()
        );
    }
    if collection.rules.is_empty() && collection.correlations.is_empty() {
        eprintln!("No rules found in specified path(s)");
        process::exit(exit_code::RULE_ERROR);
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

// ---------------------------------------------------------------------------
// Event filtering (jq / JSONPath)
// ---------------------------------------------------------------------------

/// Compiled jq filter parameterised over the JSON value type used by jaq.
type CompiledJqFilter = jaq_core::Filter<data::JustLut<Val>>;

/// Pre-compiled event filter -- either a jq filter or a JSONPath query.
pub(crate) enum EventFilter {
    /// No filter -- pass through the entire event.
    None,
    /// A compiled jq filter.
    Jq(CompiledJqFilter),
    /// A compiled JSONPath query.
    JsonPath(JsonPath),
}

/// Build an `EventFilter` from CLI arguments. Exits on parse errors.
pub(crate) fn build_event_filter(jq: Option<String>, jsonpath: Option<String>) -> EventFilter {
    if let Some(jq_expr) = jq {
        eprintln!("Event filter: jq '{jq_expr}'");
        let program = File {
            code: jq_expr.as_str(),
            path: (),
        };
        let defs = jaq_core::defs()
            .chain(jaq_std::defs())
            .chain(jaq_json::defs());
        let funs = jaq_core::funs()
            .chain(jaq_std::funs())
            .chain(jaq_json::funs());
        let arena = Arena::default();
        let modules = Loader::new(defs).load(&arena, program).unwrap_or_else(|e| {
            eprintln!("Invalid jq filter '{jq_expr}': {} module error(s)", e.len());
            process::exit(exit_code::CONFIG_ERROR);
        });
        let filter = Compiler::default()
            .with_funs(funs)
            .compile(modules)
            .unwrap_or_else(|e| {
                eprintln!("jq compilation errors ({} error(s))", e.len());
                process::exit(exit_code::CONFIG_ERROR);
            });
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_correlation_config(
    suppress: Option<String>,
    action: Option<String>,
    no_detections: bool,
    correlation_event_mode: String,
    max_correlation_events: usize,
    max_state_entries: usize,
    max_group_entries: Option<usize>,
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
        max_state_entries,
        max_group_entries,
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
            let input = json_to_val(value.clone());
            let ctx = Ctx::<data::JustLut<Val>>::new(&f.lut, Vars::new([]));
            f.id.run((ctx, input))
                .map(unwrap_valr)
                .filter_map(|r| match r {
                    Ok(val) => val_to_json(&val),
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

/// Convert a `serde_json::Value` to a jaq `Val`.
fn json_to_val(v: serde_json::Value) -> Val {
    use jaq_core::ValT;

    match v {
        serde_json::Value::Null => Val::Null,
        serde_json::Value::Bool(b) => Val::Bool(b),
        serde_json::Value::Number(n) => Val::from_num(&n.to_string()).unwrap_or(Val::Null),
        serde_json::Value::String(s) => Val::from(s),
        serde_json::Value::Array(arr) => arr.into_iter().map(json_to_val).collect(),
        serde_json::Value::Object(obj) => Val::obj(
            obj.into_iter()
                .map(|(k, v)| (Val::from(k), json_to_val(v)))
                .collect(),
        ),
    }
}

/// Drift guard: clap's compiled daemon defaults must equal the single-source
/// constants in `config::defaults`, since the resolver treats clap's
/// `DefaultValue` as the lowest layer.
#[cfg(all(test, feature = "daemon"))]
mod config_default_drift {
    use super::*;
    use crate::config::defaults;

    fn daemon_default(id: &str) -> Option<String> {
        let cmd = Cli::command();
        let engine = cmd.find_subcommand("engine")?;
        let daemon = engine.find_subcommand("daemon")?;
        daemon
            .get_arguments()
            .find(|a| a.get_id() == id)?
            .get_default_values()
            .first()
            .map(|s| s.to_string_lossy().into_owned())
    }

    fn backtest_default(id: &str) -> Option<String> {
        let cmd = Cli::command();
        let rule = cmd.find_subcommand("rule")?;
        let backtest = rule.find_subcommand("backtest")?;
        backtest
            .get_arguments()
            .find(|a| a.get_id() == id)?
            .get_default_values()
            .first()
            .map(|s| s.to_string_lossy().into_owned())
    }

    fn scorecard_default(id: &str) -> Option<String> {
        let cmd = Cli::command();
        let rule = cmd.find_subcommand("rule")?;
        let scorecard = rule.find_subcommand("scorecard")?;
        scorecard
            .get_arguments()
            .find(|a| a.get_id() == id)?
            .get_default_values()
            .first()
            .map(|s| s.to_string_lossy().into_owned())
    }

    /// The `rule backtest` input-handling flags share the single-source config
    /// defaults, just like the daemon flags.
    #[test]
    fn clap_backtest_defaults_match_config_defaults() {
        assert_eq!(
            backtest_default("input_format").as_deref(),
            Some(defaults::INPUT_FORMAT)
        );
        assert_eq!(
            backtest_default("syslog_tz").as_deref(),
            Some(defaults::SYSLOG_TZ)
        );
        assert_eq!(
            backtest_default("syslog_strip_bom"),
            Some(defaults::SYSLOG_STRIP_BOM.to_string())
        );
    }

    /// The `rule scorecard` verdict-threshold flags share the single-source
    /// config defaults, just like the daemon and backtest flags.
    #[test]
    fn clap_scorecard_defaults_match_config_defaults() {
        assert_eq!(
            scorecard_default("min_precision"),
            Some(defaults::SCORECARD_MIN_PRECISION.to_string())
        );
        assert_eq!(
            scorecard_default("tune_max_precision"),
            Some(defaults::SCORECARD_TUNE_MAX_PRECISION.to_string())
        );
        assert_eq!(
            scorecard_default("retire_max_precision"),
            Some(defaults::SCORECARD_RETIRE_MAX_PRECISION.to_string())
        );
        assert_eq!(
            scorecard_default("min_volume"),
            Some(defaults::SCORECARD_MIN_VOLUME.to_string())
        );
        assert_eq!(
            scorecard_default("stale_window"),
            Some(defaults::SCORECARD_STALE_WINDOW_DAYS.to_string())
        );
        assert_eq!(
            scorecard_default("max_fp_ratio"),
            Some(defaults::SCORECARD_MAX_FP_RATIO.to_string())
        );
        assert_eq!(
            scorecard_default("fail_on").as_deref(),
            Some(defaults::SCORECARD_FAIL_ON)
        );
    }

    #[test]
    fn clap_daemon_defaults_match_config_defaults() {
        assert_eq!(
            daemon_default("api_addr").as_deref(),
            Some(defaults::API_ADDR)
        );
        assert_eq!(
            daemon_default("input_format").as_deref(),
            Some(defaults::INPUT_FORMAT)
        );
        assert_eq!(
            daemon_default("syslog_tz").as_deref(),
            Some(defaults::SYSLOG_TZ)
        );
        assert_eq!(
            daemon_default("syslog_strip_bom"),
            Some(defaults::SYSLOG_STRIP_BOM.to_string())
        );
        assert_eq!(
            daemon_default("correlation_event_mode").as_deref(),
            Some(defaults::CORRELATION_EVENT_MODE)
        );
        assert_eq!(
            daemon_default("timestamp_fallback").as_deref(),
            Some(defaults::TIMESTAMP_FALLBACK)
        );
        assert_eq!(
            daemon_default("buffer_size"),
            Some(defaults::BUFFER_SIZE.to_string())
        );
        assert_eq!(
            daemon_default("batch_size"),
            Some(defaults::BATCH_SIZE.to_string())
        );
        assert_eq!(
            daemon_default("drain_timeout"),
            Some(defaults::DRAIN_TIMEOUT.to_string())
        );
        assert_eq!(
            daemon_default("retry_max"),
            Some(defaults::SINK_RETRY_MAX.to_string())
        );
        assert_eq!(
            daemon_default("backoff_base_ms"),
            Some(defaults::SINK_BACKOFF_BASE_MS.to_string())
        );
        assert_eq!(
            daemon_default("backoff_max_ms"),
            Some(defaults::SINK_BACKOFF_MAX_MS.to_string())
        );
        assert_eq!(
            daemon_default("batch_max"),
            Some(defaults::SINK_BATCH_MAX.to_string())
        );
        assert_eq!(
            daemon_default("batch_flush_ms"),
            Some(defaults::SINK_BATCH_FLUSH_MS.to_string())
        );
        assert_eq!(
            daemon_default("max_correlation_events"),
            Some(defaults::MAX_CORRELATION_EVENTS.to_string())
        );
        assert_eq!(
            daemon_default("max_state_entries"),
            Some(defaults::MAX_STATE_ENTRIES.to_string())
        );
        assert_eq!(
            daemon_default("state_save_interval"),
            Some(defaults::STATE_SAVE_INTERVAL.to_string())
        );
        assert_eq!(
            daemon_default("observe_fields_max_keys"),
            Some(defaults::OBSERVE_FIELDS_MAX_KEYS.to_string())
        );
    }

    /// The CLI default must match the engine's own `CorrelationConfig`
    /// default; the two are defined in different crates.
    #[test]
    fn max_state_entries_matches_engine_default() {
        assert_eq!(
            defaults::MAX_STATE_ENTRIES,
            CorrelationConfig::default().max_state_entries
        );
    }
}

/// Convert a jaq `Val` to a `serde_json::Value`.
///
/// Returns `None` only if the value cannot be represented as JSON at all
/// (currently never; non-finite floats and non-string object keys fall back
/// to their string representation).
fn val_to_json(val: &Val) -> Option<serde_json::Value> {
    use jaq_std::ValT;

    Some(match val {
        Val::Null => serde_json::Value::Null,
        Val::Bool(b) => serde_json::Value::Bool(*b),
        Val::Num(_) => {
            if let Some(i) = val.as_isize() {
                serde_json::Value::Number((i as i64).into())
            } else if let Some(f) = val.as_f64() {
                serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .unwrap_or_else(|| serde_json::Value::String(val.to_string()))
            } else {
                serde_json::Value::String(val.to_string())
            }
        }
        Val::BStr(b) | Val::TStr(b) => {
            serde_json::Value::String(String::from_utf8_lossy(b).into_owned())
        }
        Val::Arr(arr) => {
            let items: Vec<serde_json::Value> = arr.iter().filter_map(val_to_json).collect();
            serde_json::Value::Array(items)
        }
        Val::Obj(obj) => {
            let mut map = serde_json::Map::new();
            for (k, v) in obj.iter() {
                let key = match k {
                    Val::BStr(b) | Val::TStr(b) => String::from_utf8_lossy(b).into_owned(),
                    _ => k.to_string(),
                };
                if let Some(jv) = val_to_json(v) {
                    map.insert(key, jv);
                }
            }
            serde_json::Value::Object(map)
        }
    })
}
