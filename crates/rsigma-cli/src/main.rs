#[cfg(feature = "daemon")]
mod daemon;
mod fix;

use std::fs::File;
use std::io::{self, BufRead, BufReader, IsTerminal, Read};
use std::path::PathBuf;
use std::process;
use std::time::SystemTime;

use clap::{Parser, Subcommand};
use jaq_interpret::{Ctx, FilterT, ParseCtx, RcIter, Val};
use rsigma_eval::{
    CorrelationAction, CorrelationConfig, CorrelationEngine, CorrelationEventMode, Engine,
    JsonEvent, Pipeline, parse_pipeline_file,
};
use rsigma_parser::lint::{self, FileLintResult, LintConfig};
use rsigma_parser::{SigmaCollection, parse_sigma_directory, parse_sigma_file, parse_sigma_yaml};
use serde::Deserialize;
use serde_json_path::JsonPath;

#[derive(Parser)]
#[command(name = "rsigma")]
#[command(about = "Parse, validate, and evaluate Sigma detection rules")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse a single Sigma YAML file and print the AST as JSON
    Parse {
        /// Path to a Sigma YAML file
        path: PathBuf,

        /// Pretty-print JSON output
        #[arg(short, long, default_value_t = true)]
        pretty: bool,
    },

    /// Parse all Sigma rules in a directory (recursive) and report results
    Validate {
        /// Path to a directory containing Sigma YAML files
        path: PathBuf,

        /// Show details for each file (not just summary)
        #[arg(short, long)]
        verbose: bool,

        /// Processing pipeline YAML file(s) to apply (can be specified multiple times)
        #[arg(short = 'p', long = "pipeline")]
        pipelines: Vec<PathBuf>,
    },

    /// Parse a condition expression and print the AST
    Condition {
        /// The condition expression to parse
        expr: String,
    },

    /// Read Sigma YAML from stdin and print parsed AST as JSON
    Stdin {
        /// Pretty-print JSON output
        #[arg(short, long, default_value_t = true)]
        pretty: bool,
    },

    /// Lint Sigma rules against the specification
    ///
    /// Runs built-in lint checks derived from the Sigma v2.1.0 specification.
    /// Optionally also validates against a JSON schema (use --schema default
    /// to download the official schema, or --schema <path> for a local file).
    Lint {
        /// Path to a Sigma rule file or directory of rules
        path: PathBuf,

        /// JSON schema for additional validation.
        /// Use "default" to download the official Sigma schema (cached for 7 days),
        /// or provide a path to a local schema file.
        #[arg(short, long)]
        schema: Option<String>,

        /// Show details for all files, including those that pass
        #[arg(short, long)]
        verbose: bool,

        /// Color output: auto (default), always, never
        #[arg(long, default_value = "auto", value_parser = ["auto", "always", "never"])]
        color: String,

        /// Disable specific lint rules (comma-separated).
        /// Example: --disable missing_description,missing_author
        #[arg(long, value_delimiter = ',')]
        disable: Vec<String>,

        /// Path to a .rsigma-lint.yml config file.
        /// If omitted, searches for .rsigma-lint.yml in ancestor directories.
        #[arg(long = "config")]
        lint_config: Option<PathBuf>,

        /// Exclude paths matching glob patterns (can be repeated).
        /// Patterns are matched against paths relative to the lint root.
        /// Example: --exclude "config/**" --exclude "**/unsupported/**"
        #[arg(long)]
        exclude: Vec<String>,

        /// Auto-fix safe lint issues in-place.
        /// Applies format-preserving fixes to files on disk.
        #[arg(long)]
        fix: bool,
    },

    /// Run as a long-running daemon with hot-reload, health checks, and metrics
    ///
    /// Reads NDJSON events from stdin, evaluates against rules, and writes
    /// matches to stdout. Exposes health endpoints, Prometheus metrics,
    /// and a management API on the configured address.
    #[cfg(feature = "daemon")]
    Daemon {
        /// Path to a Sigma rule file or directory of rules
        #[arg(short, long)]
        rules: PathBuf,

        /// Processing pipeline YAML file(s) to apply (can be specified multiple times)
        #[arg(short = 'p', long = "pipeline")]
        pipelines: Vec<PathBuf>,

        /// jq filter to extract the event payload from each JSON object
        #[arg(long = "jq", conflicts_with = "jsonpath")]
        jq: Option<String>,

        /// JSONPath (RFC 9535) query to extract the event payload
        #[arg(long = "jsonpath", conflicts_with = "jq")]
        jsonpath: Option<String>,

        /// Include the full event JSON in each detection match output
        #[arg(long = "include-event")]
        include_event: bool,

        /// Pretty-print JSON output
        #[arg(long)]
        pretty: bool,

        /// Address for health, metrics, and API server (default: 0.0.0.0:9090)
        #[arg(long = "api-addr", default_value = "0.0.0.0:9090")]
        api_addr: String,

        /// Suppression window for correlation alerts (e.g. 5m, 1h, 30s)
        #[arg(long = "suppress")]
        suppress: Option<String>,

        /// Action after correlation fires: 'alert' (default) or 'reset'
        #[arg(long = "action", value_parser = ["alert", "reset"])]
        action: Option<String>,

        /// Suppress detection output for correlation-only rules
        #[arg(long = "no-detections")]
        no_detections: bool,

        /// Correlation event mode: none, full, or refs
        #[arg(long = "correlation-event-mode", default_value = "none")]
        correlation_event_mode: String,

        /// Max events per correlation window group
        #[arg(long = "max-correlation-events", default_value = "10")]
        max_correlation_events: usize,

        /// Event field name(s) for timestamp extraction in correlations
        #[arg(long = "timestamp-field")]
        timestamp_fields: Vec<String>,

        /// Path to SQLite database for persisting correlation state across restarts.
        /// When set, state is loaded on startup and saved periodically + on shutdown.
        #[arg(long = "state-db")]
        state_db: Option<PathBuf>,

        /// Interval in seconds between periodic state snapshots (default: 30).
        /// Only meaningful when --state-db is set.
        #[arg(long = "state-save-interval", default_value = "30", value_parser = clap::value_parser!(u64).range(1..))]
        state_save_interval: u64,

        /// Event input source. Supported schemes: stdin, http, nats://<host>:<port>/<subject>
        #[arg(long = "input", default_value = "stdin")]
        input: String,

        /// Detection output sink (can be repeated for fan-out).
        /// Supported schemes: stdout, file://<path>, nats://<host>:<port>/<subject>
        #[arg(long = "output", default_value = "stdout")]
        output: Vec<String>,

        /// Bounded channel capacity for source→engine and engine→sink queues.
        /// Higher values absorb bursts; lower values apply back-pressure sooner.
        #[arg(long = "buffer-size", default_value = "10000")]
        buffer_size: usize,

        /// Maximum events to process per engine lock acquisition.
        /// Reduces mutex overhead under load. 1 = process one at a time (default).
        #[arg(long = "batch-size", default_value = "1")]
        batch_size: usize,

        /// Seconds to wait for in-flight events to drain on shutdown (default: 5).
        #[arg(long = "drain-timeout", default_value = "5")]
        drain_timeout: u64,

        /// Input log format for event parsing.
        /// auto: try JSON → syslog → plain (default).
        /// Explicit: json, syslog, plain, logfmt (requires logfmt feature),
        /// cef (requires cef feature).
        #[arg(long = "input-format", default_value = "auto")]
        input_format: String,

        /// Default timezone offset for RFC 3164 syslog (e.g. +05:00, -08:00).
        /// Only used when --input-format is syslog or auto. Defaults to UTC.
        #[arg(long = "syslog-tz", default_value = "+00:00")]
        syslog_tz: String,
    },

    /// Evaluate events against Sigma rules
    ///
    /// Load rules from a file or directory, then evaluate JSON events.
    /// Events can be provided as a single JSON string (--event) or as
    /// NDJSON (newline-delimited JSON) from stdin.
    Eval {
        /// Path to a Sigma rule file or directory of rules
        #[arg(short, long)]
        rules: PathBuf,

        /// A single event as a JSON string, or @path to read NDJSON from a file.
        /// If omitted, reads NDJSON from stdin.
        #[arg(short, long)]
        event: Option<String>,

        /// Pretty-print JSON output
        #[arg(long)]
        pretty: bool,

        /// Processing pipeline YAML file(s) to apply (can be specified multiple times)
        #[arg(short = 'p', long = "pipeline")]
        pipelines: Vec<PathBuf>,

        /// jq filter to extract the event payload from each JSON object.
        /// Example: --jq '.event' or --jq '.records[]'
        #[arg(long = "jq", conflicts_with = "jsonpath")]
        jq: Option<String>,

        /// JSONPath (RFC 9535) query to extract the event payload.
        /// Example: --jsonpath '$.event' or --jsonpath '$.records[*]'
        #[arg(long = "jsonpath", conflicts_with = "jq")]
        jsonpath: Option<String>,

        /// Suppression window for correlation alerts.
        /// After a correlation fires for a group key, suppress re-alerts
        /// for this duration. Examples: 5m, 1h, 30s.
        #[arg(long = "suppress")]
        suppress: Option<String>,

        /// Action to take after a correlation fires.
        /// 'alert' (default): keep state, re-alert on next match.
        /// 'reset': clear window state, require threshold from scratch.
        #[arg(long = "action", value_parser = ["alert", "reset"])]
        action: Option<String>,

        /// Suppress detection-level output for rules that are only
        /// referenced by correlations (where generate=false).
        #[arg(long = "no-detections")]
        no_detections: bool,

        /// Include the full event JSON in each detection match output.
        /// Equivalent to the `rsigma.include_event` custom attribute.
        #[arg(long = "include-event")]
        include_event: bool,

        /// Correlation event inclusion mode:
        ///   none  — don't include events (default, zero overhead)
        ///   full  — include full event bodies (deflate compressed in memory)
        ///   refs  — include lightweight references (timestamp + event ID)
        /// Use --max-correlation-events to cap storage per window.
        #[arg(long = "correlation-event-mode", default_value = "none")]
        correlation_event_mode: String,

        /// Maximum events to store per correlation window group when
        /// --correlation-event-mode is not 'none'. Oldest events are
        /// evicted when the cap is reached.
        #[arg(long = "max-correlation-events", default_value = "10")]
        max_correlation_events: usize,

        /// Event field name(s) to use for timestamp extraction in correlations.
        /// Can be specified multiple times; tried in order before built-in
        /// defaults (@timestamp, timestamp, EventTime, …).
        /// Equivalent to the `rsigma.timestamp_field` custom attribute.
        #[arg(long = "timestamp-field")]
        timestamp_fields: Vec<String>,

        /// Input log format for event parsing.
        /// auto: try JSON → syslog → plain (default).
        /// Explicit: json, syslog, plain, logfmt (requires logfmt feature),
        /// cef (requires cef feature).
        #[arg(long = "input-format", default_value = "auto")]
        input_format: String,

        /// Default timezone offset for RFC 3164 syslog (e.g. +05:00, -08:00).
        /// Only used when --input-format is syslog or auto. Defaults to UTC.
        #[arg(long = "syslog-tz", default_value = "+00:00")]
        syslog_tz: String,
    },

    /// Convert Sigma rules to backend-native queries
    Convert {
        /// Path(s) to Sigma rule file(s) or directory
        rules: Vec<PathBuf>,

        /// Target backend (e.g. test)
        #[arg(short, long)]
        target: String,

        /// Output format (backend-specific, default: "default")
        #[arg(short, long, default_value = "default")]
        format: String,

        /// Processing pipeline YAML file(s) (repeatable)
        #[arg(short = 'p', long = "pipeline")]
        pipeline: Vec<PathBuf>,

        /// Skip pipeline requirement check
        #[arg(long)]
        without_pipeline: bool,

        /// Skip unsupported rules instead of failing
        #[arg(short, long)]
        skip_unsupported: bool,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Backend options as key=value pairs (repeatable)
        #[arg(short = 'O', long = "option")]
        backend_options: Vec<String>,
    },

    /// List available conversion targets (backends)
    ListTargets,

    /// List available output formats for a target
    ListFormats {
        /// Target backend name
        target: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        #[cfg(feature = "daemon")]
        Commands::Daemon {
            rules,
            pipelines,
            jq,
            jsonpath,
            include_event,
            pretty,
            api_addr,
            suppress,
            action,
            no_detections,
            correlation_event_mode,
            max_correlation_events,
            timestamp_fields,
            state_db,
            state_save_interval,
            input,
            output,
            buffer_size,
            batch_size,
            drain_timeout,
            input_format,
            syslog_tz,
        } => cmd_daemon(
            rules,
            pipelines,
            jq,
            jsonpath,
            include_event,
            pretty,
            api_addr,
            suppress,
            action,
            no_detections,
            correlation_event_mode,
            max_correlation_events,
            timestamp_fields,
            state_db,
            state_save_interval,
            input,
            output,
            buffer_size,
            batch_size,
            drain_timeout,
            input_format,
            syslog_tz,
        ),
        Commands::Parse { path, pretty } => cmd_parse(path, pretty),
        Commands::Validate {
            path,
            verbose,
            pipelines,
        } => cmd_validate(path, verbose, pipelines),
        Commands::Lint {
            path,
            schema,
            verbose,
            color,
            disable,
            lint_config,
            exclude,
            fix: apply_fix,
        } => cmd_lint(
            path,
            schema,
            verbose,
            &color,
            disable,
            lint_config,
            exclude,
            apply_fix,
        ),
        Commands::Condition { expr } => cmd_condition(expr),
        Commands::Stdin { pretty } => cmd_stdin(pretty),
        Commands::Eval {
            rules,
            event,
            pretty,
            pipelines,
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
        } => cmd_eval(
            rules,
            event,
            pretty,
            pipelines,
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
        ),
        Commands::Convert {
            rules,
            target,
            format,
            pipeline,
            without_pipeline,
            skip_unsupported,
            output,
            backend_options,
        } => cmd_convert(
            rules,
            target,
            format,
            pipeline,
            without_pipeline,
            skip_unsupported,
            output,
            backend_options,
        ),
        Commands::ListTargets => cmd_list_targets(),
        Commands::ListFormats { target } => cmd_list_formats(target),
    }
}

// ---------------------------------------------------------------------------
// Daemon subcommand
// ---------------------------------------------------------------------------

#[cfg(feature = "daemon")]
#[allow(clippy::too_many_arguments)]
fn cmd_daemon(
    rules_path: PathBuf,
    pipeline_paths: Vec<PathBuf>,
    jq: Option<String>,
    jsonpath: Option<String>,
    include_event: bool,
    pretty: bool,
    api_addr: String,
    suppress: Option<String>,
    action: Option<String>,
    no_detections: bool,
    correlation_event_mode: String,
    max_correlation_events: usize,
    timestamp_fields: Vec<String>,
    state_db: Option<PathBuf>,
    state_save_interval: u64,
    input: String,
    output: Vec<String>,
    buffer_size: usize,
    batch_size: usize,
    drain_timeout: u64,
    input_format: String,
    syslog_tz: String,
) {
    // Set up structured logging
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let pipelines = load_pipelines(&pipeline_paths);
    let event_filter = std::sync::Arc::new(build_event_filter(jq, jsonpath));
    let parsed_input_format = parse_input_format(&input_format, &syslog_tz);

    let corr_config = build_correlation_config(
        suppress,
        action,
        no_detections,
        correlation_event_mode,
        max_correlation_events,
        timestamp_fields,
    );

    let addr: std::net::SocketAddr = api_addr.parse().unwrap_or_else(|e| {
        eprintln!("Invalid API address '{api_addr}': {e}");
        process::exit(1);
    });

    let config = daemon::server::DaemonConfig {
        rules_path,
        pipelines,
        corr_config,
        include_event,
        pretty,
        api_addr: addr,
        event_filter,
        state_db,
        state_save_interval,
        input,
        output,
        buffer_size,
        batch_size,
        drain_timeout,
        input_format: parsed_input_format,
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("Failed to create Tokio runtime: {e}");
            process::exit(1);
        });

    rt.block_on(daemon::run_daemon(config));
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

fn cmd_parse(path: PathBuf, pretty: bool) {
    match parse_sigma_file(&path) {
        Ok(collection) => {
            print_warnings(&collection.errors);
            print_json(&collection, pretty);
        }
        Err(e) => {
            eprintln!("Error parsing {}: {e}", path.display());
            process::exit(1);
        }
    }
}

fn cmd_validate(path: PathBuf, verbose: bool, pipeline_paths: Vec<PathBuf>) {
    let pipelines = load_pipelines(&pipeline_paths);

    match parse_sigma_directory(&path) {
        Ok(collection) => {
            let total = collection.len();
            let rules = collection.rules.len();
            let correlations = collection.correlations.len();
            let filters = collection.filters.len();
            let parse_errors = collection.errors.len();

            println!("Parsed {total} documents from {}", path.display());
            println!("  Detection rules:   {rules}");
            println!("  Correlation rules: {correlations}");
            println!("  Filter rules:      {filters}");
            println!("  Parse errors:      {parse_errors}");

            // Always compile rules to catch compiler regressions
            let mut engine = Engine::new();
            for p in &pipelines {
                engine.add_pipeline(p.clone());
            }

            let mut compile_ok = 0usize;
            let mut compile_errors: Vec<String> = Vec::new();
            for rule in &collection.rules {
                match engine.add_rule(rule) {
                    Ok(()) => compile_ok += 1,
                    Err(e) => {
                        let id = rule.id.as_deref().unwrap_or(&rule.title);
                        compile_errors.push(format!("{id}: {e}"));
                    }
                }
            }

            if !pipelines.is_empty() {
                println!("  Pipeline applied:  {} pipeline(s)", pipelines.len(),);
            }
            println!("  Compiled OK:       {compile_ok}");
            println!("  Compile errors:    {}", compile_errors.len());

            if verbose {
                if !collection.errors.is_empty() {
                    println!("\nParse errors:");
                    for err in &collection.errors {
                        println!("  - {err}");
                    }
                }
                if !compile_errors.is_empty() {
                    println!("\nCompile errors:");
                    for err in &compile_errors {
                        println!("  - {err}");
                    }
                }
            }

            if parse_errors > 0 || !compile_errors.is_empty() {
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_lint(
    path: PathBuf,
    schema: Option<String>,
    verbose: bool,
    color: &str,
    disable: Vec<String>,
    lint_config_path: Option<PathBuf>,
    exclude: Vec<String>,
    apply_fix: bool,
) {
    let p = Painter::new(color);

    // 0. Build lint config from file + CLI flags
    let config = build_lint_config(&path, disable, lint_config_path, exclude);

    // 1. Run built-in lint checks (with suppression)
    let results: Vec<FileLintResult> = if path.is_dir() {
        match lint::lint_yaml_directory_with_config(&path, &config) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        }
    } else {
        match lint::lint_yaml_file_with_config(&path, &config) {
            Ok(r) => vec![r],
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        }
    };

    // 2. Optionally run JSON schema validation
    let schema_results = schema.map(|schema_arg| run_schema_validation(&path, &schema_arg));

    // 3. Merge schema warnings into results
    let mut all_results = results;
    if let Some(sr) = schema_results {
        merge_schema_results(&mut all_results, sr);
    }

    // 4. Render results
    let mut total_files = 0usize;
    let mut failed_files = 0usize;
    let mut total_errors = 0usize;
    let mut total_warnings = 0usize;
    let mut total_infos = 0usize;

    for result in &all_results {
        total_files += 1;
        let errors = result.error_count();
        let warnings = result.warning_count();
        let infos = result.info_count();
        total_errors += errors;
        total_warnings += warnings;
        total_infos += infos;

        let has_failures = result
            .warnings
            .iter()
            .any(|w| matches!(w.severity, lint::Severity::Error | lint::Severity::Warning));

        if result.warnings.is_empty() {
            if verbose {
                println!(
                    "{} {}",
                    p.bold(&result.path.display().to_string()),
                    p.green("OK"),
                );
            }
        } else if has_failures {
            failed_files += 1;
            // File header
            println!("{}", p.bold(&result.path.display().to_string()));
            for w in &result.warnings {
                render_lint_warning(w, &p);
            }
            println!(); // blank line between file blocks
        } else {
            // Only info/hint — show if verbose
            if verbose {
                println!("{}", p.bold(&result.path.display().to_string()));
                for w in &result.warnings {
                    render_lint_warning(w, &p);
                }
                println!();
            }
        }
    }

    // 5. Summary
    let passed = total_files - failed_files;
    let separator = "─".repeat(60);
    println!("{}", p.dim(&separator));

    let passed_str = format!("{passed} passed");
    let failed_str = format!("{failed_files} failed");
    let errors_str = format!("{total_errors} error(s)");
    let warnings_str = format!("{total_warnings} warning(s)");
    let infos_str = format!("{total_infos} info(s)");

    let passed_colored = if passed > 0 {
        p.green_bold(&passed_str)
    } else {
        p.dim(&passed_str)
    };
    let failed_colored = if failed_files > 0 {
        p.red_bold(&failed_str)
    } else {
        p.dim(&failed_str)
    };
    let errors_colored = if total_errors > 0 {
        p.red(&errors_str)
    } else {
        p.dim(&errors_str)
    };
    let warnings_colored = if total_warnings > 0 {
        p.yellow(&warnings_str)
    } else {
        p.dim(&warnings_str)
    };
    let infos_colored = if total_infos > 0 {
        p.blue(&infos_str)
    } else {
        p.dim(&infos_str)
    };

    println!(
        "Checked {} file(s): {}, {} ({}, {}, {})",
        total_files,
        passed_colored,
        failed_colored,
        errors_colored,
        warnings_colored,
        infos_colored,
    );

    // 6. Apply fixes if requested
    if apply_fix {
        let fixable: usize = all_results
            .iter()
            .flat_map(|r| &r.warnings)
            .filter(|w| {
                w.fix
                    .as_ref()
                    .is_some_and(|f| f.disposition == lint::FixDisposition::Safe)
            })
            .count();

        if fixable == 0 {
            println!("{}", p.dim("No auto-fixable issues found."));
        } else {
            let result = fix::apply_fixes(&all_results);
            println!(
                "\n{}",
                p.green_bold(&format!(
                    "Applied {} fix(es) across {} file(s).",
                    result.applied, result.files_modified,
                ))
            );
            if result.failed > 0 {
                println!(
                    "{}",
                    p.yellow(&format!(
                        "{} fix(es) could not be applied (conflicts).",
                        result.failed,
                    ))
                );
            }
        }
    }

    if total_errors > 0 {
        process::exit(1);
    }
}

fn render_lint_warning(w: &lint::LintWarning, p: &Painter) {
    let (severity_label, rule_bracket) = match w.severity {
        lint::Severity::Error => (p.red_bold("error"), p.red(&format!("[{}]", w.rule))),
        lint::Severity::Warning => (p.yellow_bold("warning"), p.yellow(&format!("[{}]", w.rule))),
        lint::Severity::Info => (p.blue("info"), p.blue(&format!("[{}]", w.rule))),
        lint::Severity::Hint => (p.dim("hint"), p.dim(&format!("[{}]", w.rule))),
    };
    println!("  {}{}: {}", severity_label, rule_bracket, w.message);
    let location = if let Some(span) = &w.span {
        format!("{} (line {})", w.path, span.start_line + 1)
    } else {
        w.path.clone()
    };
    println!("    {} {}", p.cyan("-->"), p.cyan(&location));
}

// ---------------------------------------------------------------------------
// JSON Schema validation
// ---------------------------------------------------------------------------

/// Official Sigma detection rule schema URL.
const SCHEMA_URL: &str = "https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main/json-schema/sigma-detection-rule-schema.json";

/// Cache freshness duration: 7 days in seconds.
const CACHE_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Resolve the schema JSON string from the `--schema` argument.
///
/// - `"default"`: download from GitHub and cache in XDG cache dir.
/// - anything else: treat as a local file path.
fn resolve_schema(schema_arg: &str) -> String {
    if schema_arg == "default" {
        resolve_default_schema()
    } else {
        match std::fs::read_to_string(schema_arg) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error reading schema file '{schema_arg}': {e}");
                process::exit(1);
            }
        }
    }
}

fn resolve_default_schema() -> String {
    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("rsigma");
    let cache_path = cache_dir.join("sigma-schema.json");

    // Check if cached copy is fresh
    if let Ok(meta) = std::fs::metadata(&cache_path)
        && let Ok(modified) = meta.modified()
    {
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();
        if age.as_secs() < CACHE_MAX_AGE_SECS
            && let Ok(content) = std::fs::read_to_string(&cache_path)
        {
            eprintln!("Using cached schema: {}", cache_path.display());
            return content;
        }
    }

    // Download
    eprintln!("Downloading schema from {SCHEMA_URL}...");
    match ureq::get(SCHEMA_URL).call() {
        Ok(response) => {
            let body = response.into_body().read_to_string().unwrap_or_else(|e| {
                eprintln!("Error reading schema response: {e}");
                process::exit(1);
            });

            // Cache it
            if let Err(e) = std::fs::create_dir_all(&cache_dir) {
                eprintln!("Warning: could not create cache dir: {e}");
            } else if let Err(e) = std::fs::write(&cache_path, &body) {
                eprintln!("Warning: could not cache schema: {e}");
            } else {
                eprintln!("Cached schema at {}", cache_path.display());
            }

            body
        }
        Err(e) => {
            // Offline fallback: use stale cache if available
            if let Ok(content) = std::fs::read_to_string(&cache_path) {
                eprintln!("Warning: schema download failed ({e}), using stale cache");
                content
            } else {
                eprintln!("Error downloading schema: {e}");
                process::exit(1);
            }
        }
    }
}

/// Run JSON schema validation on all YAML files at `path`.
fn run_schema_validation(path: &std::path::Path, schema_arg: &str) -> Vec<FileLintResult> {
    let schema_json_str = resolve_schema(schema_arg);
    let schema_value: serde_json::Value = match serde_json::from_str(&schema_json_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error parsing schema JSON: {e}");
            process::exit(1);
        }
    };

    let validator = jsonschema::validator_for(&schema_value).unwrap_or_else(|e| {
        eprintln!("Error compiling JSON schema: {e}");
        process::exit(1);
    });

    let mut results = Vec::new();

    if path.is_dir() {
        fn walk_schema(
            dir: &std::path::Path,
            validator: &jsonschema::Validator,
            results: &mut Vec<FileLintResult>,
        ) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    walk_schema(&p, validator, results);
                } else if matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")) {
                    results.push(validate_file_against_schema(&p, validator));
                }
            }
        }
        walk_schema(path, &validator, &mut results);
    } else {
        results.push(validate_file_against_schema(path, &validator));
    }

    results
}

fn validate_file_against_schema(
    path: &std::path::Path,
    validator: &jsonschema::Validator,
) -> FileLintResult {
    let mut warnings = Vec::new();

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            warnings.push(lint::LintWarning {
                rule: lint::LintRule::FileReadError,
                severity: lint::Severity::Error,
                message: format!("error reading file: {e}"),
                path: "/".to_string(),
                span: None,
                fix: None,
            });
            return FileLintResult {
                path: path.to_path_buf(),
                warnings,
            };
        }
    };

    for doc in serde_yaml::Deserializer::from_str(&content) {
        let yaml_value: serde_yaml::Value = match serde_yaml::Value::deserialize(doc) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Skip action fragments
        if let Some(m) = yaml_value.as_mapping()
            && let Some(action) = m
                .get(serde_yaml::Value::String("action".into()))
                .and_then(|v| v.as_str())
            && matches!(action, "global" | "reset" | "repeat")
        {
            continue;
        }

        // Convert YAML to JSON for schema validation
        let json_str = match serde_json::to_string(&yaml_value) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let json_value: serde_json::Value = match serde_json::from_str(&json_str) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Validate
        for error in validator.iter_errors(&json_value) {
            warnings.push(lint::LintWarning {
                rule: lint::LintRule::SchemaViolation,
                severity: lint::Severity::Error,
                message: format!("schema: {error}"),
                path: error.instance_path().to_string(),
                span: None,
                fix: None,
            });
        }
    }

    FileLintResult {
        path: path.to_path_buf(),
        warnings,
    }
}

/// Merge schema validation results into the main lint results.
///
/// For files already in `main_results`, append schema warnings.
/// For files only in `schema_results`, add them as new entries.
fn merge_schema_results(
    main_results: &mut Vec<FileLintResult>,
    schema_results: Vec<FileLintResult>,
) {
    use std::collections::HashMap;

    let mut index: HashMap<PathBuf, usize> = main_results
        .iter()
        .enumerate()
        .map(|(i, r)| (r.path.clone(), i))
        .collect();

    for sr in schema_results {
        if let Some(&idx) = index.get(&sr.path) {
            main_results[idx].warnings.extend(sr.warnings);
        } else {
            let idx = main_results.len();
            index.insert(sr.path.clone(), idx);
            main_results.push(sr);
        }
    }
}

fn cmd_condition(expr: String) {
    match rsigma_parser::parse_condition(&expr) {
        Ok(ast) => print_json(&ast, true),
        Err(e) => {
            eprintln!("Condition parse error: {e}");
            process::exit(1);
        }
    }
}

fn cmd_stdin(pretty: bool) {
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        eprintln!("Error reading stdin: {e}");
        process::exit(1);
    }

    match parse_sigma_yaml(&input) {
        Ok(collection) => {
            print_warnings(&collection.errors);
            print_json(&collection, pretty);
        }
        Err(e) => {
            eprintln!("Parse error: {e}");
            process::exit(1);
        }
    }
}

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
fn cmd_eval(
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
    let collection = load_collection(&rules_path);
    let pipelines = load_pipelines(&pipeline_paths);
    let has_correlations = !collection.correlations.is_empty();

    // Compile the event filter once up front
    let event_filter = build_event_filter(jq, jsonpath);

    // Resolve @file syntax
    let event_source = resolve_event_source(event_json);

    // Build correlation config from CLI flags
    let corr_config = build_correlation_config(
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
    config: CorrelationConfig,
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

            for payload in apply_event_filter(&value, event_filter) {
                let event = JsonEvent::borrow(&payload);
                let result = engine.process_event(&event);

                let total = result.detections.len() + result.correlations.len();
                if total == 0 {
                    eprintln!("No matches.");
                } else {
                    for m in &result.detections {
                        print_json(m, pretty);
                    }
                    for m in &result.correlations {
                        print_json(m, pretty);
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
    let format = parse_input_format(input_format_str, syslog_tz_str);
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
            for payload in apply_event_filter(&json_value, event_filter) {
                let event = JsonEvent::borrow(&payload);
                let result = engine.process_event(&event);
                for m in &result.detections {
                    *det_count += 1;
                    print_json(m, pretty);
                }
                for m in &result.correlations {
                    *corr_count += 1;
                    print_json(m, pretty);
                }
            }
        } else {
            // Non-JSON events: evaluate directly (no event filter).
            let result = engine.process_event(&decoded);
            for m in &result.detections {
                *det_count += 1;
                print_json(m, pretty);
            }
            for m in &result.correlations {
                *corr_count += 1;
                print_json(m, pretty);
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

    for payload in apply_event_filter(&value, event_filter) {
        let event = JsonEvent::borrow(&payload);
        let result = engine.process_event(&event);
        for m in &result.detections {
            *det_count += 1;
            print_json(m, pretty);
        }
        for m in &result.correlations {
            *corr_count += 1;
            print_json(m, pretty);
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

            let payloads = apply_event_filter(&value, event_filter);
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
                            print_json(m, pretty);
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
    let format = parse_input_format(input_format_str, syslog_tz_str);
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
            for payload in apply_event_filter(&json_value, event_filter) {
                let event = JsonEvent::borrow(&payload);
                for m in &engine.evaluate(&event) {
                    *match_count += 1;
                    print_json(m, pretty);
                }
            }
        } else {
            for m in &engine.evaluate(&decoded) {
                *match_count += 1;
                print_json(m, pretty);
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

    for payload in apply_event_filter(&value, event_filter) {
        let event = JsonEvent::borrow(&payload);
        for m in &engine.evaluate(&event) {
            *match_count += 1;
            print_json(m, pretty);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `LintConfig` from a config file (auto-discovered or explicit) + CLI `--disable` flags.
fn build_lint_config(
    path: &std::path::Path,
    disable: Vec<String>,
    lint_config_path: Option<PathBuf>,
    exclude: Vec<String>,
) -> LintConfig {
    // Load config file
    let mut config = if let Some(explicit) = lint_config_path {
        match LintConfig::load(&explicit) {
            Ok(c) => {
                eprintln!("Loaded lint config: {}", explicit.display());
                c
            }
            Err(e) => {
                eprintln!("Error loading lint config '{}': {e}", explicit.display());
                process::exit(1);
            }
        }
    } else if let Some(found) = LintConfig::find_in_ancestors(path) {
        match LintConfig::load(&found) {
            Ok(c) => {
                eprintln!("Loaded lint config: {}", found.display());
                c
            }
            Err(e) => {
                eprintln!(
                    "Warning: found .rsigma-lint.yml at {} but failed to load: {e}",
                    found.display()
                );
                LintConfig::default()
            }
        }
    } else {
        LintConfig::default()
    };

    // Merge --disable and --exclude CLI flags
    if !disable.is_empty() || !exclude.is_empty() {
        let cli_config = LintConfig {
            disabled_rules: disable.into_iter().collect(),
            exclude_patterns: exclude,
            ..Default::default()
        };
        config.merge(&cli_config);
    }

    config
}

fn load_pipelines(paths: &[PathBuf]) -> Vec<Pipeline> {
    let mut pipelines = Vec::new();
    for path in paths {
        match parse_pipeline_file(path) {
            Ok(p) => {
                eprintln!("Loaded pipeline: {} (priority {})", p.name, p.priority);
                pipelines.push(p);
            }
            Err(e) => {
                eprintln!("Error loading pipeline {}: {e}", path.display());
                process::exit(1);
            }
        }
    }
    pipelines.sort_by_key(|p| p.priority);
    pipelines
}

fn load_collection(path: &std::path::Path) -> SigmaCollection {
    let collection = if path.is_dir() {
        match parse_sigma_directory(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error loading rules from {}: {e}", path.display());
                process::exit(1);
            }
        }
    } else {
        match parse_sigma_file(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error loading rule {}: {e}", path.display());
                process::exit(1);
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

fn print_warnings(errors: &[String]) {
    if !errors.is_empty() {
        eprintln!("Warnings:");
        for err in errors {
            eprintln!("  - {err}");
        }
    }
}

// ---------------------------------------------------------------------------
// Input format parsing
// ---------------------------------------------------------------------------

#[cfg(feature = "daemon")]
fn parse_input_format(format_str: &str, syslog_tz: &str) -> rsigma_runtime::InputFormat {
    use rsigma_runtime::InputFormat;
    use rsigma_runtime::input::SyslogConfig;

    let tz_secs = parse_tz_offset(syslog_tz);

    match format_str {
        "auto" => InputFormat::Auto(SyslogConfig {
            default_tz_offset_secs: tz_secs,
        }),
        "json" => InputFormat::Json,
        "syslog" => InputFormat::Syslog(SyslogConfig {
            default_tz_offset_secs: tz_secs,
        }),
        "plain" => InputFormat::Plain,
        #[cfg(feature = "logfmt")]
        "logfmt" => InputFormat::Logfmt,
        #[cfg(feature = "cef")]
        "cef" => InputFormat::Cef,
        other => {
            eprintln!("Unknown input format: '{other}'");
            eprintln!("Supported formats: auto, json, syslog, plain");
            #[cfg(feature = "logfmt")]
            eprintln!("  (with logfmt feature): logfmt");
            #[cfg(feature = "cef")]
            eprintln!("  (with cef feature): cef");
            process::exit(1);
        }
    }
}

/// Parse a timezone offset string like "+05:00" or "-08:00" into seconds east of UTC.
#[cfg(feature = "daemon")]
fn parse_tz_offset(s: &str) -> i32 {
    let s = s.trim();
    if s == "UTC" || s == "utc" || s == "Z" || s == "+00:00" {
        return 0;
    }

    let (sign, rest) = if let Some(rest) = s.strip_prefix('+') {
        (1i32, rest)
    } else if let Some(rest) = s.strip_prefix('-') {
        (-1i32, rest)
    } else {
        eprintln!("Invalid timezone offset: '{s}' (expected +HH:MM or -HH:MM)");
        process::exit(1);
    };

    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() != 2 {
        eprintln!("Invalid timezone offset: '{s}' (expected +HH:MM or -HH:MM)");
        process::exit(1);
    }

    let hours: i32 = parts[0].parse().unwrap_or_else(|_| {
        eprintln!("Invalid timezone offset hours: '{}'", parts[0]);
        process::exit(1);
    });
    let minutes: i32 = parts[1].parse().unwrap_or_else(|_| {
        eprintln!("Invalid timezone offset minutes: '{}'", parts[1]);
        process::exit(1);
    });

    sign * (hours * 3600 + minutes * 60)
}

// ---------------------------------------------------------------------------
// Event filtering (jq / JSONPath)
// ---------------------------------------------------------------------------

/// Pre-compiled event filter — either a jq filter or a JSONPath query.
pub(crate) enum EventFilter {
    /// No filter — pass through the entire event.
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
            process::exit(1);
        }
        let Some(parsed) = parsed else {
            eprintln!("Invalid jq filter: failed to parse '{jq_expr}'");
            process::exit(1);
        };
        let filter = defs.compile(parsed);
        if !defs.errs.is_empty() {
            eprintln!("jq compilation errors ({} error(s))", defs.errs.len());
            process::exit(1);
        }
        EventFilter::Jq(filter)
    } else if let Some(jp_expr) = jsonpath {
        eprintln!("Event filter: jsonpath '{jp_expr}'");
        match JsonPath::parse(&jp_expr) {
            Ok(path) => EventFilter::JsonPath(path),
            Err(e) => {
                eprintln!("Invalid JSONPath: {e}");
                process::exit(1);
            }
        }
    } else {
        EventFilter::None
    }
}

/// Build a `CorrelationConfig` from CLI arguments. Exits on parse errors.
fn build_correlation_config(
    suppress: Option<String>,
    action: Option<String>,
    no_detections: bool,
    correlation_event_mode: String,
    max_correlation_events: usize,
    extra_timestamp_fields: Vec<String>,
) -> CorrelationConfig {
    let suppress_secs = suppress.map(|s| match rsigma_parser::Timespan::parse(&s) {
        Ok(ts) => ts.seconds,
        Err(e) => {
            eprintln!("Invalid suppress duration '{s}': {e}");
            process::exit(1);
        }
    });

    let action_on_match = action
        .map(|s| {
            s.parse::<CorrelationAction>().unwrap_or_else(|e| {
                eprintln!("{e}");
                process::exit(1);
            })
        })
        .unwrap_or_default();

    let event_mode = correlation_event_mode
        .parse::<CorrelationEventMode>()
        .unwrap_or_else(|e| {
            eprintln!("{e}");
            process::exit(1);
        });

    let mut config = CorrelationConfig {
        suppress: suppress_secs,
        action_on_match,
        emit_detections: !no_detections,
        correlation_event_mode: event_mode,
        max_correlation_events,
        ..Default::default()
    };

    // Prepend CLI --timestamp-field values so they take priority over defaults
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
            // Num is a string-encoded number
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

// ---------------------------------------------------------------------------
// Terminal color support
// ---------------------------------------------------------------------------

/// ANSI color painter that respects `--color`, `NO_COLOR`, and tty detection.
struct Painter {
    enabled: bool,
}

impl Painter {
    fn new(color_arg: &str) -> Self {
        let enabled = match color_arg {
            "always" => true,
            "never" => false,
            _ => io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        };
        Painter { enabled }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }

    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }

    fn red(&self, s: &str) -> String {
        self.paint("31", s)
    }

    fn red_bold(&self, s: &str) -> String {
        self.paint("1;31", s)
    }

    fn green(&self, s: &str) -> String {
        self.paint("32", s)
    }

    fn green_bold(&self, s: &str) -> String {
        self.paint("1;32", s)
    }

    fn yellow(&self, s: &str) -> String {
        self.paint("33", s)
    }

    fn yellow_bold(&self, s: &str) -> String {
        self.paint("1;33", s)
    }

    fn blue(&self, s: &str) -> String {
        self.paint("34", s)
    }

    fn cyan(&self, s: &str) -> String {
        self.paint("36", s)
    }
}

// ---------------------------------------------------------------------------
// Convert subcommand
// ---------------------------------------------------------------------------

fn get_backend(
    target: &str,
    options: &std::collections::HashMap<String, String>,
) -> Box<dyn rsigma_convert::Backend> {
    match target {
        "postgres" | "postgresql" | "pg" => {
            Box::new(rsigma_convert::backends::postgres::PostgresBackend::from_options(options))
        }
        "test" => Box::new(rsigma_convert::backends::test::TextQueryTestBackend::new()),
        "test_mandatory_pipeline" => {
            Box::new(rsigma_convert::backends::test::MandatoryPipelineTestBackend::new())
        }
        _ => {
            eprintln!("Unknown target: {target}");
            eprintln!("Available targets: postgres, test");
            process::exit(1);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_convert(
    rules: Vec<PathBuf>,
    target: String,
    format: String,
    pipeline_paths: Vec<PathBuf>,
    without_pipeline: bool,
    skip_unsupported: bool,
    output: Option<PathBuf>,
    backend_options: Vec<String>,
) {
    let collection = load_collection_multi(&rules);
    let pipelines = load_pipelines(&pipeline_paths);

    let options: std::collections::HashMap<String, String> = backend_options
        .iter()
        .filter_map(|opt| {
            opt.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();
    let backend = get_backend(&target, &options);

    if backend.requires_pipeline() && pipelines.is_empty() && !without_pipeline {
        eprintln!(
            "Backend '{}' requires a pipeline. Use -p or --without-pipeline.",
            target
        );
        process::exit(1);
    }

    if !backend.formats().iter().any(|(f, _)| *f == format) {
        eprintln!("Unknown format '{format}' for backend '{target}'");
        eprintln!(
            "Available: {}",
            backend
                .formats()
                .iter()
                .map(|(f, d)| format!("{f} ({d})"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        process::exit(1);
    }

    let result =
        rsigma_convert::convert_collection(backend.as_ref(), &collection, &pipelines, &format);
    match result {
        Ok(output_data) => {
            for (rule_title, error) in &output_data.errors {
                if skip_unsupported {
                    eprintln!("Warning: rule '{rule_title}' skipped: {error}");
                } else {
                    eprintln!("Error: rule '{rule_title}' failed: {error}");
                }
            }
            if !skip_unsupported && !output_data.errors.is_empty() {
                process::exit(1);
            }
            let all_queries: Vec<&str> = output_data
                .queries
                .iter()
                .flat_map(|r| r.queries.iter().map(|q| q.as_str()))
                .collect();
            let output_str = all_queries.join("\n");
            write_output(&output_str, output.as_deref());
        }
        Err(e) => {
            eprintln!("Conversion failed: {e}");
            process::exit(1);
        }
    }
}

fn cmd_list_targets() {
    println!("Available conversion targets:");
    println!("  postgres  - PostgreSQL/TimescaleDB (aliases: postgresql, pg)");
    println!("  test      - Backend-neutral test backend");
}

fn cmd_list_formats(target: String) {
    let backend = get_backend(&target, &std::collections::HashMap::new());
    println!("Available formats for '{target}':");
    for (name, desc) in backend.formats() {
        println!("  {name}  - {desc}");
    }
}

fn load_collection_multi(paths: &[PathBuf]) -> SigmaCollection {
    let mut collection = SigmaCollection::new();
    for path in paths {
        if path.is_dir() {
            match parse_sigma_directory(path) {
                Ok(dir_collection) => {
                    collection.rules.extend(dir_collection.rules);
                    collection.correlations.extend(dir_collection.correlations);
                    collection.filters.extend(dir_collection.filters);
                }
                Err(e) => {
                    eprintln!("Error parsing directory {}: {e}", path.display());
                    process::exit(1);
                }
            }
        } else if path.is_file() {
            match parse_sigma_file(path) {
                Ok(file_collection) => {
                    collection.rules.extend(file_collection.rules);
                    collection.correlations.extend(file_collection.correlations);
                    collection.filters.extend(file_collection.filters);
                }
                Err(e) => {
                    eprintln!("Error parsing {}: {e}", path.display());
                    process::exit(1);
                }
            }
        } else {
            eprintln!("Path not found: {}", path.display());
            process::exit(1);
        }
    }
    if collection.rules.is_empty() && collection.correlations.is_empty() {
        eprintln!("No rules found in specified path(s)");
        process::exit(1);
    }
    collection
}

fn write_output(content: &str, output: Option<&std::path::Path>) {
    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, content) {
                eprintln!("Error writing to {}: {e}", path.display());
                process::exit(1);
            }
        }
        None => println!("{content}"),
    }
}

fn print_json(value: &impl serde::Serialize, pretty: bool) {
    let json = if pretty {
        serde_json::to_string_pretty(value)
    } else {
        serde_json::to_string(value)
    };
    match json {
        Ok(j) => println!("{j}"),
        Err(e) => {
            eprintln!("JSON serialization error: {e}");
            process::exit(1);
        }
    }
}
