mod commands;
#[cfg(feature = "daemon")]
mod daemon;
mod fix;

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use jaq_interpret::{Ctx, FilterT, ParseCtx, RcIter, Val};
use rsigma_eval::{
    CorrelationAction, CorrelationConfig, CorrelationEventMode, Pipeline, parse_pipeline_file,
};
use rsigma_parser::{SigmaCollection, parse_sigma_directory, parse_sigma_file};
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
        Commands::Parse { path, pretty } => commands::cmd_parse(path, pretty),
        Commands::Validate {
            path,
            verbose,
            pipelines,
        } => commands::cmd_validate(path, verbose, pipelines),
        Commands::Lint {
            path,
            schema,
            verbose,
            color,
            disable,
            lint_config,
            exclude,
            fix: apply_fix,
        } => commands::cmd_lint(
            path,
            schema,
            verbose,
            &color,
            disable,
            lint_config,
            exclude,
            apply_fix,
        ),
        Commands::Condition { expr } => commands::cmd_condition(expr),
        Commands::Stdin { pretty } => commands::cmd_stdin(pretty),
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
        } => commands::cmd_eval(
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
        } => commands::cmd_convert(
            rules,
            target,
            format,
            pipeline,
            without_pipeline,
            skip_unsupported,
            output,
            backend_options,
        ),
        Commands::ListTargets => commands::cmd_list_targets(),
        Commands::ListFormats { target } => commands::cmd_list_formats(target),
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
// Shared helpers
// ---------------------------------------------------------------------------

pub(crate) fn load_pipelines(paths: &[PathBuf]) -> Vec<Pipeline> {
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

pub(crate) fn load_collection(path: &std::path::Path) -> SigmaCollection {
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
            process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Input format parsing
// ---------------------------------------------------------------------------

#[cfg(feature = "daemon")]
pub(crate) fn parse_input_format(format_str: &str, syslog_tz: &str) -> rsigma_runtime::InputFormat {
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
pub(crate) fn build_correlation_config(
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
