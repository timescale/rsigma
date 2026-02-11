use std::io::{self, BufRead, Read};
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use jaq_interpret::{Ctx, FilterT, ParseCtx, RcIter, Val};
use rsigma_eval::{
    CorrelationAction, CorrelationConfig, CorrelationEngine, Engine, Event, Pipeline,
    parse_pipeline_file,
};
use rsigma_parser::{SigmaCollection, parse_sigma_directory, parse_sigma_file, parse_sigma_yaml};
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

    /// Evaluate events against Sigma rules
    ///
    /// Load rules from a file or directory, then evaluate JSON events.
    /// Events can be provided as a single JSON string (--event) or as
    /// NDJSON (newline-delimited JSON) from stdin.
    Eval {
        /// Path to a Sigma rule file or directory of rules
        #[arg(short, long)]
        rules: PathBuf,

        /// A single event as a JSON string (if omitted, reads NDJSON from stdin)
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

        /// Event field name(s) to use for timestamp extraction in correlations.
        /// Can be specified multiple times; tried in order before built-in
        /// defaults (@timestamp, timestamp, EventTime, …).
        /// Equivalent to the `rsigma.timestamp_field` custom attribute.
        #[arg(long = "timestamp-field")]
        timestamp_fields: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Parse { path, pretty } => cmd_parse(path, pretty),
        Commands::Validate {
            path,
            verbose,
            pipelines,
        } => cmd_validate(path, verbose, pipelines),
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
            timestamp_fields,
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
            timestamp_fields,
        ),
    }
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
            let errors = collection.errors.len();

            println!("Parsed {total} documents from {}", path.display());
            println!("  Detection rules:   {rules}");
            println!("  Correlation rules: {correlations}");
            println!("  Filter rules:      {filters}");
            println!("  Parse errors:      {errors}");

            if !pipelines.is_empty() {
                // Try compiling with pipelines to check for pipeline errors
                let mut engine = Engine::new();
                for p in &pipelines {
                    engine.add_pipeline(p.clone());
                }
                match engine.add_collection(&collection) {
                    Ok(()) => {
                        println!(
                            "  Pipeline applied:  {} pipeline(s), {} rules compiled OK",
                            pipelines.len(),
                            engine.rule_count()
                        );
                    }
                    Err(e) => {
                        eprintln!("Pipeline compilation error: {e}");
                        process::exit(1);
                    }
                }
            }

            if verbose && !collection.errors.is_empty() {
                println!("\nErrors:");
                for err in &collection.errors {
                    println!("  - {err}");
                }
            }

            if errors > 0 {
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
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
    timestamp_fields: Vec<String>,
) {
    let mut collection = load_collection(&rules_path);
    let pipelines = load_pipelines(&pipeline_paths);
    let has_correlations = !collection.correlations.is_empty();

    // If --include-event is set globally, inject the custom attribute on all rules.
    if include_event {
        for rule in &mut collection.rules {
            rule.custom_attributes
                .insert("rsigma.include_event".to_string(), "true".to_string());
        }
    }

    // Compile the event filter once up front
    let event_filter = build_event_filter(jq, jsonpath);

    // Build correlation config from CLI flags
    let corr_config = build_correlation_config(suppress, action, no_detections, timestamp_fields);

    if has_correlations {
        cmd_eval_with_correlations(
            collection,
            &rules_path,
            event_json,
            pretty,
            &pipelines,
            &event_filter,
            corr_config,
        );
    } else {
        cmd_eval_detection_only(
            collection,
            &rules_path,
            event_json,
            pretty,
            &pipelines,
            &event_filter,
        );
    }
}

/// Evaluation with correlations (stateful).
fn cmd_eval_with_correlations(
    collection: SigmaCollection,
    rules_path: &std::path::Path,
    event_json: Option<String>,
    pretty: bool,
    pipelines: &[Pipeline],
    event_filter: &EventFilter,
    config: CorrelationConfig,
) {
    let mut engine = CorrelationEngine::new(config);
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

    if let Some(json_str) = event_json {
        let value: serde_json::Value = match serde_json::from_str(&json_str) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Invalid JSON event: {e}");
                process::exit(1);
            }
        };

        for payload in apply_event_filter(&value, event_filter) {
            let event = Event::from_value(&payload);
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
    } else {
        let stdin = io::stdin();
        let mut line_num = 0u64;
        let mut det_count = 0u64;
        let mut corr_count = 0u64;

        for line in stdin.lock().lines() {
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

            let value: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Invalid JSON on line {line_num}: {e}");
                    continue;
                }
            };

            for payload in apply_event_filter(&value, event_filter) {
                let event = Event::from_value(&payload);
                let result = engine.process_event(&event);

                for m in &result.detections {
                    det_count += 1;
                    print_json(m, pretty);
                }
                for m in &result.correlations {
                    corr_count += 1;
                    print_json(m, pretty);
                }
            }
        }

        eprintln!(
            "Processed {line_num} events, {det_count} detection matches, {corr_count} correlation matches."
        );
    }
}

/// Evaluation without correlations (stateless, original behavior).
fn cmd_eval_detection_only(
    collection: SigmaCollection,
    rules_path: &std::path::Path,
    event_json: Option<String>,
    pretty: bool,
    pipelines: &[Pipeline],
    event_filter: &EventFilter,
) {
    let mut engine = Engine::new();
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

    if let Some(json_str) = event_json {
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
                let event = Event::from_value(payload);
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
    } else {
        let stdin = io::stdin();
        let mut line_num = 0u64;
        let mut match_count = 0u64;

        for line in stdin.lock().lines() {
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

            let value: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Invalid JSON on line {line_num}: {e}");
                    continue;
                }
            };

            for payload in apply_event_filter(&value, event_filter) {
                let event = Event::from_value(&payload);
                let matches = engine.evaluate(&event);

                for m in &matches {
                    match_count += 1;
                    print_json(m, pretty);
                }
            }
        }

        eprintln!("Processed {line_num} events, {match_count} matches.");
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
// Event filtering (jq / JSONPath)
// ---------------------------------------------------------------------------

/// Pre-compiled event filter — either a jq filter or a JSONPath query.
enum EventFilter {
    /// No filter — pass through the entire event.
    None,
    /// A compiled jq filter.
    Jq(jaq_interpret::Filter),
    /// A compiled JSONPath query.
    JsonPath(JsonPath),
}

/// Build an `EventFilter` from CLI arguments. Exits on parse errors.
fn build_event_filter(jq: Option<String>, jsonpath: Option<String>) -> EventFilter {
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

    let mut config = CorrelationConfig {
        suppress: suppress_secs,
        action_on_match,
        emit_detections: !no_detections,
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
fn apply_event_filter(value: &serde_json::Value, filter: &EventFilter) -> Vec<serde_json::Value> {
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
