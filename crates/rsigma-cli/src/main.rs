use std::io::{self, BufRead, Read};
use std::path::PathBuf;
use std::process;
use std::time::SystemTime;

use clap::{Parser, Subcommand};
use jaq_interpret::{Ctx, FilterT, ParseCtx, RcIter, Val};
use rsigma_eval::{
    CorrelationAction, CorrelationConfig, CorrelationEngine, Engine, Event, Pipeline,
    parse_pipeline_file,
};
use rsigma_parser::lint::{self, FileLintResult};
use serde::Deserialize;
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
        Commands::Lint {
            path,
            schema,
            verbose,
        } => cmd_lint(path, schema, verbose),
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

fn cmd_lint(path: PathBuf, schema: Option<String>, verbose: bool) {
    // 1. Run built-in lint checks
    let results: Vec<FileLintResult> = if path.is_dir() {
        match lint::lint_yaml_directory(&path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        }
    } else {
        match lint::lint_yaml_file(&path) {
            Ok(r) => r,
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

    // 4. Print results
    let mut total_files = 0usize;
    let mut failed_files = 0usize;
    let mut total_errors = 0usize;
    let mut total_warnings = 0usize;

    for result in &all_results {
        total_files += 1;
        let errors = result.error_count();
        let warnings = result.warning_count();
        total_errors += errors;
        total_warnings += warnings;

        if result.warnings.is_empty() {
            if verbose {
                println!("{}: OK", result.path.display());
            }
        } else {
            failed_files += 1;
            println!("{}:", result.path.display());
            for w in &result.warnings {
                println!("  {w}");
            }
        }
    }

    let passed = total_files - failed_files;
    println!(
        "\nSummary: {passed} passed, {failed_files} failed ({total_errors} error(s), {total_warnings} warning(s))"
    );

    if total_errors > 0 {
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// JSON Schema validation
// ---------------------------------------------------------------------------

/// Official Sigma detection rule schema URL.
const SCHEMA_URL: &str =
    "https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main/json-schema/sigma-detection-rule-schema.json";

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
        && let Ok(modified) = meta.modified() {
            let age = SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default();
            if age.as_secs() < CACHE_MAX_AGE_SECS
                && let Ok(content) = std::fs::read_to_string(&cache_path) {
                    eprintln!("Using cached schema: {}", cache_path.display());
                    return content;
                }
        }

    // Download
    eprintln!("Downloading schema from {SCHEMA_URL}...");
    match ureq::get(SCHEMA_URL).call() {
        Ok(response) => {
            let body = response
                .into_body()
                .read_to_string()
                .unwrap_or_else(|e| {
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
                eprintln!(
                    "Warning: schema download failed ({e}), using stale cache"
                );
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

    let validator = jsonschema::validator_for(&schema_value)
        .unwrap_or_else(|e| {
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
                } else if matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("yml" | "yaml")
                ) {
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
                rule: lint::LintRule::MissingTitle,
                severity: lint::Severity::Error,
                message: format!("error reading file: {e}"),
                path: "/".to_string(),
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
                && matches!(action, "global" | "reset" | "repeat") {
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
                rule: lint::LintRule::InvalidStatus, // generic schema error
                severity: lint::Severity::Error,
                message: format!("schema: {error}"),
                path: error.instance_path.to_string(),
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
    let collection = load_collection(&rules_path);
    let pipelines = load_pipelines(&pipeline_paths);
    let has_correlations = !collection.correlations.is_empty();

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
            include_event,
        );
    } else {
        cmd_eval_detection_only(
            collection,
            &rules_path,
            event_json,
            pretty,
            &pipelines,
            &event_filter,
            include_event,
        );
    }
}

/// Evaluation with correlations (stateful).
#[allow(clippy::too_many_arguments)]
fn cmd_eval_with_correlations(
    collection: SigmaCollection,
    rules_path: &std::path::Path,
    event_json: Option<String>,
    pretty: bool,
    pipelines: &[Pipeline],
    event_filter: &EventFilter,
    config: CorrelationConfig,
    include_event: bool,
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
    include_event: bool,
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
