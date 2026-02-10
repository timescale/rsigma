use std::io::{self, BufRead, Read};
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use rsigma_eval::{
    CorrelationConfig, CorrelationEngine, Engine, Event, Pipeline, parse_pipeline_file,
};
use rsigma_parser::{SigmaCollection, parse_sigma_directory, parse_sigma_file, parse_sigma_yaml};

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
        #[arg(short, long)]
        pretty: bool,

        /// Processing pipeline YAML file(s) to apply (can be specified multiple times)
        #[arg(short = 'p', long = "pipeline")]
        pipelines: Vec<PathBuf>,
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
        } => cmd_eval(rules, event, pretty, pipelines),
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

fn cmd_eval(
    rules_path: PathBuf,
    event_json: Option<String>,
    pretty: bool,
    pipeline_paths: Vec<PathBuf>,
) {
    let collection = load_collection(&rules_path);
    let pipelines = load_pipelines(&pipeline_paths);
    let has_correlations = !collection.correlations.is_empty();

    if has_correlations {
        cmd_eval_with_correlations(collection, &rules_path, event_json, pretty, &pipelines);
    } else {
        cmd_eval_detection_only(collection, &rules_path, event_json, pretty, &pipelines);
    }
}

/// Evaluation with correlations (stateful).
fn cmd_eval_with_correlations(
    collection: SigmaCollection,
    rules_path: &std::path::Path,
    event_json: Option<String>,
    pretty: bool,
    pipelines: &[Pipeline],
) {
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
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

        let event = Event::from_value(&value);
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

            let event = Event::from_value(&value);
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

        let event = Event::from_value(&value);
        let matches = engine.evaluate(&event);

        if matches.is_empty() {
            eprintln!("No matches.");
        } else {
            for m in &matches {
                print_json(m, pretty);
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

            let event = Event::from_value(&value);
            let matches = engine.evaluate(&event);

            for m in &matches {
                match_count += 1;
                print_json(m, pretty);
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
