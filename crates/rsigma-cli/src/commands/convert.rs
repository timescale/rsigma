use std::path::PathBuf;
use std::process;

use clap::Args;
use rsigma_parser::{SigmaCollection, parse_sigma_directory, parse_sigma_file};

use crate::output::{OutputCtx, OutputFormat, render_json};

/// Arguments for `rsigma backend convert` (and the deprecated `rsigma convert`).
#[derive(Args, Debug)]
pub(crate) struct ConvertArgs {
    /// Path(s) to Sigma rule file(s) or directory
    pub rules: Vec<PathBuf>,

    /// Target backend (e.g. postgres, lynxdb, fibratus, test)
    #[arg(short, long)]
    pub target: String,

    /// Output format (backend-specific, default: "default")
    #[arg(short, long, default_value = "default")]
    pub format: String,

    /// Processing pipeline(s) (repeatable). Accepts builtin names (ecs_windows, sysmon) or YAML file paths
    #[arg(short = 'p', long = "pipeline")]
    pub pipeline: Vec<PathBuf>,

    /// Skip pipeline requirement check
    #[arg(long)]
    pub without_pipeline: bool,

    /// Skip unsupported rules instead of failing
    #[arg(short, long)]
    pub skip_unsupported: bool,

    /// Output file (default: stdout)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Backend options as key=value pairs (repeatable)
    #[arg(short = 'O', long = "option")]
    pub backend_options: Vec<String>,
}

fn get_backend(
    target: &str,
    options: &std::collections::HashMap<String, String>,
) -> Box<dyn rsigma_convert::Backend> {
    match target {
        "postgres" | "postgresql" | "pg" => {
            Box::new(rsigma_convert::backends::postgres::PostgresBackend::from_options(options))
        }
        "lynxdb" => Box::new(rsigma_convert::backends::lynxdb::LynxDbBackend::new()),
        "fibratus" => {
            Box::new(rsigma_convert::backends::fibratus::FibratusBackend::from_options(options))
        }
        "test" => Box::new(rsigma_convert::backends::test::TextQueryTestBackend::new()),
        "test_mandatory_pipeline" => {
            Box::new(rsigma_convert::backends::test::MandatoryPipelineTestBackend::new())
        }
        _ => {
            eprintln!("Unknown target: {target}");
            eprintln!("Available targets: postgres, lynxdb, fibratus, test");
            process::exit(crate::exit_code::CONFIG_ERROR);
        }
    }
}

pub(crate) fn cmd_convert(args: ConvertArgs, ctx: OutputCtx) {
    let ConvertArgs {
        rules,
        target,
        format,
        pipeline: pipeline_paths,
        without_pipeline,
        skip_unsupported,
        output,
        backend_options,
    } = args;

    let collection = load_collection_multi(&rules);
    let pipelines = crate::load_pipelines(&pipeline_paths);

    if pipelines.iter().any(|p| p.is_dynamic()) {
        eprintln!(
            "  note: dynamic sources are not resolved by `rsigma backend convert`. \
             Use `rsigma pipeline resolve` to inspect sources or `rsigma engine daemon` to evaluate \
             events with dynamic pipelines."
        );
    }

    let options: std::collections::HashMap<String, String> = backend_options
        .iter()
        .filter_map(|opt| {
            opt.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();
    let backend = get_backend(&target, &options);

    if backend.requires_pipeline() && pipelines.is_empty() && !without_pipeline {
        eprintln!("Backend '{target}' requires a pipeline. Use -p or --without-pipeline.");
        process::exit(crate::exit_code::CONFIG_ERROR);
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
        process::exit(crate::exit_code::CONFIG_ERROR);
    }

    if let Some(method) = options.get("correlation_method") {
        let methods = backend.correlation_methods();
        if !methods.iter().any(|(n, _)| n == method) {
            eprintln!("Unknown correlation_method '{method}' for backend '{target}'");
            if methods.is_empty() {
                eprintln!("Backend '{target}' does not support selectable correlation methods.");
            } else {
                eprintln!(
                    "Available: {}",
                    methods
                        .iter()
                        .map(|(n, d)| format!("{n} ({d})"))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            process::exit(crate::exit_code::CONFIG_ERROR);
        }
    }

    if let Some(gap) = options.get("gap")
        && rsigma_parser::Timespan::parse(gap).is_err()
    {
        eprintln!("Invalid gap '{gap}': expected a duration like 30s, 5m, 1h, 7d");
        process::exit(crate::exit_code::CONFIG_ERROR);
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
            for (rule_title, warning) in output_data.warnings() {
                eprintln!("Warning: rule '{rule_title}': {warning}");
            }
            if !skip_unsupported && !output_data.errors.is_empty() {
                process::exit(crate::exit_code::RULE_ERROR);
            }
            // `--output-format json` wraps the queries in a JSON envelope.
            // The other structured formats (`ndjson`/`csv`/`tsv`/`table`)
            // make no sense for free-form query text -- warn once on stderr
            // and fall back to the raw text path.
            if ctx.format == OutputFormat::Json && output.is_none() {
                let queries: Vec<serde_json::Value> = output_data
                    .queries
                    .iter()
                    .flat_map(|r| {
                        r.queries.iter().map(move |q| {
                            serde_json::json!({
                                "rule_title": r.rule_title,
                                "rule_id": r.rule_id,
                                "query": q,
                            })
                        })
                    })
                    .collect();
                render_json(
                    &serde_json::json!({
                        "target": target,
                        "format": format,
                        "queries": queries,
                    }),
                    ctx.pretty_json(),
                );
                return;
            }
            if ctx.explicit_format
                && !matches!(ctx.format, OutputFormat::Json | OutputFormat::Ndjson)
                && ctx.show_progress()
            {
                eprintln!(
                    "warning: `--output-format {}` is not supported by `backend convert`; falling back to raw query text.",
                    ctx.format.as_str(),
                );
            }
            let all_queries: Vec<String> = output_data
                .queries
                .iter()
                .flat_map(|r| r.queries.iter().cloned())
                .collect();
            // Defer to the backend so format-aware separators land in
            // the joined output (e.g. `---\n` between YAML rule
            // documents for the Fibratus backend, `;\n\n` between
            // PostgreSQL `view`/`continuous_aggregate` statements).
            let output_str = backend
                .finalize_output(all_queries, &format)
                .unwrap_or_else(|e| {
                    eprintln!("Output finalization failed: {e}");
                    process::exit(crate::exit_code::RULE_ERROR);
                });
            write_output(&output_str, output.as_deref());
        }
        Err(e) => {
            eprintln!("Conversion failed: {e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
}

pub(crate) fn cmd_list_targets() {
    println!("Available conversion targets:");
    println!("  postgres  - PostgreSQL/TimescaleDB (aliases: postgresql, pg)");
    println!("  lynxdb    - LynxDB log analytics engine");
    println!("  fibratus  - Fibratus Windows kernel-event detection engine");
    println!("  test      - Backend-neutral test backend");
}

pub(crate) fn cmd_list_formats(target: String) {
    let backend = get_backend(&target, &std::collections::HashMap::new());
    println!("Available formats for '{target}':");
    for (name, desc) in backend.formats() {
        println!("  {name}  - {desc}");
    }
    let methods = backend.correlation_methods();
    if !methods.is_empty() {
        println!(
            "\nCorrelation methods for '{target}' (select with -O correlation_method=NAME, default: {}):",
            backend.default_correlation_method()
        );
        for (name, desc) in methods {
            println!("  {name}  - {desc}");
        }
    }
}

/// Wrapper for the deprecated flat `rsigma list-formats TARGET` form so the
/// outer dispatch can pull the positional argument off a clap variant uniformly.
#[derive(Args, Debug)]
pub(crate) struct ListFormatsArgs {
    /// Target backend name
    pub target: String,
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
                    process::exit(crate::exit_code::RULE_ERROR);
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
                    process::exit(crate::exit_code::RULE_ERROR);
                }
            }
        } else {
            eprintln!("Path not found: {}", path.display());
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
    if collection.rules.is_empty() && collection.correlations.is_empty() {
        eprintln!("No rules found in specified path(s)");
        process::exit(crate::exit_code::RULE_ERROR);
    }
    collection
}

fn write_output(content: &str, output: Option<&std::path::Path>) {
    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, content) {
                eprintln!("Error writing to {}: {e}", path.display());
                process::exit(crate::exit_code::CONFIG_ERROR);
            }
        }
        None => println!("{content}"),
    }
}
