use std::path::PathBuf;
use std::process;

use rsigma_parser::{SigmaCollection, parse_sigma_directory, parse_sigma_file};

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
pub(crate) fn cmd_convert(
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
    let pipelines = crate::load_pipelines(&pipeline_paths);

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

pub(crate) fn cmd_list_targets() {
    println!("Available conversion targets:");
    println!("  postgres  - PostgreSQL/TimescaleDB (aliases: postgresql, pg)");
    println!("  test      - Backend-neutral test backend");
}

pub(crate) fn cmd_list_formats(target: String) {
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
