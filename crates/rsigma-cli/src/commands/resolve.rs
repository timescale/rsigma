//! CLI `resolve` command: test dynamic source resolution offline.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use rsigma_eval::parse_pipeline_file;
use rsigma_runtime::DefaultSourceResolver;
use rsigma_runtime::sources::SourceResolver;

/// Arguments for `rsigma pipeline resolve` (and the deprecated `rsigma resolve`).
#[derive(Args, Debug)]
pub struct ResolveArgs {
    /// Processing pipeline(s) containing dynamic sources
    #[arg(short = 'p', long = "pipeline", required = true)]
    pub pipelines: Vec<PathBuf>,

    /// Resolve only a specific source by ID
    #[arg(short, long)]
    pub source: Option<String>,

    /// Pretty-print JSON output
    #[arg(long)]
    pub pretty: bool,

    /// Show what would be resolved without performing resolution
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

pub fn cmd_resolve(args: ResolveArgs) {
    let ResolveArgs {
        pipelines: pipeline_paths,
        source: source_filter,
        pretty,
        dry_run,
    } = args;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("Failed to start async runtime: {e}");
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        });

    rt.block_on(async { resolve_async(pipeline_paths, source_filter, pretty, dry_run).await });
}

async fn resolve_async(
    pipeline_paths: Vec<PathBuf>,
    source_filter: Option<String>,
    pretty: bool,
    dry_run: bool,
) {
    let mut all_sources = Vec::new();

    for path in &pipeline_paths {
        let pipeline = match parse_pipeline_file(path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error reading pipeline {}: {e}", path.display());
                std::process::exit(crate::exit_code::RULE_ERROR);
            }
        };

        if !pipeline.is_dynamic() {
            eprintln!(
                "Pipeline '{}' has no dynamic sources, skipping.",
                pipeline.name
            );
            continue;
        }

        for source in &pipeline.sources {
            if let Some(ref filter) = source_filter
                && source.id != *filter
            {
                continue;
            }
            all_sources.push((pipeline.name.clone(), source.clone()));
        }
    }

    if all_sources.is_empty() {
        if source_filter.is_some() {
            eprintln!("No sources matched the filter.");
        } else {
            eprintln!("No dynamic sources found in the provided pipelines.");
        }
        std::process::exit(crate::exit_code::RULE_ERROR);
    }

    if dry_run {
        let items: Vec<_> = all_sources
            .iter()
            .map(|(pipeline_name, source)| {
                serde_json::json!({
                    "pipeline": pipeline_name,
                    "source_id": &source.id,
                    "source_type": format!("{:?}", source.source_type).split('{').next().unwrap_or("unknown").trim(),
                    "required": source.required,
                    "refresh": format!("{:?}", source.refresh),
                })
            })
            .collect();

        let output = if items.len() == 1 {
            items.into_iter().next().unwrap()
        } else {
            serde_json::Value::Array(items)
        };

        let json_str = if pretty {
            serde_json::to_string_pretty(&output).unwrap()
        } else {
            serde_json::to_string(&output).unwrap()
        };
        println!("{json_str}");
        return;
    }

    let resolver = Arc::new(DefaultSourceResolver::new());
    let mut results = Vec::new();
    let mut had_error = false;

    for (pipeline_name, source) in &all_sources {
        let source_id = source.id.clone();
        match resolver.resolve(source).await {
            Ok(value) => {
                results.push(serde_json::json!({
                    "pipeline": pipeline_name,
                    "source_id": source_id,
                    "status": "ok",
                    "data": value.data,
                }));
            }
            Err(e) => {
                had_error = true;
                results.push(serde_json::json!({
                    "pipeline": pipeline_name,
                    "source_id": source_id,
                    "status": "error",
                    "error": e.to_string(),
                }));
            }
        }
    }

    let output = if results.len() == 1 {
        results.into_iter().next().unwrap()
    } else {
        serde_json::Value::Array(results)
    };

    let json_str = if pretty {
        serde_json::to_string_pretty(&output).unwrap()
    } else {
        serde_json::to_string(&output).unwrap()
    };
    println!("{json_str}");

    if had_error {
        std::process::exit(1);
    }
}
