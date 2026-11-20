//! CLI `resolve` command: test dynamic source resolution offline.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use rsigma_eval::parse_pipeline_file;
use rsigma_runtime::DefaultSourceResolver;
use rsigma_runtime::sources::SourceResolver;
use serde::Serialize;

use crate::output::{OutputCtx, OutputFormat, Tabular, render_report};

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

    /// External source file(s) or directory of source files
    #[arg(long = "source-file", value_name = "FILE_OR_DIR")]
    pub source_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
struct SourceRow {
    pipeline: String,
    source_id: String,
    source_type: String,
    status: String,
    data_or_error: String,
}

impl Tabular for SourceRow {
    fn headers() -> &'static [&'static str] {
        &[
            "PIPELINE",
            "SOURCE_ID",
            "SOURCE_TYPE",
            "STATUS",
            "DATA_OR_ERROR",
        ]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.pipeline.clone(),
            self.source_id.clone(),
            self.source_type.clone(),
            self.status.clone(),
            self.data_or_error.clone(),
        ]
    }
}

pub fn cmd_resolve(args: ResolveArgs, ctx: OutputCtx) {
    let ResolveArgs {
        pipelines: pipeline_paths,
        source: source_filter,
        pretty,
        dry_run,
        source_files,
    } = args;

    if pretty
        && ctx.explicit_format
        && !matches!(ctx.format, OutputFormat::Json)
        && ctx.show_progress()
    {
        ctx.warn_ignored("pipeline resolve", "--pretty only applies to JSON output");
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("Failed to start async runtime: {e}");
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        });

    rt.block_on(async {
        resolve_async(
            pipeline_paths,
            source_filter,
            pretty,
            dry_run,
            source_files,
            ctx,
        )
        .await
    });
}

async fn resolve_async(
    pipeline_paths: Vec<PathBuf>,
    source_filter: Option<String>,
    pretty: bool,
    dry_run: bool,
    source_files: Vec<PathBuf>,
    ctx: OutputCtx,
) {
    use rsigma_runtime::sources::registry::load_external_sources;

    let mut all_sources = Vec::new();

    // Load external sources from --source-file flags
    match load_external_sources(&source_files) {
        Ok(external) => {
            for (source, path) in external {
                if let Some(ref filter) = source_filter
                    && source.id != *filter
                {
                    continue;
                }
                all_sources.push((format!("external:{}", path.display()), source));
            }
        }
        Err(e) => {
            eprintln!("Error loading external sources: {e}");
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        }
    }

    // Pipelines only reference sources now; the declarations come from the
    // `--source-file` flags loaded above. Parse each pipeline so a stale
    // inline `sources:` block still surfaces its migration error, and note
    // any pipeline that references no sources (the command's output is
    // driven entirely by the loaded source declarations either way).
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
                "Pipeline '{}' references no dynamic sources.",
                pipeline.name
            );
        }
    }

    if all_sources.is_empty() {
        if source_filter.is_some() {
            eprintln!("No sources matched the filter.");
        } else {
            eprintln!("No dynamic sources found in the provided pipelines or source files.");
        }
        std::process::exit(crate::exit_code::RULE_ERROR);
    }

    if dry_run {
        let rows: Vec<SourceRow> = all_sources
            .iter()
            .map(|(pipeline_name, source)| SourceRow {
                pipeline: pipeline_name.clone(),
                source_id: source.id.clone(),
                source_type: format!("{:?}", source.source_type)
                    .split('{')
                    .next()
                    .unwrap_or("unknown")
                    .trim()
                    .to_string(),
                status: "pending".into(),
                data_or_error: String::new(),
            })
            .collect();
        let legacy_items: Vec<serde_json::Value> = all_sources
            .iter()
            .map(|(pipeline_name, source)| {
                serde_json::json!({
                    "pipeline": pipeline_name,
                    "source_id": &source.id,
                    "source_type": format!("{:?}", source.source_type)
                        .split('{')
                        .next()
                        .unwrap_or("unknown")
                        .trim(),
                    "required": source.required,
                    "refresh": format!("{:?}", source.refresh),
                })
            })
            .collect();
        let legacy_output = collapse_json_items(legacy_items);
        emit_resolve(&ctx, &rows, &legacy_output, pretty);
        return;
    }

    let mut resolver = DefaultSourceResolver::new();
    let declared: Vec<_> = all_sources
        .iter()
        .map(|(_, source)| (*source).clone())
        .collect();
    if let Err(err) = resolver.prepare_taxii(&declared) {
        eprintln!("Error preparing TAXII sources: {err}");
        std::process::exit(crate::exit_code::CONFIG_ERROR);
    }
    let resolver = Arc::new(resolver);
    let mut rows = Vec::new();
    let mut legacy_items = Vec::new();
    let mut had_error = false;

    for (pipeline_name, source) in &all_sources {
        let source_id = source.id.clone();
        let source_type = format!("{:?}", source.source_type)
            .split('{')
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string();
        match resolver.resolve(source).await {
            Ok(value) => {
                let data_or_error = serde_json::to_string(&value.data).unwrap_or_default();
                legacy_items.push(serde_json::json!({
                    "pipeline": pipeline_name,
                    "source_id": source_id.clone(),
                    "status": "ok",
                    "data": value.data,
                }));
                rows.push(SourceRow {
                    pipeline: pipeline_name.clone(),
                    source_id,
                    source_type,
                    status: "ok".into(),
                    data_or_error,
                });
            }
            Err(e) => {
                had_error = true;
                let error = e.to_string();
                legacy_items.push(serde_json::json!({
                    "pipeline": pipeline_name,
                    "source_id": source_id.clone(),
                    "status": "error",
                    "error": error.clone(),
                }));
                rows.push(SourceRow {
                    pipeline: pipeline_name.clone(),
                    source_id,
                    source_type,
                    status: "error".into(),
                    data_or_error: error,
                });
            }
        }
    }

    let legacy_output = collapse_json_items(legacy_items);
    emit_resolve(&ctx, &rows, &legacy_output, pretty);

    if had_error {
        std::process::exit(1);
    }
}

fn collapse_json_items(mut items: Vec<serde_json::Value>) -> serde_json::Value {
    if items.len() == 1 {
        items.pop().unwrap_or_default()
    } else {
        serde_json::Value::Array(items)
    }
}

fn emit_resolve(
    ctx: &OutputCtx,
    rows: &[SourceRow],
    legacy_output: &serde_json::Value,
    pretty: bool,
) {
    let envelope = if rows.len() == 1 {
        serde_json::to_value(&rows[0]).unwrap_or_default()
    } else {
        serde_json::to_value(rows).unwrap_or_default()
    };

    // Preserve historical JSON defaults: compact unless --pretty, regardless
    // of TTY, when no explicit --output-format was given.
    if !ctx.explicit_format {
        let json_str = if pretty {
            serde_json::to_string_pretty(legacy_output).unwrap()
        } else {
            serde_json::to_string(legacy_output).unwrap()
        };
        println!("{json_str}");
        return;
    }

    let format = ctx.format;
    match format {
        OutputFormat::Json => {
            let pretty = pretty || ctx.pretty_json();
            crate::output::render_json(&envelope, pretty);
        }
        OutputFormat::Ndjson | OutputFormat::Table | OutputFormat::Csv | OutputFormat::Tsv => {
            render_report(ctx, &envelope, rows)
        }
    }
}
