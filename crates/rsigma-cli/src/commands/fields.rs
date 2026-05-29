use std::path::PathBuf;

use clap::Args;
use rsigma_eval::{FieldOrigin, FieldSource, Pipeline, RuleFieldSet};
use rsigma_parser::SigmaCollection;
use serde::Serialize;

use crate::output::{DelimitedWriter, OutputCtx, OutputFormat, Tabular, render_json};

/// Arguments for `rsigma rule fields` (and the deprecated `rsigma fields`).
#[derive(Args, Debug)]
pub(crate) struct FieldsArgs {
    /// Path to a Sigma rule file or directory of rules
    #[arg(short, long)]
    pub rules: PathBuf,

    /// Processing pipeline(s) to apply (repeatable). Accepts builtin names (ecs_windows, sysmon) or YAML file paths.
    /// When provided, fields are shown after pipeline transformations.
    #[arg(short = 'p', long = "pipeline")]
    pub pipelines: Vec<PathBuf>,

    /// Exclude fields from filter rules
    #[arg(long)]
    pub no_filters: bool,

    /// Deprecated alias for `--output-format json`. Hidden from `--help`.
    #[arg(long, hide = true)]
    pub json: bool,
}

pub(crate) fn cmd_fields(args: FieldsArgs, ctx: OutputCtx) {
    let FieldsArgs {
        rules: path,
        pipelines: pipeline_paths,
        no_filters,
        json,
    } = args;
    let collection = crate::load_collection(&path);
    let pipelines = crate::load_pipelines(&pipeline_paths);

    if pipelines.iter().any(|p| p.is_dynamic()) && ctx.show_progress() {
        eprintln!(
            "  note: dynamic sources are not resolved by `rsigma rule fields`. \
             Use `rsigma pipeline resolve` to inspect sources or `rsigma engine daemon` to evaluate \
             events with dynamic pipelines."
        );
    }

    let report = build_report(&collection, &pipelines, no_filters);

    // Resolve the effective format. `--json` is a deprecated alias for
    // `--output-format json` and always wins when set. Otherwise we honour
    // an *explicit* `--output-format` flag; without one, the legacy table
    // view stays the default (the TTY-aware NDJSON fallback would regress
    // the existing `rule fields` UX).
    let format = if json {
        OutputFormat::Json
    } else if ctx.explicit_format {
        ctx.format
    } else {
        OutputFormat::Table
    };

    match format {
        OutputFormat::Json => render_json(&report, true),
        OutputFormat::Ndjson => {
            // Emit one row per field plus a summary record so the stream is
            // line-oriented end to end.
            for entry in &report.fields {
                render_json(entry, false);
            }
        }
        OutputFormat::Csv => render_fields_delimited(&report, ',', &ctx),
        OutputFormat::Tsv => render_fields_delimited(&report, '\t', &ctx),
        OutputFormat::Table => print_table(&report, &ctx),
    }
}

/// Render the field catalog as CSV/TSV. Summary goes to stderr (gated on
/// `show_stats`); the data rows go to stdout.
fn render_fields_delimited(report: &FieldsReport, sep: char, ctx: &OutputCtx) {
    if ctx.show_stats() {
        let s = &report.summary;
        eprintln!(
            "Rules: {} detection, {} correlation, {} filter | Pipelines: {} | Unique fields: {}",
            s.total_rules,
            s.total_correlations,
            s.total_filters,
            s.pipelines_applied,
            s.unique_fields,
        );
    }
    let mut writer = DelimitedWriter::new(sep, FieldEntry::headers());
    for entry in &report.fields {
        writer.push(&entry.row());
    }
}

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct FieldsReport {
    summary: Summary,
    fields: Vec<FieldEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pipeline_mappings: Vec<PipelineMapping>,
}

#[derive(Debug, Serialize)]
struct Summary {
    total_rules: usize,
    total_correlations: usize,
    total_filters: usize,
    unique_fields: usize,
    pipelines_applied: usize,
}

#[derive(Debug, Serialize)]
struct FieldEntry {
    field: String,
    rule_count: usize,
    sources: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PipelineMapping {
    original: String,
    mapped_to: Vec<String>,
    pipeline: String,
}

// ---------------------------------------------------------------------------
// Pipeline mapping extraction
// ---------------------------------------------------------------------------

fn extract_pipeline_mappings(pipelines: &[Pipeline]) -> Vec<PipelineMapping> {
    use rsigma_eval::pipeline::transformations::Transformation;

    let mut mappings = Vec::new();
    for pipeline in pipelines {
        for item in &pipeline.transformations {
            match &item.transformation {
                Transformation::FieldNameMapping { mapping } => {
                    for (from, to) in mapping {
                        mappings.push(PipelineMapping {
                            original: from.clone(),
                            mapped_to: to.clone(),
                            pipeline: pipeline.name.clone(),
                        });
                    }
                }
                Transformation::FieldNamePrefixMapping { mapping } => {
                    for (prefix, replacement) in mapping {
                        mappings.push(PipelineMapping {
                            original: format!("{prefix}*"),
                            mapped_to: vec![format!("{replacement}*")],
                            pipeline: pipeline.name.clone(),
                        });
                    }
                }
                Transformation::FieldNamePrefix { prefix } => {
                    mappings.push(PipelineMapping {
                        original: "*".to_string(),
                        mapped_to: vec![format!("{prefix}*")],
                        pipeline: pipeline.name.clone(),
                    });
                }
                Transformation::FieldNameSuffix { suffix } => {
                    mappings.push(PipelineMapping {
                        original: "*".to_string(),
                        mapped_to: vec![format!("*{suffix}")],
                        pipeline: pipeline.name.clone(),
                    });
                }
                Transformation::FieldNameTransform { mapping, .. } => {
                    for (from, to) in mapping {
                        mappings.push(PipelineMapping {
                            original: from.clone(),
                            mapped_to: vec![to.clone()],
                            pipeline: pipeline.name.clone(),
                        });
                    }
                }
                _ => {}
            }
        }
    }
    mappings
}

// ---------------------------------------------------------------------------
// Report building
// ---------------------------------------------------------------------------

fn entry_from_origin(name: &str, origin: &FieldOrigin) -> FieldEntry {
    let mut sources: Vec<&FieldSource> = origin.sources.iter().collect();
    sources.sort();
    FieldEntry {
        field: name.to_string(),
        rule_count: origin.rule_titles.len(),
        sources: sources
            .into_iter()
            .map(|s| s.as_str().to_string())
            .collect(),
    }
}

fn build_report(
    collection: &SigmaCollection,
    pipelines: &[Pipeline],
    no_filters: bool,
) -> FieldsReport {
    let set = RuleFieldSet::collect(collection, pipelines, !no_filters);

    let fields: Vec<FieldEntry> = set
        .iter()
        .map(|(name, origin)| entry_from_origin(name, origin))
        .collect();

    let pipeline_mappings = extract_pipeline_mappings(pipelines);
    let unique_fields = fields.len();

    FieldsReport {
        summary: Summary {
            total_rules: collection.rules.len(),
            total_correlations: collection.correlations.len(),
            total_filters: collection.filters.len(),
            unique_fields,
            pipelines_applied: pipelines.len(),
        },
        fields,
        pipeline_mappings,
    }
}

// ---------------------------------------------------------------------------
// Table output
// ---------------------------------------------------------------------------

impl Tabular for FieldEntry {
    fn headers() -> &'static [&'static str] {
        &["FIELD", "RULES", "SOURCES"]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.field.clone(),
            self.rule_count.to_string(),
            self.sources.join(", "),
        ]
    }
}

fn print_table(report: &FieldsReport, ctx: &OutputCtx) {
    let s = &report.summary;
    if ctx.show_stats() {
        eprintln!(
            "Rules: {} detection, {} correlation, {} filter | Pipelines: {} | Unique fields: {}",
            s.total_rules,
            s.total_correlations,
            s.total_filters,
            s.pipelines_applied,
            s.unique_fields,
        );
    }

    if report.fields.is_empty() {
        if ctx.show_progress() {
            eprintln!("No fields found.");
        }
        return;
    }

    if ctx.show_stats() {
        eprintln!();
    }
    crate::output::render_table(&report.fields);

    if !report.pipeline_mappings.is_empty() && ctx.show_stats() {
        eprintln!();
        eprintln!("Pipeline field mappings:");
        for m in &report.pipeline_mappings {
            eprintln!(
                "  {} -> {} ({})",
                m.original,
                m.mapped_to.join(" | "),
                m.pipeline
            );
        }
    }
}
