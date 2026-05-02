use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use rsigma_eval::{Pipeline, apply_pipelines};
use rsigma_parser::{
    CorrelationCondition, CorrelationRule, Detection, DetectionItem, Detections, FilterRule,
    SigmaCollection, SigmaRule,
};
use serde::Serialize;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub(crate) fn cmd_fields(
    path: PathBuf,
    pipeline_paths: Vec<PathBuf>,
    no_filters: bool,
    json: bool,
) {
    let collection = crate::load_collection(&path);
    let pipelines = crate::load_pipelines(&pipeline_paths);

    let report = build_report(&collection, &pipelines, no_filters);

    if json {
        crate::print_json(&report, true);
    } else {
        print_table(&report);
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
// Field collection
// ---------------------------------------------------------------------------

/// Tracks where a field was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum FieldSource {
    Detection,
    Correlation,
    Filter,
    Metadata,
}

impl FieldSource {
    fn as_str(self) -> &'static str {
        match self {
            FieldSource::Detection => "detection",
            FieldSource::Correlation => "correlation",
            FieldSource::Filter => "filter",
            FieldSource::Metadata => "metadata",
        }
    }
}

struct FieldCollector {
    /// field_name -> (set of rule titles that reference it, set of source types)
    fields: BTreeMap<String, (BTreeSet<String>, BTreeSet<FieldSource>)>,
}

impl FieldCollector {
    fn new() -> Self {
        Self {
            fields: BTreeMap::new(),
        }
    }

    fn add(&mut self, field: &str, rule_title: &str, source: FieldSource) {
        let entry = self
            .fields
            .entry(field.to_string())
            .or_insert_with(|| (BTreeSet::new(), BTreeSet::new()));
        entry.0.insert(rule_title.to_string());
        entry.1.insert(source);
    }

    fn collect_detection_items(
        &mut self,
        detection: &Detection,
        rule_title: &str,
        source: FieldSource,
    ) {
        match detection {
            Detection::AllOf(items) => {
                for item in items {
                    self.collect_item(item, rule_title, source);
                }
            }
            Detection::AnyOf(subs) => {
                for sub in subs {
                    self.collect_detection_items(sub, rule_title, source);
                }
            }
            Detection::Keywords(_) => {}
        }
    }

    fn collect_item(&mut self, item: &DetectionItem, rule_title: &str, source: FieldSource) {
        if let Some(ref name) = item.field.name {
            self.add(name, rule_title, source);
        }
    }

    fn collect_detections(
        &mut self,
        detections: &Detections,
        rule_title: &str,
        source: FieldSource,
    ) {
        for det in detections.named.values() {
            self.collect_detection_items(det, rule_title, source);
        }
    }

    fn collect_rule(&mut self, rule: &SigmaRule) {
        self.collect_detections(&rule.detection, &rule.title, FieldSource::Detection);
        for f in &rule.fields {
            self.add(f, &rule.title, FieldSource::Metadata);
        }
    }

    fn collect_correlation(&mut self, corr: &CorrelationRule) {
        for f in &corr.group_by {
            self.add(f, &corr.title, FieldSource::Correlation);
        }
        if let CorrelationCondition::Threshold {
            field: Some(ref fields),
            ..
        } = corr.condition
        {
            for f in fields {
                self.add(f, &corr.title, FieldSource::Correlation);
            }
        }
        for alias in &corr.aliases {
            for mapped_field in alias.mapping.values() {
                self.add(mapped_field, &corr.title, FieldSource::Correlation);
            }
        }
        for f in &corr.fields {
            self.add(f, &corr.title, FieldSource::Metadata);
        }
    }

    fn collect_filter(&mut self, filter: &FilterRule) {
        self.collect_detections(&filter.detection, &filter.title, FieldSource::Filter);
        for f in &filter.fields {
            self.add(f, &filter.title, FieldSource::Metadata);
        }
    }
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

fn build_report(
    collection: &SigmaCollection,
    pipelines: &[Pipeline],
    no_filters: bool,
) -> FieldsReport {
    let mut collector = FieldCollector::new();

    if pipelines.is_empty() {
        for rule in &collection.rules {
            collector.collect_rule(rule);
        }
        for corr in &collection.correlations {
            collector.collect_correlation(corr);
        }
    } else {
        for rule in &collection.rules {
            let mut transformed = rule.clone();
            if let Err(e) = apply_pipelines(pipelines, &mut transformed) {
                eprintln!("Warning: pipeline error for '{}': {e}", rule.title);
                collector.collect_rule(rule);
                continue;
            }
            collector.collect_rule(&transformed);
        }
        for corr in &collection.correlations {
            collector.collect_correlation(corr);
        }
    }

    if !no_filters {
        for filter in &collection.filters {
            collector.collect_filter(filter);
        }
    }

    let pipeline_mappings = extract_pipeline_mappings(pipelines);

    let fields: Vec<FieldEntry> = collector
        .fields
        .into_iter()
        .map(|(name, (rules, sources))| FieldEntry {
            field: name,
            rule_count: rules.len(),
            sources: sources.iter().map(|s| s.as_str().to_string()).collect(),
        })
        .collect();

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

fn print_table(report: &FieldsReport) {
    let s = &report.summary;
    eprintln!(
        "Rules: {} detection, {} correlation, {} filter | Pipelines: {} | Unique fields: {}",
        s.total_rules, s.total_correlations, s.total_filters, s.pipelines_applied, s.unique_fields
    );

    if report.fields.is_empty() {
        eprintln!("No fields found.");
        return;
    }

    let max_field = report
        .fields
        .iter()
        .map(|f| f.field.len())
        .max()
        .unwrap_or(5)
        .max(5);
    let max_sources = report
        .fields
        .iter()
        .map(|f| f.sources.join(", ").len())
        .max()
        .unwrap_or(7)
        .max(7);

    eprintln!();
    println!(
        "{:<width_f$}  {:>5}  {:<width_s$}",
        "FIELD",
        "RULES",
        "SOURCES",
        width_f = max_field,
        width_s = max_sources,
    );
    println!(
        "{:<width_f$}  {:>5}  {:<width_s$}",
        "-".repeat(max_field),
        "-----",
        "-".repeat(max_sources),
        width_f = max_field,
        width_s = max_sources,
    );

    for entry in &report.fields {
        println!(
            "{:<width_f$}  {:>5}  {:<width_s$}",
            entry.field,
            entry.rule_count,
            entry.sources.join(", "),
            width_f = max_field,
            width_s = max_sources,
        );
    }

    if !report.pipeline_mappings.is_empty() {
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
