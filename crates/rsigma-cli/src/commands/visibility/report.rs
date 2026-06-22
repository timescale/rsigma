//! The visibility report: per-data-source scores, blind spots, and untapped
//! sources, rendered through the shared output layer.
//!
//! Renders as the full JSON document (`json`), per-data-source rows
//! (`ndjson`/`csv`/`tsv`), or a human summary with blind-spot and untapped
//! sections (`table`). `--fail-on-blind-spots` turns any blind spot into a
//! non-zero exit, the CI signal.

use serde::Serialize;

use super::analysis::{VisibilityAnalysis, level_name};
use crate::exit_code;
use crate::output::{
    DelimitedWriter, OutputCtx, OutputFormat, Painter, Tabular, render_json, render_ndjson,
};

#[derive(Debug, Clone, Serialize)]
struct Summary {
    rules: usize,
    logsources: usize,
    data_sources: usize,
    techniques: usize,
    blind_spots: usize,
    untapped: usize,
    unmapped_logsources: usize,
    events_observed: u64,
    observed_unique_keys: usize,
    /// False on the no-`--observed` baseline path.
    observed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DataSourceRow {
    data_source: String,
    score: u8,
    level: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    products: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    data_components: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    logsources: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mapped_fields: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    observed_fields: Vec<String>,
    blind_spot: bool,
}

const DATA_SOURCE_HEADERS: &[&str] = &[
    "DATA SOURCE",
    "SCORE",
    "LEVEL",
    "OBSERVED",
    "MAPPED",
    "BLIND",
];

impl Tabular for DataSourceRow {
    fn headers() -> &'static [&'static str] {
        DATA_SOURCE_HEADERS
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.data_source.clone(),
            self.score.to_string(),
            self.level.clone(),
            self.observed_fields.len().to_string(),
            self.mapped_fields.len().to_string(),
            if self.blind_spot { "yes" } else { "no" }.to_string(),
        ]
    }
}

#[derive(Debug, Clone, Serialize)]
struct UntappedRow {
    data_source: String,
    observed_fields: Vec<String>,
}

/// The full visibility report document.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct VisibilityReport {
    summary: Summary,
    data_sources: Vec<DataSourceRow>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    blind_spots: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    untapped: Vec<UntappedRow>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unmapped_logsources: Vec<String>,
    /// Whether blind spots should set the exit code. Not part of the wire shape.
    #[serde(skip)]
    fail_on_blind_spots: bool,
}

impl VisibilityReport {
    /// Build the report from the analysis.
    pub(crate) fn build(analysis: &VisibilityAnalysis, fail_on_blind_spots: bool) -> Self {
        let data_sources: Vec<DataSourceRow> = analysis
            .data_sources
            .iter()
            .map(|d| DataSourceRow {
                data_source: d.data_source.clone(),
                score: d.score,
                level: level_name(d.score).to_string(),
                products: d.products.clone(),
                data_components: d.data_components.clone(),
                logsources: d.logsources.clone(),
                mapped_fields: d.mapped_fields.clone(),
                observed_fields: d.observed_fields.clone(),
                blind_spot: d.blind_spot,
            })
            .collect();

        let blind_spots: Vec<String> = analysis
            .blind_spots()
            .iter()
            .map(|d| d.data_source.clone())
            .collect();

        let untapped: Vec<UntappedRow> = analysis
            .untapped
            .iter()
            .map(|u| UntappedRow {
                data_source: u.data_source.clone(),
                observed_fields: u.observed_fields.iter().map(|f| f.field.clone()).collect(),
            })
            .collect();

        let summary = Summary {
            rules: analysis.rules_total,
            logsources: analysis.logsources_total,
            data_sources: data_sources.len(),
            techniques: analysis.techniques.len(),
            blind_spots: blind_spots.len(),
            untapped: untapped.len(),
            unmapped_logsources: analysis.unmapped_logsources.len(),
            events_observed: analysis.events_observed,
            observed_unique_keys: analysis.observed_unique_keys,
            observed: analysis.has_observed,
        };

        VisibilityReport {
            summary,
            data_sources,
            blind_spots,
            untapped,
            unmapped_logsources: analysis.unmapped_logsources.clone(),
            fail_on_blind_spots,
        }
    }

    /// House exit code: `FINDINGS` (1) under `--fail-on-blind-spots` when any
    /// rule-expected data source has no observed telemetry, else `SUCCESS`.
    pub(crate) fn exit_code(&self) -> i32 {
        if self.fail_on_blind_spots && !self.blind_spots.is_empty() {
            exit_code::FINDINGS
        } else {
            exit_code::SUCCESS
        }
    }

    /// Render to stdout in the selected format. Machine formats emit a one-line
    /// recap on stderr (gated on `show_stats`).
    pub(crate) fn render(&self, ctx: &OutputCtx) {
        match ctx.format {
            OutputFormat::Json => render_json(self, ctx.pretty_json()),
            OutputFormat::Ndjson => {
                for d in &self.data_sources {
                    render_ndjson(d);
                }
            }
            OutputFormat::Csv => self.render_delimited(','),
            OutputFormat::Tsv => self.render_delimited('\t'),
            OutputFormat::Table => self.render_human(ctx),
        }

        if ctx.format != OutputFormat::Table && ctx.show_stats() {
            eprintln!("{}", self.stderr_summary());
        }
    }

    fn render_delimited(&self, sep: char) {
        let mut writer = DelimitedWriter::new(sep, DataSourceRow::headers());
        for d in &self.data_sources {
            writer.push(&d.row());
        }
    }

    fn stderr_summary(&self) -> String {
        let s = &self.summary;
        format!(
            "Visibility: {} data sources ({} blind spots) across {} techniques from {} rules; {} events observed.",
            s.data_sources, s.blind_spots, s.techniques, s.rules, s.events_observed,
        )
    }

    fn render_human(&self, ctx: &OutputCtx) {
        let p = Painter::new(ctx.color);
        let s = &self.summary;

        println!("{}", p.bold("Visibility summary"));
        if !s.observed {
            println!(
                "  {}: no --observed signal; showing the rule-expected baseline (all sources unobserved)",
                p.yellow("baseline")
            );
        }
        println!("  rules:        {}", s.rules);
        println!("  logsources:   {}", s.logsources);
        println!("  data sources: {}", s.data_sources);
        println!("  techniques:   {}", s.techniques);
        println!("  events:       {}", s.events_observed);

        if !self.data_sources.is_empty() {
            println!("\n{}", p.bold("Data sources"));
            crate::output::render_table(&self.data_sources);
        }

        if !self.blind_spots.is_empty() {
            println!(
                "\n{} ({}): {}",
                p.red("blind spots"),
                self.blind_spots.len(),
                self.blind_spots.join(", ")
            );
        }

        if !self.untapped.is_empty() {
            let names: Vec<&str> = self
                .untapped
                .iter()
                .map(|u| u.data_source.as_str())
                .collect();
            println!(
                "\n{} ({}): {}",
                p.yellow("untapped"),
                names.len(),
                names.join(", ")
            );
        }

        if !self.unmapped_logsources.is_empty() {
            println!(
                "\n{} ({}): {}",
                p.dim("unmapped logsources"),
                self.unmapped_logsources.len(),
                self.unmapped_logsources.join(", ")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::visibility::analysis::{DataSourceVisibility, VisibilityAnalysis};

    fn analysis(blind: bool) -> VisibilityAnalysis {
        VisibilityAnalysis {
            data_sources: vec![DataSourceVisibility {
                data_source: "Process".into(),
                score: if blind { 0 } else { 4 },
                data_components: vec!["Process Creation".into()],
                products: vec!["Windows".into()],
                logsources: vec!["process_creation/windows".into()],
                mapped_fields: vec!["CommandLine".into(), "Image".into()],
                observed_fields: if blind {
                    vec![]
                } else {
                    vec!["CommandLine".into(), "Image".into()]
                },
                blind_spot: blind,
            }],
            techniques: vec![],
            untapped: vec![],
            unmapped_logsources: vec![],
            rules_total: 1,
            logsources_total: 1,
            events_observed: if blind { 0 } else { 10 },
            observed_unique_keys: 2,
            has_observed: true,
        }
    }

    #[test]
    fn exit_code_findings_only_with_blind_spots_and_flag() {
        let blind = VisibilityReport::build(&analysis(true), true);
        assert_eq!(blind.exit_code(), exit_code::FINDINGS);

        let blind_no_flag = VisibilityReport::build(&analysis(true), false);
        assert_eq!(blind_no_flag.exit_code(), exit_code::SUCCESS);

        let clean = VisibilityReport::build(&analysis(false), true);
        assert_eq!(clean.exit_code(), exit_code::SUCCESS);
    }

    #[test]
    fn summary_counts_blind_spots() {
        let report = VisibilityReport::build(&analysis(true), false);
        assert_eq!(report.summary.blind_spots, 1);
        assert_eq!(report.blind_spots, vec!["Process".to_string()]);
    }
}
