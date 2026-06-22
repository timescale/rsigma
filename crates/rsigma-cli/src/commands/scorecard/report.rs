//! The scorecard document, its renderers, and the markdown/HTML program
//! artifact.
//!
//! The document renders through the shared output layer: `json` emits the whole
//! scorecard, `ndjson`/`csv`/`tsv` emit per-rule rows, and `table` renders the
//! human view grouped by verdict under a summary header. `--report` writes the
//! standalone keep/tune/retire artifact a program reviews on a cadence, in
//! markdown or HTML (hand-rolled, no new dependency, matching the repo's
//! `DelimitedWriter`/JUnit-writer precedent).

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use serde::Serialize;

use super::fuse::ScorecardRecord;
use super::verdict::{FailOn, Thresholds, Verdict};
use crate::commands::reports::CoverageReport;
use crate::output::{
    DelimitedWriter, OutputCtx, OutputFormat, Painter, Tabular, render_json, render_ndjson,
};

/// Which optional inputs contributed to this run (the two JSON reports are
/// required, so they are implied).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct InputManifest {
    pub(crate) metrics: bool,
    pub(crate) triage: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) metrics_window: Option<String>,
}

/// The effective verdict thresholds, echoed for reproducibility.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ThresholdsView {
    pub(crate) min_precision: f64,
    pub(crate) tune_max_precision: f64,
    pub(crate) retire_max_precision: f64,
    pub(crate) min_volume: u64,
    pub(crate) stale_window_days: u64,
    pub(crate) max_fp_ratio: f64,
}

impl From<&Thresholds> for ThresholdsView {
    fn from(t: &Thresholds) -> Self {
        Self {
            min_precision: t.min_precision,
            tune_max_precision: t.tune_max_precision,
            retire_max_precision: t.retire_max_precision,
            min_volume: t.min_volume,
            stale_window_days: t.stale_window_days,
            max_fp_ratio: t.max_fp_ratio,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ScorecardSummary {
    pub(crate) rules_total: usize,
    pub(crate) keep: usize,
    pub(crate) tune: usize,
    pub(crate) retire: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) portfolio_precision_proxy: Option<f64>,
    /// Percentage of the rule set carrying an ATT&CK tag (from the coverage
    /// report), the portfolio's ATT&CK coverage figure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) attack_tagged_pct: Option<f64>,
    pub(crate) attack_techniques: usize,
    pub(crate) thresholds: ThresholdsView,
}

/// The full scorecard document.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Scorecard {
    pub(crate) summary: ScorecardSummary,
    pub(crate) records: Vec<ScorecardRecord>,
    pub(crate) inputs: InputManifest,
}

impl Scorecard {
    pub(crate) fn build(
        records: Vec<ScorecardRecord>,
        coverage: &CoverageReport,
        thresholds: &Thresholds,
        inputs: InputManifest,
    ) -> Self {
        let keep = records
            .iter()
            .filter(|r| r.verdict == Verdict::Keep)
            .count();
        let tune = records
            .iter()
            .filter(|r| r.verdict == Verdict::Tune)
            .count();
        let retire = records
            .iter()
            .filter(|r| r.verdict == Verdict::Retire)
            .count();

        let proxies: Vec<f64> = records.iter().filter_map(|r| r.precision_proxy).collect();
        let portfolio_precision_proxy = if proxies.is_empty() {
            None
        } else {
            Some(proxies.iter().sum::<f64>() / proxies.len() as f64)
        };

        let attack_tagged_pct = if coverage.summary.rules_total > 0 {
            Some(coverage.summary.rules_tagged as f64 / coverage.summary.rules_total as f64 * 100.0)
        } else {
            None
        };

        let summary = ScorecardSummary {
            rules_total: records.len(),
            keep,
            tune,
            retire,
            portfolio_precision_proxy,
            attack_tagged_pct,
            attack_techniques: coverage.summary.techniques,
            thresholds: thresholds.into(),
        };

        Scorecard {
            summary,
            records,
            inputs,
        }
    }

    /// Whether any rule's verdict trips the `--fail-on` policy.
    pub(crate) fn fails(&self, fail_on: FailOn) -> bool {
        self.records.iter().any(|r| fail_on.triggers(r.verdict))
    }

    /// Render to stdout in the selected format, then write the optional
    /// `--report` program artifact.
    pub(crate) fn render(&self, ctx: &OutputCtx, report: Option<(&Path, ReportFormat)>) {
        match ctx.format {
            OutputFormat::Json => render_json(self, ctx.pretty_json()),
            OutputFormat::Ndjson => {
                for r in &self.records {
                    render_ndjson(r);
                }
            }
            OutputFormat::Csv => self.render_delimited(','),
            OutputFormat::Tsv => self.render_delimited('\t'),
            OutputFormat::Table => self.render_human(ctx),
        }

        if let Some((path, format)) = report {
            let artifact = match format {
                ReportFormat::Markdown => self.to_markdown(),
                ReportFormat::Html => self.to_html(),
            };
            if let Err(e) = write_string_file(path, &artifact) {
                eprintln!("Failed to write report to {}: {e}", path.display());
            } else if ctx.show_progress() {
                eprintln!("Wrote scorecard report to {}", path.display());
            }
        }

        if ctx.format != OutputFormat::Table && ctx.show_stats() {
            eprintln!("{}", self.stderr_summary());
        }
    }

    fn render_delimited(&self, sep: char) {
        let mut writer = DelimitedWriter::new(sep, ScorecardRecord::headers());
        for r in &self.records {
            writer.push(&r.row());
        }
    }

    fn stderr_summary(&self) -> String {
        let s = &self.summary;
        format!(
            "Scorecard: {} rules, {} keep / {} tune / {} retire across {} ATT&CK techniques.",
            s.rules_total, s.keep, s.tune, s.retire, s.attack_techniques,
        )
    }

    fn render_human(&self, ctx: &OutputCtx) {
        let p = Painter::new(ctx.color);
        let s = &self.summary;

        println!("{}", p.bold("Detection scorecard"));
        println!("  rules:    {}", s.rules_total);
        println!(
            "  verdicts: {} keep, {} tune, {} retire",
            p.green(&s.keep.to_string()),
            p.yellow(&s.tune.to_string()),
            p.red(&s.retire.to_string()),
        );
        if let Some(pp) = s.portfolio_precision_proxy {
            println!("  portfolio precision proxy: {pp:.2}");
        }
        if let Some(pct) = s.attack_tagged_pct {
            println!(
                "  ATT&CK:   {} techniques, {:.0}% of rules tagged",
                s.attack_techniques, pct
            );
        }
        let t = &s.thresholds;
        println!(
            "  thresholds: keep>={:.2} tune<{:.2} retire<{:.2} min_vol={} stale={}d max_fp={:.2}",
            t.min_precision,
            t.tune_max_precision,
            t.retire_max_precision,
            t.min_volume,
            t.stale_window_days,
            t.max_fp_ratio,
        );

        // Grouped by verdict, worst first: retire, then tune, then keep.
        for (verdict, label, paint) in [
            (
                Verdict::Retire,
                "Retire",
                &(|p: &Painter, s: &str| p.red_bold(s)) as &dyn Fn(&Painter, &str) -> String,
            ),
            (Verdict::Tune, "Tune", &|p, s| p.yellow_bold(s)),
            (Verdict::Keep, "Keep", &|p, s| p.green_bold(s)),
        ] {
            let group: Vec<ScorecardRecord> = self
                .records
                .iter()
                .filter(|r| r.verdict == verdict)
                .cloned()
                .collect();
            if group.is_empty() {
                continue;
            }
            println!("\n{} ({})", paint(&p, label), group.len());
            crate::output::render_table(&group);
            for r in &group {
                println!("  {}: {}", p.dim(&r.rule_title), r.reason);
            }
        }
    }

    // -- Markdown / HTML program artifact -----------------------------------

    fn to_markdown(&self) -> String {
        let s = &self.summary;
        let mut out = String::new();
        out.push_str("# Detection scorecard\n\n");
        out.push_str(&format!("- Rules: {}\n", s.rules_total));
        out.push_str(&format!(
            "- Verdicts: {} keep, {} tune, {} retire\n",
            s.keep, s.tune, s.retire
        ));
        if let Some(pp) = s.portfolio_precision_proxy {
            out.push_str(&format!("- Portfolio precision proxy: {pp:.2}\n"));
        }
        if let Some(pct) = s.attack_tagged_pct {
            out.push_str(&format!(
                "- ATT&CK: {} techniques, {:.0}% of rules tagged\n",
                s.attack_techniques, pct
            ));
        }

        for (verdict, label) in [
            (Verdict::Retire, "Retire"),
            (Verdict::Tune, "Tune"),
            (Verdict::Keep, "Keep"),
        ] {
            let group: Vec<&ScorecardRecord> = self
                .records
                .iter()
                .filter(|r| r.verdict == verdict)
                .collect();
            if group.is_empty() {
                continue;
            }
            out.push_str(&format!("\n## {} ({})\n\n", label, group.len()));
            out.push_str("| Rule | Level | Precision | Volume | FP | ATT&CK | Reason |\n");
            out.push_str("|---|---|---|---|---|---|---|\n");
            for r in group {
                out.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} | {} |\n",
                    md_cell(&r.rule_title),
                    md_cell(r.level.as_deref().unwrap_or("-")),
                    opt_f2(r.precision_proxy),
                    r.volume,
                    r.fp_signal,
                    md_cell(&attack_cell(r)),
                    md_cell(&r.reason),
                ));
            }
        }
        out
    }

    fn to_html(&self) -> String {
        let s = &self.summary;
        let mut out = String::new();
        out.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n");
        out.push_str("<meta charset=\"utf-8\">\n<title>Detection scorecard</title>\n");
        out.push_str(
            "<style>body{font-family:system-ui,sans-serif;margin:2rem}\
table{border-collapse:collapse;width:100%;margin-bottom:2rem}\
th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;font-size:.9rem}\
th{background:#f3f4f6}.retire{color:#b91c1c}.tune{color:#b45309}.keep{color:#15803d}</style>\n",
        );
        out.push_str("</head>\n<body>\n");
        out.push_str("<h1>Detection scorecard</h1>\n<ul>\n");
        out.push_str(&format!("<li>Rules: {}</li>\n", s.rules_total));
        out.push_str(&format!(
            "<li>Verdicts: <span class=\"keep\">{} keep</span>, \
<span class=\"tune\">{} tune</span>, <span class=\"retire\">{} retire</span></li>\n",
            s.keep, s.tune, s.retire
        ));
        if let Some(pp) = s.portfolio_precision_proxy {
            out.push_str(&format!("<li>Portfolio precision proxy: {pp:.2}</li>\n"));
        }
        if let Some(pct) = s.attack_tagged_pct {
            out.push_str(&format!(
                "<li>ATT&amp;CK: {} techniques, {:.0}% of rules tagged</li>\n",
                s.attack_techniques, pct
            ));
        }
        out.push_str("</ul>\n");

        for (verdict, label, class) in [
            (Verdict::Retire, "Retire", "retire"),
            (Verdict::Tune, "Tune", "tune"),
            (Verdict::Keep, "Keep", "keep"),
        ] {
            let group: Vec<&ScorecardRecord> = self
                .records
                .iter()
                .filter(|r| r.verdict == verdict)
                .collect();
            if group.is_empty() {
                continue;
            }
            out.push_str(&format!(
                "<h2 class=\"{class}\">{label} ({})</h2>\n",
                group.len()
            ));
            out.push_str(
                "<table>\n<thead><tr>\
<th>Rule</th><th>Level</th><th>Precision</th><th>Volume</th>\
<th>FP</th><th>ATT&amp;CK</th><th>Reason</th></tr></thead>\n<tbody>\n",
            );
            for r in group {
                out.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    html_cell(&r.rule_title),
                    html_cell(r.level.as_deref().unwrap_or("-")),
                    opt_f2(r.precision_proxy),
                    r.volume,
                    r.fp_signal,
                    html_cell(&attack_cell(r)),
                    html_cell(&r.reason),
                ));
            }
            out.push_str("</tbody>\n</table>\n");
        }
        out.push_str("</body>\n</html>\n");
        out
    }
}

/// The `--report` artifact format, resolved from the path extension or the
/// `--report-format` override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportFormat {
    Markdown,
    Html,
}

impl ReportFormat {
    /// Parse the `--report-format` override value.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "markdown" | "md" => Some(ReportFormat::Markdown),
            "html" | "htm" => Some(ReportFormat::Html),
            _ => None,
        }
    }

    /// Dispatch from a report path extension; `None` when the extension is not
    /// recognized (the caller then requires an explicit `--report-format`).
    pub(crate) fn from_extension(path: &Path) -> Option<Self> {
        match path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref()
        {
            Some("md" | "markdown") => Some(ReportFormat::Markdown),
            Some("html" | "htm") => Some(ReportFormat::Html),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tabular row for csv/tsv/table
// ---------------------------------------------------------------------------

const SCORECARD_HEADERS: &[&str] = &[
    "VERDICT",
    "RULE_ID",
    "TITLE",
    "LEVEL",
    "PRECISION",
    "RECALL",
    "FP_SIGNAL",
    "VOLUME",
    "LIVE_FP",
    "ATTACK",
    "REASON",
];

impl Tabular for ScorecardRecord {
    fn headers() -> &'static [&'static str] {
        SCORECARD_HEADERS
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.verdict.as_str().to_string(),
            self.rule_id.clone(),
            self.rule_title.clone(),
            self.level.clone().unwrap_or_else(|| "-".to_string()),
            opt_f2(self.precision_proxy),
            opt_f2(self.recall),
            self.fp_signal.to_string(),
            self.volume.to_string(),
            opt_f2(self.live_fp_ratio),
            attack_cell(self),
            self.reason.clone(),
        ]
    }
}

/// Format an optional ratio to two decimals, or `-` when absent.
fn opt_f2(v: Option<f64>) -> String {
    match v {
        Some(v) => format!("{v:.2}"),
        None => "-".to_string(),
    }
}

/// A compact ATT&CK cell: techniques joined by `|`, or `-` when untagged.
fn attack_cell(r: &ScorecardRecord) -> String {
    if r.attack.techniques.is_empty() {
        "-".to_string()
    } else {
        r.attack.techniques.join("|")
    }
}

/// Escape a markdown table cell: pipes break the row, newlines break the table.
fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

/// Escape the HTML special characters for element text.
fn html_cell(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn write_string_file(path: &Path, contents: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(contents.as_bytes())?;
    if !contents.ends_with('\n') {
        file.write_all(b"\n")?;
    }
    file.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_format_extension_and_override() {
        assert_eq!(
            ReportFormat::from_extension(Path::new("x.md")),
            Some(ReportFormat::Markdown)
        );
        assert_eq!(
            ReportFormat::from_extension(Path::new("x.HTML")),
            Some(ReportFormat::Html)
        );
        assert_eq!(ReportFormat::from_extension(Path::new("x.txt")), None);
        assert_eq!(
            ReportFormat::parse("markdown"),
            Some(ReportFormat::Markdown)
        );
        assert_eq!(ReportFormat::parse("html"), Some(ReportFormat::Html));
        assert_eq!(ReportFormat::parse("pdf"), None);
    }

    #[test]
    fn md_and_html_cells_escape() {
        assert_eq!(md_cell("a|b\nc"), "a\\|b c");
        assert_eq!(html_cell("a & b <c>"), "a &amp; b &lt;c&gt;");
    }

    #[test]
    fn opt_f2_formats_or_dashes() {
        assert_eq!(opt_f2(Some(0.8)), "0.80");
        assert_eq!(opt_f2(None), "-");
    }
}
