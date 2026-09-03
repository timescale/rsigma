//! `rsigma rule test`: replay embedded `rsigma.exemplars`.

use std::path::PathBuf;

use clap::Args;
use rsigma_eval::{ExemplarResult, ExemplarRunError, run_exemplars};
use rsigma_parser::ExemplarRuleKind;
use serde::Serialize;

use crate::exit_code;
use crate::output::{OutputCtx, OutputFormat, Tabular, render_report};

/// Arguments for `rsigma rule test`.
#[derive(Args, Debug)]
pub(crate) struct TestArgs {
    /// One or more Sigma rule files or directories (repeatable).
    #[arg(short, long, required = true)]
    pub rules: Vec<PathBuf>,

    /// Processing pipeline(s) to apply (repeatable). Accepts builtin names or YAML file paths.
    #[arg(short = 'p', long = "pipeline")]
    pub pipelines: Vec<PathBuf>,

    /// Exit 1 when a detection or correlation rule has no exemplars.
    #[arg(long)]
    pub fail_on_missing: bool,
}

#[derive(Debug, Serialize)]
struct TestReport {
    source: String,
    summary: TestSummary,
    results: Vec<ExemplarResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    missing: Vec<rsigma_eval::MissingExemplars>,
}

#[derive(Debug, Serialize)]
struct TestSummary {
    rules: usize,
    exemplars: usize,
    passed: usize,
    failed: usize,
    missing: usize,
}

impl Tabular for ExemplarResult {
    fn headers() -> &'static [&'static str] {
        &[
            "RULE", "KIND", "INDEX", "NAME", "EXPECT", "ACTUAL", "RESULT",
        ]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.rule_id
                .clone()
                .unwrap_or_else(|| self.rule_title.clone()),
            kind_label(self.rule_kind).to_string(),
            self.index.to_string(),
            self.name.clone(),
            self.expect.to_string(),
            self.actual.to_string(),
            if self.passed { "pass" } else { "fail" }.to_string(),
        ]
    }
}

fn kind_label(kind: ExemplarRuleKind) -> &'static str {
    match kind {
        ExemplarRuleKind::Detection => "detection",
        ExemplarRuleKind::Correlation => "correlation",
        ExemplarRuleKind::Filter => "filter",
    }
}

pub(crate) fn cmd_test(args: TestArgs, mut ctx: OutputCtx) -> i32 {
    if !ctx.explicit_format {
        ctx.format = OutputFormat::Table;
    }

    let collection = crate::load_collection_multi(&args.rules);
    let pipelines = crate::load_pipelines(&args.pipelines);
    let source = args
        .rules
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(",");

    let mut report = match run_exemplars(&collection, &pipelines) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("{err}");
            return match err {
                ExemplarRunError::Compile(_) => exit_code::RULE_ERROR,
                ExemplarRunError::Shape { .. }
                | ExemplarRunError::AmbiguousTitle(_)
                | ExemplarRunError::Reference(_) => exit_code::CONFIG_ERROR,
            };
        }
    };
    report.source = source.clone();

    let passed = report.results.iter().filter(|r| r.passed).count();
    let failed = report.results.len() - passed;
    let envelope = TestReport {
        source,
        summary: TestSummary {
            rules: collection.rules.len() + collection.correlations.len(),
            exemplars: report.results.len(),
            passed,
            failed,
            missing: report.missing.len(),
        },
        results: report.results.clone(),
        missing: report.missing.clone(),
    };

    if ctx.show_stats() {
        eprintln!(
            "Exemplars: {} | passed: {} | failed: {} | missing rules: {}",
            envelope.summary.exemplars,
            envelope.summary.passed,
            envelope.summary.failed,
            envelope.summary.missing,
        );
    }

    render_report(&ctx, &envelope, &report.results);

    let missing_fail = args.fail_on_missing && !report.missing.is_empty();
    if !report.all_passed() || missing_fail {
        exit_code::FINDINGS
    } else {
        exit_code::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tabular_row_uses_id_when_present() {
        let row = ExemplarResult {
            rule_id: Some("abc".to_string()),
            rule_title: "Whoami".to_string(),
            rule_kind: ExemplarRuleKind::Detection,
            index: 0,
            name: "whoami fires".to_string(),
            expect: rsigma_parser::Expect::Match,
            actual: rsigma_parser::Expect::Match,
            passed: true,
            diagnostic: None,
        };
        assert_eq!(row.row()[0], "abc");
        assert_eq!(row.row()[6], "pass");
    }
}
