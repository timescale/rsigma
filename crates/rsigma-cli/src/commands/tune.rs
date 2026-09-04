//! `rsigma rule tune`: propose a verified Sigma filter from FP/TP exemplars.

use std::path::PathBuf;
use std::process;

use clap::Args;
use rsigma_eval::{TuneConfig, TuneExpectationDiff, TuneReport, apply_pipelines, tune_rule};

use super::draft::{EmitMode, read_events};
use crate::output::{OutputCtx, OutputFormat, render_json};

/// Arguments for `rsigma rule tune`.
#[derive(Args, Debug)]
pub(crate) struct TuneArgs {
    /// Path to a Sigma rule file or directory.
    #[arg(short, long)]
    pub rules: PathBuf,

    /// Target rule id, falling back to an exact title.
    /// Required when the ruleset contains more than one detection rule.
    #[arg(long, value_name = "ID|TITLE")]
    pub rule: Option<String>,

    /// False-positive events as inline JSON or @path to NDJSON/EVTX.
    /// Reads NDJSON from stdin when omitted.
    #[arg(long, value_name = "JSON|@PATH", conflicts_with = "from_dispositions")]
    pub fp: Option<String>,

    /// True-positive events as inline JSON or @path to NDJSON/EVTX.
    #[arg(
        long,
        value_name = "JSON|@PATH",
        required_unless_present = "from_dispositions",
        conflicts_with = "from_dispositions"
    )]
    pub tp: Option<String>,

    /// Versioned disposition-capture spool written by `engine daemon`.
    #[arg(
        long = "from-dispositions",
        value_name = "SPOOL_DIR",
        conflicts_with_all = ["fp", "tp"]
    )]
    pub from_dispositions: Option<PathBuf>,

    /// Processing pipeline(s) applied before tuning and verification.
    #[arg(short = 'p', long = "pipeline", value_name = "PATH|NAME")]
    pub pipelines: Vec<PathBuf>,

    /// Existing backtest expectations to validate and include in the diff.
    #[arg(long, value_name = "PATH")]
    pub expectations: Option<PathBuf>,

    /// Backtest corpus scope for the false-positive input.
    #[arg(long, value_name = "RELATIVE_PATH", requires = "expectations")]
    pub fp_corpus: Option<String>,

    /// Backtest corpus scope for the true-positive input.
    #[arg(long, value_name = "RELATIVE_PATH", requires = "expectations")]
    pub tp_corpus: Option<String>,

    /// Maximum fields in one filter selection.
    #[arg(long, default_value_t = 4)]
    pub max_fields: usize,

    /// Minimum fields required in every filter selection.
    #[arg(long, default_value_t = 2)]
    pub min_fields: usize,

    /// Maximum exact values emitted as one OR list.
    #[arg(long, default_value_t = 8)]
    pub max_value_cardinality: usize,

    /// Minimum FP events required for every emitted selection.
    #[arg(long, default_value_t = 2)]
    pub min_cluster_support: usize,

    /// Maximum selections emitted in one filter rule.
    #[arg(long, default_value_t = 5)]
    pub max_clusters: usize,

    /// Emit verified clean clusters even if some FPs remain uncovered.
    #[arg(long)]
    pub allow_partial: bool,

    /// What to print: filter YAML (default) or the rationale report.
    #[arg(long, value_enum, default_value_t = EmitMode::Yaml)]
    pub emit: EmitMode,
}

pub(crate) fn cmd_tune(args: TuneArgs, ctx: OutputCtx) {
    if args.from_dispositions.is_some() {
        cmd_tune_from_dispositions(args, ctx);
        return;
    }

    let false_positives = read_corpus(args.fp.as_deref(), "false-positive");
    let true_positives = read_corpus(args.tp.as_deref(), "true-positive");

    let collection = crate::load_collection(&args.rules);
    let mut rule = match select_rule(&collection.rules, args.rule.as_deref()) {
        Ok(rule) => rule.clone(),
        Err(error) => {
            eprintln!("error: {error}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    };

    let pipelines = crate::load_pipelines(&args.pipelines);
    if !pipelines.is_empty()
        && let Err(error) = apply_pipelines(&pipelines, &mut rule)
    {
        eprintln!("error applying pipeline to {:?}: {error}", rule.title);
        process::exit(crate::exit_code::RULE_ERROR);
    }

    let mut report = tune_one(
        &rule,
        &false_positives.events,
        &true_positives.events,
        &args,
    );
    if let Some(path) = &args.expectations {
        let resolved = match super::backtest::expectations::load_and_resolve(path, &collection) {
            Ok(resolved) => resolved,
            Err(error) => {
                eprintln!("error: {error}");
                process::exit(crate::exit_code::CONFIG_ERROR);
            }
        };
        report.expectation_diff = Some(expectation_diff(
            &report,
            &rule,
            &resolved,
            args.fp.as_deref(),
            args.tp.as_deref().unwrap_or(""),
            args.fp_corpus.as_deref(),
            args.tp_corpus.as_deref(),
        ));
    }

    emit_reports(&[(rule, report)], &args, &ctx);
}

fn cmd_tune_from_dispositions(args: TuneArgs, ctx: OutputCtx) {
    let spool = args
        .from_dispositions
        .as_ref()
        .expect("clap requires the spool");
    let evidence =
        match super::disposition_spool::load_disposition_evidence(spool, args.rule.as_deref()) {
            Ok(evidence) => evidence,
            Err(error) => {
                eprintln!("error: {error}");
                process::exit(crate::exit_code::RULE_ERROR);
            }
        };

    let collection = crate::load_collection(&args.rules);
    let pipelines = crate::load_pipelines(&args.pipelines);
    let resolved_expectations =
        args.expectations.as_ref().map(
            |path| match super::backtest::expectations::load_and_resolve(path, &collection) {
                Ok(resolved) => resolved,
                Err(error) => {
                    eprintln!("error: {error}");
                    process::exit(crate::exit_code::CONFIG_ERROR);
                }
            },
        );

    let mut reports = Vec::new();
    for item in evidence {
        let mut rule = match select_rule(&collection.rules, Some(&item.rule_id)) {
            Ok(rule) => rule.clone(),
            Err(error) => {
                eprintln!("error: {error}");
                process::exit(crate::exit_code::RULE_ERROR);
            }
        };
        if !pipelines.is_empty()
            && let Err(error) = apply_pipelines(&pipelines, &mut rule)
        {
            eprintln!("error applying pipeline to {:?}: {error}", rule.title);
            process::exit(crate::exit_code::RULE_ERROR);
        }
        let mut report = tune_one(&rule, &item.false_positives, &item.true_positives, &args);
        if let Some(resolved) = &resolved_expectations {
            report.expectation_diff = Some(expectation_diff(
                &report,
                &rule,
                resolved,
                None,
                "",
                args.fp_corpus.as_deref(),
                args.tp_corpus.as_deref(),
            ));
        }
        reports.push((rule, report));
    }

    emit_reports(&reports, &args, &ctx);
}

fn tune_one(
    rule: &rsigma_parser::SigmaRule,
    false_positives: &[serde_json::Value],
    true_positives: &[serde_json::Value],
    args: &TuneArgs,
) -> TuneReport {
    let config = TuneConfig {
        max_fields: args.max_fields,
        min_fields: args.min_fields,
        max_value_cardinality: args.max_value_cardinality,
        min_cluster_support: args.min_cluster_support,
        max_clusters: args.max_clusters,
        allow_partial: args.allow_partial,
        filter_id: Some(uuid::Uuid::new_v4().to_string()),
        ..TuneConfig::default()
    };
    match tune_rule(rule, false_positives, true_positives, &config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("error tuning rule: {error}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
}

fn emit_reports(
    reports: &[(rsigma_parser::SigmaRule, TuneReport)],
    args: &TuneArgs,
    ctx: &OutputCtx,
) {
    match args.emit {
        EmitMode::Yaml => {
            if ctx.explicit_format {
                ctx.warn_unsupported("rule tune", "Sigma YAML");
            }
            for (i, (_, report)) in reports.iter().enumerate() {
                if i > 0 {
                    println!("---");
                }
                print!("{}", report.filter_yaml);
                if ctx.show_stats() {
                    print_summary_stderr(report);
                }
            }
        }
        EmitMode::Report if reports.len() == 1 => render_report(&reports[0].1, ctx),
        EmitMode::Report => render_disposition_reports(reports, ctx),
    }
}

fn render_disposition_reports(reports: &[(rsigma_parser::SigmaRule, TuneReport)], ctx: &OutputCtx) {
    #[derive(serde::Serialize)]
    struct NamedReport<'a> {
        rule_id: String,
        #[serde(flatten)]
        report: &'a TuneReport,
    }
    let named: Vec<NamedReport<'_>> = reports
        .iter()
        .map(|(rule, report)| NamedReport {
            rule_id: rule.id.clone().unwrap_or_else(|| rule.title.clone()),
            report,
        })
        .collect();
    match ctx.format {
        OutputFormat::Json => render_json(&named, true),
        OutputFormat::Ndjson => {
            for item in &named {
                render_json(item, false);
            }
        }
        OutputFormat::Table | OutputFormat::Csv | OutputFormat::Tsv => {
            if !matches!(ctx.format, OutputFormat::Table) {
                ctx.warn_unsupported("rule tune --emit report", "human report");
            }
            for (i, (rule, report)) in reports.iter().enumerate() {
                if i > 0 {
                    println!();
                }
                println!(
                    "# rule: {}",
                    rule.id.as_deref().unwrap_or(rule.title.as_str())
                );
                render_report(report, ctx);
            }
        }
    }
}

fn read_corpus(spec: Option<&str>, label: &str) -> super::draft::Corpus {
    let corpus = match read_events(spec, label) {
        Ok(corpus) => corpus,
        Err(error) => {
            eprintln!("{error}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    };
    if corpus.parse_errors > 0 {
        eprintln!(
            "error: {} {label} record(s) failed to parse; tuning requires the complete corpus",
            corpus.parse_errors
        );
        process::exit(crate::exit_code::RULE_ERROR);
    }
    corpus
}

fn select_rule<'a>(
    rules: &'a [rsigma_parser::SigmaRule],
    selector: Option<&str>,
) -> Result<&'a rsigma_parser::SigmaRule, String> {
    if rules.is_empty() {
        return Err("no detection rules found".to_string());
    }
    let Some(selector) = selector else {
        return if rules.len() == 1 {
            Ok(&rules[0])
        } else {
            Err(format!(
                "ruleset contains {} detection rules; pass --rule <id-or-title>",
                rules.len()
            ))
        };
    };

    let matches: Vec<_> = rules
        .iter()
        .filter(|rule| rule.id.as_deref() == Some(selector) || rule.title.as_str() == selector)
        .collect();
    match matches.as_slice() {
        [rule] => Ok(*rule),
        [] => Err(format!("no detection rule matched {selector:?}")),
        _ => Err(format!(
            "{} detection rules matched {selector:?}; use a unique rule id",
            matches.len()
        )),
    }
}

fn render_report(report: &TuneReport, ctx: &OutputCtx) {
    match ctx.format {
        OutputFormat::Json => render_json(report, true),
        OutputFormat::Ndjson => render_json(report, false),
        OutputFormat::Table | OutputFormat::Csv | OutputFormat::Tsv => {
            if !matches!(ctx.format, OutputFormat::Table) {
                ctx.warn_unsupported("rule tune --emit report", "human report");
            }
            println!(
                "Suppressed {}/{} false positives; protected {}/{} true positives",
                report.verification.false_positives_before
                    - report.verification.false_positives_after,
                report.verification.false_positives_before,
                report.verification.true_positives_after,
                report.verification.true_positives_before
            );
            println!();
            println!("FIELD\tSCORE\tSTABILITY\tTP HITS\tDISPOSITION\tVALUES");
            for field in &report.fields {
                println!(
                    "{}\t{:.3}\t{}\t{}\t{:?}\t{}",
                    field.field,
                    field.score,
                    field.stability,
                    field.true_positive_hits,
                    field.disposition,
                    field.values.join(", ")
                );
            }
            println!();
            println!("# Filter rule");
            print!("{}", report.filter_yaml);
            if let Some(diff) = &report.expectation_diff {
                println!();
                println!("# Backtest expectation diff");
                println!(
                    "false positives: {} -> {}; true positives: {} -> {}",
                    diff.false_positives_before,
                    diff.false_positives_after,
                    diff.true_positives_before,
                    diff.true_positives_after
                );
                if !diff.existing.is_empty() {
                    println!("existing bounds:");
                    for bound in &diff.existing {
                        println!("  - {bound}");
                    }
                }
                println!("entries to add under `expectations`:");
                print!("{}", diff.fragment);
            }
        }
    }
}

fn print_summary_stderr(report: &TuneReport) {
    eprintln!(
        "suppressed {}/{} false positives; protected {}/{} true positives",
        report.verification.false_positives_before - report.verification.false_positives_after,
        report.verification.false_positives_before,
        report.verification.true_positives_after,
        report.verification.true_positives_before
    );
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
}

fn expectation_diff(
    report: &TuneReport,
    rule: &rsigma_parser::SigmaRule,
    resolved: &super::backtest::expectations::ResolvedExpectations,
    fp_spec: Option<&str>,
    tp_spec: &str,
    fp_corpus: Option<&str>,
    tp_corpus: Option<&str>,
) -> TuneExpectationDiff {
    let rule_key = rule.id.as_deref().unwrap_or(&rule.title);
    let existing = resolved
        .expectations
        .iter()
        .filter(|expectation| expectation.rule_key == rule_key)
        .map(|expectation| match &expectation.corpus {
            Some(corpus) => format!(
                "{} [{}]: {}",
                expectation.reference,
                corpus,
                expectation.bound.describe()
            ),
            None => format!(
                "{}: {}",
                expectation.reference,
                expectation.bound.describe()
            ),
        })
        .collect();
    let fp_label = corpus_label(fp_corpus, fp_spec, "false-positives.ndjson");
    let tp_label = corpus_label(tp_corpus, Some(tp_spec), "true-positives.ndjson");
    let fragment = format!(
        "  - rule: {}\n    corpus: {}\n    exactly: {}\n  - rule: {}\n    corpus: {}\n    at_least: {}\n",
        yaml_scalar(rule_key),
        yaml_scalar(&fp_label),
        report.verification.false_positives_after,
        yaml_scalar(rule_key),
        yaml_scalar(&tp_label),
        report.verification.true_positives_after
    );
    TuneExpectationDiff {
        existing,
        false_positives_before: report.verification.false_positives_before,
        false_positives_after: report.verification.false_positives_after,
        true_positives_before: report.verification.true_positives_before,
        true_positives_after: report.verification.true_positives_after,
        fragment,
    }
}

fn corpus_label(explicit: Option<&str>, spec: Option<&str>, fallback: &str) -> String {
    if let Some(explicit) = explicit {
        return explicit.to_string();
    }
    let Some(path) = spec.and_then(|spec| spec.strip_prefix('@')) else {
        return fallback.to_string();
    };
    let path = std::path::Path::new(path);
    if path.is_relative() {
        path.to_string_lossy().into_owned()
    } else {
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(fallback)
            .to_string()
    }
}

fn yaml_scalar(value: &str) -> String {
    let bare_safe = !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        });
    if bare_safe {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_rules(yaml: &str) -> Vec<rsigma_parser::SigmaRule> {
        rsigma_parser::parse_sigma_yaml(yaml).unwrap().rules
    }

    #[test]
    fn selector_requires_explicit_target_for_multiple_rules() {
        let rules = parsed_rules(
            r#"
title: One
id: one
logsource:
    category: test
detection:
    selection:
        value: one
    condition: selection
---
title: Two
id: two
logsource:
    category: test
detection:
    selection:
        value: two
    condition: selection
"#,
        );
        assert!(select_rule(&rules, None).is_err());
        assert_eq!(select_rule(&rules, Some("two")).unwrap().title, "Two");
    }

    #[test]
    fn corpus_label_preserves_relative_scope_and_allows_override() {
        assert_eq!(
            corpus_label(None, Some("@corpus/windows/fp.ndjson"), "fallback"),
            "corpus/windows/fp.ndjson"
        );
        assert_eq!(
            corpus_label(
                Some("windows/fp.ndjson"),
                Some("@/tmp/fp.ndjson"),
                "fallback"
            ),
            "windows/fp.ndjson"
        );
    }
}
