//! Coverage report: per-technique inventory plus the optional Atomic Red Team,
//! SigmaHQ-baseline, and target-list cross-references, with rendering through
//! the shared output layer.
//!
//! The report renders as the full JSON document (`json`), per-technique rows
//! (`ndjson`/`csv`/`tsv`), or a human summary with gap sections (`table`).
//! `--fail-on-gaps` turns any requested cross-reference's uncovered set into a
//! non-zero exit, the CI signal.

use std::collections::BTreeSet;

use serde::Serialize;

use super::sources::{CrossRef, Targets};
use super::{Coverage, parent_technique};
use crate::exit_code;
use crate::output::{
    DelimitedWriter, OutputCtx, OutputFormat, Painter, Tabular, render_json, render_ndjson,
};

#[derive(Debug, Clone, Serialize)]
struct Summary {
    rules_total: usize,
    rules_tagged: usize,
    rules_untagged: usize,
    techniques: usize,
    subtechniques: usize,
    tactics: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TechniqueEntry {
    id: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tactics: Vec<String>,
    rule_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<String>,
}

const TECHNIQUE_HEADERS: &[&str] = &["TECHNIQUE", "TACTICS", "RULES"];

impl Tabular for TechniqueEntry {
    fn headers() -> &'static [&'static str] {
        TECHNIQUE_HEADERS
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.id.clone(),
            if self.tactics.is_empty() {
                "-".to_string()
            } else {
                self.tactics.join(",")
            },
            self.rule_count.to_string(),
        ]
    }
}

/// Atomic Red Team cross-reference: which techniques have atomics but no rule
/// (a detection gap) and which rules cover techniques with no atomic (a
/// validation gap).
#[derive(Debug, Clone, Serialize)]
struct AtomicsGap {
    atomics_total: usize,
    covered: usize,
    atomics_without_rule: Vec<String>,
    rules_without_atomic: Vec<String>,
}

/// SigmaHQ baseline cross-reference: which baseline techniques are uncovered
/// locally, and which local techniques the baseline does not carry.
#[derive(Debug, Clone, Serialize)]
struct BaselineGap {
    baseline_total: usize,
    covered: usize,
    baseline_not_covered: Vec<String>,
    ahead_of_baseline: Vec<String>,
}

/// Target-list cross-reference: which targeted techniques are uncovered, and
/// which are only covered through a sub-technique rule.
#[derive(Debug, Clone, Serialize)]
struct TargetGap {
    targets_total: usize,
    covered: usize,
    uncovered: Vec<String>,
    covered_via_subtechnique: Vec<String>,
}

/// The full coverage report document.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CoverageReport {
    summary: Summary,
    techniques: Vec<TechniqueEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    untagged_rules: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    atomics: Option<AtomicsGap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline: Option<BaselineGap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    targets: Option<TargetGap>,
    /// Whether uncovered cross-reference techniques should set the exit code.
    /// Not part of the serialized shape.
    #[serde(skip)]
    fail_on_gaps: bool,
}

impl CoverageReport {
    /// Build the report from the computed coverage plus the optional
    /// cross-reference inputs.
    pub(crate) fn build(
        coverage: &Coverage,
        atomics: Option<CrossRef>,
        baseline: Option<CrossRef>,
        targets: Option<Targets>,
        fail_on_gaps: bool,
    ) -> Self {
        let techniques: Vec<TechniqueEntry> = coverage
            .techniques
            .iter()
            .map(|(id, agg)| TechniqueEntry {
                id: id.clone(),
                tactics: agg.tactics.iter().cloned().collect(),
                rule_count: agg.rule_count(),
                rules: agg.titles(),
            })
            .collect();

        let subtechniques = techniques.iter().filter(|t| t.id.contains('.')).count();

        let summary = Summary {
            rules_total: coverage.rules_total,
            rules_tagged: coverage.rules_tagged,
            rules_untagged: coverage.rules_total - coverage.rules_tagged,
            techniques: techniques.len(),
            subtechniques,
            tactics: coverage.tactics.len(),
        };

        CoverageReport {
            summary,
            techniques,
            untagged_rules: coverage.untagged_rules.clone(),
            atomics: atomics.map(|a| build_atomics_gap(coverage, &a)),
            baseline: baseline.map(|b| build_baseline_gap(coverage, &b)),
            targets: targets.map(|t| build_target_gap(coverage, &t)),
            fail_on_gaps,
        }
    }

    /// House exit code: `FINDINGS` (1) under `--fail-on-gaps` when any
    /// requested cross-reference reports uncovered techniques, else `SUCCESS`.
    pub(crate) fn exit_code(&self) -> i32 {
        if self.fail_on_gaps && self.has_gaps() {
            exit_code::FINDINGS
        } else {
            exit_code::SUCCESS
        }
    }

    fn has_gaps(&self) -> bool {
        let target_gap = self
            .targets
            .as_ref()
            .is_some_and(|t| !t.uncovered.is_empty());
        let atomic_gap = self
            .atomics
            .as_ref()
            .is_some_and(|a| !a.atomics_without_rule.is_empty());
        let baseline_gap = self
            .baseline
            .as_ref()
            .is_some_and(|b| !b.baseline_not_covered.is_empty());
        target_gap || atomic_gap || baseline_gap
    }

    /// Render to stdout in the selected format. Machine formats emit a one-line
    /// recap on stderr (gated on `show_stats`) since their stdout carries only
    /// the per-technique rows.
    pub(crate) fn render(&self, ctx: &OutputCtx) {
        match ctx.format {
            OutputFormat::Json => render_json(self, ctx.pretty_json()),
            OutputFormat::Ndjson => {
                for t in &self.techniques {
                    render_ndjson(t);
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
        let mut writer = DelimitedWriter::new(sep, TechniqueEntry::headers());
        for t in &self.techniques {
            writer.push(&t.row());
        }
    }

    fn stderr_summary(&self) -> String {
        let s = &self.summary;
        format!(
            "Coverage: {} techniques ({} sub) across {} tactics from {}/{} tagged rules.",
            s.techniques, s.subtechniques, s.tactics, s.rules_tagged, s.rules_total,
        )
    }

    fn render_human(&self, ctx: &OutputCtx) {
        let p = Painter::new(ctx.color);
        let s = &self.summary;

        println!("{}", p.bold("Coverage summary"));
        println!(
            "  rules:        {} ({} tagged)",
            s.rules_total, s.rules_tagged
        );
        println!(
            "  techniques:   {} ({} sub-techniques)",
            s.techniques, s.subtechniques
        );
        println!("  tactics:      {}", s.tactics);
        if s.rules_untagged > 0 {
            println!(
                "  {}: {} rules carry no attack.* tag",
                p.yellow("untagged"),
                s.rules_untagged
            );
        }

        if !self.techniques.is_empty() {
            println!("\n{}", p.bold("Techniques"));
            crate::output::render_table(&self.techniques);
        }

        if let Some(a) = &self.atomics {
            println!("\n{}", p.bold("Atomic Red Team"));
            println!(
                "  {} of {} atomic techniques covered by a rule",
                a.covered, a.atomics_total
            );
            print_id_list(&p, "atomics with no rule", &a.atomics_without_rule);
            print_id_list(&p, "rules with no atomic", &a.rules_without_atomic);
        }

        if let Some(b) = &self.baseline {
            println!("\n{}", p.bold("SigmaHQ baseline"));
            println!(
                "  {} of {} baseline techniques covered locally",
                b.covered, b.baseline_total
            );
            print_id_list(&p, "baseline not covered", &b.baseline_not_covered);
            print_id_list(&p, "ahead of baseline", &b.ahead_of_baseline);
        }

        if let Some(t) = &self.targets {
            println!("\n{}", p.bold("Target techniques"));
            println!("  {} of {} targets covered", t.covered, t.targets_total);
            print_id_list(&p, "uncovered", &t.uncovered);
            print_id_list(&p, "covered via sub-technique", &t.covered_via_subtechnique);
        }
    }
}

fn print_id_list(p: &Painter, label: &str, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    let head = p.yellow(label);
    println!("  {head} ({}): {}", ids.len(), ids.join(", "));
}

// ---------------------------------------------------------------------------
// Cross-reference computation
// ---------------------------------------------------------------------------

fn build_atomics_gap(coverage: &Coverage, atomics: &CrossRef) -> AtomicsGap {
    let mut atomics_without_rule = Vec::new();
    let mut covered = 0usize;
    for id in &atomics.ids {
        if coverage.covers(id).covered {
            covered += 1;
        } else {
            atomics_without_rule.push(id.clone());
        }
    }
    // A rule technique has an atomic when the technique itself, or (for a
    // sub-technique) its parent, appears in the atomic set.
    let mut rules_without_atomic: Vec<String> = coverage
        .techniques
        .keys()
        .filter(|id| {
            let has_self = atomics.ids.contains(id.as_str());
            let has_parent = parent_technique(id)
                .map(|p| atomics.ids.contains(p))
                .unwrap_or(false);
            !has_self && !has_parent
        })
        .cloned()
        .collect();
    rules_without_atomic.sort();
    atomics_without_rule.sort();
    AtomicsGap {
        atomics_total: atomics.ids.len(),
        covered,
        atomics_without_rule,
        rules_without_atomic,
    }
}

fn build_baseline_gap(coverage: &Coverage, baseline: &CrossRef) -> BaselineGap {
    let mut baseline_not_covered = Vec::new();
    let mut covered = 0usize;
    for id in &baseline.ids {
        if coverage.covers(id).covered {
            covered += 1;
        } else {
            baseline_not_covered.push(id.clone());
        }
    }
    let mut ahead_of_baseline: Vec<String> = coverage
        .techniques
        .keys()
        .filter(|id| {
            let in_baseline = baseline.ids.contains(id.as_str());
            let parent_in_baseline = parent_technique(id)
                .map(|p| baseline.ids.contains(p))
                .unwrap_or(false);
            !in_baseline && !parent_in_baseline
        })
        .cloned()
        .collect();
    ahead_of_baseline.sort();
    baseline_not_covered.sort();
    BaselineGap {
        baseline_total: baseline.ids.len(),
        covered,
        baseline_not_covered,
        ahead_of_baseline,
    }
}

fn build_target_gap(coverage: &Coverage, targets: &Targets) -> TargetGap {
    let mut uncovered = Vec::new();
    let mut covered_via_subtechnique = Vec::new();
    let mut covered = 0usize;
    // Preserve the target file's order; de-dup is already done at load time.
    let mut seen = BTreeSet::new();
    for id in &targets.ids {
        if !seen.insert(id.clone()) {
            continue;
        }
        let c = coverage.covers(id);
        if c.covered {
            covered += 1;
            if c.via_subtechnique {
                covered_via_subtechnique.push(id.clone());
            }
        } else {
            uncovered.push(id.clone());
        }
    }
    TargetGap {
        targets_total: targets.ids.len(),
        covered,
        uncovered,
        covered_via_subtechnique,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::coverage::Coverage;

    fn coverage_from(yaml: &str) -> Coverage {
        Coverage::from_collection(&rsigma_parser::parse_sigma_yaml(yaml).expect("parse"))
    }

    const RULES: &str = r#"
title: PowerShell
id: 00000000-0000-0000-0000-0000000000a1
logsource: {category: process_creation, product: windows}
detection: {sel: {Image|endswith: '\powershell.exe'}, condition: sel}
tags: [attack.execution, attack.t1059.001]
---
title: Whoami
id: 00000000-0000-0000-0000-0000000000a2
logsource: {category: process_creation, product: windows}
detection: {sel: {Image|endswith: '\whoami.exe'}, condition: sel}
tags: [attack.discovery, attack.t1033]
---
title: Untagged
id: 00000000-0000-0000-0000-0000000000a3
logsource: {category: process_creation, product: windows}
detection: {sel: {Image|endswith: '\x.exe'}, condition: sel}
"#;

    fn cross_ref(ids: &[&str]) -> CrossRef {
        CrossRef {
            ids: ids.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn summary_counts_tagged_and_untagged() {
        let cov = coverage_from(RULES);
        let report = CoverageReport::build(&cov, None, None, None, false);
        assert_eq!(report.summary.rules_total, 3);
        assert_eq!(report.summary.rules_tagged, 2);
        assert_eq!(report.summary.rules_untagged, 1);
        assert_eq!(report.summary.techniques, 2); // T1059.001, T1033
        assert_eq!(report.summary.subtechniques, 1); // T1059.001
        assert_eq!(report.untagged_rules, vec!["Untagged".to_string()]);
    }

    #[test]
    fn target_parent_covered_via_subtechnique() {
        let cov = coverage_from(RULES);
        // T1059 (parent) is covered because a rule tags T1059.001.
        let targets = Targets {
            ids: vec!["T1059".to_string(), "T1003".to_string()],
        };
        let report = CoverageReport::build(&cov, None, None, Some(targets), true);
        let t = report.targets.as_ref().unwrap();
        assert_eq!(t.covered, 1);
        assert_eq!(t.covered_via_subtechnique, vec!["T1059".to_string()]);
        assert_eq!(t.uncovered, vec!["T1003".to_string()]);
        // Uncovered target under --fail-on-gaps -> findings.
        assert_eq!(report.exit_code(), exit_code::FINDINGS);
    }

    #[test]
    fn subtechnique_target_not_covered_by_parent_rule() {
        // A rule on T1059.001 does NOT cover a target of T1059.002.
        let cov = coverage_from(RULES);
        let targets = Targets {
            ids: vec!["T1059.002".to_string()],
        };
        let report = CoverageReport::build(&cov, None, None, Some(targets), false);
        let t = report.targets.as_ref().unwrap();
        assert_eq!(t.uncovered, vec!["T1059.002".to_string()]);
    }

    #[test]
    fn atomics_gap_splits_both_directions() {
        let cov = coverage_from(RULES);
        // Atomics exist for T1059 (parent of a covered sub) and T1566 (no rule).
        let atomics = cross_ref(&["T1059", "T1566"]);
        let report = CoverageReport::build(&cov, Some(atomics), None, None, false);
        let a = report.atomics.as_ref().unwrap();
        // T1059 is covered via the sub-technique rule; T1566 is not.
        assert_eq!(a.covered, 1);
        assert_eq!(a.atomics_without_rule, vec!["T1566".to_string()]);
        // T1033 has a rule but no atomic in the set.
        assert!(a.rules_without_atomic.contains(&"T1033".to_string()));
    }

    #[test]
    fn fail_on_gaps_clean_when_all_covered() {
        let cov = coverage_from(RULES);
        let targets = Targets {
            ids: vec!["T1033".to_string()],
        };
        let report = CoverageReport::build(&cov, None, None, Some(targets), true);
        assert_eq!(report.exit_code(), exit_code::SUCCESS);
    }
}
