//! Atomic Red Team test plan: the uncovered-but-testable techniques the
//! report lists as `atomics_without_rule` (computed by `build_atomics_gap` in
//! [`super::report`]), each expanded into named tests and ready-to-paste
//! `Invoke-AtomicTest` invocations.

use super::Coverage;
use super::sources::{AtomicTestMeta, AtomicsCatalog};
use crate::commands::reports::{
    AtomicsPlan, AtomicsPlanSummary, AtomicsPlanTechnique, AtomicsPlanTest,
};
use crate::output::{
    DelimitedWriter, OutputCtx, OutputFormat, Painter, Tabular, render_json, render_ndjson,
};

const PLAN_HEADERS: &[&str] = &["TECHNIQUE", "TEST", "GUID", "PLATFORMS", "INVOCATION"];

/// One runnable test row for `ndjson`/`csv`/`tsv`. GUID-less tests omit the
/// `guid` key in NDJSON, matching the JSON document's shape.
#[derive(Debug, Clone, serde::Serialize)]
struct PlanRow {
    technique: String,
    test: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    guid: Option<String>,
    platforms: String,
    invocation: String,
}

impl Tabular for PlanRow {
    fn headers() -> &'static [&'static str] {
        PLAN_HEADERS
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.technique.clone(),
            self.test.clone(),
            self.guid.clone().unwrap_or_else(|| "-".to_string()),
            if self.platforms.is_empty() {
                "-".to_string()
            } else {
                self.platforms.clone()
            },
            self.invocation.clone(),
        ]
    }
}

impl AtomicsPlan {
    /// Build a plan for every catalog technique `coverage` does not cover,
    /// using the same `Coverage::covers` rule as the atomics gap (a parent
    /// is satisfied by a sub-technique rule; a sub-technique is not satisfied
    /// by a parent rule). `--platforms` keeps tests whose
    /// `supported_platforms` intersect the filter and drops techniques that
    /// then have no tests.
    pub(crate) fn build(
        coverage: &Coverage,
        catalog: &AtomicsCatalog,
        platforms: &[String],
    ) -> Self {
        let filter: Vec<String> = platforms
            .iter()
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .map(|p| p.to_ascii_lowercase())
            .collect();

        let mut uncovered = Vec::new();
        for id in catalog.keys() {
            if !coverage.covers(id).covered {
                uncovered.push(id.clone());
            }
        }

        let mut techniques = Vec::new();
        for id in &uncovered {
            let meta = catalog.get(id);
            let tactics = meta
                .map(|m| m.tactics.iter().cloned().collect())
                .unwrap_or_default();
            let raw_tests = meta.map(|m| m.tests.as_slice()).unwrap_or(&[]);
            let tests: Vec<AtomicsPlanTest> = raw_tests
                .iter()
                .filter(|t| test_matches_platforms(t, &filter))
                .map(|t| plan_test(id, t))
                .collect();
            if !filter.is_empty() && tests.is_empty() {
                continue;
            }
            techniques.push(AtomicsPlanTechnique {
                technique: id.clone(),
                tactics,
                invocation: technique_invocation(id),
                tests,
            });
        }

        let tests_in_plan = techniques.iter().map(|t| t.tests.len()).sum();
        AtomicsPlan {
            summary: AtomicsPlanSummary {
                atomics_total: catalog.len(),
                uncovered_testable: uncovered.len(),
                techniques_in_plan: techniques.len(),
                tests_in_plan,
                platforms: filter,
            },
            techniques,
        }
    }

    pub(crate) fn render(&self, ctx: &OutputCtx) {
        let format = ctx.format;
        match format {
            OutputFormat::Json => render_json(self, ctx.pretty_json()),
            OutputFormat::Ndjson => {
                for row in self.rows() {
                    render_ndjson(&row);
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

    fn rows(&self) -> Vec<PlanRow> {
        let mut rows = Vec::new();
        for tech in &self.techniques {
            for test in &tech.tests {
                rows.push(PlanRow {
                    technique: tech.technique.clone(),
                    test: test.name.clone(),
                    guid: test.guid.clone(),
                    platforms: test.platforms.join(","),
                    invocation: test.invocation.clone(),
                });
            }
        }
        rows
    }

    fn render_delimited(&self, sep: char) {
        let mut writer = DelimitedWriter::new(sep, PlanRow::headers());
        for row in self.rows() {
            writer.push(&row.row());
        }
    }

    fn stderr_summary(&self) -> String {
        let s = &self.summary;
        format!(
            "Atomics plan: {} techniques, {} tests ({} uncovered of {} atomics).",
            s.techniques_in_plan, s.tests_in_plan, s.uncovered_testable, s.atomics_total,
        )
    }

    fn render_human(&self, ctx: &OutputCtx) {
        let p = Painter::new(ctx.color);
        let s = &self.summary;

        println!("{}", p.bold("Atomics plan"));
        println!(
            "  atomics:      {} ({} uncovered and testable)",
            s.atomics_total, s.uncovered_testable
        );
        println!(
            "  in plan:      {} techniques, {} tests",
            s.techniques_in_plan, s.tests_in_plan
        );
        if s.platforms.is_empty() {
            println!("  platforms:    all");
        } else {
            println!("  platforms:    {}", s.platforms.join(","));
        }

        for tech in &self.techniques {
            println!();
            if tech.tactics.is_empty() {
                println!("{}", p.bold(&tech.technique));
            } else {
                println!(
                    "{}  {}",
                    p.bold(&tech.technique),
                    p.dim(&tech.tactics.join(","))
                );
            }
            println!("  {}", tech.invocation);
            for test in &tech.tests {
                let guid = test.guid.as_deref().unwrap_or("-");
                let platforms = if test.platforms.is_empty() {
                    "-".to_string()
                } else {
                    test.platforms.join(",")
                };
                println!("    {}  {}  {}", test.name, guid, platforms);
                println!("    {}", test.invocation);
            }
        }
    }
}

fn technique_invocation(technique: &str) -> String {
    format!("Invoke-AtomicTest {technique}")
}

fn plan_test(technique: &str, test: &AtomicTestMeta) -> AtomicsPlanTest {
    let guid = test.guid().map(str::to_string);
    let invocation = match &guid {
        Some(g) => format!("Invoke-AtomicTest {technique} -TestGuids {g}"),
        None => technique_invocation(technique),
    };
    AtomicsPlanTest {
        name: test.name.clone(),
        guid,
        platforms: test.supported_platforms.clone(),
        invocation,
    }
}

fn test_matches_platforms(test: &AtomicTestMeta, filter: &[String]) -> bool {
    if filter.is_empty() {
        return true;
    }
    test.supported_platforms
        .iter()
        .any(|p| filter.iter().any(|f| f.eq_ignore_ascii_case(p)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::coverage::Coverage;
    use crate::commands::coverage::sources::{CrossRef, parse_atomics_index};
    use crate::commands::reports::CoverageReport;

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
"#;

    const INDEX: &str = "\
execution:
  T1059:
    atomic_tests:
      - name: Parent technique test
        auto_generated_guid: 11111111-1111-1111-1111-111111111111
        supported_platforms: [windows]
  T1059.001:
    atomic_tests:
      - name: PowerShell
        auto_generated_guid: 22222222-2222-2222-2222-222222222222
        supported_platforms: [windows]
  T1566:
    atomic_tests:
      - name: Spearphishing Attachment
        auto_generated_guid: 33333333-3333-3333-3333-333333333333
        supported_platforms: [windows]
      - name: Phishing via curl
        auto_generated_guid: 44444444-4444-4444-4444-444444444444
        supported_platforms: [linux, macos]
      - name: GUID-less phishing
        supported_platforms: [macos]
defense-evasion:
  T1566:
    atomic_tests:
      - name: Spearphishing Attachment
        auto_generated_guid: 33333333-3333-3333-3333-333333333333
        supported_platforms: [windows]
  T1027:
    atomic_tests: []
";

    fn loaded_catalog() -> AtomicsCatalog {
        parse_atomics_index(INDEX).unwrap().catalog
    }

    #[test]
    fn plan_uncovered_set_matches_atomics_gap() {
        let cov = coverage_from(RULES);
        let catalog = loaded_catalog();
        let plan = AtomicsPlan::build(&cov, &catalog, &[]);
        let cross_ref = CrossRef {
            ids: catalog.keys().cloned().collect(),
        };
        let report = CoverageReport::build(&cov, Some(&cross_ref), None, None);
        let gap = report.atomics.as_ref().unwrap();
        let plan_ids: Vec<String> = plan
            .techniques
            .iter()
            .map(|t| t.technique.clone())
            .collect();
        assert_eq!(plan.summary.atomics_total, gap.atomics_total);
        assert_eq!(
            plan.summary.uncovered_testable,
            gap.atomics_without_rule.len()
        );
        assert_eq!(plan_ids, gap.atomics_without_rule);
    }

    #[test]
    fn parent_covered_via_subtechnique_is_omitted() {
        let cov = coverage_from(RULES);
        let catalog = loaded_catalog();
        let plan = AtomicsPlan::build(&cov, &catalog, &[]);
        let ids: Vec<&str> = plan
            .techniques
            .iter()
            .map(|t| t.technique.as_str())
            .collect();
        assert!(!ids.contains(&"T1059"));
        assert!(!ids.contains(&"T1059.001"));
        assert!(ids.contains(&"T1566"));
        assert!(ids.contains(&"T1027"));
    }

    #[test]
    fn platform_filter_drops_techniques_with_no_matching_tests() {
        let cov = coverage_from(RULES);
        let catalog = loaded_catalog();
        let plan = AtomicsPlan::build(&cov, &catalog, &["linux".into()]);
        assert_eq!(plan.summary.platforms, vec!["linux".to_string()]);
        assert_eq!(plan.summary.uncovered_testable, 2); // T1027 + T1566, pre-filter
        assert_eq!(plan.techniques.len(), 1);
        assert_eq!(plan.techniques[0].technique, "T1566");
        assert_eq!(plan.techniques[0].tests.len(), 1);
        assert_eq!(plan.techniques[0].tests[0].name, "Phishing via curl");
    }

    #[test]
    fn invocations_and_guidless_entries() {
        let cov = coverage_from(RULES);
        let catalog = loaded_catalog();
        let plan = AtomicsPlan::build(&cov, &catalog, &[]);
        let t1566 = plan
            .techniques
            .iter()
            .find(|t| t.technique == "T1566")
            .unwrap();
        assert_eq!(t1566.invocation, "Invoke-AtomicTest T1566");
        assert_eq!(
            t1566.tactics,
            vec!["defense-evasion".to_string(), "execution".to_string()]
        );
        assert_eq!(t1566.tests.len(), 3);
        assert_eq!(
            t1566.tests[0].invocation,
            "Invoke-AtomicTest T1566 -TestGuids 33333333-3333-3333-3333-333333333333"
        );
        let guidless = t1566
            .tests
            .iter()
            .find(|t| t.name == "GUID-less phishing")
            .unwrap();
        assert_eq!(guidless.guid, None);
        assert_eq!(guidless.invocation, "Invoke-AtomicTest T1566");
    }
}
