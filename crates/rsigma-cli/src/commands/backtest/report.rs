//! Backtest accumulation, expected-vs-actual diff, and report rendering.
//!
//! The accumulator tallies per-rule and per-corpus-file fire counts as events
//! stream through the engine. [`Report::build`] turns those tallies plus the
//! resolved expectations into a stable, serializable document: the expectation
//! diff, per-rule statistics, the set of unexpected fires (the false-positive
//! signal on a known-benign corpus), and a per-logsource rollup of those
//! unexpected fires.
//!
//! The document renders through the shared [`OutputCtx`] layer (table for a
//! TTY, `json` for the full document, `ndjson`/`csv`/`tsv` for per-rule rows)
//! and, optionally, to a hand-rolled JUnit XML file for CI annotation.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use rsigma_eval::EvaluationResult;
use rsigma_parser::{LogSource, SigmaCollection};
use serde::Serialize;

use super::expectations::{ResolvedExpectations, UnexpectedPolicy};
use crate::exit_code;
use crate::output::{
    DelimitedWriter, OutputCtx, OutputFormat, Painter, Tabular, render_json, render_ndjson,
};

/// Accumulator key for a result: the rule id when present, else its title.
/// Mirrors how detection and correlation results populate their header, so an
/// expectation resolved to the same key lines up with what fired.
pub(crate) fn result_key(result: &EvaluationResult) -> &str {
    result
        .header
        .rule_id
        .as_deref()
        .unwrap_or(&result.header.rule_title)
}

/// Compact logsource projection used throughout the report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct LogSourceView {
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
}

impl LogSourceView {
    fn from_logsource(ls: &LogSource) -> Option<Self> {
        if ls.category.is_none() && ls.product.is_none() && ls.service.is_none() {
            return None;
        }
        Some(Self {
            category: ls.category.clone(),
            product: ls.product.clone(),
            service: ls.service.clone(),
        })
    }

    /// A stable one-line label (`product/category/service`) used for grouping
    /// and table cells. `(none)` when no component is set (e.g. correlations).
    fn label(view: &Option<Self>) -> String {
        let Some(v) = view else {
            return "(none)".to_string();
        };
        let parts: Vec<&str> = [
            v.product.as_deref(),
            v.category.as_deref(),
            v.service.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect();
        if parts.is_empty() {
            "(none)".to_string()
        } else {
            parts.join("/")
        }
    }
}

/// Per-rule metadata pulled from the loaded collection (the engine result does
/// not carry logsource, so it is resolved here by key).
struct RuleMeta {
    id: Option<String>,
    title: String,
    level: Option<String>,
    logsource: Option<LogSourceView>,
}

fn collect_rule_meta(collection: &SigmaCollection) -> BTreeMap<String, RuleMeta> {
    let mut meta = BTreeMap::new();
    for rule in &collection.rules {
        let key = rule.id.clone().unwrap_or_else(|| rule.title.clone());
        meta.insert(
            key,
            RuleMeta {
                id: rule.id.clone(),
                title: rule.title.clone(),
                level: rule.level.map(|l| l.as_str().to_string()),
                logsource: LogSourceView::from_logsource(&rule.logsource),
            },
        );
    }
    for corr in &collection.correlations {
        let key = corr.id.clone().unwrap_or_else(|| corr.title.clone());
        meta.insert(
            key,
            RuleMeta {
                id: corr.id.clone(),
                title: corr.title.clone(),
                level: corr.level.map(|l| l.as_str().to_string()),
                // Correlation rules have no logsource of their own.
                logsource: None,
            },
        );
    }
    meta
}

/// Running tally of fires, keyed by rule and by (rule, corpus file).
pub(crate) struct Accumulator {
    total: HashMap<String, u64>,
    by_file: HashMap<String, BTreeMap<String, u64>>,
    events_processed: u64,
    corpus_files: u64,
}

impl Accumulator {
    pub(crate) fn new() -> Self {
        Self {
            total: HashMap::new(),
            by_file: HashMap::new(),
            events_processed: 0,
            corpus_files: 0,
        }
    }

    /// Record one fire of `key` observed while processing `file`.
    pub(crate) fn record(&mut self, key: &str, file: &str) {
        *self.total.entry(key.to_string()).or_default() += 1;
        *self
            .by_file
            .entry(key.to_string())
            .or_default()
            .entry(file.to_string())
            .or_default() += 1;
    }

    pub(crate) fn add_events(&mut self, n: u64) {
        self.events_processed += n;
    }

    pub(crate) fn note_file(&mut self) {
        self.corpus_files += 1;
    }
}

// ---------------------------------------------------------------------------
// Serializable report document
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct Summary {
    corpus_files: u64,
    events_processed: u64,
    rules_loaded: u64,
    expectations_total: u64,
    expectations_passed: u64,
    expectations_failed: u64,
    unexpected_rules: u64,
    unexpected_fires: u64,
    unexpected_policy: String,
    duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ExpectationResult {
    /// The original reference (id or title) from the file.
    rule: String,
    rule_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    bound: String,
    actual: u64,
    pass: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RuleStat {
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<String>,
    rule_title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logsource: Option<LogSourceView>,
    fires: u64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    by_file: BTreeMap<String, u64>,
}

const RULE_HEADERS: &[&str] = &["RULE_ID", "TITLE", "LEVEL", "LOGSOURCE", "FIRES"];

impl Tabular for RuleStat {
    fn headers() -> &'static [&'static str] {
        RULE_HEADERS
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.rule_id.clone().unwrap_or_else(|| "-".to_string()),
            self.rule_title.clone(),
            self.level.clone().unwrap_or_else(|| "-".to_string()),
            LogSourceView::label(&self.logsource),
            self.fires.to_string(),
        ]
    }
}

#[derive(Debug, Clone, Serialize)]
struct UnexpectedStat {
    rule_key: String,
    rule_title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logsource: Option<LogSourceView>,
    fires: u64,
}

#[derive(Debug, Clone, Serialize)]
struct LogSourceRollup {
    logsource: String,
    unexpected_fires: u64,
    rules: Vec<String>,
}

/// The full backtest report document.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Report {
    summary: Summary,
    expectations: Vec<ExpectationResult>,
    rules: Vec<RuleStat>,
    unexpected: Vec<UnexpectedStat>,
    by_logsource: Vec<LogSourceRollup>,
    /// Effective policy, retained for exit-code and rendering decisions; not
    /// part of the serialized shape (it appears as `summary.unexpected_policy`).
    #[serde(skip)]
    policy: UnexpectedPolicy,
}

impl Report {
    /// Build the report from the accumulated tallies and resolved expectations.
    pub(crate) fn build(
        acc: Accumulator,
        collection: &SigmaCollection,
        resolved: Option<&ResolvedExpectations>,
        policy: UnexpectedPolicy,
        duration_ms: u64,
    ) -> Self {
        let meta = collect_rule_meta(collection);
        let rules_loaded = (collection.rules.len() + collection.correlations.len()) as u64;

        let empty = Vec::new();
        let expectations_in = resolved.map(|r| &r.expectations).unwrap_or(&empty);
        let has_expectations = !expectations_in.is_empty();

        // Expectation diff (in file order for stable output).
        let mut expectations = Vec::with_capacity(expectations_in.len());
        let mut expected_keys: HashSet<&str> = HashSet::new();
        let mut passed = 0u64;
        for exp in expectations_in {
            expected_keys.insert(exp.rule_key.as_str());
            let actual = match &exp.corpus {
                Some(scope) => acc
                    .by_file
                    .get(&exp.rule_key)
                    .and_then(|m| m.get(scope))
                    .copied()
                    .unwrap_or(0),
                None => acc.total.get(&exp.rule_key).copied().unwrap_or(0),
            };
            let pass = exp.bound.satisfied_by(actual);
            if pass {
                passed += 1;
            }
            expectations.push(ExpectationResult {
                rule: exp.reference.clone(),
                rule_key: exp.rule_key.clone(),
                scope: exp.corpus.clone(),
                bound: exp.bound.describe(),
                actual,
                pass,
            });
        }
        let failed = expectations.len() as u64 - passed;

        // Unexpected fires only make sense when there is something to diff:
        // with no expectations every fire would otherwise look "uncovered".
        let mut unexpected = Vec::new();
        if has_expectations {
            let mut fired: Vec<(&String, &u64)> = acc
                .total
                .iter()
                .filter(|(key, fires)| **fires > 0 && !expected_keys.contains(key.as_str()))
                .collect();
            fired.sort_by(|a, b| a.0.cmp(b.0));
            for (key, fires) in fired {
                let (title, level, logsource) = match meta.get(key) {
                    Some(m) => (m.title.clone(), m.level.clone(), m.logsource.clone()),
                    None => (key.clone(), None, None),
                };
                unexpected.push(UnexpectedStat {
                    rule_key: key.clone(),
                    rule_title: title,
                    level,
                    logsource,
                    fires: *fires,
                });
            }
        }
        let unexpected_rules = unexpected.len() as u64;
        let unexpected_fires: u64 = unexpected.iter().map(|u| u.fires).sum();

        // Per-rule stats: every rule that fired plus every rule referenced by
        // an expectation (so an asserted-but-silent rule still appears).
        let mut keys: BTreeSet<&str> = BTreeSet::new();
        for (key, fires) in &acc.total {
            if *fires > 0 {
                keys.insert(key.as_str());
            }
        }
        for key in &expected_keys {
            keys.insert(key);
        }
        let mut rules = Vec::with_capacity(keys.len());
        for key in keys {
            let by_file = acc.by_file.get(key).cloned().unwrap_or_default();
            let fires = acc.total.get(key).copied().unwrap_or(0);
            let stat = match meta.get(key) {
                Some(m) => RuleStat {
                    rule_id: m.id.clone(),
                    rule_title: m.title.clone(),
                    level: m.level.clone(),
                    logsource: m.logsource.clone(),
                    fires,
                    by_file,
                },
                None => RuleStat {
                    rule_id: None,
                    rule_title: key.to_string(),
                    level: None,
                    logsource: None,
                    fires,
                    by_file,
                },
            };
            rules.push(stat);
        }

        let by_logsource = rollup_by_logsource(&unexpected);

        let summary = Summary {
            corpus_files: acc.corpus_files,
            events_processed: acc.events_processed,
            rules_loaded,
            expectations_total: expectations.len() as u64,
            expectations_passed: passed,
            expectations_failed: failed,
            unexpected_rules,
            unexpected_fires,
            unexpected_policy: policy.as_str().to_string(),
            duration_ms,
        };

        Report {
            summary,
            expectations,
            rules,
            unexpected,
            by_logsource,
            policy,
        }
    }

    /// House exit code: findings (1) on any failed expectation, or on
    /// unexpected fires under the `fail` policy; success (0) otherwise.
    pub(crate) fn exit_code(&self) -> i32 {
        if self.summary.expectations_failed > 0 {
            return exit_code::FINDINGS;
        }
        if self.policy == UnexpectedPolicy::Fail && self.summary.unexpected_rules > 0 {
            return exit_code::FINDINGS;
        }
        exit_code::SUCCESS
    }

    /// Render to stdout in the selected format, plus optional `--report` JSON
    /// and `--junit` XML side files.
    pub(crate) fn render(
        &self,
        ctx: &OutputCtx,
        report_path: Option<&Path>,
        junit_path: Option<&Path>,
    ) {
        if let Some(path) = report_path
            && let Err(e) = write_string_file(path, &self.to_pretty_json())
        {
            eprintln!("Failed to write report to {}: {e}", path.display());
        }

        match ctx.format {
            OutputFormat::Json => render_json(self, ctx.pretty_json()),
            OutputFormat::Ndjson => {
                for rule in &self.rules {
                    render_ndjson(rule);
                }
            }
            OutputFormat::Csv => self.render_delimited(','),
            OutputFormat::Tsv => self.render_delimited('\t'),
            OutputFormat::Table => self.render_human(ctx),
        }

        if let Some(path) = junit_path
            && let Err(e) = write_string_file(path, &self.to_junit_xml())
        {
            eprintln!("Failed to write JUnit report to {}: {e}", path.display());
        }

        // For machine formats the human summary is not on stdout, so emit a
        // one-line recap on stderr (the table view already shows it).
        if ctx.format != OutputFormat::Table && ctx.show_stats() {
            eprintln!("{}", self.stderr_summary());
        }
    }

    fn render_delimited(&self, sep: char) {
        let mut writer = DelimitedWriter::new(sep, RuleStat::headers());
        for rule in &self.rules {
            writer.push(&rule.row());
        }
    }

    fn stderr_summary(&self) -> String {
        let s = &self.summary;
        format!(
            "Backtest: {} corpus files, {} events, {}/{} expectations passed, \
             {} unexpected fires across {} rules (policy: {}).",
            s.corpus_files,
            s.events_processed,
            s.expectations_passed,
            s.expectations_total,
            s.unexpected_fires,
            s.unexpected_rules,
            s.unexpected_policy,
        )
    }

    fn to_pretty_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    // -- Human (table) rendering --------------------------------------------

    fn render_human(&self, ctx: &OutputCtx) {
        let p = Painter::new(ctx.color);
        let s = &self.summary;

        println!("{}", p.bold("Backtest summary"));
        println!("  corpus files:  {}", s.corpus_files);
        println!("  events:        {}", s.events_processed);
        println!("  rules loaded:  {}", s.rules_loaded);
        println!(
            "  expectations:  {} passed, {} failed",
            s.expectations_passed, s.expectations_failed
        );
        if self.policy != UnexpectedPolicy::Ignore {
            println!(
                "  unexpected:    {} rules, {} fires (policy: {})",
                s.unexpected_rules, s.unexpected_fires, s.unexpected_policy
            );
        }

        if !self.expectations.is_empty() {
            println!("\n{}", p.bold("Expectations"));
            for e in &self.expectations {
                let tag = if e.pass {
                    p.green_bold("PASS")
                } else {
                    p.red_bold("FAIL")
                };
                let scope = match &e.scope {
                    Some(s) => format!(" [{s}]"),
                    None => String::new(),
                };
                println!(
                    "  {tag}  {}{scope}  expected {}, got {}",
                    e.rule, e.bound, e.actual
                );
            }
        }

        if !self.rules.is_empty() {
            println!("\n{}", p.bold("Rule fires"));
            crate::output::render_table(&self.rules);
        }

        if self.policy != UnexpectedPolicy::Ignore && !self.unexpected.is_empty() {
            println!("\n{}", p.bold("Unexpected fires"));
            for u in &self.unexpected {
                println!(
                    "  {}  {} ({} fires)",
                    p.yellow(&u.rule_title),
                    LogSourceView::label(&u.logsource),
                    u.fires
                );
            }

            if !self.by_logsource.is_empty() {
                println!("\n{}", p.bold("Unexpected fires by logsource"));
                for r in &self.by_logsource {
                    println!("  {}  {} fires", r.logsource, r.unexpected_fires);
                }
            }
        }
    }

    // -- JUnit XML rendering -------------------------------------------------

    /// Render a JUnit report: one test case per expectation, plus one per
    /// unexpected-firing rule when the policy is `fail`. The shape is fixed and
    /// hand-rolled (no new dependency), matching the repo's `DelimitedWriter`
    /// precedent. `time` attributes are intentionally omitted so the output is
    /// deterministic.
    fn to_junit_xml(&self) -> String {
        struct Case {
            name: String,
            classname: &'static str,
            failure: Option<String>,
        }

        let mut cases: Vec<Case> = Vec::new();
        for e in &self.expectations {
            let name = match &e.scope {
                Some(s) => format!("{} [{}]", e.rule, s),
                None => e.rule.clone(),
            };
            let failure = (!e.pass).then(|| format!("expected {}, got {}", e.bound, e.actual));
            cases.push(Case {
                name,
                classname: "rsigma.backtest.expectations",
                failure,
            });
        }
        if self.policy == UnexpectedPolicy::Fail {
            for u in &self.unexpected {
                cases.push(Case {
                    name: u.rule_title.clone(),
                    classname: "rsigma.backtest.unexpected",
                    failure: Some(format!(
                        "unexpected {} fires with no covering expectation",
                        u.fires
                    )),
                });
            }
        }

        let total = cases.len();
        let failures = cases.iter().filter(|c| c.failure.is_some()).count();

        let mut out = String::new();
        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str(&format!(
            "<testsuites tests=\"{total}\" failures=\"{failures}\">\n"
        ));
        out.push_str(&format!(
            "  <testsuite name=\"rsigma backtest\" tests=\"{total}\" failures=\"{failures}\">\n"
        ));
        for c in &cases {
            let name = xml_escape(&c.name);
            match &c.failure {
                None => out.push_str(&format!(
                    "    <testcase name=\"{name}\" classname=\"{}\"/>\n",
                    c.classname
                )),
                Some(msg) => {
                    let msg = xml_escape(msg);
                    out.push_str(&format!(
                        "    <testcase name=\"{name}\" classname=\"{}\">\n",
                        c.classname
                    ));
                    out.push_str(&format!(
                        "      <failure message=\"{msg}\">{msg}</failure>\n"
                    ));
                    out.push_str("    </testcase>\n");
                }
            }
        }
        out.push_str("  </testsuite>\n");
        out.push_str("</testsuites>\n");
        out
    }
}

/// Group unexpected fires by their rule logsource, the per-logsource
/// false-positive-density view.
fn rollup_by_logsource(unexpected: &[UnexpectedStat]) -> Vec<LogSourceRollup> {
    let mut groups: BTreeMap<String, (u64, Vec<String>)> = BTreeMap::new();
    for u in unexpected {
        let label = LogSourceView::label(&u.logsource);
        let entry = groups.entry(label).or_default();
        entry.0 += u.fires;
        entry.1.push(u.rule_key.clone());
    }
    groups
        .into_iter()
        .map(|(logsource, (unexpected_fires, mut rules))| {
            rules.sort();
            LogSourceRollup {
                logsource,
                unexpected_fires,
                rules,
            }
        })
        .collect()
}

/// Escape the five XML predefined entities for use in element text and
/// double-quoted attribute values alike, and drop characters that are not
/// legal in XML 1.0 (the C0 control range except tab, LF, and CR). Rule titles
/// are operator-controlled, so this keeps a stray control byte from producing
/// a report a strict XML parser would reject.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Legal XML 1.0 control chars are kept; the rest of C0 is dropped.
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 => {}
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
    use crate::commands::backtest::expectations::{Bound, Expectation};

    fn rules() -> SigmaCollection {
        let yaml = r#"
title: Whoami
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\whoami.exe'
    condition: selection
level: low
---
title: Netstat
id: 22222222-2222-2222-2222-222222222222
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\netstat.exe'
    condition: selection
level: informational
"#;
        rsigma_parser::parse_sigma_yaml(yaml).expect("rules parse")
    }

    fn resolved(exps: Vec<Expectation>, policy: Option<UnexpectedPolicy>) -> ResolvedExpectations {
        ResolvedExpectations {
            file_default_policy: policy,
            expectations: exps,
        }
    }

    fn exp(key: &str, scope: Option<&str>, bound: Bound) -> Expectation {
        Expectation {
            reference: key.to_string(),
            rule_key: key.to_string(),
            corpus: scope.map(str::to_string),
            bound,
        }
    }

    #[test]
    fn expectation_pass_and_fail() {
        let mut acc = Accumulator::new();
        acc.note_file();
        acc.add_events(3);
        acc.record("11111111-1111-1111-1111-111111111111", "a.ndjson");
        acc.record("11111111-1111-1111-1111-111111111111", "a.ndjson");

        let r = resolved(
            vec![
                exp(
                    "11111111-1111-1111-1111-111111111111",
                    None,
                    Bound::Range {
                        at_least: Some(1),
                        at_most: None,
                    },
                ),
                exp(
                    "22222222-2222-2222-2222-222222222222",
                    None,
                    Bound::Range {
                        at_least: Some(1),
                        at_most: None,
                    },
                ),
            ],
            None,
        );
        let report = Report::build(acc, &rules(), Some(&r), UnexpectedPolicy::Warn, 0);
        assert_eq!(report.summary.expectations_passed, 1);
        assert_eq!(report.summary.expectations_failed, 1);
        assert_eq!(report.exit_code(), exit_code::FINDINGS);
    }

    #[test]
    fn scoped_expectation_counts_one_file() {
        let mut acc = Accumulator::new();
        acc.record("11111111-1111-1111-1111-111111111111", "a.ndjson");
        acc.record("11111111-1111-1111-1111-111111111111", "b.ndjson");

        let r = resolved(
            vec![exp(
                "11111111-1111-1111-1111-111111111111",
                Some("a.ndjson"),
                Bound::Exactly(1),
            )],
            None,
        );
        let report = Report::build(acc, &rules(), Some(&r), UnexpectedPolicy::Warn, 0);
        assert_eq!(report.summary.expectations_passed, 1);
        assert_eq!(report.expectations[0].actual, 1);
    }

    #[test]
    fn unexpected_fire_under_fail_policy_sets_exit_code() {
        let mut acc = Accumulator::new();
        // Netstat fires but only Whoami is expected.
        acc.record("22222222-2222-2222-2222-222222222222", "a.ndjson");
        let r = resolved(
            vec![exp(
                "11111111-1111-1111-1111-111111111111",
                None,
                Bound::Exactly(0),
            )],
            None,
        );
        let report = Report::build(acc, &rules(), Some(&r), UnexpectedPolicy::Fail, 0);
        assert_eq!(report.summary.unexpected_rules, 1);
        assert_eq!(report.summary.unexpected_fires, 1);
        assert_eq!(report.exit_code(), exit_code::FINDINGS);
    }

    #[test]
    fn unexpected_fire_under_warn_policy_is_clean_exit() {
        let mut acc = Accumulator::new();
        acc.record("22222222-2222-2222-2222-222222222222", "a.ndjson");
        let r = resolved(
            vec![exp(
                "11111111-1111-1111-1111-111111111111",
                None,
                Bound::Exactly(0),
            )],
            None,
        );
        let report = Report::build(acc, &rules(), Some(&r), UnexpectedPolicy::Warn, 0);
        assert_eq!(report.summary.unexpected_rules, 1);
        assert_eq!(report.exit_code(), exit_code::SUCCESS);
    }

    #[test]
    fn no_expectations_means_no_unexpected_and_clean_exit() {
        let mut acc = Accumulator::new();
        acc.record("22222222-2222-2222-2222-222222222222", "a.ndjson");
        let report = Report::build(acc, &rules(), None, UnexpectedPolicy::Fail, 0);
        assert_eq!(report.summary.unexpected_rules, 0);
        assert_eq!(report.exit_code(), exit_code::SUCCESS);
        // The fired rule still shows up in per-rule stats.
        assert_eq!(report.rules.len(), 1);
        assert_eq!(report.rules[0].fires, 1);
    }

    #[test]
    fn junit_escapes_and_counts_failures() {
        let acc = Accumulator::new();
        let r = resolved(
            vec![exp(
                "22222222-2222-2222-2222-222222222222",
                None,
                Bound::Range {
                    at_least: Some(1),
                    at_most: None,
                },
            )],
            None,
        );
        let report = Report::build(acc, &rules(), Some(&r), UnexpectedPolicy::Warn, 0);
        let xml = report.to_junit_xml();
        assert!(xml.contains("failures=\"1\""));
        assert!(xml.contains("<failure"));
    }

    #[test]
    fn junit_escapes_special_characters() {
        assert_eq!(
            xml_escape(r#"a & b < c > "d" 'e'"#),
            "a &amp; b &lt; c &gt; &quot;d&quot; &apos;e&apos;"
        );
    }

    #[test]
    fn junit_drops_invalid_xml_control_chars_but_keeps_tab_nl_cr() {
        // A NUL and a vertical tab are illegal in XML 1.0 and are dropped;
        // tab/newline/carriage-return are legal and preserved.
        assert_eq!(xml_escape("a\u{0}b\u{0B}c\td\ne"), "abc\td\ne");
    }
}
