//! Integration tests for `rsigma rule backtest`: the golden JSON report and
//! JUnit XML, plus boundary and error paths (exit codes, per-file scoping,
//! correlation expectations, config-file layering). Per-rule diff and
//! expectations-parsing logic is unit-tested in the command module; these
//! tests cover the end-to-end CLI surface only.

mod common;

use std::path::{Path, PathBuf};

use common::{rsigma, temp_file};
use predicates::prelude::*;

const REPORT_GOLDEN: &str = include_str!("golden/backtest_report.json");
const JUNIT_GOLDEN: &str = include_str!("golden/backtest_junit.xml");

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/backtest")
}

fn fixture(name: &str) -> String {
    fixtures().join(name).to_string_lossy().into_owned()
}

/// Replace the volatile `duration_ms` value with 0 so the timing-free report
/// can be compared byte-for-byte against the committed golden.
fn normalize_duration(s: &str) -> String {
    s.lines()
        .map(|line| match line.find("\"duration_ms\":") {
            Some(idx) => format!("{}\"duration_ms\": 0", &line[..idx]),
            None => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn backtest_report_and_junit_match_golden() {
    let report = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    let junit = tempfile::Builder::new().suffix(".xml").tempfile().unwrap();

    rsigma()
        .args([
            "rule",
            "backtest",
            "--rules",
            &fixture("rules.yml"),
            "--corpus",
            &fixture("corpus"),
            "--expectations",
            &fixture("expectations.yml"),
            "--unexpected",
            "fail",
            "--report",
            report.path().to_str().unwrap(),
            "--junit",
            junit.path().to_str().unwrap(),
            "--output-format",
            "json",
        ])
        .assert()
        // A failed expectation (netstat exactly 0) yields exit code 1.
        .code(1);

    let actual_report = std::fs::read_to_string(report.path()).unwrap();
    assert_eq!(
        normalize_duration(&actual_report).trim_end(),
        REPORT_GOLDEN.trim_end(),
        "JSON report drifted from golden"
    );

    let actual_junit = std::fs::read_to_string(junit.path()).unwrap();
    assert_eq!(
        actual_junit.trim_end(),
        JUNIT_GOLDEN.trim_end(),
        "JUnit XML drifted from golden"
    );
}

#[test]
fn backtest_all_expectations_pass_is_exit_zero() {
    // whoami fires twice, netstat once; both satisfied, ping is unexpected but
    // the default policy is warn, so the run still succeeds.
    let exp = temp_file(
        ".yml",
        "expectations:\n  - rule: 11111111-1111-1111-1111-111111111111\n    at_least: 1\n  - rule: 22222222-2222-2222-2222-222222222222\n    at_least: 1\n",
    );
    rsigma()
        .args([
            "rule",
            "backtest",
            "--rules",
            &fixture("rules.yml"),
            "--corpus",
            &fixture("corpus"),
            "--expectations",
            exp.path().to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn backtest_unexpected_fail_policy_fails_the_run() {
    // Only whoami is expected; ping and netstat fire unexpectedly. Under the
    // fail policy that is exit code 1 even though the whoami expectation passes.
    let exp = temp_file(
        ".yml",
        "expectations:\n  - rule: 11111111-1111-1111-1111-111111111111\n    at_least: 1\n",
    );
    rsigma()
        .args([
            "rule",
            "backtest",
            "--rules",
            &fixture("rules.yml"),
            "--corpus",
            &fixture("corpus"),
            "--expectations",
            exp.path().to_str().unwrap(),
            "--unexpected",
            "fail",
        ])
        .assert()
        .code(1);
}

#[test]
fn backtest_per_file_scoping() {
    // whoami fires once in b.ndjson; scoped exactly:1 must pass even though the
    // corpus-wide count is 2.
    let exp = temp_file(
        ".yml",
        "expectations:\n  - rule: 11111111-1111-1111-1111-111111111111\n    corpus: b.ndjson\n    exactly: 1\n",
    );
    rsigma()
        .args([
            "rule",
            "backtest",
            "--rules",
            &fixture("rules.yml"),
            "--corpus",
            &fixture("corpus"),
            "--expectations",
            exp.path().to_str().unwrap(),
            "--unexpected",
            "ignore",
        ])
        .assert()
        .success();
}

#[test]
fn backtest_unknown_rule_in_expectations_is_config_error() {
    let exp = temp_file(
        ".yml",
        "expectations:\n  - rule: Nonexistent Rule\n    at_least: 1\n",
    );
    rsigma()
        .args([
            "rule",
            "backtest",
            "--rules",
            &fixture("rules.yml"),
            "--corpus",
            &fixture("corpus"),
            "--expectations",
            exp.path().to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("not in the loaded ruleset"));
}

#[test]
fn backtest_missing_corpus_path_is_config_error() {
    rsigma()
        .args([
            "rule",
            "backtest",
            "--rules",
            &fixture("rules.yml"),
            "--corpus",
            "/tmp/nonexistent_rsigma_corpus_dir",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("corpus path not found"));
}

#[test]
fn backtest_missing_rules_is_config_error() {
    rsigma()
        .args(["rule", "backtest", "--corpus", &fixture("corpus")])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("no rules path"));
}

#[test]
fn backtest_without_expectations_reports_stats_and_exits_zero() {
    // No expectations file: stats-only mode. Every rule fired, but nothing is
    // diffed and nothing is unexpected, so the run succeeds.
    rsigma()
        .args([
            "rule",
            "backtest",
            "--rules",
            &fixture("rules.yml"),
            "--corpus",
            &fixture("corpus"),
            "--output-format",
            "ndjson",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Whoami Execution"));
}

#[test]
fn backtest_correlation_rule_expectation() {
    let rules = temp_file(
        ".yml",
        r#"
title: Login Failure
id: 00000000-0000-0000-0000-0000000000a1
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        EventType: login_failure
    condition: selection
level: low
---
title: Brute Force
id: 00000000-0000-0000-0000-0000000000a2
correlation:
    type: event_count
    rules:
        - 00000000-0000-0000-0000-0000000000a1
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 3
level: high
"#,
    );
    let corpus = temp_file(
        ".ndjson",
        r#"{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:01Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:02Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:03Z"}
"#,
    );
    let exp = temp_file(
        ".yml",
        "expectations:\n  - rule: 00000000-0000-0000-0000-0000000000a2\n    at_least: 1\n",
    );
    rsigma()
        .args([
            "rule",
            "backtest",
            "--rules",
            rules.path().to_str().unwrap(),
            "--corpus",
            corpus.path().to_str().unwrap(),
            "--expectations",
            exp.path().to_str().unwrap(),
            "--unexpected",
            "ignore",
            "--output-format",
            "ndjson",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Brute Force"));
}

#[test]
fn backtest_config_file_layering() {
    // rules and corpus come from the config file; only --config is passed.
    let cfg = temp_file(
        ".yaml",
        &format!(
            "backtest:\n  rules: {}\n  corpus:\n    - {}\n",
            fixture("rules.yml"),
            fixture("corpus"),
        ),
    );
    rsigma()
        .args([
            "rule",
            "backtest",
            "--config",
            cfg.path().to_str().unwrap(),
            "--output-format",
            "ndjson",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Whoami Execution"));
}

#[test]
fn backtest_table_output_is_human_readable() {
    rsigma()
        .args([
            "rule",
            "backtest",
            "--rules",
            &fixture("rules.yml"),
            "--corpus",
            &fixture("corpus"),
            "--expectations",
            &fixture("expectations.yml"),
            "--output-format",
            "table",
        ])
        .assert()
        // netstat exactly:0 fails, so exit code 1 under the default warn policy.
        .code(1)
        .stdout(predicate::str::contains("Backtest summary"))
        .stdout(predicate::str::contains("PASS"))
        .stdout(predicate::str::contains("FAIL"));
}

#[cfg(feature = "evtx")]
#[test]
fn backtest_evtx_corpus() {
    // Reuse the runtime crate's committed EVTX fixture. A `.evtx` corpus path
    // routes through the feature-gated adapter.
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rsigma-runtime/tests/fixtures/security.evtx");
    let rule = temp_file(
        ".yml",
        r#"
title: Windows Logon
id: 00000000-0000-0000-0000-000000004624
logsource:
    product: windows
    service: security
detection:
    selection:
        Event.System.EventID: 4624
    condition: selection
level: medium
"#,
    );
    let exp = temp_file(
        ".yml",
        "expectations:\n  - rule: 00000000-0000-0000-0000-000000004624\n    at_least: 1\n",
    );
    rsigma()
        .args([
            "rule",
            "backtest",
            "--rules",
            rule.path().to_str().unwrap(),
            "--corpus",
            fixture.to_str().unwrap(),
            "--expectations",
            exp.path().to_str().unwrap(),
            "--unexpected",
            "ignore",
            "--output-format",
            "ndjson",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Windows Logon"));
}

#[test]
fn backtest_dry_run_prints_config() {
    rsigma()
        .args([
            "rule",
            "backtest",
            "--rules",
            &fixture("rules.yml"),
            "--corpus",
            &fixture("corpus"),
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("input_format"));
}
