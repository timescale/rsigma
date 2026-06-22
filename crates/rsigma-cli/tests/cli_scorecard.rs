//! Integration tests for `rsigma rule scorecard`: the golden JSON document and
//! markdown report, plus boundary and error paths (exit codes, `--fail-on`,
//! malformed/unreadable inputs, config-file layering, degradation when the
//! optional inputs are absent). The fusion join, verdict bands, and exposition
//! parser are unit-tested in the command module; these tests cover the
//! end-to-end CLI surface only and never touch the network.

mod common;

use std::path::{Path, PathBuf};

use common::{rsigma, temp_file};
use predicates::prelude::*;

const REPORT_GOLDEN: &str = include_str!("golden/scorecard_report.json");
const MARKDOWN_GOLDEN: &str = include_str!("golden/scorecard_report.md");

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/scorecard")
}

fn fixture(name: &str) -> String {
    fixtures().join(name).to_string_lossy().into_owned()
}

fn normalize_eol(s: &str) -> String {
    s.replace("\r\n", "\n")
}

#[test]
fn scorecard_full_inputs_matches_golden() {
    let output = rsigma()
        .args([
            "rule",
            "scorecard",
            "--backtest",
            &fixture("backtest.json"),
            "--coverage",
            &fixture("coverage.json"),
            "--metrics",
            &fixture("metrics.txt"),
            "--triage",
            &fixture("triage.json"),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let actual: serde_json::Value = serde_json::from_slice(&output).expect("stdout is valid JSON");
    let expected: serde_json::Value =
        serde_json::from_str(REPORT_GOLDEN).expect("golden is valid JSON");
    assert_eq!(actual, expected, "scorecard document drifted from golden");
}

#[test]
fn scorecard_markdown_report_matches_golden() {
    let report = tempfile::Builder::new().suffix(".md").tempfile().unwrap();
    rsigma()
        .args([
            "rule",
            "scorecard",
            "--backtest",
            &fixture("backtest.json"),
            "--coverage",
            &fixture("coverage.json"),
            "--metrics",
            &fixture("metrics.txt"),
            "--triage",
            &fixture("triage.json"),
            "--report",
            report.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    let actual = std::fs::read_to_string(report.path()).unwrap();
    assert_eq!(
        normalize_eol(&actual).trim_end(),
        normalize_eol(MARKDOWN_GOLDEN).trim_end(),
        "markdown report drifted from golden"
    );
}

#[test]
fn scorecard_required_inputs_only_succeeds() {
    // With only the two required JSON reports the scorecard still produces a
    // corpus-derived table.
    rsigma()
        .args([
            "rule",
            "scorecard",
            "--backtest",
            &fixture("backtest.json"),
            "--coverage",
            &fixture("coverage.json"),
            "--output-format",
            "table",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Detection scorecard"))
        .stdout(predicate::str::contains("Retire"));
}

#[test]
fn scorecard_metrics_absent_degrades_to_corpus_volume() {
    // Without --metrics the keep rule's volume is its corpus fires only (10),
    // not the production-enriched 110.
    let output = rsigma()
        .args([
            "rule",
            "scorecard",
            "--backtest",
            &fixture("backtest.json"),
            "--coverage",
            &fixture("coverage.json"),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let doc: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let keep = doc["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["rule_id"] == "k1")
        .unwrap();
    assert_eq!(keep["volume"], 10);
    assert!(keep.get("production_volume").is_none());
}

#[test]
fn scorecard_fail_on_retire_exits_one() {
    // The fixtures carry retire-grade rules, so --fail-on retire trips the gate.
    rsigma()
        .args([
            "rule",
            "scorecard",
            "--backtest",
            &fixture("backtest.json"),
            "--coverage",
            &fixture("coverage.json"),
            "--fail-on",
            "retire",
            "--output-format",
            "table",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "at or worse than --fail-on retire",
        ));
}

#[test]
fn scorecard_default_fail_on_none_is_clean_exit() {
    // Retire-grade rules present, but the default --fail-on none reports only.
    rsigma()
        .args([
            "rule",
            "scorecard",
            "--backtest",
            &fixture("backtest.json"),
            "--coverage",
            &fixture("coverage.json"),
        ])
        .assert()
        .success();
}

#[test]
fn scorecard_malformed_report_is_config_error() {
    let bad = temp_file(".json", "this is not json {");
    rsigma()
        .args([
            "rule",
            "scorecard",
            "--backtest",
            bad.path().to_str().unwrap(),
            "--coverage",
            &fixture("coverage.json"),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("could not parse backtest report"));
}

#[test]
fn scorecard_unreadable_input_is_input_error() {
    rsigma()
        .args([
            "rule",
            "scorecard",
            "--backtest",
            "/no/such/backtest/report.json",
            "--coverage",
            &fixture("coverage.json"),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("could not read"));
}

#[test]
fn scorecard_missing_required_flag_is_config_error() {
    rsigma()
        .args(["rule", "scorecard", "--coverage", &fixture("coverage.json")])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("no backtest report"));
}

#[test]
fn scorecard_bad_report_format_is_config_error() {
    // An unrecognized extension with no --report-format override is a flag error.
    let out = tempfile::Builder::new().suffix(".txt").tempfile().unwrap();
    rsigma()
        .args([
            "rule",
            "scorecard",
            "--backtest",
            &fixture("backtest.json"),
            "--coverage",
            &fixture("coverage.json"),
            "--report",
            out.path().to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("cannot determine report format"));
}

#[test]
fn scorecard_config_file_layering() {
    // fail_on comes from the config file; only --config and the two reports are
    // passed on the command line.
    let cfg = temp_file(".yaml", "scorecard:\n  fail_on: retire\n");
    rsigma()
        .args([
            "rule",
            "scorecard",
            "--backtest",
            &fixture("backtest.json"),
            "--coverage",
            &fixture("coverage.json"),
            "--config",
            cfg.path().to_str().unwrap(),
            "--output-format",
            "table",
        ])
        .assert()
        // fail_on retire from config + retire-grade rules -> exit 1.
        .code(1);
}

#[test]
fn scorecard_reads_reports_from_config() {
    // Both required reports come from the config file; only --config is passed.
    let cfg = temp_file(
        ".yaml",
        &format!(
            "scorecard:\n  backtest: {}\n  coverage: {}\n",
            fixture("backtest.json"),
            fixture("coverage.json"),
        ),
    );
    rsigma()
        .args([
            "rule",
            "scorecard",
            "--config",
            cfg.path().to_str().unwrap(),
            "--output-format",
            "table",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Detection scorecard"));
}

#[test]
fn scorecard_dry_run_prints_config_section() {
    rsigma()
        .args([
            "rule",
            "scorecard",
            "--backtest",
            &fixture("backtest.json"),
            "--coverage",
            &fixture("coverage.json"),
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("min_precision"));
}
