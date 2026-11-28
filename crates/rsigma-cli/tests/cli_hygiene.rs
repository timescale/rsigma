//! Integration tests for `rsigma rule hygiene`: the golden JSON document plus
//! boundary and error paths (output formats, `--fail-on` exit codes, the
//! `--report` file, config-file layering, and unreadable inputs). The signal
//! classifiers, the metrics parser, and the outlier test are unit-tested in the
//! command module and the shared modules; these tests cover the end-to-end CLI
//! surface only and never touch the network.

use crate::common;

use std::path::{Path, PathBuf};

use common::{rsigma, temp_file};
use predicates::prelude::*;

const REPORT_GOLDEN: &str = include_str!("golden/hygiene_report.json");

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hygiene")
}

fn fixture(name: &str) -> String {
    fixtures().join(name).to_string_lossy().into_owned()
}

#[test]
fn hygiene_full_inputs_matches_golden() {
    let output = rsigma()
        .args([
            "rule",
            "hygiene",
            "-r",
            &fixture("rules.yml"),
            "--metrics",
            &fixture("metrics.txt"),
            "--fields",
            &fixture("fields.json"),
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
    assert_eq!(actual, expected, "hygiene document drifted from golden");
}

#[test]
fn hygiene_static_signals_need_only_rules() {
    // With no metrics or fields, the static signals (untagged, no-owner,
    // incomplete-ads, deprecated) still report; silence/noisy/broken-fields do
    // not appear because their sources are absent.
    let output = rsigma()
        .args([
            "rule",
            "hygiene",
            "-r",
            &fixture("rules.yml"),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let doc: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(doc["summary"]["never_fired"], 0);
    assert_eq!(doc["summary"]["noisy"], 0);
    assert_eq!(doc["summary"]["broken_coverage"], 0);
    assert_eq!(doc["summary"]["metrics_source"], false);
    assert_eq!(doc["untagged"][0], "Delta Untagged Orphan");
    assert_eq!(doc["stale_status"][0], "Foxtrot Deprecated");
}

#[test]
fn hygiene_corpus_replay_is_offline_fire_source() {
    // Replaying a corpus that fires only Alpha and Bravo leaves the other rules
    // silent, with no Prometheus source. The corpus directory is walked.
    let output = rsigma()
        .args([
            "rule",
            "hygiene",
            "-r",
            &fixture("rules.yml"),
            "--corpus",
            &fixture("corpus"),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let doc: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(doc["summary"]["metrics_source"], true);
    let silent: Vec<&str> = doc["never_fired"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(silent.contains(&"Charlie Quiet"));
    // Alpha and Bravo fired in the corpus, so they are not silent.
    assert!(!silent.contains(&"Alpha Clean"));
    assert!(!silent.contains(&"Bravo Noisy"));
}

#[test]
fn hygiene_corpus_replay_counts_correlation_referenced_rules() {
    let rules = temp_file(
        ".yml",
        r#"
title: Login Failure
name: login_failure
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
name: brute_force
correlation:
    type: event_count
    rules:
        - login_failure
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: high
"#,
    );
    let corpus = temp_file(
        ".ndjson",
        r#"{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:01Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:02Z"}
"#,
    );
    let output = rsigma()
        .args([
            "rule",
            "hygiene",
            "-r",
            rules.path().to_str().unwrap(),
            "--corpus",
            corpus.path().to_str().unwrap(),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let doc: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(doc["summary"]["metrics_source"], true);
    let silent: Vec<&str> = doc["never_fired"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(!silent.contains(&"Login Failure"), "silent: {silent:?}");
    assert!(!silent.contains(&"Brute Force"), "silent: {silent:?}");
}

#[test]
fn hygiene_corpus_missing_path_is_config_error() {
    rsigma()
        .args([
            "rule",
            "hygiene",
            "-r",
            &fixture("rules.yml"),
            "--corpus",
            "/no/such/corpus",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("corpus path not found"));
}

#[test]
fn hygiene_empty_corpus_dir_is_config_error() {
    // An empty corpus directory must not silently mark every rule silent; it is
    // a configuration error so `--fail-on silent` cannot trip on a non-run.
    let dir = tempfile::tempdir().unwrap();
    rsigma()
        .args([
            "rule",
            "hygiene",
            "-r",
            &fixture("rules.yml"),
            "--corpus",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("no corpus files found"));
}

#[test]
fn hygiene_fail_on_silent_exits_one() {
    rsigma()
        .args([
            "rule",
            "hygiene",
            "-r",
            &fixture("rules.yml"),
            "--metrics",
            &fixture("metrics.txt"),
            "--fail-on",
            "silent",
            "--output-format",
            "table",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("--fail-on policy matched"));
}

#[test]
fn hygiene_fail_on_unmatched_condition_is_clean_exit() {
    // No correlation rules and every rule has a tag or owner gap only; a
    // condition that matches nothing must not fail. `broken-fields` needs the
    // fields snapshot, which is omitted here, so nothing is broken.
    rsigma()
        .args([
            "rule",
            "hygiene",
            "-r",
            &fixture("rules.yml"),
            "--metrics",
            &fixture("metrics.txt"),
            "--fail-on",
            "broken-fields",
        ])
        .assert()
        .success();
}

#[test]
fn hygiene_default_no_fail_on_is_clean_exit() {
    // Findings present, but with no --fail-on the command reports only.
    rsigma()
        .args([
            "rule",
            "hygiene",
            "-r",
            &fixture("rules.yml"),
            "--metrics",
            &fixture("metrics.txt"),
            "--output-format",
            "table",
        ])
        .assert()
        .success();
}

#[test]
fn hygiene_report_file_is_written() {
    let report = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    rsigma()
        .args([
            "rule",
            "hygiene",
            "-r",
            &fixture("rules.yml"),
            "--metrics",
            &fixture("metrics.txt"),
            "--fields",
            &fixture("fields.json"),
            "--report",
            report.path().to_str().unwrap(),
            "--output-format",
            "table",
        ])
        .assert()
        .success();
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(report.path()).unwrap())
            .expect("report file is valid JSON");
    let expected: serde_json::Value = serde_json::from_str(REPORT_GOLDEN).unwrap();
    assert_eq!(written, expected, "report file drifted from golden");
}

#[test]
fn hygiene_csv_emits_flagged_rows() {
    rsigma()
        .args([
            "rule",
            "hygiene",
            "-r",
            &fixture("rules.yml"),
            "--metrics",
            &fixture("metrics.txt"),
            "--output-format",
            "csv",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("RULE,KIND,SIGNALS"))
        .stdout(predicate::str::contains("Bravo Noisy,detection,noisy"));
}

#[test]
fn hygiene_invalid_fail_on_is_config_error() {
    rsigma()
        .args([
            "rule",
            "hygiene",
            "-r",
            &fixture("rules.yml"),
            "--fail-on",
            "bogus",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("invalid --fail-on"));
}

#[test]
fn hygiene_invalid_silent_threshold_is_config_error() {
    rsigma()
        .args([
            "rule",
            "hygiene",
            "-r",
            &fixture("rules.yml"),
            "--silent-threshold",
            "soon",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("invalid --silent-threshold"));
}

#[test]
fn hygiene_no_rules_is_config_error() {
    rsigma()
        .args(["rule", "hygiene"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("no rules path"));
}

#[test]
fn hygiene_unreadable_metrics_is_config_error() {
    rsigma()
        .args([
            "rule",
            "hygiene",
            "-r",
            &fixture("rules.yml"),
            "--metrics",
            "/no/such/metrics.txt",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("could not read metrics"));
}

#[test]
fn hygiene_config_file_layering() {
    // The fail-on policy and the rules path both come from the config file;
    // only --config is passed on the command line.
    let cfg = temp_file(
        ".yaml",
        &format!(
            "hygiene:\n  rules:\n    - {}\n  metrics: {}\n  fail_on:\n    - silent\n",
            fixture("rules.yml"),
            fixture("metrics.txt"),
        ),
    );
    rsigma()
        .args([
            "rule",
            "hygiene",
            "--config",
            cfg.path().to_str().unwrap(),
            "--output-format",
            "table",
        ])
        .assert()
        // silent rule present + fail_on silent from config -> exit 1.
        .code(1);
}

#[test]
fn hygiene_dry_run_prints_config_section() {
    rsigma()
        .args(["rule", "hygiene", "-r", &fixture("rules.yml"), "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("silent_threshold"));
}
