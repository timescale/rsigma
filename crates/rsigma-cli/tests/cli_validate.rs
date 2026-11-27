//! Integration tests for the validate subcommand.

use crate::common;

use common::{PIPELINE_YAML, SIMPLE_RULE, rsigma, temp_file};
use predicates::prelude::*;

const SIMPLE_RULE_WINDASH: &str = r#"
title: Test Windash
id: 00000000-0000-0000-0000-000000000002
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|windash|contains: "-exec"
    condition: selection
level: medium
"#;

#[test]
fn validate_directory_with_valid_rules() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rule1.yml"), SIMPLE_RULE).unwrap();
    std::fs::write(dir.path().join("rule2.yml"), SIMPLE_RULE_WINDASH).unwrap();

    rsigma()
        .args(["rule", "validate", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Detection rules:"))
        .stdout(predicate::str::contains("Compiled OK:"));
}

#[test]
fn validate_directory_with_errors() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bad.yml"), "42").unwrap();

    rsigma()
        .args([
            "rule",
            "validate",
            dir.path().to_str().unwrap(),
            "--verbose",
        ])
        .assert()
        .stdout(predicate::str::contains("Parsed"));
}

#[test]
fn validate_single_file() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args(["rule", "validate", rule.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Detection rules:   1"))
        .stdout(predicate::str::contains("Compiled OK:       1"));
}

#[test]
fn validate_single_file_with_invalid_rule() {
    let rule = temp_file(
        ".yml",
        &SIMPLE_RULE_WINDASH.replace("CommandLine|windash|contains", "CommandLine|gt"),
    );
    rsigma()
        .args([
            "rule",
            "validate",
            rule.path().to_str().unwrap(),
            "--verbose",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("Parse errors:      1"))
        .stdout(predicate::str::contains("|gt"));
}

#[test]
fn validate_single_file_with_yaml_syntax_error() {
    let rule = temp_file(".yml", "title: [unclosed\n");
    let path = rule.path().to_str().unwrap();
    rsigma()
        .args(["rule", "validate", path, "--verbose"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("Parse errors:      1"))
        .stdout(predicate::str::contains(path));
}

#[test]
fn validate_nonexistent_directory() {
    rsigma()
        .args(["rule", "validate", "/tmp/nonexistent_rsigma_dir"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn validate_with_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rule.yml"), SIMPLE_RULE).unwrap();
    let pipeline = temp_file(".yml", PIPELINE_YAML);

    rsigma()
        .args([
            "rule",
            "validate",
            dir.path().to_str().unwrap(),
            "-p",
            pipeline.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Pipeline applied:"));
}

#[test]
fn validate_rejects_an_unknown_correlation_reference() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("correlation.yml"),
        r#"
title: Unknown Reference
correlation:
    type: event_count
    rules: [missing_rule]
    group-by: [User]
    timespan: 5m
    condition:
        gte: 2
"#,
    )
    .unwrap();

    rsigma()
        .args([
            "rule",
            "validate",
            dir.path().to_str().unwrap(),
            "--verbose",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "unknown rule reference: missing_rule",
        ));
}

fn validate_rules(yaml: &str) -> assert_cmd::assert::Assert {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rules.yml"), yaml).unwrap();
    rsigma()
        .args([
            "rule",
            "validate",
            dir.path().to_str().unwrap(),
            "--verbose",
        ])
        .assert()
}

const LOGIN_DETECTION: &str = r#"
logsource:
    category: test
    product: test
detection:
    selection:
        EventType: login
    condition: selection
"#;

fn correlation_on(rule_ref: &str) -> String {
    format!(
        "title: Many Logins\ncorrelation:\n    type: event_count\n    rules: [{rule_ref}]\n    group-by: [User]\n    timespan: 5m\n    condition:\n        gte: 2\n"
    )
}

#[test]
fn validate_rejects_a_reference_to_a_duplicate_rule_name() {
    let yaml = format!(
        "title: Login A\nname: login\n{LOGIN_DETECTION}---\ntitle: Login B\nname: login\n{LOGIN_DETECTION}---\n{}",
        correlation_on("login")
    );
    validate_rules(&yaml)
        .failure()
        .stdout(predicate::str::contains(
            "login: ambiguous rule reference matches 'Login A', 'Login B'",
        ));
}

#[test]
fn validate_rejects_a_reference_to_a_duplicate_rule_id() {
    let yaml = format!(
        "title: Login A\nid: login-id\n{LOGIN_DETECTION}---\ntitle: Login B\nid: login-id\n{LOGIN_DETECTION}---\n{}",
        correlation_on("login-id")
    );
    validate_rules(&yaml)
        .failure()
        .stdout(predicate::str::contains(
            "login-id: ambiguous rule reference matches 'Login A', 'Login B'",
        ));
}

#[test]
fn validate_rejects_a_reference_to_a_name_that_is_another_rules_id() {
    let yaml = format!(
        "title: Login A\nid: login\n{LOGIN_DETECTION}---\ntitle: Login B\nname: login\n{LOGIN_DETECTION}---\n{}",
        correlation_on("login")
    );
    validate_rules(&yaml)
        .failure()
        .stdout(predicate::str::contains(
            "login: ambiguous rule reference matches 'Login A', 'Login B'",
        ));
}

#[test]
fn validate_accepts_unreferenced_duplicate_identities() {
    let yaml = format!(
        "title: Login A\nid: login\nname: login\n{LOGIN_DETECTION}---\ntitle: Login B\nname: login\n{LOGIN_DETECTION}---\ntitle: Login C\nid: login\n{LOGIN_DETECTION}"
    );
    validate_rules(&yaml)
        .success()
        .stdout(predicate::str::contains("Compile errors:    0"));
}

#[test]
fn validate_accepts_a_reference_to_a_rule_whose_name_equals_its_own_id() {
    let yaml = format!(
        "title: Login A\nid: login\nname: login\n{LOGIN_DETECTION}---\n{}",
        correlation_on("login")
    );
    validate_rules(&yaml)
        .success()
        .stdout(predicate::str::contains("Compile errors:    0"));
}

fn warned_rule() -> tempfile::NamedTempFile {
    temp_file(
        ".yml",
        &SIMPLE_RULE.replace("status: test", "status: bogus"),
    )
}

#[test]
fn validate_parse_warning_passes_by_default() {
    let rule = warned_rule();
    rsigma()
        .args([
            "rule",
            "validate",
            rule.path().to_str().unwrap(),
            "--verbose",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Parse errors:      0"))
        .stdout(predicate::str::contains("Parse warnings:    1"))
        .stdout(predicate::str::contains(
            "Parse warnings:\n  - invalid status: 'bogus'",
        ))
        .stdout(predicate::str::contains("Compiled OK:       1"));
}

#[test]
fn validate_fail_level_warning_fails_on_parse_warning() {
    let rule = warned_rule();
    rsigma()
        .args([
            "rule",
            "validate",
            rule.path().to_str().unwrap(),
            "--fail-level",
            "warning",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("Parse warnings:    1"));
}

#[test]
fn validate_fail_level_warning_passes_a_clean_rule() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "rule",
            "validate",
            rule.path().to_str().unwrap(),
            "--fail-level",
            "warning",
        ])
        .assert()
        .success();
}

#[test]
fn validate_fail_level_rejects_info() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "rule",
            "validate",
            rule.path().to_str().unwrap(),
            "--fail-level",
            "info",
        ])
        .assert()
        .code(predicate::ne(0))
        .stderr(predicate::str::contains("invalid value 'info'"));
}

#[test]
fn validate_json_reports_parse_warnings_separately() {
    let rule = warned_rule();
    let output = rsigma()
        .args([
            "--output-format",
            "json",
            "rule",
            "validate",
            rule.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["parse_errors"], 0);
    assert_eq!(report["summary"]["parse_warnings"], 1);
    assert_eq!(report["parse_errors"], serde_json::json!([]));
    assert_eq!(
        report["parse_warnings"],
        serde_json::json!(["invalid status: 'bogus'"])
    );
}

#[test]
fn validate_ndjson_marks_parse_warning_rows() {
    let rule = warned_rule();
    let output = rsigma()
        .args([
            "--output-format",
            "ndjson",
            "rule",
            "validate",
            rule.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let rows: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["status"], "parse_warning");
    assert_eq!(rows[0]["errors"], "invalid status: 'bogus'");
}

#[test]
fn validate_rejects_an_undefined_condition_reference() {
    let rule = temp_file(
        ".yml",
        r#"
title: Missing Reference
correlation:
    type: temporal
    rules: [login]
    group-by: [User]
    timespan: 5m
    condition: login and not mfa
"#,
    );
    rsigma()
        .args([
            "rule",
            "validate",
            rule.path().to_str().unwrap(),
            "--verbose",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("Parse errors:      1"))
        .stdout(predicate::str::contains(
            "condition references 'mfa', which is not in correlation.rules",
        ));
}
