//! Integration tests for the eval subcommand (detection, pipeline,
//! jq/jsonpath, correlation, filter, timestamp) and CLI edge cases.

mod common;

use common::{PIPELINE_YAML, SIMPLE_RULE, rsigma, temp_file};
use predicates::prelude::*;

/// Multi-document YAML: a detection rule + an event_count correlation.
const CORRELATION_RULES: &str = r#"
title: Detection
id: 00000000-0000-0000-0000-000000000010
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
correlation:
    type: event_count
    rules:
        - 00000000-0000-0000-0000-000000000010
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 3
level: high
"#;

const FILTER_RULES: &str = r#"
title: Base Rule
id: 00000000-0000-0000-0000-000000000020
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        TargetFilename|endswith: ".exe"
    condition: selection
level: medium
---
title: Filter FP
logsource:
    category: test
    product: test
filter:
    rules:
        - 00000000-0000-0000-0000-000000000020
    selection:
        TargetFilename|endswith: "\\trusted.exe"
    condition: not selection
"#;

// ---------------------------------------------------------------------------
// eval subcommand — detection-only
// ---------------------------------------------------------------------------

#[test]
fn eval_single_event_match() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "download malware.exe"}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Test Rule"));
}

#[test]
fn eval_single_event_no_match() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "notepad.exe"}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("No matches"));
}

#[test]
fn eval_invalid_json_event() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            "{not valid json}",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid JSON"));
}

#[test]
fn eval_ndjson_stdin() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let events = r#"{"CommandLine": "run malware.exe"}
{"CommandLine": "notepad.exe"}
{"CommandLine": "inject malware payload"}
"#;
    rsigma()
        .args(["eval", "--rules", rule.path().to_str().unwrap()])
        .write_stdin(events)
        .assert()
        .success()
        .stderr(predicate::str::contains("2 matches"));
}

#[test]
fn eval_ndjson_skips_blank_lines() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let events = r#"{"CommandLine": "malware"}

{"CommandLine": "clean"}

"#;
    rsigma()
        .args(["eval", "--rules", rule.path().to_str().unwrap()])
        .write_stdin(events)
        .assert()
        .success()
        .stderr(predicate::str::contains("Processed"));
}

#[test]
fn eval_at_file_single_event() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let events = temp_file(".json", r#"{"CommandLine": "download malware.exe"}"#);
    let at_path = format!("@{}", events.path().to_str().unwrap());
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            &at_path,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Test Rule"))
        .stderr(predicate::str::contains("1 events"));
}

#[test]
fn eval_at_file_ndjson() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let events = temp_file(
        ".ndjson",
        r#"{"CommandLine": "run malware.exe"}
{"CommandLine": "notepad.exe"}
{"CommandLine": "inject malware payload"}
"#,
    );
    let at_path = format!("@{}", events.path().to_str().unwrap());
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            &at_path,
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 matches"));
}

#[test]
fn eval_at_file_not_found() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            "@/tmp/nonexistent_rsigma_events.json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Event file not found"));
}

#[test]
fn eval_pretty_output() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "malware"}"#,
            "--pretty",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("  "));
}

#[test]
fn eval_include_event() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "malware"}"#,
            "--include-event",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("CommandLine"));
}

// ---------------------------------------------------------------------------
// eval subcommand — with pipeline
// ---------------------------------------------------------------------------

#[test]
fn eval_with_pipeline() {
    let pipeline = temp_file(".yml", PIPELINE_YAML);
    let rule = temp_file(".yml", SIMPLE_RULE);

    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "-p",
            pipeline.path().to_str().unwrap(),
            "--event",
            r#"{"process.command_line": "malware"}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Test Rule"));
}

// ---------------------------------------------------------------------------
// eval subcommand — jq / jsonpath filters
// ---------------------------------------------------------------------------

#[test]
fn eval_jq_filter() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let event = r#"{"wrapper": {"CommandLine": "malware"}}"#;
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            event,
            "--jq",
            ".wrapper",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Test Rule"));
}

#[test]
fn eval_jsonpath_filter() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let event = r#"{"data": {"CommandLine": "malware"}}"#;
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            event,
            "--jsonpath",
            "$.data",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Test Rule"));
}

#[test]
fn eval_jq_and_jsonpath_conflict() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            "{}",
            "--jq",
            ".",
            "--jsonpath",
            "$",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

// ---------------------------------------------------------------------------
// eval subcommand — correlation
// ---------------------------------------------------------------------------

#[test]
fn eval_correlation_fires() {
    let rule = temp_file(".yml", CORRELATION_RULES);
    let events = r#"{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:01Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:02Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:03Z"}
"#;
    rsigma()
        .args(["eval", "--rules", rule.path().to_str().unwrap()])
        .write_stdin(events)
        .assert()
        .success()
        .stderr(predicate::str::contains("correlation"))
        .stdout(predicate::str::contains("Brute Force"));
}

#[test]
fn eval_correlation_below_threshold() {
    let rule = temp_file(".yml", CORRELATION_RULES);
    let events = r#"{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:01Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:02Z"}
"#;
    rsigma()
        .args(["eval", "--rules", rule.path().to_str().unwrap()])
        .write_stdin(events)
        .assert()
        .success()
        .stderr(predicate::str::contains("0 correlation"));
}

#[test]
fn eval_correlation_with_suppress() {
    let rule = temp_file(".yml", CORRELATION_RULES);
    let events = r#"{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:01Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:02Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:03Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:04Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:05Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:06Z"}
"#;
    let output = rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--suppress",
            "5m",
        ])
        .write_stdin(events)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout_str = String::from_utf8(output).unwrap();
    let brute_force_count = stdout_str.matches("Brute Force").count();
    assert_eq!(
        brute_force_count, 1,
        "expected 1 correlation alert with suppress, got {brute_force_count}"
    );
}

#[test]
fn eval_correlation_action_reset() {
    let rule = temp_file(".yml", CORRELATION_RULES);
    let events = r#"{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:01Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:02Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:03Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:04Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:05Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:06Z"}
"#;
    let output = rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--action",
            "reset",
        ])
        .write_stdin(events)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout_str = String::from_utf8(output).unwrap();
    let brute_force_count = stdout_str.matches("Brute Force").count();
    assert_eq!(
        brute_force_count, 2,
        "expected 2 correlation alerts with reset action, got {brute_force_count}"
    );
}

#[test]
fn eval_no_detections_flag() {
    let rule = temp_file(".yml", CORRELATION_RULES);
    let events = r#"{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:01Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:02Z"}
{"EventType": "login_failure", "User": "admin", "@timestamp": "2025-01-01T00:00:03Z"}
"#;
    let output = rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--no-detections",
        ])
        .write_stdin(events)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout_str = String::from_utf8(output).unwrap();
    assert!(
        stdout_str.contains("Brute Force"),
        "correlation should still fire"
    );
    assert!(
        !stdout_str.contains("\"rule_title\":\"Detection\""),
        "detection-level output should be suppressed"
    );
}

// ---------------------------------------------------------------------------
// eval subcommand — filter rules
// ---------------------------------------------------------------------------

#[test]
fn eval_filter_excludes_match() {
    let rule = temp_file(".yml", FILTER_RULES);
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"TargetFilename": "C:\\Windows\\trusted.exe"}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("No matches"));
}

#[test]
fn eval_filter_allows_match() {
    let rule = temp_file(".yml", FILTER_RULES);
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"TargetFilename": "C:\\Users\\evil.exe"}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Base Rule"));
}

// ---------------------------------------------------------------------------
// eval subcommand — timestamp fields
// ---------------------------------------------------------------------------

#[test]
fn eval_custom_timestamp_field() {
    let rule = temp_file(".yml", CORRELATION_RULES);
    let events = r#"{"EventType": "login_failure", "User": "admin", "my_ts": "2025-01-01T00:00:01Z"}
{"EventType": "login_failure", "User": "admin", "my_ts": "2025-01-01T00:00:02Z"}
{"EventType": "login_failure", "User": "admin", "my_ts": "2025-01-01T00:00:03Z"}
"#;
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--timestamp-field",
            "my_ts",
        ])
        .write_stdin(events)
        .assert()
        .success()
        .stdout(predicate::str::contains("Brute Force"));
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn no_subcommand_shows_help() {
    rsigma()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn eval_missing_rules_arg() {
    rsigma()
        .args(["eval", "--event", "{}"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--rules"));
}

#[test]
fn eval_nonexistent_rules_path() {
    rsigma()
        .args([
            "eval",
            "--rules",
            "/tmp/nonexistent_rsigma_rules.yml",
            "--event",
            "{}",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn version_flag() {
    rsigma()
        .args(["--version"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rsigma"));
}

#[test]
fn help_flag() {
    rsigma()
        .args(["--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Parse, validate, and evaluate"));
}
