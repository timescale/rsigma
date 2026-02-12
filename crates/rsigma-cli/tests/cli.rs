//! Integration tests for the `rsigma-cli` binary.
//!
//! Each test launches the binary via `assert_cmd`, writes any required
//! fixture files to a temp directory, and asserts on exit code + output.

use std::io::Write;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(deprecated)]
fn rsigma() -> Command {
    Command::cargo_bin("rsigma-cli").expect("binary not found")
}

/// Write `contents` to a temporary file with the given suffix and return it.
fn temp_file(suffix: &str, contents: &str) -> NamedTempFile {
    let mut f = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SIMPLE_RULE: &str = r#"
title: Test Rule
id: 00000000-0000-0000-0000-000000000001
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|contains: "malware"
    condition: selection
level: high
"#;

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

/// Multi-document YAML: a detection rule + an event_count correlation.
///
/// The correlation section is nested under `correlation:` as required by
/// the Sigma correlation specification.
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
filter:
    rules:
        - 00000000-0000-0000-0000-000000000020
logsource:
    category: test
    product: test
detection:
    filter_trusted:
        TargetFilename|endswith: "\\trusted.exe"
    condition: not filter_trusted
"#;

const PIPELINE_YAML: &str = r#"
name: test-pipeline
priority: 10
transformations:
  - type: field_name_mapping
    mapping:
      CommandLine: process.command_line
"#;

// ---------------------------------------------------------------------------
// parse subcommand
// ---------------------------------------------------------------------------

#[test]
fn parse_valid_rule() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args(["parse", rule.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Test Rule"))
        .stdout(predicate::str::contains("malware"));
}

#[test]
fn parse_nonexistent_file() {
    rsigma()
        .args(["parse", "/tmp/nonexistent_rsigma_test.yml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn parse_invalid_yaml() {
    // A bare number is valid YAML but not a Sigma rule mapping — the parser
    // succeeds with an empty collection and emits a warning.
    let bad = temp_file(".yml", "42");
    rsigma()
        .args(["parse", bad.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Warning"));
}

// ---------------------------------------------------------------------------
// condition subcommand
// ---------------------------------------------------------------------------

#[test]
fn condition_valid() {
    rsigma()
        .args(["condition", "selection1 and not filter"])
        .assert()
        .success()
        .stdout(predicate::str::contains("And"))
        .stdout(predicate::str::contains("selection1"))
        .stdout(predicate::str::contains("filter"));
}

#[test]
fn condition_complex() {
    rsigma()
        .args(["condition", "1 of selection* or (filter1 and filter2)"])
        .assert()
        .success()
        .stdout(predicate::str::contains("selection*"));
}

#[test]
fn condition_invalid() {
    rsigma()
        .args(["condition", "invalid !!! syntax"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

// ---------------------------------------------------------------------------
// stdin subcommand
// ---------------------------------------------------------------------------

#[test]
fn stdin_valid_rule() {
    rsigma()
        .args(["stdin"])
        .write_stdin(SIMPLE_RULE)
        .assert()
        .success()
        .stdout(predicate::str::contains("Test Rule"));
}

#[test]
fn stdin_invalid_yaml() {
    // Bare number — valid YAML scalar but not a Sigma rule mapping.
    // Parser succeeds with an empty collection and emits a warning.
    rsigma()
        .args(["stdin"])
        .write_stdin("12345")
        .assert()
        .success()
        .stderr(predicate::str::contains("Warning"));
}

// ---------------------------------------------------------------------------
// validate subcommand
// ---------------------------------------------------------------------------

#[test]
fn validate_directory_with_valid_rules() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rule1.yml"), SIMPLE_RULE).unwrap();
    std::fs::write(dir.path().join("rule2.yml"), SIMPLE_RULE_WINDASH).unwrap();

    rsigma()
        .args(["validate", dir.path().to_str().unwrap()])
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
        .args(["validate", dir.path().to_str().unwrap(), "--verbose"])
        .assert()
        // May succeed (0 rules parsed) or fail depending on error handling
        .stdout(predicate::str::contains("Parsed"));
}

#[test]
fn validate_nonexistent_directory() {
    rsigma()
        .args(["validate", "/tmp/nonexistent_rsigma_dir"])
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
            "validate",
            dir.path().to_str().unwrap(),
            "-p",
            pipeline.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Pipeline applied:"));
}

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
        // Pretty output should have indentation
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
        // Output should contain the event payload
        .stdout(predicate::str::contains("CommandLine"));
}

// ---------------------------------------------------------------------------
// eval subcommand — with pipeline
// ---------------------------------------------------------------------------

#[test]
fn eval_with_pipeline() {
    // Pipeline maps CommandLine -> process.command_line
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
    // 3 login failures for same user should trigger the event_count correlation
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
    // Only 2 failures — below threshold of 3
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
    // 6 failures — should fire once then suppress for 5m
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

    // Count how many times "Brute Force" appears — with suppress, should be 1
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
    // 6 failures with reset action: first 3 fire + reset, then next 3 fire again
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
    // With --no-detections, correlation output should still appear
    assert!(
        stdout_str.contains("Brute Force"),
        "correlation should still fire"
    );
    // Detection-level matches for the base rule should be suppressed
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
    // This event matches the base rule but the filter should exclude it
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
    // This event matches the base rule and should NOT be filtered
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
    // Use a custom timestamp field
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
