//! Integration tests for the `rsigma` binary.
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
    Command::cargo_bin("rsigma").expect("binary not found")
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
logsource:
    category: test
    product: test
filter:
    rules:
        - 00000000-0000-0000-0000-000000000020
    selection:
        TargetFilename|endswith: "\\trusted.exe"
    condition: selection
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

// ---------------------------------------------------------------------------
// lint subcommand
// ---------------------------------------------------------------------------

const LINT_VALID_RULE: &str = r#"
title: Valid Rule
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
status: test
description: A valid detection rule for testing
author: tester
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
tags:
    - attack.execution
    - attack.t1059
date: '2025-01-15'
modified: '2025-06-01'
"#;

const LINT_INVALID_LEVEL: &str = r#"
title: Bad Level
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: important
"#;

const LINT_INVALID_STATUS: &str = r#"
title: Bad Status
status: invalid_status
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#;

const LINT_INVALID_DATE: &str = r#"
title: Bad Date
date: 'Jan 2025'
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#;

const LINT_INVALID_TAGS: &str = r#"
title: Bad Tags
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
tags:
    - 'Invalid Tag'
    - attack.execution
    - attack.execution
"#;

const LINT_MISSING_DETECTION: &str = r#"
title: No Detection
logsource:
    category: test
"#;

const LINT_DEPRECATED_NO_RELATED: &str = r#"
title: Deprecated Rule
status: deprecated
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#;

const LINT_VALID_CORRELATION: &str = r#"
title: Brute Force
description: Correlation for brute force detection
author: tester
correlation:
    type: event_count
    rules:
        - 929a690e-bef0-4204-a928-ef5e620d6fcc
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 100
level: high
"#;

const LINT_INVALID_CORRELATION: &str = r#"
title: Bad Correlation
correlation:
    type: invalid_type
    rules:
        - some-rule
    timespan: 1hour
"#;

const LINT_VALID_FILTER: &str = r#"
title: Filter Admin
description: Filter for admin users
author: tester
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - 929a690e-bef0-4204-a928-ef5e620d6fcc
    selection:
        User|startswith: 'adm_'
    condition: selection
"#;

const LINT_FILTER_WITH_LEVEL: &str = r#"
title: Filter With Level
logsource:
    category: test
level: high
filter:
    rules:
        - some-rule
    selection:
        User: admin
    condition: selection
"#;

const LINT_MULTI_DOC: &str = r#"
action: global
logsource:
    product: windows
---
title: Rule A
detection:
    selection:
        EventID: 1
    condition: selection
level: high
---
title: Rule B
detection:
    selection:
        EventID: 2
    condition: selection
level: invalid_level
"#;

#[test]
fn lint_valid_rule_passes() {
    let rule = temp_file(".yml", LINT_VALID_RULE);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 failed"));
}

#[test]
fn lint_valid_rule_verbose() {
    let rule = temp_file(".yml", LINT_VALID_RULE);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap(), "--verbose"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn lint_invalid_level() {
    let rule = temp_file(".yml", LINT_INVALID_LEVEL);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("invalid_level"))
        .stdout(predicate::str::contains("important"));
}

#[test]
fn lint_invalid_status() {
    let rule = temp_file(".yml", LINT_INVALID_STATUS);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("invalid_status"));
}

#[test]
fn lint_invalid_date() {
    let rule = temp_file(".yml", LINT_INVALID_DATE);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("invalid_date"));
}

#[test]
fn lint_invalid_tags() {
    let rule = temp_file(".yml", LINT_INVALID_TAGS);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .stdout(predicate::str::contains("invalid_tag"))
        .stdout(predicate::str::contains("duplicate_tags"));
}

#[test]
fn lint_missing_detection() {
    let rule = temp_file(".yml", LINT_MISSING_DETECTION);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("missing_detection"));
}

#[test]
fn lint_deprecated_without_related() {
    let rule = temp_file(".yml", LINT_DEPRECATED_NO_RELATED);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .stdout(predicate::str::contains("deprecated_without_related"));
}

#[test]
fn lint_valid_correlation() {
    let rule = temp_file(".yml", LINT_VALID_CORRELATION);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 failed"));
}

#[test]
fn lint_invalid_correlation() {
    let rule = temp_file(".yml", LINT_INVALID_CORRELATION);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("invalid_correlation_type"))
        .stdout(predicate::str::contains("invalid_timespan_format"));
}

#[test]
fn lint_valid_filter() {
    let rule = temp_file(".yml", LINT_VALID_FILTER);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 failed"));
}

#[test]
fn lint_filter_has_level() {
    let rule = temp_file(".yml", LINT_FILTER_WITH_LEVEL);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .stdout(predicate::str::contains("filter_has_level"));
}

#[test]
fn lint_multi_doc_yaml() {
    let rule = temp_file(".yml", LINT_MULTI_DOC);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("invalid_level"))
        .stdout(predicate::str::contains("1 failed"));
}

#[test]
fn lint_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("good.yml"), LINT_VALID_RULE).unwrap();
    std::fs::write(dir.path().join("bad.yml"), LINT_INVALID_LEVEL).unwrap();

    rsigma()
        .args(["lint", dir.path().to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("1 failed"))
        .stdout(predicate::str::contains("invalid_level"));
}

#[test]
fn lint_nonexistent_path() {
    rsigma()
        .args(["lint", "/tmp/nonexistent_rsigma_lint_path.yml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn lint_with_local_schema() {
    // Create a minimal JSON schema that requires "title" to be a string
    let schema_json = r#"{
        "$schema": "https://json-schema.org/draft/2020-12/schema#",
        "type": "object",
        "required": ["title"],
        "properties": {
            "title": { "type": "string", "maxLength": 10 }
        }
    }"#;
    let schema_file = temp_file(".json", schema_json);

    // A rule with a title longer than 10 chars should fail schema validation
    let rule_yaml = r#"
title: This Title Is Way Too Long
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#;
    let rule = temp_file(".yml", rule_yaml);

    rsigma()
        .args([
            "lint",
            rule.path().to_str().unwrap(),
            "--schema",
            schema_file.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("schema:"));
}
