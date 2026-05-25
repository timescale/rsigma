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
            "engine",
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
fn eval_bloom_prefilter_flag_is_accepted() {
    // Smoke test: --bloom-prefilter must be accepted and produce the same
    // match output as the default path. Bloom is purely an optimization;
    // results must be identical.
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--bloom-prefilter",
            "--event",
            r#"{"CommandLine": "download malware.exe"}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Test Rule"));
}

#[test]
fn eval_bloom_prefilter_with_max_bytes() {
    // --bloom-max-bytes pairs with --bloom-prefilter; both must be accepted.
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--bloom-prefilter",
            "--bloom-max-bytes",
            "131072", // 128 KB
            "--event",
            r#"{"CommandLine": "download malware.exe"}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Test Rule"));
}

#[test]
fn eval_bloom_prefilter_rejects_non_matching_event() {
    // Pure-digit event cannot share trigrams with the alphabetical needles
    // in the test rule. Bloom rejects, --bloom-prefilter must produce
    // identical (no-match) output.
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--bloom-prefilter",
            "--event",
            r#"{"CommandLine": "0123456789"}"#,
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("No matches"));
}

#[test]
fn eval_single_event_no_match() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "engine",
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
            "engine",
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
        .args(["engine", "eval", "--rules", rule.path().to_str().unwrap()])
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
        .args(["engine", "eval", "--rules", rule.path().to_str().unwrap()])
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
        .args(["engine", "eval", "--rules", rule.path().to_str().unwrap()])
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
        .args(["engine", "eval", "--rules", rule.path().to_str().unwrap()])
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
// eval subcommand — input formats
// ---------------------------------------------------------------------------

#[test]
fn eval_syslog_input_format() {
    let syslog_rule = temp_file(
        ".yml",
        r#"
title: Sudo Usage
id: 00000000-0000-0000-0000-000000000099
status: test
logsource:
    product: linux
    service: auth
detection:
    keywords:
        - 'sudo'
    condition: keywords
level: low
"#,
    );
    let events = "<38>Apr 25 14:30:00 web01 sudo: admin : TTY=pts/0 ; COMMAND=/bin/bash\n";
    let output = rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            syslog_rule.path().to_str().unwrap(),
            "--input-format",
            "syslog",
        ])
        .write_stdin(events)
        .output()
        .unwrap();
    assert!(output.status.success());
    insta::assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r#"{"rule_title":"Sudo Usage","rule_id":"00000000-0000-0000-0000-000000000099","level":"low","tags":[],"matched_selections":["keywords"],"matched_fields":[]}"#);
}

#[test]
fn eval_plain_input_format() {
    let plain_rule = temp_file(
        ".yml",
        r#"
title: Error Detected
id: 00000000-0000-0000-0000-000000000097
status: test
logsource:
    category: application
detection:
    keywords:
        - 'CRITICAL ERROR'
    condition: keywords
level: high
"#,
    );
    let output = rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            plain_rule.path().to_str().unwrap(),
            "--input-format",
            "plain",
        ])
        .write_stdin("CRITICAL ERROR in module X\n")
        .output()
        .unwrap();
    assert!(output.status.success());
    insta::assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r#"{"rule_title":"Error Detected","rule_id":"00000000-0000-0000-0000-000000000097","level":"high","tags":[],"matched_selections":["keywords"],"matched_fields":[]}"#);
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
        .args(["engine", "eval", "--event", "{}"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--rules"));
}

#[test]
fn eval_nonexistent_rules_path() {
    rsigma()
        .args([
            "engine",
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
// eval subcommand — field observability (--observe-fields)
// ---------------------------------------------------------------------------

/// Helper: run `engine eval` with `--observe-fields --observe-fields-report
/// <path>` against an inline event, and return the parsed report JSON.
fn run_eval_with_observation(
    rule_yaml: &str,
    event_json: &str,
    extra_flags: &[&str],
) -> serde_json::Value {
    let rule = temp_file(".yml", rule_yaml);
    let report_file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    let mut args: Vec<&str> = vec![
        "engine",
        "eval",
        "--rules",
        rule.path().to_str().unwrap(),
        "--event",
        event_json,
        "--observe-fields",
        "--observe-fields-report",
        report_file.path().to_str().unwrap(),
    ];
    args.extend_from_slice(extra_flags);
    rsigma().args(&args).assert().success();
    let body = std::fs::read_to_string(report_file.path()).unwrap();
    serde_json::from_str(&body).expect("report file should be valid JSON")
}

#[test]
fn observe_fields_emits_full_report_to_file() {
    let report = run_eval_with_observation(
        SIMPLE_RULE,
        r#"{"CommandLine":"malware","User":"alice","src_ip":"10.0.0.1"}"#,
        &[],
    );
    let summary = &report["summary"];
    assert_eq!(summary["events_observed"].as_u64().unwrap(), 1);
    assert_eq!(summary["unique_keys_observed"].as_u64().unwrap(), 3);
    assert_eq!(summary["overflow_dropped"].as_u64().unwrap(), 0);
    assert!(summary["rule_fields_loaded"].as_u64().unwrap() >= 1);
    assert_eq!(summary["intersection_count"].as_u64().unwrap(), 1); // CommandLine
    assert_eq!(summary["unknown_count"].as_u64().unwrap(), 2); // User + src_ip
}

#[test]
fn observe_fields_unknown_lists_event_fields_no_rule_references() {
    let report = run_eval_with_observation(
        SIMPLE_RULE,
        r#"{"CommandLine":"malware","User":"alice","src_ip":"10.0.0.1"}"#,
        &[],
    );
    let names: Vec<&str> = report["unknown"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["field"].as_str())
        .collect();
    assert!(names.contains(&"User"));
    assert!(names.contains(&"src_ip"));
    assert!(!names.contains(&"CommandLine"));
}

#[test]
fn observe_fields_missing_lists_rule_fields_never_observed() {
    // No CommandLine in the event => rule's CommandLine field is "missing".
    let report = run_eval_with_observation(SIMPLE_RULE, r#"{"User":"alice"}"#, &[]);
    let items = report["missing"].as_array().unwrap();
    let cmd_entry = items
        .iter()
        .find(|e| e["field"] == "CommandLine")
        .expect("CommandLine should be flagged missing");
    assert!(cmd_entry["rule_count"].as_u64().unwrap() >= 1);
    let sources: Vec<&str> = cmd_entry["sources"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s.as_str())
        .collect();
    assert!(sources.contains(&"detection"));
}

#[test]
fn observe_fields_max_keys_caps_distinct_fields() {
    let report = run_eval_with_observation(
        SIMPLE_RULE,
        r#"{"a":1,"b":2,"c":3,"d":4,"e":5}"#,
        &["--observe-fields-max-keys", "2"],
    );
    let summary = &report["summary"];
    assert_eq!(summary["unique_keys_observed"].as_u64().unwrap(), 2);
    assert_eq!(summary["overflow_dropped"].as_u64().unwrap(), 3);
    assert_eq!(summary["max_keys"].as_u64().unwrap(), 2);
}

#[test]
fn observe_fields_writes_to_stderr_when_no_report_path() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let output = rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine":"malware","extra":"hello"}"#,
            "--observe-fields",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The report is JSON on stderr; check for stable summary fields.
    assert!(stderr.contains("\"events_observed\""));
    assert!(stderr.contains("\"unknown\""));
    assert!(stderr.contains("\"missing\""));
    // And detections stay on stdout (rule fires on the matching event).
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Test Rule"));
}

#[test]
fn observe_fields_report_without_observe_flag_is_rejected() {
    // clap `requires` should refuse `--observe-fields-report` when
    // `--observe-fields` is not also supplied, so a typo at the CLI
    // surface fails fast instead of silently producing no report.
    let rule = temp_file(".yml", SIMPLE_RULE);
    let report_file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine":"malware"}"#,
            "--observe-fields-report",
            report_file.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--observe-fields"));
}

#[test]
fn observe_fields_max_keys_zero_is_rejected() {
    // NonZeroUsize value parser refuses 0; otherwise every observation
    // would count as overflow with no useful tracking.
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine":"malware"}"#,
            "--observe-fields",
            "--observe-fields-max-keys",
            "0",
        ])
        .assert()
        .failure();
}

#[test]
fn observe_fields_off_by_default_emits_no_report() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let output = rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine":"malware","extra":"hello"}"#,
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("\"events_observed\""));
    assert!(!stderr.contains("\"unknown\""));
}
