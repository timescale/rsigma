//! Integration tests for the per-sink `?format=` parameter: the channels that
//! accept it, the specs that reject it at startup, the byte-for-byte
//! neutrality of the default NDJSON path, and OCSF output end to end through
//! the daemon.

#![cfg(feature = "daemon")]

mod common;

use std::time::Duration;

use common::{DaemonProcess, SIMPLE_RULE, http_post, poll_until, rsigma, temp_file};
use predicates::str::contains;
use serde_json::Value;

const MATCHING_EVENT: &str = "{\"CommandLine\":\"run malware.exe\"}\n";
const EVENT_BODY: &str = r#"{"CommandLine":"run malware.exe"}"#;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

/// Every parseable JSON line currently in `path`.
fn lines(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

/// Wait for a line in `path` matching `predicate`.
fn wait_for_line(path: &std::path::Path, predicate: impl Fn(&Value) -> bool) -> Option<Value> {
    poll_until(Duration::from_secs(10), || {
        lines(path).into_iter().find(|line| predicate(line))
    })
}

/// Run a stdin-fed daemon with the given extra args and return the assertion.
fn daemon_with(args: &[&str], stdin: &str) -> assert_cmd::assert::Assert {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let mut cmd = rsigma();
    cmd.args([
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--api-addr",
        "127.0.0.1:0",
    ])
    .args(args)
    .timeout(COMMAND_TIMEOUT)
    .write_stdin(stdin.to_string())
    .assert()
}

/// Run a daemon expected to reject its configuration before reading events.
fn daemon_startup_failure(args: &[&str]) -> assert_cmd::assert::Assert {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let mut cmd = rsigma();
    cmd.args([
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--api-addr",
        "127.0.0.1:0",
    ])
    .args(args)
    .timeout(COMMAND_TIMEOUT)
    .assert()
}

#[test]
fn explicit_ndjson_format_is_accepted_on_a_findings_sink() {
    let out = temp_file(".ndjson", "");
    let spec = format!("file://{}?format=ndjson", out.path().display());
    daemon_with(&["--output", &spec], MATCHING_EVENT).success();

    let written = std::fs::read_to_string(out.path()).unwrap();
    assert!(
        written.contains("Test Rule"),
        "an explicit ndjson sink must still deliver detections: {written}",
    );
}

/// Naming the default must not change it: a spec with no `format` parameter and
/// a spec that names `ndjson` must produce the same bytes.
#[test]
fn explicit_ndjson_matches_the_default_byte_for_byte() {
    let implicit = temp_file(".ndjson", "");
    let explicit = temp_file(".ndjson", "");
    let implicit_spec = format!("file://{}", implicit.path().display());
    let explicit_spec = format!("file://{}?format=ndjson", explicit.path().display());

    daemon_with(&["--output", &implicit_spec], MATCHING_EVENT).success();
    daemon_with(&["--output", &explicit_spec], MATCHING_EVENT).success();

    let implicit = std::fs::read_to_string(implicit.path()).unwrap();
    let explicit = std::fs::read_to_string(explicit.path()).unwrap();
    assert_eq!(
        implicit, explicit,
        "?format=ndjson must be the default path"
    );
    assert!(
        !implicit.is_empty(),
        "the run should have emitted a finding"
    );
}

#[test]
fn unknown_format_value_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!("file://{}?format=bogus", out.path().display());
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("Unknown sink format"));
}

#[test]
fn bare_format_parameter_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!("file://{}?format", out.path().display());
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("Unknown sink format"));
}

#[test]
fn duplicate_format_parameter_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!("file://{}?format=ndjson&format=ocsf", out.path().display());
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("may be specified only once"));
}

#[test]
fn unknown_ocsf_version_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!(
        "file://{}?format=ocsf&ocsf_version=9.9.9",
        out.path().display()
    );
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("Invalid ocsf_version"));
}

#[test]
fn ocsf_version_without_ocsf_format_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!(
        "file://{}?format=ndjson&ocsf_version=1.3.0",
        out.path().display()
    );
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("only valid with format=ocsf"));
}

#[test]
fn duplicate_ocsf_version_parameter_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!(
        "file://{}?format=ocsf&ocsf_version=1.1.0&ocsf_version=1.3.0",
        out.path().display()
    );
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("ocsf_version= may be specified only once"));
}

#[cfg(feature = "daemon-otlp")]
#[test]
fn format_on_an_otlp_sink_is_a_startup_error() {
    daemon_startup_failure(&["--output", "otlphttp://127.0.0.1:1?format=ndjson"])
        .failure()
        .stderr(contains("not supported on OTLP sinks"));
}

#[test]
fn format_on_the_dlq_spec_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let dlq = temp_file(".ndjson", "");
    let out_spec = format!("file://{}", out.path().display());
    let dlq_spec = format!("file://{}?format=ndjson", dlq.path().display());
    daemon_startup_failure(&["--output", &out_spec, "--dlq", &dlq_spec])
        .failure()
        .stderr(contains("only supported on findings sinks"));
}

#[test]
fn format_on_the_audit_sink_spec_is_a_startup_error() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");
    let audit_out = dir.path().join("audit.ndjson");
    let audit_spec = format!("file://{}?format=ndjson", audit_out.display());
    let audit_spec = format!("'{}'", audit_spec.replace('\'', "''"));
    let config = temp_file(
        ".yaml",
        &format!("daemon:\n  api:\n    audit:\n      enabled: true\n      sink: {audit_spec}\n"),
    );

    daemon_startup_failure(&[
        "--config",
        config.path().to_str().unwrap(),
        "--state-db",
        db.to_str().unwrap(),
    ])
    .failure()
    .stderr(contains("only supported on findings sinks"));
}

#[cfg(feature = "daemon-otlp")]
#[test]
fn ocsf_on_an_otlp_sink_is_a_startup_error() {
    daemon_with(&["--output", "otlphttp://127.0.0.1:1?format=ocsf"], "")
        .failure()
        .stderr(contains("not supported on OTLP sinks"));
}

/// Two sinks on one daemon, one OCSF and one default: each gets its own
/// serialization of the same detection.
#[test]
fn mixed_format_fan_out_serializes_per_sink() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let native = temp_file(".ndjson", "");
    let ocsf = temp_file(".ndjson", "");
    let native_spec = format!("file://{}", native.path().display());
    let ocsf_spec = format!("file://{}?format=ocsf", ocsf.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--output", &native_spec, "--output", &ocsf_spec],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), EVENT_BODY);
    assert_eq!(status, 200);

    let finding = wait_for_line(ocsf.path(), |line| line["class_uid"] == 2004)
        .expect("the OCSF sink never received a class-2004 finding");
    assert_eq!(finding["action_id"], 0);
    assert_eq!(finding["type_uid"], 200401);
    assert_eq!(finding["finding_info"]["title"], "Test Rule");
    assert_eq!(finding["finding_info"]["analytic"]["uid"], SIMPLE_RULE_ID);
    assert_eq!(finding["severity"], "High");
    assert_eq!(finding["metadata"]["version"], "1.1.0");
    assert_eq!(
        finding["unmapped"]["matched_selections"],
        serde_json::json!(["selection"])
    );

    let native = wait_for_line(native.path(), |line| line["rule_title"] == "Test Rule")
        .expect("the default sink never received the native line");
    assert!(
        native.get("class_uid").is_none(),
        "the default sink must be untouched by the OCSF sibling: {native}",
    );
}

#[test]
fn ocsf_fan_out_preserves_finding_identity_and_time() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let first = temp_file(".ndjson", "");
    let second = temp_file(".ndjson", "");
    let first_spec = format!("file://{}?format=ocsf", first.path().display());
    let second_spec = format!("file://{}?format=ocsf", second.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--output", &first_spec, "--output", &second_spec],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), EVENT_BODY);
    assert_eq!(status, 200);

    let first = wait_for_line(first.path(), |line| line["class_uid"] == 2004)
        .expect("the first OCSF sink never received the finding");
    let second = wait_for_line(second.path(), |line| line["class_uid"] == 2004)
        .expect("the second OCSF sink never received the finding");
    assert_eq!(first["finding_info"]["uid"], second["finding_info"]["uid"]);
    assert_eq!(first["metadata"]["uid"], second["metadata"]["uid"]);
    assert_eq!(first["time"], second["time"]);
}

const SIMPLE_RULE_ID: &str = "00000000-0000-0000-0000-000000000001";

const GROUP_AND_DEDUP_PIPELINE: &str = r#"
dedup:
  fingerprint:
    - rule
  repeat_interval: 1s
  resolve_timeout: 1h
group:
  by:
    - match.CommandLine
  group_wait: 0s
  resolve_timeout: 2s
"#;

/// Incidents and dedup sidecar lines reach an OCSF sink as class-2004 findings.
#[test]
fn incidents_and_dedup_lines_are_ocsf_findings_on_ocsf_sink() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let pipeline = temp_file(".yml", GROUP_AND_DEDUP_PIPELINE);
    let native = temp_file(".ndjson", "");
    let native_spec = format!("file://{}", native.path().display());
    let ocsf = temp_file(".ndjson", "");
    let ocsf_spec = format!("file://{}?format=ocsf", ocsf.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--alert-pipeline",
            pipeline.path().to_str().unwrap(),
            "--output",
            &native_spec,
            "--output",
            &ocsf_spec,
        ],
    );

    // Three identical events: the first opens the incident, the rest fold into
    // the dedup alert so a `repeat` sidecar record is due on the next tick.
    for _ in 0..3 {
        let (status, _) = http_post(&daemon.url("/api/v1/events"), EVENT_BODY);
        assert_eq!(status, 200);
    }

    let created = wait_for_line(ocsf.path(), |line| {
        line["class_uid"] == 2004 && line["unmapped"]["state"] == "open"
    })
    .expect("an open incident never reached the OCSF sink as a finding");
    assert_eq!(created["activity_name"], "Create");
    assert_eq!(created["status"], "New");
    assert_eq!(created["count"], 1);
    assert_eq!(
        created["finding_info"]["related_analytics"][0]["name"],
        SIMPLE_RULE_ID
    );

    let dedup_ocsf = wait_for_line(ocsf.path(), |line| line["activity_name"] == "Update")
        .expect("a dedup repeat finding never reached the OCSF sink");
    assert_eq!(dedup_ocsf["class_uid"], 2004);
    assert_eq!(
        dedup_ocsf["unmapped"]["enrichments"]["dedup_state"],
        "repeat",
    );

    let dedup_native = wait_for_line(native.path(), |line| {
        line.pointer("/enrichments/dedup_state").is_some()
    })
    .expect("a dedup sidecar line never reached the native sink");
    assert!(
        dedup_native.get("class_uid").is_none(),
        "native sink keeps the flat summary wire: {dedup_native}",
    );

    // Once `resolve_timeout` elapses with no further results, the incident
    // resolves and closes the finding.
    let closed = wait_for_line(ocsf.path(), |line| {
        line["class_uid"] == 2004 && line["unmapped"]["state"] == "resolved"
    })
    .expect("the resolved incident never reached the OCSF sink");
    assert_eq!(closed["activity_name"], "Close");
    assert_eq!(closed["activity_id"], 3);
    assert_eq!(closed["type_uid"], 200403);
    assert_eq!(closed["status"], "Resolved");
    assert_eq!(closed["status_id"], 4);
    assert_eq!(
        closed["finding_info"]["uid"], created["finding_info"]["uid"],
        "both emissions describe the same incident",
    );
}
