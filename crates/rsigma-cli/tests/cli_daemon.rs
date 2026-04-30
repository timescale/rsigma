//! Integration tests for daemon state persistence and streaming pipeline.

mod common;

use common::{SIMPLE_RULE, rsigma, temp_file};
use tempfile::TempDir;

const DAEMON_CORRELATION_RULES: &str = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many Logins
id: many-logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 300s
    condition:
        gte: 3
level: high
"#;

#[cfg(feature = "daemon")]
#[test]
fn daemon_state_db_created_on_first_run() {
    let rules = temp_file(".yml", DAEMON_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("state.db");

    assert!(!db_path.exists());

    rsigma()
        .args([
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--state-db",
            db_path.to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--no-detections",
        ])
        .write_stdin("")
        .assert()
        .success();

    assert!(db_path.exists(), "state.db should be created on first run");
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_state_persists_across_restarts() {
    let rules = temp_file(".yml", DAEMON_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("state.db");

    // Run 1: send 2 events (below threshold of 3), state should be saved
    let events_run1 = "{\"EventType\":\"login\",\"User\":\"admin\"}\n\
                        {\"EventType\":\"login\",\"User\":\"admin\"}\n";
    let output1 = rsigma()
        .args([
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--state-db",
            db_path.to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--no-detections",
        ])
        .write_stdin(events_run1)
        .output()
        .unwrap();

    assert!(output1.status.success());
    let stdout1 = String::from_utf8_lossy(&output1.stdout);
    assert!(
        stdout1.trim().is_empty(),
        "Run 1: no correlation output expected (only 2 events), got: {stdout1}"
    );

    // Run 2: send 1 more event — restored 2 + new 1 = 3, should trigger
    let events_run2 = "{\"EventType\":\"login\",\"User\":\"admin\"}\n";
    let output2 = rsigma()
        .args([
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--state-db",
            db_path.to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--no-detections",
        ])
        .write_stdin(events_run2)
        .output()
        .unwrap();

    assert!(output2.status.success());
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(
        stdout2.contains("\"rule_title\":\"Many Logins\""),
        "Run 2: correlation should fire with restored state, got: {stdout2}"
    );
    assert!(
        stdout2.contains("\"aggregated_value\":3.0"),
        "Run 2: aggregated value should be 3.0, got: {stdout2}"
    );
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_state_db_multiple_groups() {
    let rules = temp_file(".yml", DAEMON_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("state.db");

    // Run 1: 2 events for admin, 1 for bob
    let events_run1 = "{\"EventType\":\"login\",\"User\":\"admin\"}\n\
                        {\"EventType\":\"login\",\"User\":\"admin\"}\n\
                        {\"EventType\":\"login\",\"User\":\"bob\"}\n";
    rsigma()
        .args([
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--state-db",
            db_path.to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--no-detections",
        ])
        .write_stdin(events_run1)
        .assert()
        .success();

    // Run 2: 1 event for admin (fires), 1 for bob (still 2, no fire)
    let events_run2 = "{\"EventType\":\"login\",\"User\":\"admin\"}\n\
                        {\"EventType\":\"login\",\"User\":\"bob\"}\n";
    let output = rsigma()
        .args([
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--state-db",
            db_path.to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--no-detections",
        ])
        .write_stdin(events_run2)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "exactly one correlation should fire (admin), got: {stdout}"
    );
    assert!(lines[0].contains("\"aggregated_value\":3.0"));
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_without_state_db_works() {
    let rules = temp_file(".yml", DAEMON_CORRELATION_RULES);

    let events = "{\"EventType\":\"login\",\"User\":\"admin\"}\n\
                   {\"EventType\":\"login\",\"User\":\"admin\"}\n\
                   {\"EventType\":\"login\",\"User\":\"admin\"}\n";
    let output = rsigma()
        .args([
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--no-detections",
        ])
        .write_stdin(events)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"rule_title\":\"Many Logins\""),
        "daemon should work without --state-db, got: {stdout}"
    );
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_detection_only_with_state_db() {
    let rules_yaml = r#"
title: Test Rule
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: "whoami"
    condition: selection
level: medium
"#;
    let rules = temp_file(".yml", rules_yaml);
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("state.db");

    let output = rsigma()
        .args([
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--state-db",
            db_path.to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
        ])
        .write_stdin("{\"CommandLine\":\"cmd /c whoami\"}\n")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"rule_title\":\"Test Rule\""),
        "detection should still work with --state-db on detection-only rules"
    );
}

// ---------------------------------------------------------------------------
// Streaming pipeline tests
// ---------------------------------------------------------------------------

#[cfg(feature = "daemon")]
#[test]
fn daemon_streaming_stdin_stdout() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let event = r#"{"CommandLine":"malware.exe"}"#;

    let output = rsigma()
        .args([
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--input",
            "stdin",
            "--output",
            "stdout",
        ])
        .write_stdin(format!("{event}\n"))
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"rule_title\":\"Test Rule\""),
        "stdin->stdout pipeline should produce detection output: {stdout}"
    );
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_streaming_file_output() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let dir = TempDir::new().unwrap();
    let out_path = dir.path().join("detections.ndjson");
    let event = r#"{"CommandLine":"malware.exe"}"#;

    let output = rsigma()
        .args([
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--output",
            &format!("file://{}", out_path.display()),
        ])
        .write_stdin(format!("{event}\n"))
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.is_empty() || !stdout.contains("\"rule_title\""),
        "file output should NOT write to stdout: {stdout}"
    );

    let file_content = std::fs::read_to_string(&out_path).unwrap();
    assert!(
        file_content.contains("\"rule_title\":\"Test Rule\""),
        "file sink should contain detection output: {file_content}"
    );
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_streaming_fanout_stdout_and_file() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let dir = TempDir::new().unwrap();
    let out_path = dir.path().join("detections.ndjson");
    let event = r#"{"CommandLine":"malware.exe"}"#;

    let output = rsigma()
        .args([
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--output",
            "stdout",
            "--output",
            &format!("file://{}", out_path.display()),
        ])
        .write_stdin(format!("{event}\n"))
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"rule_title\":\"Test Rule\""),
        "fan-out should write to stdout: {stdout}"
    );

    let file_content = std::fs::read_to_string(&out_path).unwrap();
    assert!(
        file_content.contains("\"rule_title\":\"Test Rule\""),
        "fan-out should also write to file: {file_content}"
    );
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_streaming_no_match_produces_no_output() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let event = r#"{"CommandLine":"benign.exe"}"#;

    let output = rsigma()
        .args([
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
        ])
        .write_stdin(format!("{event}\n"))
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "non-matching event should produce no stdout output: {stdout}"
    );
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_streaming_batch_size() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let events = (0..5)
        .map(|_| r#"{"CommandLine":"malware.exe"}"#)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    let output = rsigma()
        .args([
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--batch-size",
            "4",
        ])
        .write_stdin(events)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let matches: Vec<_> = stdout.lines().collect();
    assert_eq!(
        matches.len(),
        5,
        "batch-size=4 should still produce 5 detections: got {count}",
        count = matches.len()
    );
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_streaming_custom_buffer_size() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let event = r#"{"CommandLine":"malware.exe"}"#;

    let output = rsigma()
        .args([
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--buffer-size",
            "16",
        ])
        .write_stdin(format!("{event}\n"))
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"rule_title\":\"Test Rule\""),
        "small buffer-size should still produce output: {stdout}"
    );
}
