//! Integration tests for daemon state persistence and streaming pipeline.

#![cfg(feature = "daemon")]

mod common;

use common::{SIMPLE_RULE, rsigma, temp_file};
use rusqlite::params;
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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
            "engine",
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

// ---------------------------------------------------------------------------
// Input format tests
// ---------------------------------------------------------------------------

#[cfg(feature = "daemon")]
#[test]
fn daemon_syslog_input_format() {
    let syslog_rule = r#"
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
"#;
    let rule = temp_file(".yml", syslog_rule);
    let syslog_line = "<38>Apr 25 14:30:00 web01 sudo: admin : TTY=pts/0 ; COMMAND=/bin/bash";

    let output = rsigma()
        .args([
            "engine",
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--input-format",
            "syslog",
        ])
        .write_stdin(format!("{syslog_line}\n"))
        .output()
        .unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r#"{"rule_title":"Sudo Usage","rule_id":"00000000-0000-0000-0000-000000000099","level":"low","tags":[],"matched_selections":["keywords"],"matched_fields":[]}"#);
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_auto_format_detects_syslog() {
    let syslog_rule = r#"
title: Sudo Usage
id: 00000000-0000-0000-0000-000000000098
status: test
logsource:
    product: linux
    service: auth
detection:
    keywords:
        - 'sudo'
    condition: keywords
level: low
"#;
    let rule = temp_file(".yml", syslog_rule);
    let syslog_line = "<38>Apr 25 14:30:00 web01 sudo: admin : TTY=pts/0 ; COMMAND=/bin/bash";

    let output = rsigma()
        .args([
            "engine",
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--input-format",
            "auto",
        ])
        .write_stdin(format!("{syslog_line}\n"))
        .output()
        .unwrap();

    assert!(output.status.success());
    insta::assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r#"{"rule_title":"Sudo Usage","rule_id":"00000000-0000-0000-0000-000000000098","level":"low","tags":[],"matched_selections":["keywords"],"matched_fields":[]}"#);
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_plain_input_format() {
    let plain_rule = r#"
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
"#;
    let rule = temp_file(".yml", plain_rule);

    let output = rsigma()
        .args([
            "engine",
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
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
// State restore mode tests
// ---------------------------------------------------------------------------

#[cfg(feature = "daemon")]
#[test]
fn daemon_clear_state_prevents_restore() {
    let rules = temp_file(".yml", DAEMON_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("state.db");

    // Run 1: send 2 events to build state (below threshold)
    let events_run1 = "{\"EventType\":\"login\",\"User\":\"admin\"}\n\
                        {\"EventType\":\"login\",\"User\":\"admin\"}\n";
    rsigma()
        .args([
            "engine",
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

    // Run 2: send 1 event with --clear-state. State is wiped, so total is 1, not 3.
    let output = rsigma()
        .args([
            "engine",
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--state-db",
            db_path.to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--no-detections",
            "--clear-state",
        ])
        .write_stdin("{\"EventType\":\"login\",\"User\":\"admin\"}\n")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "--clear-state should prevent restore, so correlation should not fire: {stdout}"
    );
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_keep_state_forces_restore() {
    let rules = temp_file(".yml", DAEMON_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("state.db");

    // Run 1: send 2 events (below threshold)
    let events_run1 = "{\"EventType\":\"login\",\"User\":\"admin\"}\n\
                        {\"EventType\":\"login\",\"User\":\"admin\"}\n";
    rsigma()
        .args([
            "engine",
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

    // Run 2: send 1 event with --keep-state. Restored 2 + 1 = 3, should fire.
    let output = rsigma()
        .args([
            "engine",
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--state-db",
            db_path.to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--no-detections",
            "--keep-state",
        ])
        .write_stdin("{\"EventType\":\"login\",\"User\":\"admin\"}\n")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"rule_title\":\"Many Logins\""),
        "--keep-state should restore correlation state: {stdout}"
    );
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_clear_state_and_keep_state_conflict() {
    let rules = temp_file(".yml", DAEMON_CORRELATION_RULES);

    rsigma()
        .args([
            "engine",
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--clear-state",
            "--keep-state",
        ])
        .write_stdin("")
        .assert()
        .failure();
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_timestamp_fallback_skip() {
    let rules = temp_file(".yml", DAEMON_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("state.db");

    // Send 4 events WITHOUT timestamps with --timestamp-fallback skip.
    // Detection fires (stateless), but correlation should not count them
    // because events without parseable timestamps are skipped.
    let events = "{\"EventType\":\"login\",\"User\":\"admin\"}\n\
                   {\"EventType\":\"login\",\"User\":\"admin\"}\n\
                   {\"EventType\":\"login\",\"User\":\"admin\"}\n\
                   {\"EventType\":\"login\",\"User\":\"admin\"}\n";
    let output = rsigma()
        .args([
            "engine",
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--state-db",
            db_path.to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--no-detections",
            "--timestamp-fallback",
            "skip",
        ])
        .write_stdin(events)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("Many Logins"),
        "--timestamp-fallback skip should prevent correlation from firing: {stdout}"
    );
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_timestamp_fallback_wallclock_default() {
    let rules = temp_file(".yml", DAEMON_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("state.db");

    // Same events without timestamps, but default (wallclock) fallback.
    // Correlation should fire because wallclock substitutes current time.
    let events = "{\"EventType\":\"login\",\"User\":\"admin\"}\n\
                   {\"EventType\":\"login\",\"User\":\"admin\"}\n\
                   {\"EventType\":\"login\",\"User\":\"admin\"}\n";
    let output = rsigma()
        .args([
            "engine",
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--state-db",
            db_path.to_str().unwrap(),
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
        "default wallclock fallback should allow correlation to fire: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// Schema migration test
// ---------------------------------------------------------------------------

#[cfg(feature = "daemon")]
#[test]
fn daemon_state_db_migration_from_old_schema() {
    let rules = temp_file(".yml", DAEMON_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("state.db");

    // Step 1: Create a state DB with the OLD schema (no source_sequence/source_timestamp)
    // by running the daemon once to get a valid snapshot, then stripping the new columns.
    let events = "{\"EventType\":\"login\",\"User\":\"admin\"}\n\
                   {\"EventType\":\"login\",\"User\":\"admin\"}\n";
    rsigma()
        .args([
            "engine",
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--state-db",
            db_path.to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--no-detections",
        ])
        .write_stdin(events)
        .assert()
        .success();

    // Extract the snapshot, then recreate the DB with old schema
    let snapshot: String = {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.query_row(
            "SELECT snapshot FROM rsigma_correlation_state WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap()
    };

    // Recreate with old schema (no source_sequence/source_timestamp columns)
    std::fs::remove_file(&db_path).unwrap();
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE rsigma_correlation_state (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 snapshot TEXT NOT NULL,
                 updated_at INTEGER NOT NULL
             );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO rsigma_correlation_state (id, snapshot, updated_at) VALUES (1, ?1, ?2)",
            params![&snapshot, 1000i64],
        )
        .unwrap();
    }

    // Verify old schema has no source columns
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let mut stmt = conn
            .prepare("PRAGMA table_info(rsigma_correlation_state)")
            .unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert!(
            !columns.contains(&"source_sequence".to_string()),
            "old schema should not have source_sequence"
        );
    }

    // Step 2: Run daemon with --keep-state on the old DB.
    // It should auto-migrate and restore the snapshot.
    let output = rsigma()
        .args([
            "engine",
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--state-db",
            db_path.to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
            "--no-detections",
            "--keep-state",
        ])
        .write_stdin("{\"EventType\":\"login\",\"User\":\"admin\"}\n")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"rule_title\":\"Many Logins\""),
        "migrated DB should restore state (2 from old + 1 new = 3): {stdout}"
    );

    // Step 3: Verify schema was migrated (new columns exist)
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let mut stmt = conn
        .prepare("PRAGMA table_info(rsigma_correlation_state)")
        .unwrap();
    let columns: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    assert!(
        columns.contains(&"source_sequence".to_string()),
        "schema should be migrated to include source_sequence"
    );
    assert!(
        columns.contains(&"source_timestamp".to_string()),
        "schema should be migrated to include source_timestamp"
    );
}

/// Regression test: a daemon reading from stdin must shut down promptly on
/// SIGINT even when stdin is idle (open but no pending line, no EOF).
///
/// `tokio::io::stdin()` reads via an uncancellable blocking thread that the
/// runtime waits for at shutdown, so the daemon used to hang on Ctrl+C until
/// another line or EOF arrived. The dedicated `std::thread`-based stdin reader
/// fixes that. This is Unix-only because it relies on POSIX signal delivery.
#[cfg(all(unix, feature = "daemon"))]
#[test]
fn daemon_stdin_exits_promptly_on_sigint() {
    use std::io::{BufRead, BufReader};
    use std::net::TcpStream;
    use std::process::{Command as StdCommand, Stdio};
    use std::time::{Duration, Instant};

    let rules = temp_file(".yml", SIMPLE_RULE);

    let mut child = StdCommand::new(common::rsigma_bin())
        .args([
            "engine",
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
        ])
        // Hold the write end of stdin open for the whole test: the source has
        // no input and never sees EOF, which is the scenario that used to hang.
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn daemon");
    let _stdin = child.stdin.take().expect("piped stdin");

    // Forward stderr lines so we can read the bound API address.
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { return };
            if tx.send(line).is_err() {
                return;
            }
        }
    });

    let kill_and_reap = |child: &mut std::process::Child| {
        let _ = child.kill();
        let _ = child.wait();
    };

    // Wait for the "API server listening" line and pull out the address.
    let addr_deadline = Instant::now() + Duration::from_secs(10);
    let api_addr = loop {
        let remaining = addr_deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        match rx.recv_timeout(remaining) {
            Ok(line) if line.contains("API server listening") => {
                let addr = serde_json::from_str::<serde_json::Value>(&line)
                    .ok()
                    .and_then(|v| v["fields"]["addr"].as_str().map(str::to_string));
                if let Some(addr) = addr {
                    break addr;
                }
            }
            Ok(_) => {}
            Err(_) => {
                kill_and_reap(&mut child);
                panic!("daemon never logged its API address within 10s");
            }
        }
    };

    // Connect to the API socket. Once it accepts, the serve task has polled
    // its graceful-shutdown future, so the SIGINT handler is installed and the
    // signal will trigger a clean shutdown rather than the default kill.
    let socket: std::net::SocketAddr = api_addr.parse().expect("valid api addr");
    let ready_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect_timeout(&socket, Duration::from_millis(200)).is_ok() {
            break;
        }
        if Instant::now() >= ready_deadline {
            kill_and_reap(&mut child);
            panic!("daemon API never became reachable within 5s");
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    let signaled = StdCommand::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("failed to run kill");
    assert!(signaled.success(), "kill -INT did not succeed");

    // The default drain timeout is 5s; a healthy shutdown is near-instant, so
    // 10s is a generous bound that still fails fast if the runtime hangs.
    let exit_deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait().expect("try_wait failed") {
            Some(status) => break status,
            None => {
                if Instant::now() >= exit_deadline {
                    kill_and_reap(&mut child);
                    panic!("daemon did not exit within 10s of SIGINT (stdin shutdown hang)");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    };

    assert!(
        status.success(),
        "daemon should exit cleanly on SIGINT, got {status:?}"
    );
}
