//! Integration tests for the daemon's stdin batch contract: reading stdin to
//! EOF, carrying state between runs, flushing sinks, and reporting failures.

#![cfg(feature = "daemon")]

mod common;

use std::path::Path;

use assert_cmd::Command;
use common::{rsigma, temp_file};
use rusqlite::params;
use tempfile::TempDir;

const BATCH_CORRELATION_RULES: &str = r#"
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
    timespan: 600s
    condition:
        gte: 3
level: high
"#;

/// A one-shot batch run over stdin that persists correlation state.
fn batch(rules: &Path, db: &Path) -> Command {
    let mut cmd = rsigma();
    cmd.args([
        "engine",
        "daemon",
        "-r",
        rules.to_str().unwrap(),
        "--api-addr",
        "127.0.0.1:0",
        "--state-db",
        db.to_str().unwrap(),
        "--timestamp-fallback",
        "skip",
        "--no-detections",
    ]);
    cmd
}

/// Load the single-row snapshot in `table`, let `f` change it, and write it
/// back.
#[allow(dead_code)]
fn patch_snapshot(db: &Path, table: &str, f: impl FnOnce(&mut serde_json::Value)) {
    let conn = rusqlite::Connection::open(db).unwrap();
    let snapshot: String = conn
        .query_row(
            &format!("SELECT snapshot FROM {table} WHERE id = 1"),
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
    f(&mut value);
    conn.execute(
        &format!("UPDATE {table} SET snapshot = ?1 WHERE id = 1"),
        params![value.to_string()],
    )
    .unwrap();
}

/// Replace the single-row snapshot in `table` with raw text.
#[allow(dead_code)]
fn set_raw_snapshot(db: &Path, table: &str, text: &str) {
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.execute(
        &format!("UPDATE {table} SET snapshot = ?1 WHERE id = 1"),
        params![text],
    )
    .unwrap();
}

#[test]
fn batch_runs_carry_a_correlation_window_across_runs() {
    let rules = temp_file(".yml", BATCH_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("state.db");

    let run1 = concat!(
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T10:00:00Z"}"#,
        "\n",
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T10:01:00Z"}"#,
        "\n",
    );
    let output1 = batch(rules.path(), &db).write_stdin(run1).output().unwrap();
    assert!(
        output1.status.success(),
        "run 1 should exit 0, got {:?}: {}",
        output1.status,
        String::from_utf8_lossy(&output1.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output1.stdout).trim().is_empty(),
        "run 1 has two events, below the threshold of three"
    );

    let run2 = concat!(
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T10:02:00Z"}"#,
        "\n",
        r#"{"EventType":"login","User":"admin"}"#,
        "\n",
    );
    let output2 = batch(rules.path(), &db).write_stdin(run2).output().unwrap();
    assert!(
        output2.status.success(),
        "run 2 should exit 0, got {:?}: {}",
        output2.status,
        String::from_utf8_lossy(&output2.stderr)
    );
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(
        stdout2.contains("\"rule_title\":\"Many Logins\""),
        "run 2 should fire the correlation over the restored window, got: {stdout2}"
    );
    assert!(
        stdout2.contains("\"aggregated_value\":3.0"),
        "the event without a timestamp is skipped, so the value stays 3.0, got: {stdout2}"
    );
}

#[test]
fn batch_run_leaves_a_single_state_file() {
    let rules = temp_file(".yml", BATCH_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("state.db");

    batch(rules.path(), &db)
        .write_stdin(r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T10:00:00Z"}"#)
        .assert()
        .success();

    assert!(db.exists(), "state.db should exist after a batch run");
    assert!(
        !dir.path().join("state.db-wal").exists(),
        "the write-ahead log should be folded back into state.db"
    );
    assert!(
        !dir.path().join("state.db-shm").exists(),
        "the shared-memory file should be gone after the process exits"
    );
}

#[test]
fn batch_run_flushes_a_file_sink_before_exit() {
    let rules = temp_file(".yml", BATCH_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("state.db");
    let output = dir.path().join("detections.ndjson");
    let output_spec = format!("file://{}", output.display());

    let events = concat!(
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T10:00:00Z"}"#,
        "\n",
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T10:01:00Z"}"#,
        "\n",
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T10:02:00Z"}"#,
        "\n",
    );
    batch(rules.path(), &db)
        .args(["--output", &output_spec])
        .write_stdin(events)
        .assert()
        .success();

    let written = std::fs::read_to_string(&output).unwrap_or_default();
    assert!(
        written.contains("\"rule_title\":\"Many Logins\""),
        "the file sink should hold the correlation line once the process exits, got: {written}"
    );
}
