//! Integration tests for the daemon's stdin batch contract: reading stdin to
//! EOF, carrying state between runs, flushing sinks, and reporting failures.

#![cfg(feature = "daemon")]

mod common;

use std::path::Path;

use assert_cmd::Command;
use common::{DaemonProcess, http_get, rsigma, temp_file};
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

const RISK_YAML: &str = r#"
score:
  default_score: 60
objects:
  - type: rule
    selector: rule
incident:
  score_threshold: 100000
  window: 1h
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

/// Read the stored snapshot version for `table`.
fn snapshot_version(db: &Path, table: &str) -> u64 {
    let conn = rusqlite::Connection::open(db).unwrap();
    let snapshot: String = conn
        .query_row(
            &format!("SELECT snapshot FROM {table} WHERE id = 1"),
            [],
            |row| row.get(0),
        )
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
    value["version"].as_u64().unwrap()
}

/// Load the single-row snapshot in `table`, let `f` change it, and write it
/// back.
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

#[test]
fn batch_run_refuses_an_incompatible_correlation_snapshot() {
    let rules = temp_file(".yml", BATCH_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("state.db");
    let event = concat!(
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T10:00:00Z"}"#,
        "\n",
    );

    batch(rules.path(), &db)
        .write_stdin(event)
        .assert()
        .success();
    patch_snapshot(&db, "rsigma_correlation_state", |snapshot| {
        snapshot["version"] = serde_json::json!(99);
    });

    let output = batch(rules.path(), &db)
        .write_stdin(event)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "an incompatible snapshot should be a configuration error, got {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"store\":\"correlation\""),
        "stderr should name the correlation store, got: {stderr}"
    );
    assert!(
        stderr.contains("--clear-state"),
        "stderr should point at --clear-state, got: {stderr}"
    );
    assert_eq!(
        snapshot_version(&db, "rsigma_correlation_state"),
        99,
        "nothing should be written to the database before the refusal"
    );
}

#[test]
fn batch_run_refuses_an_unreadable_correlation_snapshot() {
    let rules = temp_file(".yml", BATCH_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("state.db");
    let event = concat!(
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T10:00:00Z"}"#,
        "\n",
    );

    batch(rules.path(), &db)
        .write_stdin(event)
        .assert()
        .success();
    set_raw_snapshot(&db, "rsigma_correlation_state", "not json");

    let output = batch(rules.path(), &db)
        .write_stdin(event)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "an unreadable snapshot should be a configuration error, got {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"store\":\"correlation\""),
        "stderr should name the correlation store, got: {stderr}"
    );
}

#[test]
fn batch_run_with_clear_state_replaces_an_incompatible_snapshot() {
    let rules = temp_file(".yml", BATCH_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("state.db");
    let event = concat!(
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T10:00:00Z"}"#,
        "\n",
    );

    batch(rules.path(), &db)
        .write_stdin(event)
        .assert()
        .success();
    let current = snapshot_version(&db, "rsigma_correlation_state");
    patch_snapshot(&db, "rsigma_correlation_state", |snapshot| {
        snapshot["version"] = serde_json::json!(99);
    });

    batch(rules.path(), &db)
        .args(["--clear-state"])
        .write_stdin(event)
        .assert()
        .success();
    assert_eq!(
        snapshot_version(&db, "rsigma_correlation_state"),
        current,
        "--clear-state should replace the incompatible snapshot with a current one"
    );
}

#[test]
fn batch_run_with_clear_state_starts_fresh_from_an_unreadable_snapshot() {
    let rules = temp_file(".yml", BATCH_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("state.db");
    let event = concat!(
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T10:00:00Z"}"#,
        "\n",
    );

    batch(rules.path(), &db)
        .write_stdin(event)
        .assert()
        .success();
    let current = snapshot_version(&db, "rsigma_correlation_state");
    set_raw_snapshot(&db, "rsigma_correlation_state", "not json");

    batch(rules.path(), &db)
        .args(["--clear-state"])
        .write_stdin(event)
        .assert()
        .success();
    assert_eq!(
        snapshot_version(&db, "rsigma_correlation_state"),
        current,
        "--clear-state should replace an unreadable snapshot with a current one"
    );
}

#[test]
fn batch_run_refuses_an_incompatible_risk_snapshot() {
    let rules = temp_file(".yml", common::SIMPLE_RULE);
    let risk = temp_file(".yml", RISK_YAML);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("state.db");
    let event = concat!(r#"{"CommandLine":"malware a"}"#, "\n");

    batch(rules.path(), &db)
        .args(["--risk", risk.path().to_str().unwrap()])
        .write_stdin(event)
        .assert()
        .success();
    patch_snapshot(&db, "rsigma_risk_state", |snapshot| {
        snapshot["version"] = serde_json::json!(99);
    });

    let output = batch(rules.path(), &db)
        .args(["--risk", risk.path().to_str().unwrap()])
        .write_stdin(event)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "an incompatible risk snapshot should be a configuration error, got {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"store\":\"risk\""),
        "stderr should name the risk store, got: {stderr}"
    );
}

#[test]
fn http_daemon_still_starts_fresh_on_an_incompatible_snapshot() {
    let rules = temp_file(".yml", BATCH_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("state.db");
    let event = concat!(
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T10:00:00Z"}"#,
        "\n",
    );

    batch(rules.path(), &db)
        .write_stdin(event)
        .assert()
        .success();
    patch_snapshot(&db, "rsigma_correlation_state", |snapshot| {
        snapshot["version"] = serde_json::json!(99);
    });

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rules.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--state-db",
        db.to_str().unwrap(),
    ]);
    let (status, _) = http_get(&daemon.url("/healthz"));
    assert_eq!(
        status, 200,
        "an HTTP daemon should keep starting fresh on an incompatible snapshot"
    );
}

#[cfg(feature = "daemon-otlp")]
#[test]
fn batch_run_exits_4_when_a_delivery_is_lost() {
    let rules = temp_file(".yml", common::SIMPLE_RULE);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("state.db");

    let output = batch(rules.path(), &db)
        .args([
            "--output",
            "otlphttp://127.0.0.1:1",
            "--sink-retry-max",
            "0",
        ])
        .write_stdin(concat!(r#"{"CommandLine":"malware a"}"#, "\n"))
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(4),
        "a lost delivery should be a runtime error, got {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Batch run did not complete cleanly"),
        "stderr should carry the batch summary, got: {stderr}"
    );
    assert!(
        stderr.contains("\"undelivered\":1"),
        "the summary should count the lost delivery, got: {stderr}"
    );
    assert!(
        !dir.path().join("state.db-wal").exists(),
        "the state database should still be folded into a single file"
    );
}

#[cfg(feature = "daemon-otlp")]
#[test]
fn batch_run_exits_0_when_a_failed_delivery_reaches_the_dlq() {
    let rules = temp_file(".yml", common::SIMPLE_RULE);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("state.db");
    let dlq = dir.path().join("dlq.ndjson");
    let dlq_spec = format!("file://{}", dlq.display());

    batch(rules.path(), &db)
        .args([
            "--output",
            "otlphttp://127.0.0.1:1",
            "--sink-retry-max",
            "0",
            "--dlq",
            &dlq_spec,
        ])
        .write_stdin(concat!(r#"{"CommandLine":"malware a"}"#, "\n"))
        .assert()
        .success();

    let dlqd = std::fs::read_to_string(&dlq).unwrap_or_default();
    assert!(
        dlqd.contains("sink delivery failure"),
        "the DLQ file should hold the failed delivery, got: {dlqd}"
    );
}

#[test]
fn batch_run_exits_4_on_a_stdin_read_error() {
    let rules = temp_file(".yml", BATCH_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("state.db");

    let output = batch(rules.path(), &db)
        .write_stdin(b"{\"EventType\":\"login\",\"User\":\"a\"}\n\xff\xfe\n".to_vec())
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(4),
        "a stdin read error should be a runtime error, got {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"input_read_error\":true"),
        "the summary should report the read error, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn batch_run_exits_4_when_the_state_save_fails() {
    use std::os::unix::fs::PermissionsExt;

    let rules = temp_file(".yml", BATCH_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("state.db");
    let event = concat!(
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T10:00:00Z"}"#,
        "\n",
    );

    batch(rules.path(), &db)
        .write_stdin(event)
        .assert()
        .success();

    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o444)).unwrap();
    if std::fs::OpenOptions::new().write(true).open(&db).is_ok() {
        eprintln!("skipping: the database still opens for writing (running as root)");
        return;
    }

    let output = batch(rules.path(), &db)
        .write_stdin(event)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(4),
        "a failed final save should be a runtime error, got {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"state_save_failed\":true"),
        "the summary should report the failed save, got: {stderr}"
    );
    assert!(
        stderr.contains("Failed to save state on shutdown"),
        "the shutdown save error should still be logged, got: {stderr}"
    );
}

#[test]
fn stream_mode_starts_fresh_on_an_incompatible_snapshot_and_outlives_end_of_input() {
    let rules = temp_file(".yml", BATCH_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("state.db");
    let event = concat!(
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T10:00:00Z"}"#,
        "\n",
    );

    batch(rules.path(), &db)
        .write_stdin(event)
        .assert()
        .success();
    patch_snapshot(&db, "rsigma_correlation_state", |snapshot| {
        snapshot["version"] = serde_json::json!(99);
    });

    // `DaemonProcess` gives the daemon an empty stdin, so input ends at once.
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rules.path().to_str().unwrap(),
        "--stdin-mode",
        "stream",
        "--api-addr",
        "127.0.0.1:0",
        "--state-db",
        db.to_str().unwrap(),
    ]);
    let ended = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !daemon
        .stderr_lines()
        .iter()
        .any(|line| line.contains("waiting for a shutdown signal"))
    {
        assert!(
            std::time::Instant::now() < ended,
            "stream mode never reported end of input; stderr: {:#?}",
            daemon.stderr_lines()
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let (status, _) = http_get(&daemon.url("/healthz"));
    assert_eq!(
        status, 200,
        "a stream-mode daemon should start fresh and keep serving after end of input"
    );
}

#[cfg(unix)]
#[test]
fn stream_mode_exits_0_on_a_signal_and_saves_state() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command as StdCommand, Stdio};
    use std::time::{Duration, Instant};

    let rules = temp_file(".yml", BATCH_CORRELATION_RULES);
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("state.db");

    let mut child = StdCommand::new(common::rsigma_bin())
        .args([
            "engine",
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--stdin-mode",
            "stream",
            "--api-addr",
            "127.0.0.1:0",
            "--state-db",
            db.to_str().unwrap(),
            "--timestamp-fallback",
            "skip",
            "--no-detections",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn daemon");
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin
        .write_all(
            concat!(
                r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T10:00:00Z"}"#,
                "\n",
            )
            .as_bytes(),
        )
        .unwrap();
    drop(stdin);

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

    // The signal handler is installed once the API listens, and the source
    // reports end of input after the event above was read.
    let mut listening = false;
    let mut ended = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !(listening && ended) {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        match rx.recv_timeout(remaining) {
            Ok(line) => {
                listening |= line.contains("API server listening");
                ended |= line.contains("waiting for a shutdown signal");
            }
            Err(_) => {
                common::terminate_child(&mut child, Duration::from_secs(2));
                panic!("daemon never listened and reached end of input within 10s");
            }
        }
    }

    std::thread::sleep(Duration::from_millis(200));
    assert!(
        child.try_wait().unwrap().is_none(),
        "a stream-mode daemon must keep running after end of input"
    );

    let signaled = StdCommand::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("failed to run kill");
    assert!(signaled.success(), "kill -INT did not succeed");

    let exit_deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= exit_deadline {
            common::terminate_child(&mut child, Duration::from_secs(2));
            panic!("daemon did not exit within 10s of SIGINT");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(
        status.code(),
        Some(0),
        "a stream-mode daemon stopped by a signal should exit 0, got {status:?}"
    );
    let tail: Vec<String> =
        std::iter::from_fn(|| rx.recv_timeout(Duration::from_secs(1)).ok()).collect();
    assert!(
        !tail
            .iter()
            .any(|line| line.contains("Batch run did not complete cleanly")),
        "stream mode should not report a batch result; stderr: {tail:#?}"
    );
    assert!(
        snapshot_version(&db, "rsigma_correlation_state") > 0,
        "the shutdown save should persist the correlation state"
    );
}
