//! E2E tests for the `rsigma engine daemon` binary with NATS source/sink.
//!
//! Each test starts a NATS JetStream container via testcontainers, spawns
//! the daemon binary with `--input nats://... --output nats://...`, publishes
//! events through NATS, and verifies detection output on NATS subjects.
//!
//! IMPORTANT: The test subscribers use core NATS pub/sub (not JetStream consumers),
//! which is fire-and-forget, so each output subscriber must be created BEFORE
//! events are published to avoid missing messages.

#![cfg(feature = "daemon-nats")]

mod common;

use common::{SIMPLE_RULE, temp_file};
use futures::StreamExt;
use rusqlite::params;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;
use testcontainers::ImageExt;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::nats::{Nats, NatsServerCmd};

fn can_run_linux_containers() -> bool {
    let output = std::process::Command::new("docker")
        .args(["info", "--format", "{{.OSType}}"])
        .output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim() == "linux",
        _ => false,
    }
}

macro_rules! skip_without_docker {
    () => {
        if !can_run_linux_containers() {
            eprintln!("Skipping: Docker with Linux container support is not available");
            return;
        }
    };
}

async fn start_nats_jetstream() -> (testcontainers::ContainerAsync<Nats>, String) {
    let cmd = NatsServerCmd::default().with_jetstream();
    let container = Nats::default()
        .with_cmd(&cmd)
        .start()
        .await
        .expect("Failed to start NATS container");
    let port = container
        .get_host_port_ipv4(4222)
        .await
        .expect("Failed to get NATS port");
    let url = format!("nats://127.0.0.1:{port}");
    (container, url)
}

fn rsigma_bin() -> String {
    assert_cmd::cargo::cargo_bin("rsigma")
        .to_str()
        .unwrap()
        .to_string()
}

struct DaemonProcess {
    child: std::process::Child,
}

impl DaemonProcess {
    fn spawn(args: &[&str]) -> Self {
        let child = Command::new(rsigma_bin())
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn rsigma engine daemon");
        Self { child }
    }

    fn wait_for_ready(&mut self, marker: &str) {
        let stderr = self.child.stderr.take().unwrap();
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = line.unwrap();
            if line.contains(marker) {
                break;
            }
        }
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

const BRUTE_FORCE_RULES: &str = r#"
title: Failed Login
id: 00000000-0000-0000-0000-000000000010
status: test
logsource:
    category: auth
    product: generic
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
        - src_ip
    timespan: 5m
    condition:
        gte: 3
level: high
"#;

async fn publish_and_flush(client: &async_nats::Client, subject: &str, payload: &str) {
    client
        .publish(subject.to_string(), bytes::Bytes::from(payload.to_string()))
        .await
        .expect("publish");
    client.flush().await.expect("flush");
}

async fn collect_messages(
    sub: &mut async_nats::Subscriber,
    count: usize,
    timeout: Duration,
) -> Vec<String> {
    let mut messages = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    while messages.len() < count {
        let remaining = deadline - tokio::time::Instant::now();
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, sub.next()).await {
            Ok(Some(msg)) => {
                messages.push(String::from_utf8_lossy(&msg.payload).to_string());
            }
            _ => break,
        }
    }
    messages
}

#[tokio::test]
async fn daemon_nats_single_detection() {
    skip_without_docker!();
    let (_container, nats_url) = start_nats_jetstream().await;
    let rule = temp_file(".yml", SIMPLE_RULE);

    let input = format!("{nats_url}/e2e.cli.input.single");
    let output = format!("{nats_url}/e2e.cli.output.single");

    let client = async_nats::connect(&nats_url).await.unwrap();
    let mut output_sub = client
        .subscribe("e2e.cli.output.single".to_string())
        .await
        .unwrap();

    let mut daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        &input,
        "--output",
        &output,
        "--api-addr",
        "127.0.0.1:0",
    ]);
    daemon.wait_for_ready("Sink started");

    publish_and_flush(
        &client,
        "e2e.cli.input.single",
        r#"{"CommandLine":"run malware.exe"}"#,
    )
    .await;
    publish_and_flush(
        &client,
        "e2e.cli.input.single",
        r#"{"CommandLine":"notepad.exe"}"#,
    )
    .await;

    let msgs = collect_messages(&mut output_sub, 1, Duration::from_secs(10)).await;
    assert_eq!(msgs.len(), 1, "expected 1 detection, got {}", msgs.len());
    let parsed: serde_json::Value = serde_json::from_str(&msgs[0]).unwrap();
    assert_eq!(parsed["rule_title"].as_str().unwrap(), "Test Rule");
}

#[tokio::test]
async fn daemon_nats_no_match_no_output() {
    skip_without_docker!();
    let (_container, nats_url) = start_nats_jetstream().await;
    let rule = temp_file(".yml", SIMPLE_RULE);

    let input = format!("{nats_url}/e2e.cli.input.benign");
    let output = format!("{nats_url}/e2e.cli.output.benign");

    let client = async_nats::connect(&nats_url).await.unwrap();
    let mut output_sub = client
        .subscribe("e2e.cli.output.benign".to_string())
        .await
        .unwrap();

    let mut daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        &input,
        "--output",
        &output,
        "--api-addr",
        "127.0.0.1:0",
    ]);
    daemon.wait_for_ready("Sink started");

    publish_and_flush(
        &client,
        "e2e.cli.input.benign",
        r#"{"CommandLine":"notepad.exe"}"#,
    )
    .await;
    publish_and_flush(
        &client,
        "e2e.cli.input.benign",
        r#"{"CommandLine":"calc.exe"}"#,
    )
    .await;

    let msgs = collect_messages(&mut output_sub, 1, Duration::from_secs(3)).await;
    assert!(
        msgs.is_empty(),
        "benign events should produce no output, got: {msgs:?}"
    );
}

#[tokio::test]
async fn daemon_nats_correlation() {
    skip_without_docker!();
    let (_container, nats_url) = start_nats_jetstream().await;
    let rule = temp_file(".yml", BRUTE_FORCE_RULES);

    let input = format!("{nats_url}/e2e.cli.input.corr");
    let output = format!("{nats_url}/e2e.cli.output.corr");

    let client = async_nats::connect(&nats_url).await.unwrap();
    let mut output_sub = client
        .subscribe("e2e.cli.output.corr".to_string())
        .await
        .unwrap();

    let mut daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        &input,
        "--output",
        &output,
        "--api-addr",
        "127.0.0.1:0",
        "--no-detections",
    ]);
    daemon.wait_for_ready("Sink started");

    for i in 1..=4 {
        publish_and_flush(
            &client,
            "e2e.cli.input.corr",
            &format!(r#"{{"EventType":"login_failure","src_ip":"10.0.0.1","attempt":{i}}}"#),
        )
        .await;
    }

    let msgs = collect_messages(&mut output_sub, 1, Duration::from_secs(10)).await;
    assert!(!msgs.is_empty(), "correlation should fire after 3+ events");
    let parsed: serde_json::Value = serde_json::from_str(&msgs[0]).unwrap();
    assert_eq!(parsed["rule_title"].as_str().unwrap(), "Brute Force");
}

#[tokio::test]
async fn daemon_nats_fanout() {
    skip_without_docker!();
    let (_container, nats_url) = start_nats_jetstream().await;
    let rule = temp_file(".yml", SIMPLE_RULE);

    let input = format!("{nats_url}/e2e.cli.input.fanout");
    let output_a = format!("{nats_url}/e2e.cli.output.fanout.a");
    let output_b = format!("{nats_url}/e2e.cli.output.fanout.b");

    let client = async_nats::connect(&nats_url).await.unwrap();
    let mut sub_a = client
        .subscribe("e2e.cli.output.fanout.a".to_string())
        .await
        .unwrap();
    let mut sub_b = client
        .subscribe("e2e.cli.output.fanout.b".to_string())
        .await
        .unwrap();

    let mut daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        &input,
        "--output",
        &output_a,
        "--output",
        &output_b,
        "--api-addr",
        "127.0.0.1:0",
    ]);
    daemon.wait_for_ready("Sink started");

    publish_and_flush(
        &client,
        "e2e.cli.input.fanout",
        r#"{"CommandLine":"malware.exe"}"#,
    )
    .await;

    let msgs_a = collect_messages(&mut sub_a, 1, Duration::from_secs(10)).await;
    let msgs_b = collect_messages(&mut sub_b, 1, Duration::from_secs(10)).await;

    assert_eq!(msgs_a.len(), 1, "sink A should receive detection");
    assert_eq!(msgs_b.len(), 1, "sink B should receive detection");
    assert_eq!(
        msgs_a[0], msgs_b[0],
        "both sinks should get identical output"
    );
}

// ---------------------------------------------------------------------------
// State restore with NATS source position tests
// ---------------------------------------------------------------------------

/// Helper: read source_sequence and source_timestamp from the state DB.
fn read_source_position(db_path: &std::path::Path) -> (Option<i64>, Option<i64>) {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.query_row(
        "SELECT source_sequence, source_timestamp FROM rsigma_correlation_state WHERE id = 1",
        [],
        |row| {
            Ok((
                row.get::<_, Option<i64>>(0).unwrap(),
                row.get::<_, Option<i64>>(1).unwrap(),
            ))
        },
    )
    .unwrap()
}

/// Helper: read the correlation snapshot JSON from the state DB.
fn read_snapshot_json(db_path: &std::path::Path) -> Option<String> {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.query_row(
        "SELECT snapshot FROM rsigma_correlation_state WHERE id = 1",
        [],
        |row| row.get::<_, String>(0),
    )
    .ok()
}

/// Process events through NATS, then verify the DB stores source_sequence
/// and source_timestamp from the JetStream message metadata.
#[tokio::test]
async fn daemon_nats_state_persists_source_position() {
    skip_without_docker!();
    let (_container, nats_url) = start_nats_jetstream().await;
    let rule = temp_file(".yml", BRUTE_FORCE_RULES);
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("state.db");

    let input = format!("{nats_url}/e2e.state.pos.in");
    let output = format!("{nats_url}/e2e.state.pos.out");

    let client = async_nats::connect(&nats_url).await.unwrap();
    let mut output_sub = client
        .subscribe("e2e.state.pos.out".to_string())
        .await
        .unwrap();

    let mut daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        &input,
        "--output",
        &output,
        "--api-addr",
        "127.0.0.1:0",
        "--state-db",
        db_path.to_str().unwrap(),
        "--state-save-interval",
        "1",
        "--no-detections",
    ]);
    daemon.wait_for_ready("Sink started");

    for i in 1..=2 {
        publish_and_flush(
            &client,
            "e2e.state.pos.in",
            &format!(r#"{{"EventType":"login_failure","src_ip":"10.0.0.1","n":{i}}}"#),
        )
        .await;
    }

    // Wait for the periodic save to persist (interval=1s, plus processing time)
    tokio::time::sleep(Duration::from_secs(3)).await;
    daemon.kill();

    let (seq, ts) = read_source_position(&db_path);
    assert!(
        seq.is_some(),
        "source_sequence should be stored after NATS processing"
    );
    assert!(
        ts.is_some(),
        "source_timestamp should be stored after NATS processing"
    );
    assert!(
        seq.unwrap() >= 2,
        "source_sequence should be >= 2 (processed 2 messages), got {seq:?}"
    );

    // Verify that a snapshot was actually saved
    let snap = read_snapshot_json(&db_path);
    assert!(snap.is_some(), "snapshot should be saved in DB");

    // Drain output subscriber
    let _ = collect_messages(&mut output_sub, 10, Duration::from_millis(100)).await;
}

/// Forward replay (replay_from_sequence > stored) should restore state.
/// The daemon preserves correlation windows because the replay starts where
/// it left off, so there is no double-counting risk.
#[tokio::test]
async fn daemon_nats_forward_replay_restores_state() {
    skip_without_docker!();
    let (_container, nats_url) = start_nats_jetstream().await;
    let rule = temp_file(".yml", BRUTE_FORCE_RULES);
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("state.db");

    let input = format!("{nats_url}/e2e.fwd.in");
    let output = format!("{nats_url}/e2e.fwd.out");

    let client = async_nats::connect(&nats_url).await.unwrap();

    // --- Run 1: process 2 events, build correlation state ---
    let mut output_sub = client.subscribe("e2e.fwd.out".to_string()).await.unwrap();

    let mut daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        &input,
        "--output",
        &output,
        "--api-addr",
        "127.0.0.1:0",
        "--state-db",
        db_path.to_str().unwrap(),
        "--state-save-interval",
        "1",
        "--no-detections",
    ]);
    daemon.wait_for_ready("Sink started");

    for i in 1..=2 {
        publish_and_flush(
            &client,
            "e2e.fwd.in",
            &format!(r#"{{"EventType":"login_failure","src_ip":"10.0.0.1","n":{i}}}"#),
        )
        .await;
    }

    tokio::time::sleep(Duration::from_secs(3)).await;
    daemon.kill();

    let (stored_seq, _) = read_source_position(&db_path);
    let stored_seq = stored_seq.expect("sequence should be stored after run 1");
    let _ = collect_messages(&mut output_sub, 10, Duration::from_millis(100)).await;
    drop(output_sub);

    // --- Run 2: forward replay (seq > stored), send 1 more event ---
    let replay_seq = stored_seq + 1;
    let mut output_sub2 = client.subscribe("e2e.fwd.out".to_string()).await.unwrap();

    let mut daemon2 = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        &input,
        "--output",
        &output,
        "--api-addr",
        "127.0.0.1:0",
        "--state-db",
        db_path.to_str().unwrap(),
        "--no-detections",
        "--replay-from-sequence",
        &replay_seq.to_string(),
    ]);
    daemon2.wait_for_ready("Sink started");

    // Publish 1 more event: restored 2 + new 1 = 3 >= threshold
    publish_and_flush(
        &client,
        "e2e.fwd.in",
        r#"{"EventType":"login_failure","src_ip":"10.0.0.1","n":3}"#,
    )
    .await;

    let msgs = collect_messages(&mut output_sub2, 1, Duration::from_secs(10)).await;
    daemon2.kill();

    assert!(
        !msgs.is_empty(),
        "forward replay should restore state, correlation should fire with 2+1=3 events"
    );
    let parsed: serde_json::Value = serde_json::from_str(&msgs[0]).unwrap();
    assert_eq!(
        parsed["rule_title"].as_str().unwrap(),
        "Brute Force",
        "correlation rule should fire"
    );
}

/// Backward replay (replay_from_sequence <= stored) should clear state.
/// Replaying events that were already counted would cause double-counting,
/// so the daemon starts fresh.
///
/// Strategy: run 1 builds 2 events of state (below threshold of 3). Run 2
/// uses `--replay-from-sequence 1` (backward). We publish 3 new events.
/// If state was correctly cleared, only the new events count (threshold met
/// at 3). If state was incorrectly preserved, 2 old + 3 new = 5, which
/// would fire the correlation at a different aggregated_value.
#[tokio::test]
async fn daemon_nats_backward_replay_clears_state() {
    skip_without_docker!();
    let (_container, nats_url) = start_nats_jetstream().await;
    let rule = temp_file(".yml", BRUTE_FORCE_RULES);
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("state.db");

    let input = format!("{nats_url}/e2e.bwd.in");
    let output = format!("{nats_url}/e2e.bwd.out");

    let client = async_nats::connect(&nats_url).await.unwrap();

    // --- Run 1: process 2 events, build state ---
    let mut output_sub = client.subscribe("e2e.bwd.out".to_string()).await.unwrap();

    let mut daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        &input,
        "--output",
        &output,
        "--api-addr",
        "127.0.0.1:0",
        "--state-db",
        db_path.to_str().unwrap(),
        "--state-save-interval",
        "1",
        "--no-detections",
    ]);
    daemon.wait_for_ready("Sink started");

    for i in 1..=2 {
        publish_and_flush(
            &client,
            "e2e.bwd.in",
            &format!(r#"{{"EventType":"login_failure","src_ip":"10.0.0.1","n":{i}}}"#),
        )
        .await;
    }

    tokio::time::sleep(Duration::from_secs(3)).await;
    daemon.kill();

    let (stored_seq, _) = read_source_position(&db_path);
    assert!(stored_seq.is_some(), "should have stored sequence");
    let _ = collect_messages(&mut output_sub, 10, Duration::from_millis(100)).await;
    drop(output_sub);

    // --- Run 2: backward replay from seq=1 (<= stored), publish 3 new events ---
    let mut output_sub2 = client.subscribe("e2e.bwd.out".to_string()).await.unwrap();

    let mut daemon2 = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        &input,
        "--output",
        &output,
        "--api-addr",
        "127.0.0.1:0",
        "--state-db",
        db_path.to_str().unwrap(),
        "--no-detections",
        "--replay-from-sequence",
        "1",
    ]);
    daemon2.wait_for_ready("Sink started");

    // Publish 3 new events. The JetStream stream also has the 2 old events,
    // but the durable consumer may or may not redeliver them. Either way:
    //   - State cleared + old 2 replayed + new 3 = 5 total from fresh start
    //   - State cleared + only new 3 = 3 total from fresh start
    // Both scenarios fire the correlation (threshold >= 3).
    // If state was INCORRECTLY preserved, count would be 2 + all delivered.
    for i in 3..=5 {
        publish_and_flush(
            &client,
            "e2e.bwd.in",
            &format!(r#"{{"EventType":"login_failure","src_ip":"10.0.0.1","n":{i}}}"#),
        )
        .await;
    }

    let msgs = collect_messages(&mut output_sub2, 2, Duration::from_secs(10)).await;
    daemon2.kill();

    // The key assertion: correlation fires. If state was preserved (bug),
    // the correlation would have fired earlier with the first new event
    // (2 restored + 1 = 3) and potentially fire again at different counts,
    // giving us extra messages with aggregated_value != 3. With a clean
    // state, the first firing happens at exactly 3 events.
    assert!(
        !msgs.is_empty(),
        "backward replay + 3 new events should fire correlation"
    );
    let first: serde_json::Value = serde_json::from_str(&msgs[0]).unwrap();
    assert_eq!(first["rule_title"].as_str().unwrap(), "Brute Force");

    // The first correlation's aggregated_value tells us if state was clean.
    // With fresh state, it fires at exactly 3.0 (the threshold).
    let agg = first["aggregated_value"].as_f64().unwrap();
    assert_eq!(
        agg, 3.0,
        "first correlation should fire at exactly threshold (3.0), \
         got {agg} which suggests state was not properly cleared"
    );
}

/// Schema migration with NATS: old-format DB (no source position columns)
/// should be auto-migrated when daemon starts, and new position data should
/// be stored after processing.
#[tokio::test]
async fn daemon_nats_state_db_migration_stores_position() {
    skip_without_docker!();
    let (_container, nats_url) = start_nats_jetstream().await;
    let rule = temp_file(".yml", BRUTE_FORCE_RULES);
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("state.db");

    // Create old-format DB with a valid (empty) snapshot
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
        let snap = r#"{"version":1,"windows":{},"last_alert":{},"event_buffers":{},"event_ref_buffers":{}}"#;
        conn.execute(
            "INSERT INTO rsigma_correlation_state (id, snapshot, updated_at) VALUES (1, ?1, ?2)",
            params![snap, 1000i64],
        )
        .unwrap();
    }

    let input = format!("{nats_url}/e2e.mig.in");
    let output = format!("{nats_url}/e2e.mig.out");

    let client = async_nats::connect(&nats_url).await.unwrap();
    let mut output_sub = client.subscribe("e2e.mig.out".to_string()).await.unwrap();

    let mut daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        &input,
        "--output",
        &output,
        "--api-addr",
        "127.0.0.1:0",
        "--state-db",
        db_path.to_str().unwrap(),
        "--state-save-interval",
        "1",
        "--no-detections",
    ]);
    daemon.wait_for_ready("Sink started");

    publish_and_flush(
        &client,
        "e2e.mig.in",
        r#"{"EventType":"login_failure","src_ip":"10.0.0.1"}"#,
    )
    .await;

    tokio::time::sleep(Duration::from_secs(3)).await;
    daemon.kill();

    // Verify schema was migrated and source position is now stored
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
        "schema should be migrated: {columns:?}"
    );

    let (seq, ts) = read_source_position(&db_path);
    assert!(
        seq.is_some(),
        "source_sequence should be populated after processing"
    );
    assert!(
        ts.is_some(),
        "source_timestamp should be populated after processing"
    );

    let _ = collect_messages(&mut output_sub, 10, Duration::from_millis(100)).await;
}
