//! E2E tests for the daemon's live detection tail
//! (`GET /api/v1/detections/stream`) and the `rsigma engine tail` client.
//!
//! Each test spawns `rsigma engine daemon --input http`, opens a tail, posts
//! matching events through `/api/v1/events`, and asserts the detections the
//! tail streams back. Capture is live, so events are posted only after the
//! session shows up in `rsigma_tail_active_sessions`.

#![cfg(feature = "daemon")]

mod common;

use std::process::{Command as StdCommand, Stdio};
use std::time::Duration;

use common::{DaemonProcess, http_get, http_post, poll_until, rsigma_bin, temp_file};
use serde_json::Value;
use tempfile::TempDir;

const RULE: &str = r#"
title: Whoami Detector
id: 00000000-0000-0000-0000-0000000000bb
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|contains: "whoami"
    condition: selection
level: high
"#;

/// Spawn an HTTP-input daemon with the tail enabled via `--enable-tail` (the
/// tail is opt-in / disabled by default).
fn spawn_tail(rule_path: &str) -> DaemonProcess {
    DaemonProcess::spawn_http_with_args(rule_path, &["--enable-tail"])
}

/// Build a rules directory holding two rules with distinct titles and levels,
/// so the level / rule filters have something to discriminate.
fn two_rule_dir() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("high.yml"),
        r#"
title: High Alpha
id: 00000000-0000-0000-0000-0000000000c1
status: test
logsource: { category: test }
detection:
    selection:
        CommandLine|contains: "alpha"
    condition: selection
level: high
"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("low.yml"),
        r#"
title: Low Beta
id: 00000000-0000-0000-0000-0000000000c2
status: test
logsource: { category: test }
detection:
    selection:
        CommandLine|contains: "beta"
    condition: selection
level: low
"#,
    )
    .unwrap();
    dir
}

/// Read the `rsigma_tail_active_sessions` gauge from `/metrics`.
fn active_sessions(metrics_url: &str) -> u64 {
    let (_, body) = http_get(metrics_url);
    body.lines()
        .find_map(|l| l.strip_prefix("rsigma_tail_active_sessions "))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

fn wait_active(metrics_url: &str, n: u64) {
    poll_until(Duration::from_secs(5), || {
        (active_sessions(metrics_url) >= n).then_some(())
    })
    .expect("tail sessions did not become active within 5s");
}

/// Split a tail response body into (detection lines, summary record).
fn split_stream(body: &str) -> (Vec<Value>, Value) {
    let mut lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    let summary_line = lines.pop().expect("at least a summary line");
    let summary: Value = serde_json::from_str(summary_line).expect("summary is JSON");
    assert!(
        summary.get("rsigma_tail_summary").is_some(),
        "last line must be the summary record, got: {summary_line}"
    );
    let detections = lines
        .iter()
        .map(|l| serde_json::from_str(l).expect("detection line is JSON"))
        .collect();
    (detections, summary)
}

/// Post `payload` once the tail session is active, on a background thread.
fn post_when_active(daemon: &DaemonProcess, payload: &'static str) -> std::thread::JoinHandle<()> {
    let metrics_url = daemon.url("/metrics");
    let post_url = daemon.url("/api/v1/events");
    std::thread::spawn(move || {
        wait_active(&metrics_url, 1);
        let (status, _) = http_post(&post_url, payload);
        assert_eq!(status, 200);
    })
}

#[test]
fn tail_disabled_by_default_returns_503() {
    let rule = temp_file(".yml", RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let (status, body) = http_get(&daemon.url("/api/v1/detections/stream"));
    assert_eq!(status, 503);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"], "detection tail disabled");
}

#[test]
fn tail_enabled_via_config() {
    let rule = temp_file(".yml", RULE);
    // The config layer enables the tail (instead of the --enable-tail flag).
    let daemon = DaemonProcess::spawn_http_with_args_env(
        rule.path().to_str().unwrap(),
        &[],
        &[("RSIGMA_DAEMON__TAIL__ENABLED", "true")],
    );

    let (status, _) = http_get(&daemon.url("/api/v1/detections/stream?duration=1s"));
    assert_eq!(status, 200);
}

#[test]
fn tail_invalid_level_returns_400() {
    let rule = temp_file(".yml", RULE);
    let daemon = spawn_tail(rule.path().to_str().unwrap());

    let (status, _) = http_get(&daemon.url("/api/v1/detections/stream?level=bogus"));
    assert_eq!(status, 400);
}

#[test]
fn tail_streams_live_detections() {
    let rule = temp_file(".yml", RULE);
    let daemon = spawn_tail(rule.path().to_str().unwrap());

    let poster = post_when_active(&daemon, "{\"CommandLine\":\"run whoami\"}");
    let (status, body) = http_get(&daemon.url("/api/v1/detections/stream?duration=3s"));
    poster.join().unwrap();
    assert_eq!(status, 200);

    let (detections, summary) = split_stream(&body);
    assert!(summary["rsigma_tail_summary"]["streamed"].as_u64().unwrap() >= 1);
    assert!(
        detections
            .iter()
            .any(|d| d["rule_title"] == "Whoami Detector")
    );
}

#[test]
fn tail_level_filter_excludes_lower_severity() {
    let dir = two_rule_dir();
    let daemon = spawn_tail(dir.path().to_str().unwrap());

    let poster = post_when_active(
        &daemon,
        "{\"CommandLine\":\"alpha\"}\n{\"CommandLine\":\"beta\"}",
    );
    let (status, body) = http_get(&daemon.url("/api/v1/detections/stream?duration=3s&level=high"));
    poster.join().unwrap();
    assert_eq!(status, 200);

    let (detections, _) = split_stream(&body);
    assert!(detections.iter().any(|d| d["rule_title"] == "High Alpha"));
    assert!(
        !detections.iter().any(|d| d["rule_title"] == "Low Beta"),
        "low-severity detection must be filtered out: {body}"
    );
}

#[test]
fn tail_rule_filter_matches_title_substring() {
    let dir = two_rule_dir();
    let daemon = spawn_tail(dir.path().to_str().unwrap());

    let poster = post_when_active(
        &daemon,
        "{\"CommandLine\":\"alpha\"}\n{\"CommandLine\":\"beta\"}",
    );
    let (status, body) = http_get(&daemon.url("/api/v1/detections/stream?duration=3s&rule=alpha"));
    poster.join().unwrap();
    assert_eq!(status, 200);

    let (detections, _) = split_stream(&body);
    assert!(detections.iter().any(|d| d["rule_title"] == "High Alpha"));
    assert!(!detections.iter().any(|d| d["rule_title"] == "Low Beta"));
}

#[test]
fn tail_limit_ends_stream_early() {
    let rule = temp_file(".yml", RULE);
    let daemon = spawn_tail(rule.path().to_str().unwrap());

    let poster = post_when_active(
        &daemon,
        "{\"CommandLine\":\"whoami 1\"}\n{\"CommandLine\":\"whoami 2\"}\n{\"CommandLine\":\"whoami 3\"}",
    );
    // Long duration, but limit=2 must end the stream after two detections.
    let (status, body) = http_get(&daemon.url("/api/v1/detections/stream?duration=20s&limit=2"));
    poster.join().unwrap();
    assert_eq!(status, 200);

    let (detections, summary) = split_stream(&body);
    assert_eq!(detections.len(), 2, "limit should cap streamed detections");
    assert_eq!(summary["rsigma_tail_summary"]["streamed"], 2);
}

#[test]
fn tail_session_cap_returns_409() {
    let rule = temp_file(".yml", RULE);
    let daemon = spawn_tail(rule.path().to_str().unwrap());

    let metrics_url = daemon.url("/metrics");
    let hold_a = daemon.url("/api/v1/detections/stream?duration=3s");
    let hold_b = daemon.url("/api/v1/detections/stream?duration=3s");
    let a = std::thread::spawn(move || http_get(&hold_a));
    let b = std::thread::spawn(move || http_get(&hold_b));

    wait_active(&metrics_url, 2);
    let (status, body) = http_get(&daemon.url("/api/v1/detections/stream?duration=1s"));
    assert_eq!(status, 409, "third session over the cap should 409");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert!(v["error"].as_str().unwrap().contains("capacity"));

    let _ = a.join();
    let _ = b.join();
}

#[test]
fn tail_client_streams_detection() {
    let rule = temp_file(".yml", RULE);
    let daemon = spawn_tail(rule.path().to_str().unwrap());

    // The client ends after one detection (--limit 1), so it exits promptly.
    let child = StdCommand::new(rsigma_bin())
        .args([
            "engine",
            "tail",
            "--addr",
            daemon.api_addr(),
            "--duration",
            "5s",
            "--limit",
            "1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn engine tail");

    wait_active(&daemon.url("/metrics"), 1);
    let (status, _) = http_post(&daemon.url("/api/v1/events"), r#"{"CommandLine":"whoami"}"#);
    assert_eq!(status, 200);

    let output = child.wait_with_output().expect("tail client exits");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Whoami Detector"),
        "client did not stream the detection: {stdout}"
    );
}
