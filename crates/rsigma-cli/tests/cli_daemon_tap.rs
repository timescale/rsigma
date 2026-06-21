//! E2E tests for the daemon's live event tap (`GET /api/v1/tap`) and the
//! `rsigma engine tap` client.
//!
//! Each test spawns `rsigma engine daemon --input http`, opens a tap, posts a
//! few events through `/api/v1/events`, and asserts what the tap streams back.
//! Capture is live, so events are posted only after the session shows up in
//! `rsigma_tap_active_sessions`.

#![cfg(feature = "daemon")]

mod common;

use std::process::{Command as StdCommand, Stdio};
use std::time::Duration;

use common::{DaemonProcess, http_get, http_post, poll_until, rsigma, rsigma_bin, temp_file};
use predicates::prelude::*;
use serde_json::Value;

/// Spawn an HTTP-input daemon with the tap enabled via `--enable-tap` (the
/// tap is opt-in / disabled by default).
fn spawn_tap(rule_path: &str) -> DaemonProcess {
    DaemonProcess::spawn_http_with_args(rule_path, &["--enable-tap"])
}

const RULE: &str = r#"
title: Whoami Detector
id: 00000000-0000-0000-0000-0000000000aa
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

/// Read the `rsigma_tap_active_sessions` gauge from `/metrics`.
fn active_sessions(metrics_url: &str) -> u64 {
    let (_, body) = http_get(metrics_url);
    body.lines()
        .find_map(|l| l.strip_prefix("rsigma_tap_active_sessions "))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

/// Block until at least `n` tap sessions are active (or panic after 5s).
fn wait_active(metrics_url: &str, n: u64) {
    poll_until(Duration::from_secs(5), || {
        (active_sessions(metrics_url) >= n).then_some(())
    })
    .expect("tap sessions did not become active within 5s");
}

/// Split a tap response body into (event lines, summary record). The final
/// non-empty line is always the `rsigma_tap_summary` record.
fn split_capture(body: &str) -> (Vec<Value>, Value) {
    let mut lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    let summary_line = lines.pop().expect("at least a summary line");
    let summary: Value = serde_json::from_str(summary_line).expect("summary is JSON");
    assert!(
        summary.get("rsigma_tap_summary").is_some(),
        "last line must be the summary record, got: {summary_line}"
    );
    let events = lines
        .iter()
        .map(|l| serde_json::from_str(l).expect("event line is JSON"))
        .collect();
    (events, summary)
}

#[test]
fn tap_disabled_by_default_returns_503() {
    let rule = temp_file(".yml", RULE);
    // No tap config: the tap is off by default.
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let (status, body) = http_get(&daemon.url("/api/v1/tap"));
    assert_eq!(status, 503);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"], "event tap disabled");
}

#[test]
fn tap_enabled_via_config() {
    let rule = temp_file(".yml", RULE);
    // The config layer enables the tap (instead of the --enable-tap flag).
    let daemon = DaemonProcess::spawn_http_with_args_env(
        rule.path().to_str().unwrap(),
        &[],
        &[("RSIGMA_DAEMON__TAP__ENABLED", "true")],
    );

    let (status, _body) = http_get(&daemon.url("/api/v1/tap?duration=1s"));
    assert_eq!(status, 200);
}

#[test]
fn tap_duration_over_max_returns_400() {
    let rule = temp_file(".yml", RULE);
    let daemon = spawn_tap(rule.path().to_str().unwrap());

    // Default max_duration is 5m; 10m must be rejected.
    let (status, body) = http_get(&daemon.url("/api/v1/tap?duration=10m"));
    assert_eq!(status, 400);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert!(
        v["error"].as_str().unwrap().contains("exceeds"),
        "unexpected error: {v}"
    );
}

#[test]
fn tap_invalid_stage_returns_400() {
    let rule = temp_file(".yml", RULE);
    let daemon = spawn_tap(rule.path().to_str().unwrap());

    let (status, _body) = http_get(&daemon.url("/api/v1/tap?stage=bogus"));
    assert_eq!(status, 400);
}

#[test]
fn tap_captures_decoded_events() {
    let rule = temp_file(".yml", RULE);
    let daemon = spawn_tap(rule.path().to_str().unwrap());

    let metrics_url = daemon.url("/metrics");
    let post_url = daemon.url("/api/v1/events");
    let poster = std::thread::spawn(move || {
        wait_active(&metrics_url, 1);
        let (status, _) = http_post(
            &post_url,
            "{\"CommandLine\":\"whoami\"}\n{\"CommandLine\":\"id\"}",
        );
        assert_eq!(status, 200);
    });

    let (status, body) = http_get(&daemon.url("/api/v1/tap?duration=3s&stage=decoded"));
    poster.join().unwrap();
    assert_eq!(status, 200);

    let (events, summary) = split_capture(&body);
    assert!(summary["rsigma_tap_summary"]["captured"].as_u64().unwrap() >= 2);
    assert_eq!(summary["rsigma_tap_summary"]["stage"], "decoded");
    assert!(events.iter().any(|e| e["CommandLine"] == "whoami"));
    assert!(events.iter().any(|e| e["CommandLine"] == "id"));
}

#[test]
fn tap_redacts_named_fields_server_side() {
    let rule = temp_file(".yml", RULE);
    let daemon = spawn_tap(rule.path().to_str().unwrap());

    let metrics_url = daemon.url("/metrics");
    let post_url = daemon.url("/api/v1/events");
    let poster = std::thread::spawn(move || {
        wait_active(&metrics_url, 1);
        http_post(&post_url, r#"{"CommandLine":"whoami","src_ip":"10.0.0.1"}"#);
    });

    let (status, body) = http_get(&daemon.url("/api/v1/tap?duration=3s&redact=src_ip"));
    poster.join().unwrap();
    assert_eq!(status, 200);

    // The raw value must never cross the wire, not even to the tapping client.
    assert!(!body.contains("10.0.0.1"), "redacted value leaked: {body}");
    let (events, _summary) = split_capture(&body);
    let event = events
        .iter()
        .find(|e| e["CommandLine"] == "whoami")
        .unwrap();
    assert!(
        event["src_ip"]
            .as_str()
            .unwrap()
            .starts_with("rsigma:redacted:"),
        "src_ip not redacted: {event}"
    );
}

#[test]
fn tap_limit_ends_stream_early() {
    let rule = temp_file(".yml", RULE);
    let daemon = spawn_tap(rule.path().to_str().unwrap());

    let metrics_url = daemon.url("/metrics");
    let post_url = daemon.url("/api/v1/events");
    let poster = std::thread::spawn(move || {
        wait_active(&metrics_url, 1);
        http_post(
            &post_url,
            "{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n{\"a\":4}\n{\"a\":5}",
        );
    });

    // Long duration, but limit=2 must end the capture after two events.
    let (status, body) = http_get(&daemon.url("/api/v1/tap?duration=20s&limit=2"));
    poster.join().unwrap();
    assert_eq!(status, 200);

    let (events, summary) = split_capture(&body);
    assert_eq!(events.len(), 2, "limit should cap streamed events");
    assert_eq!(summary["rsigma_tap_summary"]["captured"], 2);
}

#[test]
fn tap_raw_stage_captures_unparsed_line() {
    let rule = temp_file(".yml", RULE);
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--input-format", "syslog", "--enable-tap"],
    );

    let syslog = "<34>Oct 11 22:14:15 mymachine su: tap raw test";
    let metrics_url = daemon.url("/metrics");
    let post_url = daemon.url("/api/v1/events");
    let line = syslog.to_string();
    let poster = std::thread::spawn(move || {
        wait_active(&metrics_url, 1);
        http_post(&post_url, &line);
    });

    let (status, body) = http_get(&daemon.url("/api/v1/tap?duration=3s&stage=raw"));
    poster.join().unwrap();
    assert_eq!(status, 200);

    // The raw stage captures the line exactly as received, before parsing.
    assert!(
        body.contains(syslog),
        "raw syslog line not captured verbatim: {body}"
    );
}

#[test]
fn tap_session_cap_returns_409() {
    let rule = temp_file(".yml", RULE);
    let daemon = spawn_tap(rule.path().to_str().unwrap());

    // Default max_sessions is 2: hold two open, then a third must 409.
    let metrics_url = daemon.url("/metrics");
    let hold_a = daemon.url("/api/v1/tap?duration=3s");
    let hold_b = daemon.url("/api/v1/tap?duration=3s");
    let a = std::thread::spawn(move || http_get(&hold_a));
    let b = std::thread::spawn(move || http_get(&hold_b));

    wait_active(&metrics_url, 2);
    let (status, body) = http_get(&daemon.url("/api/v1/tap?duration=1s"));
    assert_eq!(status, 409, "third session over the cap should 409");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert!(v["error"].as_str().unwrap().contains("capacity"));

    let _ = a.join();
    let _ = b.join();
}

#[test]
fn tap_fixture_replays_with_engine_eval() {
    let rule = temp_file(".yml", RULE);
    let daemon = spawn_tap(rule.path().to_str().unwrap());
    let fixture = tempfile::Builder::new()
        .suffix(".ndjson")
        .tempfile()
        .unwrap();
    let fixture_path = fixture.path().to_str().unwrap().to_string();

    // Run the client; it streams for the capture window, then writes the fixture.
    let mut child = StdCommand::new(rsigma_bin())
        .args([
            "engine",
            "tap",
            "--addr",
            daemon.api_addr(),
            "--duration",
            "3s",
            "--redact-fields",
            "src_ip",
            "-o",
            &fixture_path,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn engine tap");

    wait_active(&daemon.url("/metrics"), 1);
    let (status, _) = http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"whoami","src_ip":"10.0.0.1"}"#,
    );
    assert_eq!(status, 200);

    assert!(child.wait().expect("tap client exits").success());

    let fixture_body = std::fs::read_to_string(&fixture_path).unwrap();
    // The fixture holds the event (no summary record) with src_ip redacted.
    assert!(!fixture_body.contains("10.0.0.1"), "fixture leaked src_ip");
    assert!(
        !fixture_body.contains("rsigma_tap_summary"),
        "summary leaked into fixture"
    );
    assert!(fixture_body.contains("whoami"));

    // Round-trip: the captured fixture replays and fires the same rule.
    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "-e",
            &format!("@{fixture_path}"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Whoami Detector"));
}
