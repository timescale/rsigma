//! E2E tests for the `rsigma engine daemon` HTTP input mode and REST API.
//!
//! Each test spawns the daemon with `--input http`, discovers the actual
//! API port from the structured log output, and exercises the endpoints.

#![cfg(feature = "daemon")]

mod common;

use common::{DaemonProcess, SIMPLE_RULE, http_get, http_post, poll_until, temp_file};
use std::time::Duration;

// ---------------------------------------------------------------------------
// API endpoint tests
// ---------------------------------------------------------------------------

#[test]
fn healthz_returns_ok() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let (status, body) = http_get(&daemon.url("/healthz"));
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "ok");
}

#[test]
fn readyz_returns_ready() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let (status, body) = http_get(&daemon.url("/readyz"));
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "ready");
    assert_eq!(v["rules_loaded"], true);
}

#[test]
fn list_rules_returns_counts() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let (status, body) = http_get(&daemon.url("/api/v1/rules"));
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["detection_rules"], 1);
    assert_eq!(v["correlation_rules"], 0);
}

#[test]
fn status_returns_running() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let (status, body) = http_get(&daemon.url("/api/v1/status"));
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "running");
    assert_eq!(v["detection_rules"], 1);
    assert!(v["uptime_seconds"].as_f64().unwrap() >= 0.0);
}

#[test]
fn metrics_returns_prometheus_format() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let (status, body) = http_get(&daemon.url("/metrics"));
    assert_eq!(status, 200);
    assert!(
        body.contains("rsigma_events_processed_total"),
        "metrics should contain rsigma_events_processed_total"
    );
}

#[test]
fn reload_triggers_successfully() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    // The file watcher may fill the reload channel on startup (especially on
    // macOS where FSEvents fires multiple events). Retry until the debounce
    // drains the channel and a slot opens.
    let mut status = 0;
    let mut body = String::new();
    for _ in 0..10 {
        (status, body) = http_post(&daemon.url("/api/v1/reload"), "");
        if status == 200 {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_eq!(
        status, 200,
        "reload should succeed after retries, got {status}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "reload_triggered");
}

// ---------------------------------------------------------------------------
// HTTP event ingestion tests
// ---------------------------------------------------------------------------

#[test]
fn ingest_single_event_accepted() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let (status, body) = http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe"}"#,
    );
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["accepted"], 1);
}

#[test]
fn ingest_ndjson_batch() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let batch = r#"{"CommandLine":"malware.exe"}
{"CommandLine":"notepad.exe"}
{"CommandLine":"calc.exe"}"#;

    let (status, body) = http_post(&daemon.url("/api/v1/events"), batch);
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["accepted"], 3);
}

#[test]
fn ingest_updates_status_counters() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe"}"#,
    );

    let body = poll_until(Duration::from_secs(5), || {
        let (_, body) = http_get(&daemon.url("/api/v1/status"));
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        let processed = v["events_processed"].as_u64()?;
        let matched = v["detection_matches"].as_u64()?;
        (processed >= 1 && matched >= 1).then_some(body)
    })
    .expect("status counters never reflected the ingested event within 5s");

    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        v["events_processed"].as_u64().unwrap() >= 1,
        "events_processed should be at least 1 after ingestion"
    );
    assert!(
        v["detection_matches"].as_u64().unwrap() >= 1,
        "detection_matches should be at least 1 for matching event"
    );
}

#[test]
fn metrics_include_per_rule_labels_after_detection() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe"}"#,
    );

    let body = poll_until(Duration::from_secs(5), || {
        let (status, body) = http_get(&daemon.url("/metrics"));
        (status == 200
            && body.contains("rsigma_detection_matches_by_rule_total")
            && body.contains(r#"rule_title="Test Rule""#)
            && body.contains(r#"level="high""#))
        .then_some(body)
    })
    .expect("per-rule detection metrics never appeared within 5s");

    assert!(
        body.contains("rsigma_detection_matches_by_rule_total"),
        "metrics should contain per-rule detection counter"
    );
    assert!(
        body.contains(r#"rule_title="Test Rule""#),
        "metrics should contain rule_title label"
    );
    assert!(
        body.contains(r#"level="high""#),
        "metrics should contain level label"
    );
}
