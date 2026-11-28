//! E2E tests for the `rsigma engine daemon` HTTP input mode and REST API.
//!
//! Each test spawns the daemon with `--input http`, discovers the actual
//! API port from the structured log output, and exercises the endpoints.

#![cfg(feature = "daemon")]

use crate::common;

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
    for phase in [
        "parse",
        "decode_merge",
        "observe",
        "evaluate",
        "result_merge",
        "dispatch",
    ] {
        assert!(
            body.contains(&format!(
                r#"rsigma_batch_phase_duration_seconds_sum{{phase="{phase}"}}"#
            )),
            "missing phase {phase}"
        );
    }
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
fn parse_error_is_processed_once_and_routed_to_dlq() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let dlq = temp_file(".ndjson", "");
    let dlq_spec = format!("file://{}", dlq.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--dlq", &dlq_spec, "--input-format", "json"],
    );

    let (status, body) = http_post(
        &daemon.url("/api/v1/events"),
        "not json\n{\"CommandLine\":\"malware.exe\"}",
    );
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["accepted"],
        2
    );

    let dlq_body = poll_until(Duration::from_secs(5), || {
        let body = std::fs::read_to_string(dlq.path()).ok()?;
        body.contains("not json").then_some(body)
    })
    .expect("parse error was not routed to the DLQ");
    assert!(dlq_body.contains("parse error"));

    let metrics = poll_until(Duration::from_secs(5), || {
        let (_, body) = http_get(&daemon.url("/metrics"));
        body.contains("rsigma_events_parse_errors_total 1")
            .then_some(body)
    })
    .expect("parse error metric was not incremented exactly once");
    assert!(metrics.contains("rsigma_events_processed_total 1"));
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

fn post_bytes(url: &str, body: Vec<u8>) -> (u16, String) {
    match ureq::post(url).send(&body[..]) {
        Ok(resp) => {
            let status = resp.status().as_u16();
            (status, resp.into_body().read_to_string().unwrap())
        }
        Err(ureq::Error::StatusCode(code)) => (code, String::new()),
        Err(e) => panic!("HTTP POST failed: {e}"),
    }
}

#[test]
fn ingest_forwards_the_lines_around_invalid_utf8() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let body = b"{\"CommandLine\":\"malware.exe a\"}\n{\"x\":\"\xff\"}\n{\"CommandLine\":\"malware.exe b\"}\n"
        .to_vec();
    let (status, response) = post_bytes(&daemon.url("/api/v1/events"), body);
    assert_eq!(
        status, 200,
        "a byte that is not UTF-8 must not refuse the batch"
    );
    let v: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(v["accepted"], 3);

    let metrics = poll_until(Duration::from_secs(5), || {
        let (_, body) = http_get(&daemon.url("/metrics"));
        body.lines()
            .any(|l| l == "rsigma_detection_matches_total 2")
            .then_some(body)
    })
    .expect("both matching lines should be evaluated");
    assert!(
        metrics
            .lines()
            .any(|l| l == r#"rsigma_input_invalid_utf8_total{source="http"} 1"#),
        "{metrics}"
    );
}

#[test]
fn ingest_with_an_over_long_line_forwards_nothing() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let mut body = b"{\"CommandLine\":\"malware.exe a\"}\n".to_vec();
    body.extend(std::iter::repeat_n(b'x', 1024 * 1024 + 1));
    body.extend_from_slice(b"\n{\"CommandLine\":\"malware.exe b\"}\n");
    let (status, _) = post_bytes(&daemon.url("/api/v1/events"), body);
    assert_eq!(status, 413);

    let (status, _) = http_post(
        &daemon.url("/api/v1/events"),
        "{\"CommandLine\":\"benign\"}\n",
    );
    assert_eq!(status, 200);
    poll_until(Duration::from_secs(5), || {
        let (_, body) = http_get(&daemon.url("/api/v1/status"));
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        (v["events_processed"].as_u64()? >= 1).then_some(())
    })
    .expect("the follow-up event should be processed");
    let (_, body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["events_processed"], 1,
        "no line of the refused request may be forwarded"
    );
    assert_eq!(v["detection_matches"], 0);
}
