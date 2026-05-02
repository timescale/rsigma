//! E2E tests for the `rsigma daemon` HTTP input mode and REST API.
//!
//! Each test spawns the daemon with `--input http`, discovers the actual
//! API port from the structured log output, and exercises the endpoints.

#![cfg(feature = "daemon")]

mod common;

use common::{SIMPLE_RULE, temp_file};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

fn rsigma_bin() -> String {
    assert_cmd::cargo::cargo_bin("rsigma")
        .to_str()
        .unwrap()
        .to_string()
}

struct DaemonProcess {
    child: std::process::Child,
    api_addr: String,
}

impl DaemonProcess {
    fn spawn(args: &[&str]) -> Self {
        let mut child = Command::new(rsigma_bin())
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn rsigma daemon");

        let stderr = child.stderr.take().unwrap();
        let reader = BufReader::new(stderr);
        let mut api_addr = String::new();

        for line in reader.lines() {
            let line = line.unwrap();
            if line.contains("API server listening")
                && let Some(addr) = extract_addr(&line)
            {
                api_addr = addr;
            }
            if line.contains("Sink started") {
                break;
            }
        }

        assert!(
            !api_addr.is_empty(),
            "failed to discover API address from daemon stderr"
        );

        Self { child, api_addr }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.api_addr)
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

/// Extract the `addr` field from a structured JSON log line.
/// Log format: `{"fields":{"message":"API server listening","addr":"127.0.0.1:PORT"},...}`
fn extract_addr(line: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v["fields"]["addr"].as_str().map(|s| s.to_string()))
}

fn spawn_http_daemon(rule_path: &str) -> DaemonProcess {
    DaemonProcess::spawn(&[
        "daemon",
        "-r",
        rule_path,
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ])
}

fn http_get(url: &str) -> (u16, String) {
    let resp = ureq::get(url).call().expect("HTTP GET failed");
    let status = resp.status().as_u16();
    let body = resp.into_body().read_to_string().unwrap();
    (status, body)
}

fn http_post(url: &str, body: &str) -> (u16, String) {
    match ureq::post(url).send(body) {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.into_body().read_to_string().unwrap();
            (status, body)
        }
        Err(ureq::Error::StatusCode(code)) => (code, String::new()),
        Err(e) => panic!("HTTP POST failed: {e}"),
    }
}

// ---------------------------------------------------------------------------
// API endpoint tests
// ---------------------------------------------------------------------------

#[test]
fn healthz_returns_ok() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = spawn_http_daemon(rule.path().to_str().unwrap());

    let (status, body) = http_get(&daemon.url("/healthz"));
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "ok");
}

#[test]
fn readyz_returns_ready() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = spawn_http_daemon(rule.path().to_str().unwrap());

    let (status, body) = http_get(&daemon.url("/readyz"));
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "ready");
    assert_eq!(v["rules_loaded"], true);
}

#[test]
fn list_rules_returns_counts() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = spawn_http_daemon(rule.path().to_str().unwrap());

    let (status, body) = http_get(&daemon.url("/api/v1/rules"));
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["detection_rules"], 1);
    assert_eq!(v["correlation_rules"], 0);
}

#[test]
fn status_returns_running() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = spawn_http_daemon(rule.path().to_str().unwrap());

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
    let daemon = spawn_http_daemon(rule.path().to_str().unwrap());

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
    let daemon = spawn_http_daemon(rule.path().to_str().unwrap());

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
    let daemon = spawn_http_daemon(rule.path().to_str().unwrap());

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
    let daemon = spawn_http_daemon(rule.path().to_str().unwrap());

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
    let daemon = spawn_http_daemon(rule.path().to_str().unwrap());

    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe"}"#,
    );

    // Give the engine a moment to process
    std::thread::sleep(Duration::from_millis(500));

    let (_, body) = http_get(&daemon.url("/api/v1/status"));
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
    let daemon = spawn_http_daemon(rule.path().to_str().unwrap());

    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe"}"#,
    );

    std::thread::sleep(Duration::from_millis(500));

    let (status, body) = http_get(&daemon.url("/metrics"));
    assert_eq!(status, 200);
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
