//! E2E tests for the `rsigma engine daemon` with dynamic pipelines.
//!
//! Tests exercise the full lifecycle: source resolution at startup,
//! detection with dynamically-resolved pipelines, source refresh on
//! file change, error policy enforcement, and API-triggered re-resolution.
//!
//! Source declarations live in standalone `--source` files (pipeline-embedded
//! `sources:` blocks were removed in v0.19.0); a pipeline references them via
//! `${source.*}` templates. The primary mechanism tested is vars +
//! value_placeholders:
//! - An external source resolves to a list of values
//! - Pipeline var references the source via `${source.*}` template
//! - Template expansion fills in the var
//! - `value_placeholders` transformation substitutes `%var%` in detection items

#![cfg(feature = "daemon")]

mod common;

use common::{temp_file, terminate_child};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
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
    stderr_lines: Arc<Mutex<Vec<String>>>,
}

impl DaemonProcess {
    fn spawn(args: &[&str]) -> Self {
        let mut child = Command::new(rsigma_bin())
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn rsigma engine daemon");

        let stderr = child.stderr.take().unwrap();
        let stderr_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let lines_clone = stderr_lines.clone();

        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                lines_clone.lock().unwrap().push(line);
            }
        });

        let mut api_addr = String::new();
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(15);

        loop {
            if start.elapsed() > timeout {
                let lines = stderr_lines.lock().unwrap();
                panic!(
                    "daemon did not start within timeout. stderr:\n{}",
                    lines.join("\n")
                );
            }

            let lines = stderr_lines.lock().unwrap();
            for line in lines.iter() {
                if line.contains("API server listening")
                    && api_addr.is_empty()
                    && let Some(addr) = extract_addr(line)
                {
                    api_addr = addr;
                }
            }
            let found_sink = lines.iter().any(|l| l.contains("Sink started"));
            drop(lines);

            if !api_addr.is_empty() && found_sink {
                break;
            }

            std::thread::sleep(Duration::from_millis(50));
        }

        Self {
            child,
            api_addr,
            stderr_lines,
        }
    }

    fn spawn_expect_exit(args: &[&str]) -> std::process::ExitStatus {
        let mut child = Command::new(rsigma_bin())
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn rsigma engine daemon");

        let timeout = Duration::from_secs(10);
        let start = std::time::Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if start.elapsed() > timeout {
                terminate_child(&mut child, Duration::from_secs(2));
                panic!("daemon did not exit within timeout");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.api_addr)
    }

    #[allow(dead_code)]
    fn stderr_log(&self) -> String {
        self.stderr_lines.lock().unwrap().join("\n")
    }

    fn kill(&mut self) {
        terminate_child(&mut self.child, Duration::from_secs(5));
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

fn extract_addr(line: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v["fields"]["addr"].as_str().map(|s| s.to_string()))
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

fn retry_reload(daemon: &DaemonProcess) {
    for _ in 0..10 {
        let (status, _) = http_post(&daemon.url("/api/v1/reload"), "");
        if status == 200 {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("reload failed after retries");
}

fn http_delete(url: &str) -> (u16, String) {
    match ureq::delete(url).call() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.into_body().read_to_string().unwrap();
            (status, body)
        }
        Err(ureq::Error::StatusCode(code)) => (code, String::new()),
        Err(e) => panic!("HTTP DELETE failed: {e}"),
    }
}

/// Read and parse the daemon `/api/v1/status` payload.
fn read_status(daemon: &DaemonProcess) -> serde_json::Value {
    let (_, body) = http_get(&daemon.url("/api/v1/status"));
    serde_json::from_str(&body).expect("status should be valid JSON")
}

/// Poll `/api/v1/status` until `pred` holds, returning the matching payload.
/// Replaces fixed sleeps that waited for asynchronous event processing.
fn wait_for_status(
    daemon: &DaemonProcess,
    deadline: Duration,
    pred: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    let end = std::time::Instant::now() + deadline;
    loop {
        let v = read_status(daemon);
        if pred(&v) {
            return v;
        }
        if std::time::Instant::now() >= end {
            panic!("status condition not met within {deadline:?}: {v}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Like [`wait_for_status`] but returns whether the condition was observed
/// instead of panicking. Used for best-effort waits (e.g. a source resolve
/// attempt completing) where a later assertion is the real check.
fn observe_status(
    daemon: &DaemonProcess,
    deadline: Duration,
    pred: impl Fn(&serde_json::Value) -> bool,
) -> bool {
    let end = std::time::Instant::now() + deadline;
    loop {
        if pred(&read_status(daemon)) {
            return true;
        }
        if std::time::Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Post `payload` repeatedly until `detection_matches` reaches `target` or the
/// deadline elapses. Robust to asynchronous reload/re-resolution: events posted
/// before the rebuilt engine is live simply do not match, so the loop keeps
/// trying until the new engine takes effect.
fn wait_for_detections(
    daemon: &DaemonProcess,
    payload: &str,
    target: u64,
    deadline: Duration,
) -> serde_json::Value {
    let end = std::time::Instant::now() + deadline;
    loop {
        http_post(&daemon.url("/api/v1/events"), payload);
        std::thread::sleep(Duration::from_millis(100));
        let v = read_status(daemon);
        if v["detection_matches"].as_u64().unwrap_or(0) >= target {
            return v;
        }
        if std::time::Instant::now() >= end {
            panic!("detection_matches did not reach {target} within {deadline:?}: {v}");
        }
    }
}

/// Total source-resolution activity (resolves + errors) reported by the daemon.
/// Used to detect that a triggered re-resolution has completed.
fn resolve_activity(v: &serde_json::Value) -> u64 {
    let ds = &v["dynamic_sources"];
    ds["resolves_total"].as_u64().unwrap_or(0) + ds["errors_total"].as_u64().unwrap_or(0)
}

// Rule that uses a %placeholder% for the detection value.
// The pipeline var `malicious_commands` is filled dynamically from a source.
const DYNAMIC_VAR_RULE: &str = r#"
title: Dynamic Var Rule
id: 00000000-0000-0000-0000-000000000099
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|contains|expand: "%malicious_commands%"
    condition: selection
level: high
"#;

fn write_source_file(path: &std::path::Path, content: &str) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f.sync_all().unwrap();
}

/// A pipeline that references the external `cmd_list` source (no inline
/// declaration, which is rejected since v0.19.0).
fn dynamic_pipeline_yaml() -> String {
    r#"
name: dynamic-test
priority: 10
vars:
  malicious_commands:
    - "${source.cmd_list}"
transformations:
  - type: value_placeholders
"#
    .to_string()
}

/// A standalone `--source` file declaring the `cmd_list` file source.
fn sources_yaml(source_path: &str) -> String {
    format!(
        r#"
sources:
  - id: cmd_list
    type: file
    path: {source_path}
    format: json
    refresh: watch
    on_error: use_cached
"#
    )
}

/// A standalone `--source` file whose `cmd_list` source is required and fails
/// hard when unreachable.
fn sources_yaml_required_fail(source_path: &str) -> String {
    format!(
        r#"
sources:
  - id: cmd_list
    type: file
    path: {source_path}
    format: json
    refresh: once
    required: true
    on_error: fail
"#
    )
}

// ---------------------------------------------------------------------------
// Test: daemon starts with dynamic pipeline, resolves file source, detects
// ---------------------------------------------------------------------------

#[test]
fn daemon_with_dynamic_pipeline_detects_via_var_expansion() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");
    write_source_file(&source_path, r#"["malware.exe", "evil.bat"]"#);

    let rule_file = temp_file(".yml", DYNAMIC_VAR_RULE);
    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(".yml", &sources_yaml(source_path.to_str().unwrap()));

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
        "--source",
        sources_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    let (status, _) = http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe --payload"}"#,
    );
    assert_eq!(status, 200);

    let v = wait_for_status(&daemon, Duration::from_secs(10), |v| {
        v["events_processed"].as_u64().unwrap_or(0) >= 1
    });
    assert!(
        v["detection_matches"].as_u64().unwrap() >= 1,
        "dynamic var expansion should enable detection: {v}"
    );
}

// ---------------------------------------------------------------------------
// Test: non-matching event does not trigger detection
// ---------------------------------------------------------------------------

#[test]
fn daemon_dynamic_pipeline_no_false_positive() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");
    write_source_file(&source_path, r#"["malware.exe", "evil.bat"]"#);

    let rule_file = temp_file(".yml", DYNAMIC_VAR_RULE);
    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(".yml", &sources_yaml(source_path.to_str().unwrap()));

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
        "--source",
        sources_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    let (status, _) = http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"notepad.exe"}"#,
    );
    assert_eq!(status, 200);

    let v = wait_for_status(&daemon, Duration::from_secs(10), |v| {
        v["events_processed"].as_u64().unwrap_or(0) >= 1
    });
    assert_eq!(
        v["detection_matches"].as_u64().unwrap(),
        0,
        "benign event should not trigger detection"
    );
}

// ---------------------------------------------------------------------------
// Test: reload preserves dynamic pipeline detection (sanity check)
// ---------------------------------------------------------------------------

#[test]
fn daemon_reload_preserves_dynamic_detection() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");
    write_source_file(&source_path, r#"["malware.exe"]"#);

    let rule_file = temp_file(".yml", DYNAMIC_VAR_RULE);
    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(".yml", &sources_yaml(source_path.to_str().unwrap()));

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
        "--source",
        sources_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    // Initial detection works
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe --payload"}"#,
    );
    wait_for_status(&daemon, Duration::from_secs(10), |v| {
        v["detection_matches"].as_u64().unwrap_or(0) >= 1
    });

    // Reload (source file unchanged), then confirm detection still works. The
    // reload is asynchronous, so re-post until the rebuilt engine matches
    // instead of sleeping for a fixed window.
    retry_reload(&daemon);
    let v = wait_for_detections(
        &daemon,
        r#"{"CommandLine":"malware.exe --payload"}"#,
        2,
        Duration::from_secs(10),
    );
    assert!(
        v["detection_matches"].as_u64().unwrap() >= 2,
        "detection should still work after reload: {v}"
    );
}

// ---------------------------------------------------------------------------
// Test: source file change triggers re-resolution and updated detection
// ---------------------------------------------------------------------------

#[test]
fn daemon_source_refresh_on_file_change() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");

    // Initial source only matches "unlikely_string" (won't match test events)
    write_source_file(&source_path, r#"["unlikely_string_xyz"]"#);

    let rule_file = temp_file(".yml", DYNAMIC_VAR_RULE);
    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(".yml", &sources_yaml(source_path.to_str().unwrap()));

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
        "--source",
        sources_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    // Initially should NOT detect. Wait until the event is processed, then
    // assert no detection occurred.
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe --payload"}"#,
    );
    let v = wait_for_status(&daemon, Duration::from_secs(10), |v| {
        v["events_processed"].as_u64().unwrap_or(0) >= 1
    });
    assert_eq!(
        v["detection_matches"].as_u64().unwrap(),
        0,
        "should NOT detect with non-matching source data"
    );

    // Update source file to include "malware.exe"
    write_source_file(&source_path, r#"["malware.exe"]"#);

    // Trigger a reload to pick up new source data and rebuild the engine, then
    // re-post until the rebuilt engine detects.
    retry_reload(&daemon);
    let v = wait_for_detections(
        &daemon,
        r#"{"CommandLine":"malware.exe --payload"}"#,
        1,
        Duration::from_secs(10),
    );
    assert!(
        v["detection_matches"].as_u64().unwrap() >= 1,
        "should detect after source file update + reload: {v}"
    );
}

// ---------------------------------------------------------------------------
// Test: error policy use_cached serves stale data when source disappears
// ---------------------------------------------------------------------------

#[test]
fn daemon_error_policy_use_cached() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");
    write_source_file(&source_path, r#"["malware.exe"]"#);

    let rule_file = temp_file(".yml", DYNAMIC_VAR_RULE);
    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(".yml", &sources_yaml(source_path.to_str().unwrap()));

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
        "--source",
        sources_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    // Initial detection should work
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe --payload"}"#,
    );
    wait_for_status(&daemon, Duration::from_secs(10), |v| {
        v["detection_matches"].as_u64().unwrap_or(0) >= 1
    });

    // Remove the source file (simulate source becoming unavailable)
    std::fs::remove_file(&source_path).unwrap();

    // Trigger manual re-resolution and wait for the resolve attempt to land
    // (it fails because the file is gone; use_cached then serves the previous
    // value). Best-effort wait: the real check is that detection still works.
    let before = resolve_activity(&read_status(&daemon));
    let (status, _) = http_post(&daemon.url("/api/v1/sources/resolve"), "");
    assert_eq!(status, 200);
    observe_status(&daemon, Duration::from_secs(5), |v| {
        resolve_activity(v) > before
    });

    // Detection should STILL work because use_cached serves the previous value
    let v = wait_for_detections(
        &daemon,
        r#"{"CommandLine":"malware.exe --payload"}"#,
        2,
        Duration::from_secs(10),
    );
    assert!(
        v["detection_matches"].as_u64().unwrap() >= 2,
        "use_cached should allow detection to continue: {v}"
    );
}

// ---------------------------------------------------------------------------
// Test: required source with on_error:fail causes daemon exit at startup
// ---------------------------------------------------------------------------

#[test]
fn daemon_required_source_fail_exits() {
    let rule_file = temp_file(".yml", DYNAMIC_VAR_RULE);
    let sources_file = temp_file(
        ".yml",
        &sources_yaml_required_fail("/nonexistent/path/that/does/not/exist.json"),
    );

    let status = DaemonProcess::spawn_expect_exit(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "--source",
        sources_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    assert!(
        !status.success(),
        "daemon should exit with non-zero when a required source with on_error:fail is unreachable"
    );
}

// ---------------------------------------------------------------------------
// Test: POST /api/v1/sources/resolve triggers re-resolution
// ---------------------------------------------------------------------------

#[test]
fn daemon_api_sources_resolve_triggers_re_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");

    // Start with a value that won't match
    write_source_file(&source_path, r#"["unlikely_string_xyz"]"#);

    let rule_file = temp_file(".yml", DYNAMIC_VAR_RULE);
    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(".yml", &sources_yaml(source_path.to_str().unwrap()));

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
        "--source",
        sources_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    // Verify initial state: no detection (after the event is processed).
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe --payload"}"#,
    );
    let v = wait_for_status(&daemon, Duration::from_secs(10), |v| {
        v["events_processed"].as_u64().unwrap_or(0) >= 1
    });
    assert_eq!(v["detection_matches"].as_u64().unwrap(), 0);

    // Update file content
    write_source_file(&source_path, r#"["malware.exe"]"#);

    // Trigger re-resolution via API, wait for it to land, then reload to
    // rebuild the engine with the new data and re-post until detection works.
    let before = resolve_activity(&read_status(&daemon));
    let (status, _) = http_post(&daemon.url("/api/v1/sources/resolve"), "");
    assert_eq!(status, 200);
    observe_status(&daemon, Duration::from_secs(5), |v| {
        resolve_activity(v) > before
    });
    retry_reload(&daemon);

    let v = wait_for_detections(
        &daemon,
        r#"{"CommandLine":"malware.exe --payload"}"#,
        1,
        Duration::from_secs(10),
    );
    assert!(
        v["detection_matches"].as_u64().unwrap() >= 1,
        "should detect after re-resolution + reload: {v}"
    );
}

// ---------------------------------------------------------------------------
// Test: /api/v1/status includes dynamic_sources summary
// ---------------------------------------------------------------------------

#[test]
fn daemon_status_includes_dynamic_sources() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");
    write_source_file(&source_path, r#"["test"]"#);

    let rule_file = temp_file(".yml", DYNAMIC_VAR_RULE);
    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(".yml", &sources_yaml(source_path.to_str().unwrap()));

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
        "--source",
        sources_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    let (status, body) = http_get(&daemon.url("/api/v1/status"));
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        v["dynamic_sources"].is_object(),
        "status should include dynamic_sources: {v}"
    );
    assert!(
        v["dynamic_sources"]["resolves_total"].as_u64().unwrap() >= 1,
        "should have at least one resolve from startup"
    );
}

// ---------------------------------------------------------------------------
// Test: Prometheus metrics include source resolution counters
// ---------------------------------------------------------------------------

#[test]
fn daemon_metrics_include_source_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");
    write_source_file(&source_path, r#"["test"]"#);

    let rule_file = temp_file(".yml", DYNAMIC_VAR_RULE);
    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(".yml", &sources_yaml(source_path.to_str().unwrap()));

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
        "--source",
        sources_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    let (status, body) = http_get(&daemon.url("/metrics"));
    assert_eq!(status, 200);
    assert!(
        body.contains("rsigma_source_resolves_total"),
        "metrics should include source resolution counter"
    );
    assert!(
        body.contains("rsigma_source_resolve_seconds"),
        "metrics should include source resolution latency histogram"
    );
    assert!(
        body.contains("cmd_list"),
        "metrics should include the source_id label"
    );
}

// ---------------------------------------------------------------------------
// Test: DELETE /api/v1/sources/cache/{source_id} invalidates cache
// ---------------------------------------------------------------------------

#[test]
fn daemon_cache_invalidation_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");
    write_source_file(&source_path, r#"["test"]"#);

    let rule_file = temp_file(".yml", DYNAMIC_VAR_RULE);
    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(".yml", &sources_yaml(source_path.to_str().unwrap()));

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
        "--source",
        sources_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    let (status, body) = http_delete(&daemon.url("/api/v1/sources/cache/cmd_list"));
    assert_eq!(status, 200, "cache invalidation should succeed: {body}");
}

// ---------------------------------------------------------------------------
// Test: GET /api/v1/sources returns source list
// ---------------------------------------------------------------------------

#[test]
fn daemon_sources_list_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");
    write_source_file(&source_path, r#"["test"]"#);

    let rule_file = temp_file(".yml", DYNAMIC_VAR_RULE);
    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(".yml", &sources_yaml(source_path.to_str().unwrap()));

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
        "--source",
        sources_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    let (status, body) = http_get(&daemon.url("/api/v1/sources"));
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let sources = v["sources"]
        .as_array()
        .expect("response should have a 'sources' array");
    assert!(!sources.is_empty(), "should have at least one source");
    assert_eq!(sources[0]["source_id"], "cmd_list");
}

// ---------------------------------------------------------------------------
// Test: rsigma pipeline resolve command (CLI) works with external sources
// ---------------------------------------------------------------------------

#[test]
fn cli_resolve_command_resolves_sources() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");
    write_source_file(&source_path, r#"["malware.exe", "evil.bat"]"#);

    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(".yml", &sources_yaml(source_path.to_str().unwrap()));

    let output = Command::new(rsigma_bin())
        .args([
            "pipeline",
            "resolve",
            "-p",
            pipeline_file.path().to_str().unwrap(),
            "--source-file",
            sources_file.path().to_str().unwrap(),
            "--pretty",
        ])
        .output()
        .expect("failed to run rsigma pipeline resolve");

    assert!(
        output.status.success(),
        "resolve should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    // Output should contain the resolved source with its data
    let fallback = vec![v.clone()];
    let sources = v.as_array().unwrap_or(&fallback);
    let cmd_list_source = sources
        .iter()
        .find(|s| s["source_id"] == "cmd_list" || s["id"] == "cmd_list")
        .unwrap_or(&sources[0]);
    assert_eq!(cmd_list_source["status"], "ok");
    assert_eq!(
        cmd_list_source["data"],
        serde_json::json!(["malware.exe", "evil.bat"]),
        "default JSON must preserve typed source data: {stdout}"
    );
    assert!(
        cmd_list_source.get("data_or_error").is_none(),
        "default JSON must preserve the legacy schema: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// Test: rsigma pipeline resolve --dry-run shows metadata without resolving
// ---------------------------------------------------------------------------

#[test]
fn cli_resolve_dry_run_shows_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");
    write_source_file(&source_path, r#"["x"]"#);

    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(".yml", &sources_yaml(source_path.to_str().unwrap()));

    let output = Command::new(rsigma_bin())
        .args([
            "pipeline",
            "resolve",
            "-p",
            pipeline_file.path().to_str().unwrap(),
            "--source-file",
            sources_file.path().to_str().unwrap(),
            "--dry-run",
            "--pretty",
        ])
        .output()
        .expect("failed to run rsigma pipeline resolve --dry-run");

    assert!(
        output.status.success(),
        "resolve --dry-run should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let fallback = vec![value.clone()];
    let sources = value.as_array().unwrap_or(&fallback);
    let source = sources
        .iter()
        .find(|source| source["source_id"] == "cmd_list")
        .expect("dry-run should include cmd_list metadata");
    assert!(
        source.get("required").is_some(),
        "missing required: {stdout}"
    );
    assert!(source.get("refresh").is_some(), "missing refresh: {stdout}");
    assert!(
        source.get("data_or_error").is_none(),
        "default dry-run JSON must preserve the legacy schema: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// Test: rsigma rule validate --resolve-sources checks source reachability
// ---------------------------------------------------------------------------

#[test]
fn cli_validate_resolve_sources_passes() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");
    write_source_file(&source_path, r#"["test"]"#);

    let rule_dir = tempfile::tempdir().unwrap();
    let rule_path = rule_dir.path().join("rule.yml");
    std::fs::write(&rule_path, DYNAMIC_VAR_RULE).unwrap();

    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(".yml", &sources_yaml(source_path.to_str().unwrap()));

    let output = Command::new(rsigma_bin())
        .args([
            "rule",
            "validate",
            rule_dir.path().to_str().unwrap(),
            "-p",
            pipeline_file.path().to_str().unwrap(),
            "--source",
            sources_file.path().to_str().unwrap(),
            "--resolve-sources",
        ])
        .output()
        .expect("failed to run rsigma rule validate");

    assert!(
        output.status.success(),
        "validate --resolve-sources should pass when sources are reachable: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// Test: rsigma rule validate --resolve-sources fails for unreachable source
// ---------------------------------------------------------------------------

#[test]
fn cli_validate_resolve_sources_fails_unreachable() {
    let rule_dir = tempfile::tempdir().unwrap();
    let rule_path = rule_dir.path().join("rule.yml");
    std::fs::write(&rule_path, DYNAMIC_VAR_RULE).unwrap();

    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(
        ".yml",
        &sources_yaml_required_fail("/nonexistent/path/does/not/exist.json"),
    );

    let output = Command::new(rsigma_bin())
        .args([
            "rule",
            "validate",
            rule_dir.path().to_str().unwrap(),
            "-p",
            pipeline_file.path().to_str().unwrap(),
            "--source",
            sources_file.path().to_str().unwrap(),
            "--resolve-sources",
        ])
        .output()
        .expect("failed to run rsigma rule validate");

    assert!(
        !output.status.success(),
        "validate --resolve-sources should fail when sources are unreachable"
    );
}

// ---------------------------------------------------------------------------
// Test: include expansion - transformation injected from source
// ---------------------------------------------------------------------------

#[test]
fn daemon_include_expansion_detects() {
    let dir = tempfile::tempdir().unwrap();

    // Source file contains transformation YAML (as JSON array).
    // The mapping says: when a rule uses "CommandLine", look for "cmd" in events.
    let transforms_path = dir.path().join("transforms.json");
    write_source_file(
        &transforms_path,
        r#"[{"type": "field_name_mapping", "mapping": {"CommandLine": "cmd"}}]"#,
    );

    // External source declaring the transforms feed.
    let sources_file = temp_file(
        ".yml",
        &format!(
            r#"
sources:
  - id: transforms
    type: file
    path: {}
    format: json
    refresh: watch
    on_error: use_cached
"#,
            transforms_path.to_str().unwrap()
        ),
    );

    // Pipeline uses an include directive to inject transformations from the source.
    let pipeline_yaml = r#"
name: include-test
priority: 10
transformations:
  - include: "${source.transforms}"
"#;
    let pipeline_file = temp_file(".yml", pipeline_yaml);

    // Rule uses standard Sigma field name "CommandLine".
    // After include expansion applies the mapping, the engine looks for "cmd" in events.
    let rule = r#"
title: Include Test Rule
id: 00000000-0000-0000-0000-000000000098
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|contains: "malware"
    condition: selection
level: high
"#;
    let rule_file = temp_file(".yml", rule);

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
        "--source",
        sources_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--allow-remote-include",
    ]);

    // Event uses the MAPPED field name "cmd" (which the rule's CommandLine maps to)
    let (status, _) = http_post(&daemon.url("/api/v1/events"), r#"{"cmd":"malware.exe"}"#);
    assert_eq!(status, 200);

    std::thread::sleep(Duration::from_millis(500));

    let (_, body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        v["detection_matches"].as_u64().unwrap() >= 1,
        "include-expanded field mapping should enable detection: {v}"
    );
}

fn rebuild_total(body: &str, result: &str) -> u64 {
    let prefix = format!("rsigma_source_rebuilds_total{{result=\"{result}\"}}");
    body.lines()
        .find(|line| line.starts_with(&prefix))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

#[test]
fn source_value_change_rebuilds_without_reload() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");
    write_source_file(&source_path, r#"["unlikely_string_xyz"]"#);

    let rule_file = temp_file(".yml", DYNAMIC_VAR_RULE);
    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(".yml", &sources_yaml(source_path.to_str().unwrap()));

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
        "--source",
        sources_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe --payload"}"#,
    );
    let v = wait_for_status(&daemon, Duration::from_secs(10), |v| {
        v["events_processed"].as_u64().unwrap_or(0) >= 1
    });
    assert_eq!(v["detection_matches"].as_u64().unwrap(), 0);

    write_source_file(&source_path, r#"["malware.exe"]"#);
    let v = wait_for_detections(
        &daemon,
        r#"{"CommandLine":"malware.exe --payload"}"#,
        1,
        Duration::from_secs(15),
    );
    assert!(
        v["detection_matches"].as_u64().unwrap() >= 1,
        "a watched source change should rebuild rules without /api/v1/reload: {v}"
    );
}

#[test]
fn source_value_unchanged_interval_does_not_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");
    write_source_file(&source_path, r#"["malware.exe"]"#);
    let sources = format!(
        r#"
sources:
  - id: cmd_list
    type: file
    path: {}
    format: json
    refresh: 1s
"#,
        source_path.display()
    );

    let rule_file = temp_file(".yml", DYNAMIC_VAR_RULE);
    let pipeline_file = temp_file(".yml", &dynamic_pipeline_yaml());
    let sources_file = temp_file(".yml", &sources);
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
        "--source",
        sources_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    let baseline = resolve_activity(&read_status(&daemon));
    wait_for_status(&daemon, Duration::from_secs(8), |v| {
        resolve_activity(v) > baseline
    });
    let (_, metrics) = http_get(&daemon.url("/metrics"));
    assert_eq!(
        rebuild_total(&metrics, "success"),
        0,
        "the same source value must not rebuild rules:\n{metrics}"
    );
}

#[test]
fn source_value_lookup_only_does_not_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("directory.json");
    write_source_file(&source_path, r#"{"10.0.0.5":"alice"}"#);
    let sources = format!(
        r#"
sources:
  - id: employee_directory
    type: file
    path: {}
    format: json
    refresh: watch
"#,
        source_path.display()
    );
    let enrichers = r#"
enrichers:
  - id: employee
    kind: detection
    type: lookup
    inject_field: employee
    source: employee_directory
    default: unknown
"#;
    let rule = r#"
title: Static Rule
id: 00000000-0000-0000-0000-000000000097
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|contains: malware
    condition: selection
level: high
"#;

    let rule_file = temp_file(".yml", rule);
    let sources_file = temp_file(".yml", &sources);
    let enrichers_file = temp_file(".yml", enrichers);
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "--source",
        sources_file.path().to_str().unwrap(),
        "--enrichers",
        enrichers_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    let baseline = resolve_activity(&read_status(&daemon));
    write_source_file(&source_path, r#"{"10.0.0.5":"bob"}"#);
    wait_for_status(&daemon, Duration::from_secs(10), |v| {
        resolve_activity(v) > baseline
    });
    let (_, metrics) = http_get(&daemon.url("/metrics"));
    assert_eq!(
        rebuild_total(&metrics, "success"),
        0,
        "a lookup-only source must not rebuild rules:\n{metrics}"
    );
}
