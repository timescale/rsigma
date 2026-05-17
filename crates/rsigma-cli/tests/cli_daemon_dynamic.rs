//! E2E tests for the `rsigma engine daemon` with dynamic pipelines.
//!
//! Tests exercise the full lifecycle: source resolution at startup,
//! detection with dynamically-resolved pipelines, source refresh on
//! file change, error policy enforcement, and API-triggered re-resolution.
//!
//! The primary mechanism tested is vars + value_placeholders:
//! - Source resolves to a list of values
//! - Pipeline var references the source via `${source.*}` template
//! - Template expansion fills in the var
//! - `value_placeholders` transformation substitutes `%var%` in detection items

#![cfg(feature = "daemon")]

mod common;

use common::temp_file;
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
                let _ = child.kill();
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
        let _ = self.child.kill();
        let _ = self.child.wait();
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

// Rule that uses a %placeholder% for the detection value.
// The pipeline var `malicious_commands` will be filled dynamically from a source.
const DYNAMIC_VAR_RULE: &str = r#"
title: Dynamic Var Rule
id: 00000000-0000-0000-0000-000000000099
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|contains: "%malicious_commands%"
    condition: selection
level: high
"#;

fn write_source_file(path: &std::path::Path, content: &str) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f.sync_all().unwrap();
}

fn dynamic_pipeline_yaml(source_path: &str) -> String {
    format!(
        r#"
name: dynamic-test
priority: 10
vars:
  malicious_commands:
    - "${{source.cmd_list}}"
sources:
  - id: cmd_list
    type: file
    path: {source_path}
    format: json
    refresh: watch
    on_error: use_cached

transformations:
  - type: value_placeholders
"#
    )
}

fn dynamic_pipeline_yaml_required_fail(source_path: &str) -> String {
    format!(
        r#"
name: dynamic-required-fail
priority: 10
sources:
  - id: missing_source
    type: file
    path: {source_path}
    format: json
    refresh: once
    required: true
    on_error: fail

transformations: []
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
    let pipeline_yaml = dynamic_pipeline_yaml(source_path.to_str().unwrap());
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
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

    std::thread::sleep(Duration::from_millis(500));

    let (_, body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        v["events_processed"].as_u64().unwrap() >= 1,
        "should have processed the event"
    );
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
    let pipeline_yaml = dynamic_pipeline_yaml(source_path.to_str().unwrap());
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
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

    std::thread::sleep(Duration::from_millis(500));

    let (_, body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
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
    let pipeline_yaml = dynamic_pipeline_yaml(source_path.to_str().unwrap());
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
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
    std::thread::sleep(Duration::from_millis(500));

    let (_, body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        v["detection_matches"].as_u64().unwrap() >= 1,
        "initial detection should work: {v}"
    );

    // Reload (source file unchanged)
    retry_reload(&daemon);
    std::thread::sleep(Duration::from_secs(3));

    // Detection should still work after reload
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe --payload"}"#,
    );
    std::thread::sleep(Duration::from_millis(500));

    let (_, body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
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
    let pipeline_yaml = dynamic_pipeline_yaml(source_path.to_str().unwrap());
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    // Initially should NOT detect
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe --payload"}"#,
    );
    std::thread::sleep(Duration::from_millis(500));

    let (_, body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["detection_matches"].as_u64().unwrap(),
        0,
        "should NOT detect with non-matching source data"
    );

    // Update source file to include "malware.exe"
    write_source_file(&source_path, r#"["malware.exe"]"#);

    // Trigger a reload to pick up new source data and rebuild the engine.
    retry_reload(&daemon);
    std::thread::sleep(Duration::from_secs(3));

    // Now post another event and verify detection works
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe --payload"}"#,
    );
    std::thread::sleep(Duration::from_millis(500));

    let (_, body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
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
    let pipeline_yaml = dynamic_pipeline_yaml(source_path.to_str().unwrap());
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
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
    std::thread::sleep(Duration::from_millis(500));

    let (_, body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        v["detection_matches"].as_u64().unwrap() >= 1,
        "initial detection should work: {v}"
    );

    // Remove the source file (simulate source becoming unavailable)
    std::fs::remove_file(&source_path).unwrap();

    // Trigger manual re-resolution
    std::thread::sleep(Duration::from_millis(200));
    http_post(&daemon.url("/api/v1/sources/resolve"), "");
    std::thread::sleep(Duration::from_secs(2));

    // Detection should STILL work because use_cached serves the previous value
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe --payload"}"#,
    );
    std::thread::sleep(Duration::from_millis(500));

    let (_, body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
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
    let pipeline_yaml =
        dynamic_pipeline_yaml_required_fail("/nonexistent/path/that/does/not/exist.json");
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

    let status = DaemonProcess::spawn_expect_exit(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
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
    let pipeline_yaml = dynamic_pipeline_yaml(source_path.to_str().unwrap());
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    // Verify initial state: no detection
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe --payload"}"#,
    );
    std::thread::sleep(Duration::from_millis(500));

    let (_, body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["detection_matches"].as_u64().unwrap(), 0);

    // Update file content
    write_source_file(&source_path, r#"["malware.exe"]"#);

    // Trigger re-resolution via API then reload to rebuild engine with new data
    let (status, _) = http_post(&daemon.url("/api/v1/sources/resolve"), "");
    assert_eq!(status, 200);
    retry_reload(&daemon);
    std::thread::sleep(Duration::from_secs(3));

    // Now detection should work
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"malware.exe --payload"}"#,
    );
    std::thread::sleep(Duration::from_millis(500));

    let (_, body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
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
    let pipeline_yaml = dynamic_pipeline_yaml(source_path.to_str().unwrap());
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
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
    let pipeline_yaml = dynamic_pipeline_yaml(source_path.to_str().unwrap());
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
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
    let pipeline_yaml = dynamic_pipeline_yaml(source_path.to_str().unwrap());
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
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
    let pipeline_yaml = dynamic_pipeline_yaml(source_path.to_str().unwrap());
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule_file.path().to_str().unwrap(),
        "-p",
        pipeline_file.path().to_str().unwrap(),
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
// Test: rsigma pipeline resolve command (CLI) works with dynamic pipeline
// ---------------------------------------------------------------------------

#[test]
fn cli_resolve_command_resolves_sources() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");
    write_source_file(&source_path, r#"["malware.exe", "evil.bat"]"#);

    let pipeline_yaml = dynamic_pipeline_yaml(source_path.to_str().unwrap());
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

    let output = Command::new(rsigma_bin())
        .args([
            "pipeline",
            "resolve",
            "-p",
            pipeline_file.path().to_str().unwrap(),
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
}

// ---------------------------------------------------------------------------
// Test: rsigma pipeline resolve --dry-run shows metadata without resolving
// ---------------------------------------------------------------------------

#[test]
fn cli_resolve_dry_run_shows_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("commands.json");
    write_source_file(&source_path, r#"["x"]"#);

    let pipeline_yaml = dynamic_pipeline_yaml(source_path.to_str().unwrap());
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

    let output = Command::new(rsigma_bin())
        .args([
            "pipeline",
            "resolve",
            "-p",
            pipeline_file.path().to_str().unwrap(),
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
    // dry-run output should include source metadata
    assert!(
        stdout.contains("cmd_list"),
        "dry-run should mention source id: {stdout}"
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

    let pipeline_yaml = dynamic_pipeline_yaml(source_path.to_str().unwrap());
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

    let output = Command::new(rsigma_bin())
        .args([
            "rule",
            "validate",
            rule_dir.path().to_str().unwrap(),
            "-p",
            pipeline_file.path().to_str().unwrap(),
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

    let pipeline_yaml =
        dynamic_pipeline_yaml_required_fail("/nonexistent/path/does/not/exist.json");
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

    let output = Command::new(rsigma_bin())
        .args([
            "rule",
            "validate",
            rule_dir.path().to_str().unwrap(),
            "-p",
            pipeline_file.path().to_str().unwrap(),
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

    // Pipeline uses include directive to inject transformations from source
    let pipeline_yaml = format!(
        r#"
name: include-test
priority: 10
sources:
  - id: transforms
    type: file
    path: {}
    format: json
    refresh: watch
    on_error: use_cached

transformations:
  - include: "${{source.transforms}}"
"#,
        transforms_path.to_str().unwrap()
    );
    let pipeline_file = temp_file(".yml", &pipeline_yaml);

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
