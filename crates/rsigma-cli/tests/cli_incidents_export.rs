//! E2E tests for `rsigma engine incidents export`.
//!
//! Spawns a daemon with a grouping alert pipeline, opens an incident, and
//! exercises the client: both renderings, writing to a file, and the error
//! paths where the daemon's own hint has to reach the operator.

#![cfg(feature = "daemon")]

mod common;

use common::{DaemonProcess, http_get, http_post, poll_until, temp_file};
use std::process::Command;
use std::time::Duration;

const RULE: &str = r#"
title: Malware sample execution
id: 00000000-0000-0000-0000-0000000000ad
status: test
description: Detects the malware sample marker on a command line.
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|contains: "malware"
    condition: selection
level: high
custom_attributes:
    rsigma.ads.response:
        - Isolate the host.
"#;

const GROUPING: &str = r#"
group:
  by:
    - match.CommandLine
  group_wait: 0s
  resolve_timeout: 1h
"#;

struct Fixture {
    daemon: DaemonProcess,
    _rule: tempfile::NamedTempFile,
    _pipeline: tempfile::NamedTempFile,
    _output: tempfile::NamedTempFile,
}

fn fixture() -> Fixture {
    let rule = temp_file(".yml", RULE);
    let pipeline = temp_file(".yml", GROUPING);
    let output = tempfile::NamedTempFile::new().unwrap();
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--alert-pipeline",
        pipeline.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--output",
        &format!("file://{}", output.path().to_str().unwrap()),
    ]);
    Fixture {
        daemon,
        _rule: rule,
        _pipeline: pipeline,
        _output: output,
    }
}

fn open_incident(daemon: &DaemonProcess) -> String {
    let body = serde_json::to_string(&serde_json::json!({"CommandLine": "malware x"})).unwrap();
    assert_eq!(http_post(&daemon.url("/api/v1/events"), &body).0, 200);
    poll_until(Duration::from_secs(10), || {
        let (status, body) = http_get(&daemon.url("/api/v1/incidents"));
        if status != 200 {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        let incident = v["incidents"].as_array()?.first()?;
        if incident["bundle_ready"] != serde_json::json!(true) {
            return None;
        }
        Some(incident["incident_id"].as_str()?.to_string())
    })
    .expect("no incident opened within 10s")
}

/// Run `rsigma engine incidents export` against the fixture's daemon.
fn export(fixture: &Fixture, extra: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rsigma"));
    command.args(["engine", "incidents", "export"]);
    command.args(extra);
    command.args(["--addr", fixture.daemon.api_addr()]);
    command.output().expect("failed to run rsigma")
}

#[test]
fn export_writes_the_json_bundle_to_stdout() {
    let fixture = fixture();
    let id = open_incident(&fixture.daemon);

    let output = export(&fixture, &[&id]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bundle: serde_json::Value = serde_json::from_slice(&output.stdout).expect("invalid JSON");
    assert_eq!(bundle["incident"]["incident_id"], serde_json::json!(id));
    assert_eq!(bundle["schema_version"], serde_json::json!(1));
}

#[test]
fn export_writes_the_markdown_bundle_to_a_file() {
    let fixture = fixture();
    let id = open_incident(&fixture.daemon);

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bundle.md");
    let output = export(
        &fixture,
        &[
            &id,
            "--bundle-format",
            "markdown",
            "--output",
            path.to_str().unwrap(),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "the bundle went to the file");

    let report = std::fs::read_to_string(&path).unwrap();
    assert!(report.starts_with(&format!("# Incident {id}\n")));
    assert!(report.contains("Isolate the host."));

    // The sibling temporary file is renamed, never left behind.
    let entries: Vec<_> = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries.len(), 1, "{entries:?}");
}

#[test]
fn export_surfaces_the_daemons_hint_for_an_unknown_incident() {
    let fixture = fixture();
    open_incident(&fixture.daemon);

    let output = export(&fixture, &["nosuchincident"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("HTTP 404"), "{stderr}");
    assert!(stderr.contains("no such open incident"), "{stderr}");
    // The daemon's hint is preserved rather than reduced to a status code.
    assert!(stderr.contains("already resolved"), "{stderr}");
}

/// Two tokens: one that can list incidents, and one that can also read
/// bundles.
const AUTH_CONFIG: &str = r#"
daemon:
  api:
    auth:
      roles:
        incident-reader: ["incidents:read"]
        bundle-reader: ["incidents:read", "incident-bundles:read"]
      tokens:
        - name: lister
          role: incident-reader
          token_env: TEST_TOKEN_LISTER
        - name: bundler
          role: bundle-reader
          token_env: TEST_TOKEN_BUNDLER
"#;

#[test]
fn reading_a_bundle_needs_more_than_reading_incidents() {
    let rule = temp_file(".yml", RULE);
    let pipeline = temp_file(".yml", GROUPING);
    let config = temp_file(".yaml", AUTH_CONFIG);
    let daemon = DaemonProcess::spawn_with_env(
        &[
            "engine",
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--alert-pipeline",
            pipeline.path().to_str().unwrap(),
            "--config",
            config.path().to_str().unwrap(),
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
        ],
        &[
            ("TEST_TOKEN_LISTER", "tok-lister"),
            ("TEST_TOKEN_BUNDLER", "tok-bundler"),
        ],
    );

    // Authorization is decided before the handler runs, so the split shows up
    // on any id: the refused token never reaches the lookup, and the permitted
    // one does and reports the id as unknown.
    let export_with = |token: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rsigma"));
        command
            .args([
                "engine",
                "incidents",
                "export",
                "any-id",
                "--addr",
                daemon.api_addr(),
            ])
            .env("RSIGMA_API_TOKEN", token)
            .output()
            .expect("failed to run rsigma")
    };

    let refused = export_with("tok-lister");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("HTTP 403"), "{stderr}");

    // The bundle token gets past authorization and reaches the handler, which
    // reports the unknown id.
    let allowed = export_with("tok-bundler");
    let stderr = String::from_utf8_lossy(&allowed.stderr);
    assert!(stderr.contains("HTTP 404"), "{stderr}");
}

#[test]
fn export_fails_clearly_when_the_daemon_is_unreachable() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rsigma"));
    let output = command
        .args([
            "engine",
            "incidents",
            "export",
            "abc",
            "--addr",
            // Port 1 on loopback: reserved and never listening.
            "127.0.0.1:1",
        ])
        .output()
        .expect("failed to run rsigma");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("is the daemon running?"), "{stderr}");
}
