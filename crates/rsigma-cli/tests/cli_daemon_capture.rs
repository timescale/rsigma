//! Integration coverage for verdict-driven capture and disposition spooling.

#![cfg(feature = "daemon")]

mod common;

use common::{
    DaemonProcess, SIMPLE_RULE, http_get, http_post, poll_until, rsigma, spawn_expect_failure,
    temp_file,
};
use std::time::Duration;
use tempfile::TempDir;

const GROUP_PIPELINE_YAML: &str = r#"
group:
  by:
    - match.CommandLine
  group_wait: 0s
  resolve_timeout: 1h
"#;

fn capture_config(spool_dir: &std::path::Path) -> String {
    format!(
        "daemon:\n  capture:\n    spool_dir: {}\n",
        spool_dir.display()
    )
}

#[test]
fn capture_requires_dispositions() {
    let rules = temp_file(".yml", SIMPLE_RULE);
    let spool = TempDir::new().unwrap();
    let config = temp_file(".yaml", &capture_config(spool.path()));
    let stderr = spawn_expect_failure(
        &[
            "engine",
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--config",
            config.path().to_str().unwrap(),
            "--enable-capture",
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
        ],
        Duration::from_secs(10),
    );
    assert!(
        stderr.contains("daemon.capture.enabled requires daemon.dispositions.enabled"),
        "expected dispositions requirement, got: {stderr}"
    );
}

#[test]
fn capture_requires_group_by() {
    let rules = temp_file(".yml", SIMPLE_RULE);
    let spool = TempDir::new().unwrap();
    let config = temp_file(".yaml", &capture_config(spool.path()));
    let stderr = spawn_expect_failure(
        &[
            "engine",
            "daemon",
            "-r",
            rules.path().to_str().unwrap(),
            "--config",
            config.path().to_str().unwrap(),
            "--enable-capture",
            "--enable-dispositions",
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
        ],
        Duration::from_secs(10),
    );
    assert!(
        stderr.contains("group_by") || stderr.contains("Capture requires"),
        "expected group_by requirement, got: {stderr}"
    );
}

#[test]
fn accepted_tp_writes_backtestable_bundle() {
    let rules = temp_file(".yml", SIMPLE_RULE);
    let pipeline = temp_file(".yml", GROUP_PIPELINE_YAML);
    let spool = TempDir::new().unwrap();
    let config = temp_file(".yaml", &capture_config(spool.path()));
    let sink = tempfile::NamedTempFile::new().unwrap();
    let sink_path = sink.path().to_str().unwrap().to_string();

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rules.path().to_str().unwrap(),
        "--alert-pipeline",
        pipeline.path().to_str().unwrap(),
        "--config",
        config.path().to_str().unwrap(),
        "--enable-capture",
        "--enable-dispositions",
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--output",
        &format!("file://{sink_path}"),
    ]);

    let body = serde_json::to_string(&serde_json::json!({"CommandLine": "malware x"})).unwrap();
    let (status, _) = http_post(&daemon.url("/api/v1/events"), &body);
    assert_eq!(status, 200);

    let incident_id = poll_until(Duration::from_secs(5), || {
        let (status, body) = http_get(&daemon.url("/api/v1/incidents"));
        if status != 200 {
            return None;
        }
        let value: serde_json::Value = serde_json::from_str(&body).ok()?;
        value["incidents"]
            .as_array()?
            .first()?
            .get("incident_id")?
            .as_str()
            .map(str::to_string)
    })
    .expect("open incident never appeared");

    let (status, response) = http_post(
        &daemon.url("/api/v1/dispositions"),
        &serde_json::json!({
            "verdict": "true_positive",
            "scope": "incident",
            "incident_id": incident_id,
        })
        .to_string(),
    );
    assert_eq!(status, 200, "disposition ingest failed: {response}");
    assert!(
        response.contains("queued") || response.contains("written") || response.contains("exists"),
        "expected a capture spool status, got: {response}"
    );

    let bundle = poll_until(Duration::from_secs(5), || {
        let tp = spool.path().join("tp");
        let entries = std::fs::read_dir(&tp).ok()?;
        for entry in entries.flatten() {
            let manifest = entry.path().join("manifest.json");
            if manifest.is_file() {
                return Some(entry.path());
            }
        }
        None
    })
    .expect("TP bundle was never written");

    let corpus = std::fs::read_to_string(bundle.join("corpus/events.ndjson")).unwrap();
    assert!(
        corpus.contains("malware x"),
        "bare corpus should contain the source event: {corpus}"
    );
    assert!(bundle.join("expectations.yml").is_file());
    assert!(bundle.join("provenance/events.ndjson").is_file());

    rsigma()
        .args([
            "rule",
            "backtest",
            "-r",
            rules.path().to_str().unwrap(),
            "--corpus",
            bundle.join("corpus").to_str().unwrap(),
            "--expectations",
            bundle.join("expectations.yml").to_str().unwrap(),
        ])
        .assert()
        .success();
}
