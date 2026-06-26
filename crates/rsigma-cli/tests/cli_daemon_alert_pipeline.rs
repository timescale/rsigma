//! E2E tests for the daemon's `--alert-pipeline` flag (dedup stage).
//!
//! Spawns `rsigma engine daemon` with an alert-pipeline config that
//! deduplicates by `(rule, match.CommandLine)`, sends the same
//! detection-triggering event several times over `--input http`, and asserts
//! that only the first fire reaches the file sink while the rest fold into the
//! active alert (visible on `rsigma_dedup_results_total{action="folded"}`).

#![cfg(feature = "daemon")]

mod common;

use common::{DaemonProcess, http_get, http_post, poll_until, temp_file};
use std::time::Duration;

const ALERT_PIPELINE_YAML: &str = r#"
dedup:
  fingerprint:
    - rule
    - match.CommandLine
  repeat_interval: 0
  resolve_timeout: 1h
"#;

/// Read `rsigma_dedup_results_total{action="<action>"}` from a Prometheus
/// text exposition body.
fn dedup_action(metrics: &str, action: &str) -> Option<u64> {
    let needle = format!("rsigma_dedup_results_total{{action=\"{action}\"}}");
    metrics.lines().find_map(|line| {
        line.trim()
            .strip_prefix(&needle)
            .and_then(|rest| rest.trim().parse::<f64>().ok())
            .map(|v| v as u64)
    })
}

#[test]
fn dedup_folds_duplicate_detections() {
    let rule = temp_file(".yml", common::SIMPLE_RULE);
    let alert_pipeline = temp_file(".yml", ALERT_PIPELINE_YAML);

    let output_file = tempfile::NamedTempFile::new().unwrap();
    let output_path = output_file.path().to_str().unwrap().to_string();

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--alert-pipeline",
        alert_pipeline.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--output",
        &format!("file://{output_path}"),
    ]);

    // Three identical detections: the first passes through, the next two fold.
    let body =
        serde_json::to_string(&serde_json::json!({"CommandLine": "malware sample"})).unwrap();
    for _ in 0..3 {
        let (status, _) = http_post(&daemon.url("/api/v1/events"), &body);
        assert_eq!(status, 200, "POST /api/v1/events did not accept the event");
    }

    // Wait until the metrics show one emitted and two folded.
    let folded = poll_until(Duration::from_secs(5), || {
        let (_, metrics) = http_get(&daemon.url("/metrics"));
        match (
            dedup_action(&metrics, "emitted"),
            dedup_action(&metrics, "folded"),
        ) {
            (Some(1), Some(2)) => Some(()),
            _ => None,
        }
    });
    assert!(
        folded.is_some(),
        "expected exactly one emitted and two folded dedup results within 5s"
    );

    // Exactly one detection line should have reached the file sink.
    let lines: Vec<String> = std::fs::read_to_string(&output_path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "only the first fire should reach the sink; got {lines:?}"
    );

    let parsed: serde_json::Value = serde_json::from_str(&lines[0]).expect("invalid NDJSON");
    assert_eq!(parsed["rule_title"], serde_json::json!("Test Rule"));
    // The first fire is a normal detection: no dedup_state annotation.
    assert!(
        parsed.get("enrichments").is_none() || parsed["enrichments"].get("dedup_state").is_none()
    );
}
