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

const GROUP_PIPELINE_YAML: &str = r#"
group:
  by:
    - match.CommandLine
  group_wait: 0s
  resolve_timeout: 1h
"#;

#[test]
fn grouping_annotates_incident_id_and_exposes_open_incidents() {
    let rule = temp_file(".yml", common::SIMPLE_RULE);
    let alert_pipeline = temp_file(".yml", GROUP_PIPELINE_YAML);

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

    // Two identical detections (no dedup): both pass through and group into one
    // incident keyed on CommandLine.
    let body = serde_json::to_string(&serde_json::json!({"CommandLine": "malware x"})).unwrap();
    for _ in 0..2 {
        let (status, _) = http_post(&daemon.url("/api/v1/events"), &body);
        assert_eq!(status, 200);
    }

    // Both pass-through lines carry the same incident_id.
    let lines = poll_until(Duration::from_secs(5), || {
        let text = std::fs::read_to_string(&output_path).ok()?;
        let lines: Vec<String> = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.to_string())
            .collect();
        (lines.len() >= 2).then_some(lines)
    })
    .expect("two grouped detections never landed in the file sink");

    let id0 =
        serde_json::from_str::<serde_json::Value>(&lines[0]).unwrap()["enrichments"]["incident_id"]
            .as_str()
            .expect("first detection must carry incident_id")
            .to_string();
    let id1 =
        serde_json::from_str::<serde_json::Value>(&lines[1]).unwrap()["enrichments"]["incident_id"]
            .as_str()
            .expect("second detection must carry incident_id")
            .to_string();
    assert_eq!(id0, id1, "both detections share one incident");

    // The admin endpoint reports the open incident with two contributing
    // results.
    let incident = poll_until(Duration::from_secs(5), || {
        let (status, body) = http_get(&daemon.url("/api/v1/incidents"));
        if status != 200 {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        let incidents = v["incidents"].as_array()?;
        incidents.first().cloned()
    })
    .expect("GET /api/v1/incidents never reported the open incident");

    assert_eq!(incident["incident_id"], serde_json::json!(id0));
    assert_eq!(incident["result_count"], serde_json::json!(2));
    assert_eq!(
        incident["group_by"]["match.CommandLine"],
        serde_json::json!("malware x")
    );
}

/// Read a plain (unlabeled) counter from a Prometheus text body.
fn counter(metrics: &str, name: &str) -> Option<u64> {
    metrics.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix(name)
            .filter(|rest| rest.starts_with(' '))
            .and_then(|rest| rest.trim().parse::<f64>().ok())
            .map(|v| v as u64)
    })
}

#[test]
fn silence_mutes_matching_detections() {
    let rule = temp_file(".yml", common::SIMPLE_RULE);
    // An empty alert-pipeline config still enables the layer, so an API
    // silence applies.
    let alert_pipeline = temp_file(".yml", "{}\n");

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

    // Create a silence matching the rule's CommandLine, before sending events.
    let silence = serde_json::json!({
        "matchers": [{"selector": "match.CommandLine", "op": "=~", "value": "malware.*"}],
        "comment": "test maintenance",
        "created_by": "ops"
    })
    .to_string();
    let (status, _) = http_post(&daemon.url("/api/v1/silences"), &silence);
    assert_eq!(status, 201, "silence creation should return 201");

    // It shows up active on the silences view.
    let (gs, gbody) = http_get(&daemon.url("/api/v1/silences"));
    assert_eq!(gs, 200);
    let view: serde_json::Value = serde_json::from_str(&gbody).unwrap();
    assert_eq!(view["count"], serde_json::json!(1));
    assert_eq!(view["silences"][0]["state"], serde_json::json!("active"));
    assert_eq!(view["silences"][0]["origin"], serde_json::json!("api"));

    // Three matching detections, all silenced.
    let body = serde_json::to_string(&serde_json::json!({"CommandLine": "malware z"})).unwrap();
    for _ in 0..3 {
        let (s, _) = http_post(&daemon.url("/api/v1/events"), &body);
        assert_eq!(s, 200);
    }

    // Wait until the metrics confirm three results were silenced.
    let ok = poll_until(Duration::from_secs(5), || {
        let (_, m) = http_get(&daemon.url("/metrics"));
        (counter(&m, "rsigma_silenced_total") == Some(3)).then_some(())
    });
    assert!(ok.is_some(), "expected three silenced results");

    // Nothing reached the sink.
    let text = std::fs::read_to_string(&output_path).unwrap_or_default();
    let lines = text.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(lines, 0, "silenced detections must not reach the sink");
}

const CRIT_RULE: &str = r#"
title: Critical Thing
id: 00000000-0000-0000-0000-0000000000c1
logsource: {category: test, product: test}
detection:
  selection:
    kind|contains: critical
    SourceIp|contains: "."
  condition: selection
level: critical
"#;

const HIGH_RULE: &str = r#"
title: High Thing
id: 00000000-0000-0000-0000-0000000000a1
logsource: {category: test, product: test}
detection:
  selection:
    kind|contains: high
    SourceIp|contains: "."
  condition: selection
level: high
"#;

const INHIBIT_PIPELINE_YAML: &str = r#"
inhibit_rules:
  - name: crit-inhibits-high
    source_match:
      - selector: level
        op: "="
        value: critical
    target_match:
      - selector: level
        op: "="
        value: high
    equal:
      - match.SourceIp
    duration: 5m
"#;

/// Read `rsigma_inhibited_total{rule="<rule>"}` from a Prometheus text body.
fn inhibited(metrics: &str, rule: &str) -> Option<u64> {
    let needle = format!("rsigma_inhibited_total{{rule=\"{rule}\"}}");
    metrics.lines().find_map(|line| {
        line.trim()
            .strip_prefix(&needle)
            .and_then(|rest| rest.trim().parse::<f64>().ok())
            .map(|v| v as u64)
    })
}

#[test]
fn inhibition_mutes_high_while_critical_active() {
    let rules_dir = tempfile::tempdir().unwrap();
    std::fs::write(rules_dir.path().join("crit.yml"), CRIT_RULE).unwrap();
    std::fs::write(rules_dir.path().join("high.yml"), HIGH_RULE).unwrap();
    let alert_pipeline = temp_file(".yml", INHIBIT_PIPELINE_YAML);

    let output_file = tempfile::NamedTempFile::new().unwrap();
    let output_path = output_file.path().to_str().unwrap().to_string();

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rules_dir.path().to_str().unwrap(),
        "--alert-pipeline",
        alert_pipeline.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--output",
        &format!("file://{output_path}"),
    ]);

    // Critical source on 10.0.0.1 first; wait until it lands so the source is
    // registered before the target arrives.
    let crit =
        serde_json::to_string(&serde_json::json!({"kind": "critical", "SourceIp": "10.0.0.1"}))
            .unwrap();
    assert_eq!(http_post(&daemon.url("/api/v1/events"), &crit).0, 200);
    let saw_crit = poll_until(Duration::from_secs(5), || {
        let text = std::fs::read_to_string(&output_path).ok()?;
        (text.lines().filter(|l| !l.trim().is_empty()).count() >= 1).then_some(())
    });
    assert!(saw_crit.is_some(), "critical source should reach the sink");

    // High target on the same IP (inhibited) and on a different IP (passes).
    let high_same =
        serde_json::to_string(&serde_json::json!({"kind": "high", "SourceIp": "10.0.0.1"}))
            .unwrap();
    let high_other =
        serde_json::to_string(&serde_json::json!({"kind": "high", "SourceIp": "10.0.0.2"}))
            .unwrap();
    assert_eq!(http_post(&daemon.url("/api/v1/events"), &high_same).0, 200);
    assert_eq!(http_post(&daemon.url("/api/v1/events"), &high_other).0, 200);

    // Wait until one inhibition is recorded.
    let ok = poll_until(Duration::from_secs(5), || {
        let (_, m) = http_get(&daemon.url("/metrics"));
        (inhibited(&m, "crit-inhibits-high") == Some(1)).then_some(())
    });
    assert!(
        ok.is_some(),
        "the same-IP high target should be inhibited once"
    );

    // Two lines reached the sink: the critical source and the other-IP high.
    let lines = poll_until(Duration::from_secs(5), || {
        let text = std::fs::read_to_string(&output_path).ok()?;
        let n = text.lines().filter(|l| !l.trim().is_empty()).count();
        (n >= 2).then_some(n)
    })
    .expect("critical + other-IP high should both reach the sink");
    assert_eq!(lines, 2, "only the same-IP high target is muted");
}
