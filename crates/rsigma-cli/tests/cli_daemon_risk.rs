//! E2E tests for the daemon's `--risk` flag (risk-based alerting).
//!
//! Spawns `rsigma engine daemon` with a risk config, sends detection-triggering
//! events over `--input http`, and asserts that each firing is annotated with a
//! risk score and risk objects, that an entity crossing the score threshold
//! emits a `RiskIncidentResult`, that the incident is visible on
//! `GET /api/v1/risk` and the metrics, and that the accumulator state survives a
//! restart.

#![cfg(feature = "daemon")]

use crate::common;

use common::{DaemonProcess, http_get, http_post, poll_until, temp_file};
use std::time::Duration;

const RISK_YAML: &str = r#"
score:
  default_score: 60
objects:
  - type: rule
    selector: rule
incident:
  score_threshold: 100
  window: 1h
  cooldown: 1h
"#;

/// Read `rsigma_risk_incidents_emitted_total{trigger="<trigger>"}` from a
/// Prometheus text exposition body.
fn risk_incidents(metrics: &str, trigger: &str) -> Option<u64> {
    let needle = format!("rsigma_risk_incidents_emitted_total{{trigger=\"{trigger}\"}}");
    metrics.lines().find_map(|line| {
        line.trim()
            .strip_prefix(&needle)
            .and_then(|rest| rest.trim().parse::<f64>().ok())
            .map(|v| v as u64)
    })
}

fn nonblank_lines(path: &str) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect()
}

#[test]
fn risk_annotates_and_emits_incident_on_score_threshold() {
    let rule = temp_file(".yml", common::SIMPLE_RULE);
    let risk = temp_file(".yml", RISK_YAML);

    let output_file = tempfile::NamedTempFile::new().unwrap();
    let output_path = output_file.path().to_str().unwrap().to_string();

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--risk",
        risk.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--output",
        &format!("file://{output_path}"),
    ]);

    // Two firings of the same rule: each scores 60, so the second crosses the
    // 100 threshold and the entity (the rule id) emits one risk incident.
    let body =
        serde_json::to_string(&serde_json::json!({"CommandLine": "malware sample"})).unwrap();
    for _ in 0..2 {
        let (status, _) = http_post(&daemon.url("/api/v1/events"), &body);
        assert_eq!(status, 200, "POST /api/v1/events did not accept the event");
    }

    // Wait for exactly one score-triggered incident.
    let ok = poll_until(Duration::from_secs(5), || {
        let (_, m) = http_get(&daemon.url("/metrics"));
        (risk_incidents(&m, "score") == Some(1)).then_some(())
    });
    assert!(ok.is_some(), "expected one score-triggered risk incident");

    // The file sink carries both annotated detections plus the incident line.
    let lines = poll_until(Duration::from_secs(5), || {
        let lines = nonblank_lines(&output_path);
        (lines.len() >= 3).then_some(lines)
    })
    .expect("two detections plus one incident should reach the sink");

    let mut saw_annotation = false;
    let mut saw_incident = false;
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("invalid NDJSON");
        if let Some(id) = v.get("risk_incident_id") {
            saw_incident = true;
            assert!(id.as_str().is_some_and(|s| !s.is_empty()));
            assert_eq!(v["trigger"], serde_json::json!("score"));
            assert_eq!(v["entity_type"], serde_json::json!("rule"));
            assert_eq!(v["score"], serde_json::json!(120));
        } else if v.get("rule_title").is_some() {
            let enr = &v["enrichments"];
            assert_eq!(enr["risk.score"], serde_json::json!(60));
            assert_eq!(enr["risk.objects"][0]["type"], serde_json::json!("rule"));
            saw_annotation = true;
        }
    }
    assert!(saw_annotation, "a detection should carry risk annotation");
    assert!(saw_incident, "the incident line should reach the sink");

    // The admin endpoint reports the open entity with its accumulated score.
    let entity = poll_until(Duration::from_secs(5), || {
        let (status, body) = http_get(&daemon.url("/api/v1/risk"));
        if status != 200 {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        v["entities"].as_array()?.first().cloned()
    })
    .expect("GET /api/v1/risk never reported the open entity");
    assert_eq!(entity["entity_type"], serde_json::json!("rule"));
    assert_eq!(entity["score"], serde_json::json!(120));
}

#[test]
fn risk_state_survives_restart() {
    let rule = temp_file(".yml", common::SIMPLE_RULE);
    // A high threshold so the entity accumulates without firing, leaving open
    // state to persist.
    let risk = temp_file(
        ".yml",
        "score:\n  default_score: 60\nobjects:\n  - type: rule\n    selector: rule\nincident:\n  score_threshold: 100000\n  window: 1h\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let state_db = dir.path().join("state.db");
    let state_db = state_db.to_str().unwrap().to_string();

    // First daemon: accumulate risk on one entity, then wait for a periodic save.
    {
        let daemon = DaemonProcess::spawn(&[
            "engine",
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--risk",
            risk.path().to_str().unwrap(),
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
            "--state-db",
            &state_db,
            "--state-save-interval",
            "1",
        ]);
        let body = serde_json::to_string(&serde_json::json!({"CommandLine": "malware a"})).unwrap();
        assert_eq!(http_post(&daemon.url("/api/v1/events"), &body).0, 200);
        let opened = poll_until(Duration::from_secs(5), || {
            let (status, body) = http_get(&daemon.url("/api/v1/risk"));
            if status != 200 {
                return None;
            }
            let v: serde_json::Value = serde_json::from_str(&body).ok()?;
            (v["count"] == serde_json::json!(1)).then_some(())
        });
        assert!(opened.is_some(), "an entity should be tracked");
        std::thread::sleep(Duration::from_secs(2));
    } // first daemon killed and reaped on drop

    // Second daemon on the same state DB restores the tracked entity.
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--risk",
        risk.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--state-db",
        &state_db,
        "--state-save-interval",
        "1",
        "--keep-state",
    ]);
    let restored = poll_until(Duration::from_secs(5), || {
        let (status, body) = http_get(&daemon.url("/api/v1/risk"));
        if status != 200 {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        (v["count"] == serde_json::json!(1)).then_some(())
    });
    assert!(
        restored.is_some(),
        "the tracked entity should be restored after restart"
    );
}

/// Read `rsigma_risk_evictions_total{reason="<reason>"}` from a Prometheus
/// text exposition body.
fn risk_evictions(metrics: &str, reason: &str) -> Option<u64> {
    let needle = format!("rsigma_risk_evictions_total{{reason=\"{reason}\"}}");
    metrics.lines().find_map(|line| {
        line.trim()
            .strip_prefix(&needle)
            .and_then(|rest| rest.trim().parse::<f64>().ok())
            .map(|v| v as u64)
    })
}

fn open_entities(daemon: &DaemonProcess) -> Option<Vec<serde_json::Value>> {
    let (status, body) = http_get(&daemon.url("/api/v1/risk"));
    if status != 200 {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    v["entities"].as_array().cloned()
}

#[test]
fn a_full_entity_store_reclaims_room_for_a_fresh_entity() {
    let rule = temp_file(".yml", common::SIMPLE_RULE);
    let risk = temp_file(
        ".yml",
        "score:\n  default_score: 1\nobjects:\n  - type: cmd\n    selector: match.CommandLine\n\
         incident:\n  score_threshold: 3\n  window: 1h\n  caps:\n    max_open_entities: 2\n",
    );
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--risk",
        risk.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);
    let (_, m) = http_get(&daemon.url("/metrics"));
    assert_eq!(risk_evictions(&m, "cap"), Some(0));
    assert_eq!(risk_evictions(&m, "aged"), Some(0));

    let post = |cmd: &str| {
        let body = serde_json::json!({ "CommandLine": cmd }).to_string();
        assert_eq!(http_post(&daemon.url("/api/v1/events"), &body).0, 200);
    };
    post("malware one");
    post("malware two");
    let full = poll_until(Duration::from_secs(5), || {
        (open_entities(&daemon)?.len() == 2).then_some(())
    });
    assert!(full.is_some(), "two entities should fill the store");

    // A third entity takes the store's last slot and crosses the threshold.
    for _ in 0..3 {
        post("malware three");
    }
    let fired = poll_until(Duration::from_secs(5), || {
        let (_, m) = http_get(&daemon.url("/metrics"));
        (risk_incidents(&m, "score") == Some(1)).then_some(m)
    })
    .expect("the fresh entity should raise a risk incident");
    assert_eq!(risk_evictions(&fired, "cap"), Some(1));
    assert_eq!(risk_evictions(&fired, "aged"), Some(0));
    let entities = open_entities(&daemon).unwrap();
    assert_eq!(entities.len(), 2);
    assert!(
        entities
            .iter()
            .any(|e| e["entity_value"] == serde_json::json!("malware three") && e["score"] == 3)
    );
}

#[test]
fn risk_aggregates_beyond_the_sample_cap_survive_restart() {
    let rule = temp_file(".yml", common::SIMPLE_RULE);
    let risk = temp_file(
        ".yml",
        "score:\n  default_score: 60\nobjects:\n  - type: rule\n    selector: rule\n\
         incident:\n  score_threshold: 100000\n  window: 1h\n  caps:\n    max_results_per_incident: 1\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let state_db = dir.path().join("state.db");
    let state_db = state_db.to_str().unwrap().to_string();
    let args = |keep: bool| {
        let mut args = vec![
            "engine",
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--risk",
            risk.path().to_str().unwrap(),
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
            "--state-db",
            &state_db,
            "--state-save-interval",
            "1",
        ];
        if keep {
            args.push("--keep-state");
        }
        args.into_iter().map(str::to_string).collect::<Vec<_>>()
    };
    let score_of = |daemon: &DaemonProcess| {
        poll_until(Duration::from_secs(5), || {
            let entity = open_entities(daemon)?.first().cloned()?;
            (entity["result_count"] == 3).then_some(entity["score"].clone())
        })
    };

    {
        let args = args(false);
        let daemon = DaemonProcess::spawn(&args.iter().map(String::as_str).collect::<Vec<_>>());
        let body = serde_json::json!({ "CommandLine": "malware a" }).to_string();
        for _ in 0..3 {
            assert_eq!(http_post(&daemon.url("/api/v1/events"), &body).0, 200);
        }
        assert_eq!(score_of(&daemon), Some(serde_json::json!(180)));
        std::thread::sleep(Duration::from_secs(2));
    }

    let args = args(true);
    let daemon = DaemonProcess::spawn(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(
        score_of(&daemon),
        Some(serde_json::json!(180)),
        "the restored entity keeps every contribution's score, not just its one sample"
    );
}

#[test]
fn lowering_the_entity_cap_on_reload_takes_effect_at_once() {
    let rule = temp_file(".yml", common::SIMPLE_RULE);
    let config = |cap: usize| {
        format!(
            "score:\n  default_score: 1\nobjects:\n  - type: cmd\n    selector: match.CommandLine\n\
             incident:\n  score_threshold: 100\n  window: 1h\n  caps:\n    max_open_entities: {cap}\n"
        )
    };
    let risk = temp_file(".yml", &config(3));
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--risk",
        risk.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);
    for cmd in ["malware one", "malware two", "malware three"] {
        let body = serde_json::json!({ "CommandLine": cmd }).to_string();
        assert_eq!(http_post(&daemon.url("/api/v1/events"), &body).0, 200);
    }
    let full = poll_until(Duration::from_secs(5), || {
        (open_entities(&daemon)?.len() == 3).then_some(())
    });
    assert!(full.is_some(), "three entities should be tracked");

    std::fs::write(risk.path(), config(1)).unwrap();
    // The file watcher may already have queued a reload for this write, in
    // which case the API answers 429 and the queued reload applies the edit.
    let status = http_post(&daemon.url("/api/v1/reload"), "").0;
    assert!(
        status == 200 || status == 429,
        "reload POST should return 200 or 429, got {status}"
    );
    let trimmed = poll_until(Duration::from_secs(5), || {
        let (_, m) = http_get(&daemon.url("/metrics"));
        (open_entities(&daemon)?.len() == 1 && risk_evictions(&m, "cap") == Some(2)).then_some(())
    });
    assert!(
        trimmed.is_some(),
        "the reload should reclaim entities down to the new cap"
    );
}
