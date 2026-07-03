//! E2E tests for the daemon's schema-observability surface.
//!
//! Spawns `rsigma engine daemon --observe-schemas ...`, posts events through
//! `/api/v1/events`, and asserts what `/api/v1/schemas` and `/metrics` report.

#![cfg(feature = "daemon")]

mod common;

use common::{DaemonProcess, http_delete, http_get, http_post, poll_until, temp_file};
use serde_json::Value;
use std::time::Duration;

const RULE: &str = r#"
title: Whoami Detector
id: 00000000-0000-0000-0000-000000000056
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|contains: "whoami"
    condition: selection
level: high
"#;

fn wait_for_events_observed(daemon: &DaemonProcess, expected: u64) -> Value {
    poll_until(Duration::from_secs(5), || {
        let (status, body) = http_get(&daemon.url("/api/v1/schemas"));
        if status != 200 {
            return None;
        }
        let v: Value = serde_json::from_str(&body).ok()?;
        let observed = v["summary"]["events_observed"].as_u64()?;
        if observed >= expected { Some(v) } else { None }
    })
    .expect("events not observed within 5s")
}

#[test]
fn schemas_endpoint_returns_503_when_observer_disabled() {
    let rule = temp_file(".yml", RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let (status, body) = http_get(&daemon.url("/api/v1/schemas"));
    assert_eq!(status, 503);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"], "schema observation disabled");
}

#[test]
fn schemas_endpoint_reports_per_schema_and_unknown_counts() {
    let rule = temp_file(".yml", RULE);
    let daemon =
        DaemonProcess::spawn_http_with_args(rule.path().to_str().unwrap(), &["--observe-schemas"]);

    // One ECS event, one flat Sysmon event, one unrecognized-but-structured
    // (generic_json), and one field-less object (unknown).
    let payload = concat!(
        r#"{"ecs.version":"8.11.0","CommandLine":"whoami"}"#,
        "\n",
        r#"{"EventID":1,"ProcessGuid":"{x}","CommandLine":"whoami"}"#,
        "\n",
        r#"{"vendor_blob":"x"}"#,
        "\n",
        "{}",
    );
    let (status, _body) = http_post(&daemon.url("/api/v1/events"), payload);
    assert_eq!(status, 200);

    let report = wait_for_events_observed(&daemon, 4);
    assert_eq!(report["summary"]["classified"].as_u64().unwrap(), 3);
    assert_eq!(report["summary"]["unknown"].as_u64().unwrap(), 1);

    let by_schema = report["by_schema"].as_array().unwrap();
    let count_for = |name: &str| -> u64 {
        by_schema
            .iter()
            .find(|e| e["schema"] == name)
            .and_then(|e| e["count"].as_u64())
            .unwrap_or(0)
    };
    assert_eq!(count_for("ecs"), 1);
    assert_eq!(count_for("sysmon"), 1);
    assert_eq!(count_for("generic_json"), 1);

    // Metrics surface the same signal.
    let (status, metrics) = http_get(&daemon.url("/metrics"));
    assert_eq!(status, 200);
    assert!(metrics.contains("rsigma_events_by_schema_total"));
    assert!(metrics.contains(r#"schema="ecs""#));
    assert!(metrics.contains("rsigma_events_unknown_schema_total 1"));
}

#[test]
fn suggestions_endpoint_requires_discover_flag() {
    let rule = temp_file(".yml", RULE);
    // Observer on, but discovery sampling off: 503 with a discover hint.
    let daemon =
        DaemonProcess::spawn_http_with_args(rule.path().to_str().unwrap(), &["--observe-schemas"]);
    let (status, body) = http_get(&daemon.url("/api/v1/schemas/suggestions"));
    assert_eq!(status, 503);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"], "schema discovery sampling disabled");
}

#[test]
fn suggestions_endpoint_mines_unrecognized_shapes() {
    let rule = temp_file(".yml", RULE);
    let daemon =
        DaemonProcess::spawn_http_with_args(rule.path().to_str().unwrap(), &["--discover-schemas"]);

    // Four same-shape vendor events. They carry fields, so they classify as the
    // low-specificity generic_json catch-all, which the discovery sampler treats
    // as unrecognized.
    let payload = concat!(
        r#"{"vendor":"acme","event_type":"alert","n":1}"#,
        "\n",
        r#"{"vendor":"acme","event_type":"alert","n":2}"#,
        "\n",
        r#"{"vendor":"acme","event_type":"alert","n":3}"#,
        "\n",
        r#"{"vendor":"acme","event_type":"alert","n":4}"#,
    );
    let (status, _body) = http_post(&daemon.url("/api/v1/events"), payload);
    assert_eq!(status, 200);

    // Wait until all four are observed (as generic_json).
    let _ = wait_for_events_observed(&daemon, 4);

    let suggestions = poll_until(Duration::from_secs(5), || {
        let (status, body) = http_get(&daemon.url("/api/v1/schemas/suggestions"));
        if status != 200 {
            return None;
        }
        let v: Value = serde_json::from_str(&body).ok()?;
        let candidates = v["candidates"].as_array()?;
        if candidates.is_empty() {
            return None;
        }
        Some(v)
    })
    .expect("no suggestions within 5s");

    let candidates = suggestions["candidates"].as_array().unwrap();
    assert!(!candidates.is_empty());
    // Online proposals are presence-only and tagged keys-only.
    assert_eq!(candidates[0]["source"], "keys-only");
    assert!(
        suggestions["signatures_yaml"]
            .as_str()
            .unwrap()
            .contains("field_present")
    );

    // The cluster gauge is exposed and non-zero after a scrape.
    let (status, metrics) = http_get(&daemon.url("/metrics"));
    assert_eq!(status, 200);
    assert!(metrics.contains("rsigma_unknown_schema_clusters"));
}

#[test]
fn schemas_delete_resets_observer() {
    let rule = temp_file(".yml", RULE);
    let daemon =
        DaemonProcess::spawn_http_with_args(rule.path().to_str().unwrap(), &["--observe-schemas"]);

    let payload = concat!(
        r#"{"ecs.version":"8.11.0","CommandLine":"whoami"}"#,
        "\n",
        r#"{"EventID":1,"ProcessGuid":"{x}","CommandLine":"whoami"}"#,
    );
    let (status, _body) = http_post(&daemon.url("/api/v1/events"), payload);
    assert_eq!(status, 200);
    let _ = wait_for_events_observed(&daemon, 2);

    // Reset clears the since-reset counters and reports what was cleared.
    let (status, body) = http_delete(&daemon.url("/api/v1/schemas"));
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "reset");
    assert_eq!(v["previous_classified"].as_u64().unwrap(), 2);

    // A fresh snapshot starts from zero.
    let (status, body) = http_get(&daemon.url("/api/v1/schemas"));
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["summary"]["events_observed"].as_u64().unwrap(), 0);
    assert_eq!(v["summary"]["classified"].as_u64().unwrap(), 0);
}

#[test]
fn schemas_delete_requires_observer() {
    let rule = temp_file(".yml", RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());
    let (status, _body) = http_delete(&daemon.url("/api/v1/schemas"));
    assert_eq!(status, 503);
}
