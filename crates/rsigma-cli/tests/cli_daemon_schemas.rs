//! E2E tests for the daemon's schema-observability surface.
//!
//! Spawns `rsigma engine daemon --observe-schemas ...`, posts events through
//! `/api/v1/events`, and asserts what `/api/v1/schemas` and `/metrics` report.

#![cfg(feature = "daemon")]

mod common;

use common::{DaemonProcess, http_get, http_post, poll_until, temp_file};
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
