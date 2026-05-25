//! E2E tests for the daemon's field-observability surface.
//!
//! Each test spawns `rsigma engine daemon --observe-fields ...` against a
//! tiny rule, posts a few events through `/api/v1/events`, and asserts
//! what the `/api/v1/fields/*` endpoints report.

#![cfg(feature = "daemon")]

mod common;

use common::{DaemonProcess, http_delete, http_get, http_post, poll_until, temp_file};
use serde_json::Value;
use std::time::Duration;

const RULE: &str = r#"
title: Whoami Detector
id: 00000000-0000-0000-0000-000000000055
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
        let (status, body) = http_get(&daemon.url("/api/v1/fields"));
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
fn fields_endpoints_return_503_when_observer_disabled() {
    let rule = temp_file(".yml", RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    for path in [
        "/api/v1/fields",
        "/api/v1/fields/unknown",
        "/api/v1/fields/missing",
    ] {
        let (status, body) = http_get(&daemon.url(path));
        assert_eq!(status, 503, "{path} should be 503 when observer disabled");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"], "field observation disabled");
    }

    let (status, _body) = http_delete(&daemon.url("/api/v1/fields/observer"));
    assert_eq!(status, 503);
}

#[test]
fn unknown_endpoint_lists_event_fields_no_rule_references() {
    let rule = temp_file(".yml", RULE);
    let daemon =
        DaemonProcess::spawn_http_with_args(rule.path().to_str().unwrap(), &["--observe-fields"]);

    // Two events: one matching the rule, one with extra unknown fields.
    let payload = "{\"CommandLine\":\"whoami\",\"User\":\"alice\"}\n\
                   {\"CommandLine\":\"id\",\"src_ip\":\"10.0.0.1\",\"User\":\"bob\"}";
    let (status, _body) = http_post(&daemon.url("/api/v1/events"), payload);
    assert_eq!(status, 200);

    let full = wait_for_events_observed(&daemon, 2);
    assert_eq!(full["summary"]["events_observed"].as_u64().unwrap(), 2);

    let (status, body) = http_get(&daemon.url("/api/v1/fields/unknown"));
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    let names: Vec<&str> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["field"].as_str())
        .collect();
    // User and src_ip are observed but not referenced by the rule. CommandLine is referenced.
    assert!(names.contains(&"User"), "User should be flagged unknown");
    assert!(
        names.contains(&"src_ip"),
        "src_ip should be flagged unknown"
    );
    assert!(
        !names.contains(&"CommandLine"),
        "CommandLine is rule-referenced, must not appear in unknown"
    );
}

#[test]
fn missing_endpoint_lists_rule_fields_never_observed() {
    let rule = temp_file(".yml", RULE);
    let daemon =
        DaemonProcess::spawn_http_with_args(rule.path().to_str().unwrap(), &["--observe-fields"]);

    // Post an event that does NOT contain CommandLine, so the rule field
    // is unobserved.
    let (status, _body) = http_post(&daemon.url("/api/v1/events"), r#"{"User":"alice"}"#);
    assert_eq!(status, 200);
    wait_for_events_observed(&daemon, 1);

    let (status, body) = http_get(&daemon.url("/api/v1/fields/missing"));
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    let items = v["items"].as_array().unwrap();
    let cmd_entry = items
        .iter()
        .find(|e| e["field"] == "CommandLine")
        .expect("CommandLine should be flagged missing");
    assert!(cmd_entry["rule_count"].as_u64().unwrap() >= 1);
    let sources: Vec<&str> = cmd_entry["sources"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s.as_str())
        .collect();
    assert!(sources.contains(&"detection"));
}

#[test]
fn full_endpoint_reports_summary_unknown_and_missing() {
    let rule = temp_file(".yml", RULE);
    let daemon =
        DaemonProcess::spawn_http_with_args(rule.path().to_str().unwrap(), &["--observe-fields"]);

    let payload = r#"{"CommandLine":"whoami","User":"alice"}"#;
    let (status, _body) = http_post(&daemon.url("/api/v1/events"), payload);
    assert_eq!(status, 200);
    let v = wait_for_events_observed(&daemon, 1);

    let summary = &v["summary"];
    assert_eq!(summary["events_observed"].as_u64().unwrap(), 1);
    assert!(summary["unique_keys_observed"].as_u64().unwrap() >= 2);
    assert_eq!(summary["overflow_dropped"].as_u64().unwrap(), 0);
    assert!(summary["rule_fields_loaded"].as_u64().unwrap() >= 1);
    // CommandLine is in both the rule and the event -> intersection_count > 0.
    assert!(summary["intersection_count"].as_u64().unwrap() >= 1);

    assert!(v["unknown"]["items"].is_array());
    assert!(v["missing"]["items"].is_array());
}

#[test]
fn delete_observer_resets_counters() {
    let rule = temp_file(".yml", RULE);
    let daemon =
        DaemonProcess::spawn_http_with_args(rule.path().to_str().unwrap(), &["--observe-fields"]);

    let (status, _body) = http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"whoami","User":"alice"}"#,
    );
    assert_eq!(status, 200);
    wait_for_events_observed(&daemon, 1);

    let (status, body) = http_delete(&daemon.url("/api/v1/fields/observer"));
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "reset");
    assert!(v["previous_events"].as_u64().unwrap() >= 1);
    assert!(v["previous_keys"].as_u64().unwrap() >= 2);

    // Right after reset the observer should report a clean slate.
    let (status, body) = http_get(&daemon.url("/api/v1/fields"));
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["summary"]["events_observed"].as_u64().unwrap(), 0);
    assert_eq!(v["summary"]["unique_keys_observed"].as_u64().unwrap(), 0);
    assert_eq!(v["summary"]["overflow_dropped"].as_u64().unwrap(), 0);
}

#[test]
fn overflow_cap_drops_new_keys_after_capacity_reached() {
    let rule = temp_file(".yml", RULE);
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--observe-fields", "--observe-fields-max-keys", "2"],
    );

    let payload = r#"{"a":1,"b":2,"c":3,"d":4}"#;
    let (status, _body) = http_post(&daemon.url("/api/v1/events"), payload);
    assert_eq!(status, 200);
    let v = wait_for_events_observed(&daemon, 1);

    let summary = &v["summary"];
    assert_eq!(summary["unique_keys_observed"].as_u64().unwrap(), 2);
    assert_eq!(summary["overflow_dropped"].as_u64().unwrap(), 2);
    assert_eq!(summary["max_keys"].as_u64().unwrap(), 2);
}

#[test]
fn fields_unknown_pagination_returns_next_offset() {
    let rule = temp_file(".yml", RULE);
    let daemon =
        DaemonProcess::spawn_http_with_args(rule.path().to_str().unwrap(), &["--observe-fields"]);

    // Five unknown fields plus the rule's CommandLine.
    let payload = r#"{"CommandLine":"whoami","a":1,"b":2,"c":3,"d":4,"e":5}"#;
    let (status, _body) = http_post(&daemon.url("/api/v1/events"), payload);
    assert_eq!(status, 200);
    wait_for_events_observed(&daemon, 1);

    let (status, body) = http_get(&daemon.url("/api/v1/fields/unknown?limit=2&offset=0"));
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    assert_eq!(v["limit"].as_u64().unwrap(), 2);
    assert_eq!(v["offset"].as_u64().unwrap(), 0);
    assert_eq!(v["total"].as_u64().unwrap(), 5);
    assert_eq!(v["next_offset"].as_u64().unwrap(), 2);
}

#[test]
fn metrics_includes_field_observer_counters_when_enabled() {
    let rule = temp_file(".yml", RULE);
    let daemon =
        DaemonProcess::spawn_http_with_args(rule.path().to_str().unwrap(), &["--observe-fields"]);

    let (status, _body) = http_post(&daemon.url("/api/v1/events"), r#"{"CommandLine":"whoami"}"#);
    assert_eq!(status, 200);
    wait_for_events_observed(&daemon, 1);

    let (status, body) = http_get(&daemon.url("/metrics"));
    assert_eq!(status, 200);
    assert!(body.contains("rsigma_fields_observed_total"));
    assert!(body.contains("rsigma_fields_observer_unique_keys"));
    assert!(body.contains("rsigma_fields_observer_overflow_dropped_total"));
}
