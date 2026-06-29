//! E2E tests for the read-only correlation introspection endpoints
//! `GET /api/v1/correlations` and `GET /api/v1/correlations/state`.

#![cfg(feature = "daemon")]

mod common;

use std::time::Duration;

use common::{DaemonProcess, http_get, http_post, poll_until, temp_file};

const CORR_RULE: &str = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many Logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 3
level: high
"#;

fn post_login(daemon: &DaemonProcess, user: &str) {
    let body = serde_json::to_string(&serde_json::json!({
        "EventType": "login",
        "User": user,
    }))
    .unwrap();
    assert_eq!(
        http_post(&daemon.url("/api/v1/events"), &body).0,
        200,
        "POST /api/v1/events did not accept the event"
    );
}

#[test]
fn correlations_endpoint_lists_compiled_correlations() {
    let rule = temp_file(".yml", CORR_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let (status, body) = http_get(&daemon.url("/api/v1/correlations"));
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["count"], 1);
    assert_eq!(v["correlations"][0]["type"], "event_count");
    assert_eq!(v["correlations"][0]["threshold"], ">= 3");
    assert_eq!(v["correlations"][0]["title"], "Many Logins");
}

#[test]
fn correlations_state_reports_gap_below_threshold() {
    let rule = temp_file(".yml", CORR_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    // Two logins for admin: below the gte:3 threshold.
    post_login(&daemon, "admin");
    post_login(&daemon, "admin");

    let group = poll_until(Duration::from_secs(5), || {
        let (status, body) = http_get(&daemon.url("/api/v1/correlations/state"));
        if status != 200 {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        let groups = v["groups"].as_array()?;
        let g = groups
            .iter()
            .find(|g| g["group_key_display"].as_str() == Some("User=admin"))?;
        (g["got"].as_f64() == Some(2.0)).then(|| g.clone())
    })
    .expect("admin group with got=2 within 5s");

    assert_eq!(group["met"], false);
    assert_eq!(group["threshold"], ">= 3");
    assert_eq!(group["entries"], 2);
}

#[test]
fn correlations_state_group_filter() {
    let rule = temp_file(".yml", CORR_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    post_login(&daemon, "admin");
    post_login(&daemon, "alice");

    // Wait until both groups exist, then filter to alice only.
    let filtered = poll_until(Duration::from_secs(5), || {
        let (status, body) = http_get(&daemon.url("/api/v1/correlations/state?group=alice"));
        if status != 200 {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        let groups = v["groups"].as_array()?;
        (groups.len() == 1).then(|| v.clone())
    })
    .expect("exactly one alice group within 5s");

    assert_eq!(filtered["groups"][0]["group_key_display"], "User=alice");
}

#[test]
fn correlation_endpoints_empty_without_correlations() {
    let rule = temp_file(".yml", common::SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let (s1, b1) = http_get(&daemon.url("/api/v1/correlations"));
    assert_eq!(s1, 200);
    let v1: serde_json::Value = serde_json::from_str(&b1).unwrap();
    assert_eq!(v1["count"], 0);

    let (s2, b2) = http_get(&daemon.url("/api/v1/correlations/state"));
    assert_eq!(s2, 200);
    let v2: serde_json::Value = serde_json::from_str(&b2).unwrap();
    assert_eq!(v2["count"], 0);
    assert_eq!(v2["groups"].as_array().unwrap().len(), 0);
}
