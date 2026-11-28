//! E2E tests for the read-only correlation introspection endpoints
//! `GET /api/v1/correlations` and `GET /api/v1/correlations/state`.

#![cfg(feature = "daemon")]

use crate::common;

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

#[test]
fn daemon_chained_correlation_carries_child_events() {
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chained_events");
    let rules = fixtures.join("rules.yml");
    let out = temp_file(".ndjson", "");
    let out_spec = format!("file://{}", out.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rules.to_str().unwrap(),
        &["--correlation-event-mode", "full", "--output", &out_spec],
    );

    let events = std::fs::read_to_string(fixtures.join("events.ndjson")).unwrap();
    for event in events.lines() {
        assert_eq!(http_post(&daemon.url("/api/v1/events"), event).0, 200);
    }

    let parent = poll_until(Duration::from_secs(5), || {
        std::fs::read_to_string(out.path())
            .unwrap_or_default()
            .lines()
            .find(|line| line.contains("Repeated brute force bursts"))
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
    })
    .expect("the chained correlation reaches the sink");

    let ids: Vec<&str> = parent["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["a1", "a2", "a3", "a4"]);
    let sources = parent["event_sources"].as_array().unwrap();
    assert_eq!(sources.len(), 4);
    assert!(sources.iter().all(|s| {
        s["rule"] == "failed_login" && s["via"] == "5b0c6f7e-0000-4000-8000-000000000002"
    }));
}

fn post_login_at(daemon: &DaemonProcess, user: &str, timestamp: &str) {
    let body = serde_json::to_string(&serde_json::json!({
        "EventType": "login",
        "User": user,
        "@timestamp": timestamp,
    }))
    .unwrap();
    assert_eq!(http_post(&daemon.url("/api/v1/events"), &body).0, 200);
}

fn future_skipped_total(daemon: &DaemonProcess) -> Option<u64> {
    let (_, body) = http_get(&daemon.url("/metrics"));
    body.lines()
        .find_map(|l| l.strip_prefix("rsigma_correlation_future_events_skipped_total "))
        .and_then(|v| v.trim().parse().ok())
}

#[test]
fn far_future_events_are_skipped_and_counted() {
    let rule = temp_file(".yml", CORR_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    post_login_at(&daemon, "admin", "9999-12-31T23:59:59Z");
    post_login_at(&daemon, "alice", "2024-01-01T00:00:00Z");

    poll_until(Duration::from_secs(5), || {
        (future_skipped_total(&daemon) == Some(1)).then_some(())
    })
    .expect("one future skip counted within 5s");
    let (_, body) = http_get(&daemon.url("/api/v1/correlations/state"));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let groups: Vec<_> = v["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["group_key_display"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(groups, ["User=alice"]);
}

#[test]
fn max_future_skew_flag_widens_the_bound() {
    let rule = temp_file(".yml", CORR_RULE);
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--max-future-skew", "3650d"],
    );
    let ahead = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();
    post_login_at(&daemon, "admin", &ahead);

    let group = poll_until(Duration::from_secs(5), || {
        let (_, body) = http_get(&daemon.url("/api/v1/correlations/state"));
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        v["groups"].as_array()?.first().cloned()
    })
    .expect("admin group within 5s");
    // Accepted, and clamped to the wall clock.
    let latest = group["latest"].as_i64().unwrap();
    assert!(latest <= chrono::Utc::now().timestamp());
    assert_eq!(future_skipped_total(&daemon), Some(0));
}

const ABSENCE_RULE: &str = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: MFA
id: mfa-rule
logsource:
    category: auth
detection:
    selection:
        EventType: mfa
    condition: selection
---
title: Login without MFA
correlation:
    type: temporal_ordered
    rules: [login-rule, mfa-rule]
    group-by: [User]
    timespan: 1s
    condition: login-rule and not mfa-rule
"#;

/// An hour-long window, so the idle tick cannot fire it during a short run.
fn hour_absence_rule() -> String {
    ABSENCE_RULE.replace("timespan: 1s", "timespan: 1h")
}

fn login_line(ts: i64, user: &str) -> String {
    format!(r#"{{"@timestamp": {ts}, "EventType": "login", "User": "{user}"}}"#)
}

#[test]
fn finite_stdin_without_state_db_fires_the_trailing_obligation() {
    let rule = temp_file(".yml", &hour_absence_rule());
    common::rsigma()
        .args([
            "engine",
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--input",
            "stdin",
            "--api-addr",
            "127.0.0.1:0",
        ])
        .write_stdin(format!("{}\n", login_line(1000, "alice")))
        .assert()
        .success()
        .stdout(predicates::str::contains("Login without MFA"));
}

#[test]
fn state_db_carries_a_pending_obligation_between_runs() {
    let rule = temp_file(".yml", &hour_absence_rule());
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");
    let base = [
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        "stdin",
        "--api-addr",
        "127.0.0.1:0",
        "--state-db",
        db.to_str().unwrap(),
    ];

    let first = common::rsigma()
        .args(base)
        .write_stdin(format!("{}\n", login_line(1000, "alice")))
        .assert()
        .success();
    assert!(
        !String::from_utf8_lossy(&first.get_output().stdout).contains("Login without MFA"),
        "a finite run with --state-db must not finalize"
    );

    let second = common::rsigma()
        .args(base)
        .write_stdin(format!("{}\n", login_line(5000, "bob")))
        .assert()
        .success();
    assert!(
        String::from_utf8_lossy(&second.get_output().stdout).contains("Login without MFA"),
        "the restored obligation must fire when the clock passes its deadline"
    );
}

#[test]
fn idle_daemon_fires_an_absence_deadline_and_reports_metrics() {
    let rule = temp_file(".yml", ABSENCE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let (status, body) = http_get(&daemon.url("/metrics"));
    assert_eq!(status, 200);
    for family in [
        "rsigma_correlation_absence_pending",
        "rsigma_correlation_absence_fired_total",
        "rsigma_correlation_absence_cancelled_total",
        "rsigma_correlation_absence_refused_total",
        "rsigma_correlation_absence_late_negatives_total",
    ] {
        assert!(
            body.contains(family),
            "missing {family} on the first scrape"
        );
    }

    let body = serde_json::to_string(&serde_json::json!({
        "EventType": "login",
        "User": "alice",
    }))
    .unwrap();
    assert_eq!(http_post(&daemon.url("/api/v1/events"), &body).0, 200);

    let fired = poll_until(Duration::from_secs(10), || {
        let (status, body) = http_get(&daemon.url("/metrics"));
        if status != 200 {
            return None;
        }
        let fired = body
            .lines()
            .find(|line| line.starts_with("rsigma_correlation_absence_fired_total "))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u64>().ok())?;
        (fired >= 1).then_some(body)
    })
    .expect("absence fired within 10s");

    assert!(
        fired.contains("rsigma_correlation_absence_pending 0"),
        "{fired}"
    );
}
