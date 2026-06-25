//! E2E tests for `engine daemon --logsource-routing`.

#![cfg(feature = "daemon")]

mod common;

use common::{DaemonProcess, http_get, http_post, poll_until, temp_file};
use serde_json::Value;
use std::time::Duration;

/// One Linux rule and one Windows rule, both matching `whoami` on content so
/// only the logsource decides which fires.
const RULES: &str = r#"
title: Linux Whoami
id: r-linux
status: test
logsource:
    product: linux
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
---
title: Windows Whoami
id: r-windows
status: test
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
"#;

fn poll_status(daemon: &DaemonProcess, want: impl Fn(&Value) -> bool) -> Value {
    poll_until(Duration::from_secs(5), || {
        let (status, body) = http_get(&daemon.url("/api/v1/status"));
        if status != 200 {
            return None;
        }
        let v: Value = serde_json::from_str(&body).ok()?;
        want(&v).then_some(v)
    })
    .expect("status counters never reached the expected state within 5s")
}

#[test]
fn prunes_conflicting_product_and_exposes_metric() {
    let rule = temp_file(".yml", RULES);
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--logsource-routing"],
    );

    // The event tags itself product: windows, so the linux rule is pruned and
    // only the windows rule fires.
    let (status, _) = http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"cmd /c whoami","product":"windows"}"#,
    );
    assert_eq!(status, 200);

    let v = poll_status(&daemon, |v| {
        v["detection_matches"].as_u64().unwrap_or(0) >= 1
    });
    assert_eq!(
        v["detection_matches"].as_u64().unwrap_or(0),
        1,
        "only the windows rule should fire; the linux rule is pruned"
    );

    // The pruned-rule counter surfaces on /metrics (one always-evaluated linux
    // rule pruned for the windows event).
    let metrics = poll_until(Duration::from_secs(5), || {
        let (s, body) = http_get(&daemon.url("/metrics"));
        if s != 200 {
            return None;
        }
        body.contains("rsigma_rules_pruned_by_logsource_total 1")
            .then_some(body)
    });
    assert!(
        metrics.is_some(),
        "expected rsigma_rules_pruned_by_logsource_total to reach 1"
    );
}

#[test]
fn static_event_logsource_prunes_via_daemon() {
    let rule = temp_file(".yml", RULES);
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--logsource-routing",
            "--event-logsource",
            "product=windows",
        ],
    );

    // The event carries no product field; the static override supplies it, so
    // only the windows rule fires.
    let (status, _) = http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"cmd /c whoami"}"#,
    );
    assert_eq!(status, 200);

    let v = poll_status(&daemon, |v| {
        v["detection_matches"].as_u64().unwrap_or(0) >= 1
    });
    assert_eq!(v["detection_matches"].as_u64().unwrap_or(0), 1);
}
