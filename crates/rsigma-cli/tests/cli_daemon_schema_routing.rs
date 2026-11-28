//! E2E tests for `engine daemon --schema-routing`.

#![cfg(feature = "daemon")]

use crate::common;

use common::{DaemonProcess, http_get, http_post, poll_until, temp_file};
use serde_json::Value;
use std::time::Duration;

const RULE: &str = r#"
title: Whoami
id: r-whoami
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
"#;

const CORR_RULES: &str = r#"
title: Whoami
id: r-whoami
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
---
title: Repeated whoami by user
correlation:
    type: event_count
    rules:
        - r-whoami
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 2
level: high
"#;

const SCHEMA_CONFIG: &str = r#"
routing:
  on_unknown: warn
  bindings:
    - schema: ecs
      pipelines: [ecs_windows]
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
fn routes_ecs_event_through_bound_pipeline() {
    let rule = temp_file(".yml", RULE);
    let schema = temp_file(".yml", SCHEMA_CONFIG);
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--schema-routing",
            "--schema-config",
            schema.path().to_str().unwrap(),
        ],
    );

    // The rule field CommandLine is mapped to process.command_line by the
    // ecs_windows pipeline that the `ecs` schema is bound to. The detection
    // only fires if the event was routed through that pipeline.
    let (status, _body) = http_post(
        &daemon.url("/api/v1/events"),
        r#"{"ecs.version":"8.0.0","process.command_line":"cmd /c whoami"}"#,
    );
    assert_eq!(status, 200);

    poll_status(&daemon, |v| {
        v["detection_matches"].as_u64().unwrap_or(0) >= 1
    });
}

/// A Windows ECS event also reports `host.os.kernel`. With logsource routing
/// it must still be attributed to Windows, so the Windows rule fires.
#[test]
fn windows_ecs_event_with_kernel_version_keeps_windows_rules() {
    let rule = temp_file(".yml", RULE);
    let schema = temp_file(".yml", SCHEMA_CONFIG);
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--schema-routing",
            "--schema-config",
            schema.path().to_str().unwrap(),
            "--logsource-routing",
        ],
    );

    let (status, _body) = http_post(
        &daemon.url("/api/v1/events"),
        r#"{"ecs.version":"8.11.0","winlog.channel":"Security","host.os.kernel":"10.0.19045","process.command_line":"cmd /c whoami"}"#,
    );
    assert_eq!(status, 200);

    poll_status(&daemon, |v| {
        v["detection_matches"].as_u64().unwrap_or(0) >= 1
    });
}

/// Two signatures that tie at the same specificity but imply different
/// products: the event is evaluated without the schema-derived product, so
/// the Windows rule fires, and the ambiguity counter records it.
#[test]
fn ambiguous_classification_fails_open_and_is_counted() {
    let rule = temp_file(".yml", RULE);
    let schema = temp_file(
        ".yml",
        r#"
schemas:
  - name: vendor_a
    specificity: 70
    match:
      - field_present: vendor_marker
  - name: vendor_b
    specificity: 70
    match:
      - field_present: vendor_marker
routing:
  on_unknown: warn
  bindings:
    - schema: vendor_a
      pipelines: []
      logsource:
        product: linux
    - schema: vendor_b
      pipelines: []
      logsource:
        product: windows
"#,
    );
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--schema-routing",
            "--schema-config",
            schema.path().to_str().unwrap(),
            "--logsource-routing",
        ],
    );

    let (status, _body) = http_post(
        &daemon.url("/api/v1/events"),
        r#"{"vendor_marker":true,"CommandLine":"cmd /c whoami"}"#,
    );
    assert_eq!(status, 200);

    poll_status(&daemon, |v| {
        v["detection_matches"].as_u64().unwrap_or(0) >= 1
    });
    let metrics = poll_until(Duration::from_secs(5), || {
        let (s, body) = http_get(&daemon.url("/metrics"));
        (s == 200 && body.contains("rsigma_events_ambiguous_logsource_total 1")).then_some(body)
    });
    assert!(
        metrics.is_some(),
        "expected rsigma_events_ambiguous_logsource_total to reach 1"
    );
}

#[test]
fn cross_schema_correlation_via_daemon() {
    let rule = temp_file(".yml", CORR_RULES);
    let schema = temp_file(".yml", SCHEMA_CONFIG);
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--schema-routing",
            "--schema-config",
            schema.path().to_str().unwrap(),
        ],
    );

    // Same user alice, once as ECS (user.name) and once Sigma-native (User).
    // Schema-aware group-by over the shared store lands them in one window.
    let batch = concat!(
        r#"{"ecs.version":"8.0.0","process.command_line":"cmd /c whoami","user.name":"alice"}"#,
        "\n",
        r#"{"CommandLine":"cmd /c whoami","User":"alice"}"#,
    );
    let (status, _body) = http_post(&daemon.url("/api/v1/events"), batch);
    assert_eq!(status, 200);

    poll_status(&daemon, |v| {
        v["correlation_matches"].as_u64().unwrap_or(0) >= 1
    });
}
