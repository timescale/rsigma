//! Integration tests for `engine eval --dump-correlation-state`.

mod common;

use common::{rsigma, temp_file};
use predicates::prelude::*;

const CORR_RULES: &str = r#"
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

#[test]
fn dump_shows_gap_for_near_miss_event_count() {
    let rule = temp_file(".yml", CORR_RULES);
    let stdin = concat!(
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T00:00:00Z"}"#,
        "\n",
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T00:00:10Z"}"#,
        "\n",
    );
    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "--dump-correlation-state",
            "--no-stats",
        ])
        .write_stdin(stdin)
        .assert()
        .success()
        // The snapshot goes to stderr to keep stdout machine-consumable.
        .stderr(predicate::str::contains("correlation state snapshot"))
        .stderr(predicate::str::contains("\"got\": 2.0"))
        .stderr(predicate::str::contains("\"threshold\": \">= 3\""))
        .stderr(predicate::str::contains("\"met\": false"))
        .stderr(predicate::str::contains(
            "\"group_key_display\": \"User=admin\"",
        ));
}

#[test]
fn dump_marks_met_when_threshold_reached() {
    let rule = temp_file(".yml", CORR_RULES);
    let stdin = concat!(
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T00:00:00Z"}"#,
        "\n",
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T00:00:10Z"}"#,
        "\n",
        r#"{"EventType":"login","User":"admin","@timestamp":"2026-01-01T00:00:20Z"}"#,
        "\n",
    );
    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "--dump-correlation-state",
            "--no-stats",
        ])
        .write_stdin(stdin)
        .assert()
        .success()
        .stderr(predicate::str::contains("\"met\": true"));
}

#[test]
fn dump_warns_when_no_correlations() {
    let rule = temp_file(
        ".yml",
        r#"
title: Detection Only
id: det-1
logsource:
    category: test
detection:
    selection:
        A: 1
    condition: selection
"#,
    );
    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "--dump-correlation-state",
            "--no-stats",
            "-e",
            r#"{"A":1}"#,
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "--dump-correlation-state needs correlation rules",
        ));
}
