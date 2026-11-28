//! Integration tests for `rsigma hunt run` that need neither the
//! `hunt-postgres` feature nor a database: `--emit sql` and the rejection
//! paths, all through the real binary.

use crate::common;

use common::{rsigma, temp_file};
use predicates::prelude::*;

const RULE: &str = r#"
title: Suspicious Process Start
id: 00000000-0000-0000-0000-000000000101
logsource:
    category: process_creation
detection:
    selection:
        Image: /usr/bin/curl
        CommandLine|contains: "--insecure"
    condition: selection
level: medium
"#;

const CORRELATION: &str = r#"
title: Repeated Hits
correlation:
    type: event_count
    rules:
        - Suspicious Process Start
    group-by:
        - Image
    timespan: 10m
    condition:
        gte: 5
"#;

#[test]
fn emit_sql_prints_wrapped_query_without_connecting() {
    let rule = temp_file(".yml", RULE);
    rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "--target",
            "postgres",
            "--since",
            "2026-07-01T00:00:00Z",
            "--until",
            "2026-07-02T00:00:00Z",
            "--emit",
            "sql",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("-- timestamp_field: time\n"))
        .stdout(predicate::str::contains(
            "-- rule: Suspicious Process Start (id: 00000000-0000-0000-0000-000000000101)\n",
        ))
        .stdout(predicate::str::contains(
            "SELECT * FROM (SELECT * FROM security_events WHERE \"Image\" ILIKE '/usr/bin/curl'",
        ))
        .stdout(predicate::str::contains(
            "WHERE time >= '2026-07-01T00:00:00+00:00'::timestamptz \
             AND time < '2026-07-02T00:00:00+00:00'::timestamptz \
             ORDER BY time LIMIT 1000;",
        ));
}

#[test]
fn emit_sql_jsonb_mode_extracts_from_the_json_column() {
    let rule = temp_file(".yml", RULE);
    rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "-t",
            "postgres",
            "-O",
            "table=events",
            "-O",
            "json_field=data",
            "--emit",
            "sql",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("-- json_field: data\n"))
        .stdout(predicate::str::contains(
            "FROM events WHERE data->>'Image' ILIKE '/usr/bin/curl'",
        ));
}

#[test]
fn correlation_rules_are_rejected_with_a_pointer() {
    let rules = temp_file(".yml", &format!("{RULE}\n---\n{CORRELATION}"));
    rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rules.path().to_str().unwrap(),
            "-t",
            "postgres",
            "--emit",
            "sql",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("detection rules only"))
        .stderr(predicate::str::contains("Repeated Hits"))
        .stderr(predicate::str::contains("rsigma backend convert"));
}

#[test]
fn non_postgres_targets_are_rejected_with_a_pointer() {
    let rule = temp_file(".yml", RULE);
    rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "-t",
            "splunk",
            "--emit",
            "sql",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "hunt run supports --target postgres only; 'splunk' is convert-only",
        ))
        .stderr(predicate::str::contains("rsigma backend convert -t splunk"));
}

#[test]
fn empty_window_is_rejected() {
    let rule = temp_file(".yml", RULE);
    rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "-t",
            "postgres",
            "--since",
            "2026-07-02T00:00:00Z",
            "--until",
            "2026-07-01T00:00:00Z",
            "--emit",
            "sql",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("empty hunt window"));
}

#[test]
fn invalid_time_bound_is_rejected() {
    let rule = temp_file(".yml", RULE);
    rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "-t",
            "postgres",
            "--since",
            "next tuesday",
            "--emit",
            "sql",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "invalid time bound 'next tuesday'",
        ));
}

/// `--timeout` is validated on every path, including `--emit sql`, and a
/// value that would render `statement_timeout = 0` (disabling the server
/// timeout) is rejected rather than truncated.
#[test]
fn timeout_is_validated_even_for_emit_sql() {
    let rule = temp_file(".yml", RULE);
    let base = |timeout: &str| {
        let mut cmd = rsigma();
        cmd.args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "-t",
            "postgres",
            "--emit",
            "sql",
            "--timeout",
            timeout,
        ]);
        cmd
    };
    base("never")
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "invalid --timeout 'never': expected a duration",
        ));
    base("500us")
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "invalid --timeout '500us': must be between 1ms",
        ));
    base("0s").assert().code(3).stderr(predicate::str::contains(
        "invalid --timeout '0s': must be between 1ms",
    ));
}

/// Without the `hunt-postgres` feature, `--emit events` fails with a pointed
/// message instead of connecting.
#[cfg(not(feature = "hunt-postgres"))]
#[test]
fn events_mode_without_the_feature_is_a_pointed_error() {
    let rule = temp_file(".yml", RULE);
    rsigma()
        .args([
            "hunt",
            "run",
            "-r",
            rule.path().to_str().unwrap(),
            "-t",
            "postgres",
            "--dsn",
            "postgres://hunter@archive/siem",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "built without the 'hunt-postgres' feature",
        ));
}
