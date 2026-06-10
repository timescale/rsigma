//! Integration tests for the convert, list-targets, and list-formats subcommands.
//!
//! Uses insta inline snapshot testing for full stdout/stderr output verification.

mod common;

use common::{rsigma, temp_file};
use insta::assert_snapshot;
use predicates::prelude::*;
use tempfile::TempDir;

const SIMPLE_DETECTION: &str = r#"
title: Detect Whoami
id: 00000000-0000-0000-0000-000000000100
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;

const CORRELATION_RULES: &str = r#"
title: Failed Login
id: 00000000-0000-0000-0000-000000000200
status: test
logsource:
    category: auth
    product: generic
detection:
    selection:
        EventType: login_failure
    condition: selection
level: low
---
title: Brute Force
correlation:
    type: event_count
    rules:
        - 00000000-0000-0000-0000-000000000200
    group-by:
        - src_ip
    timespan: 5m
    condition:
        gte: 5
level: high
"#;

// ---------------------------------------------------------------------------
// convert subcommand
// ---------------------------------------------------------------------------

#[test]
fn convert_simple_rule_to_postgres() {
    let rule = temp_file(".yml", SIMPLE_DETECTION);
    let output = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "--target",
            "postgres",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r#"SELECT * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'"#);
}

#[test]
fn convert_with_format_view() {
    let rule = temp_file(".yml", SIMPLE_DETECTION);
    let output = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "--target",
            "postgres",
            "--format",
            "view",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r#"CREATE OR REPLACE VIEW sigma_00000000_0000_0000_0000_000000000100 AS SELECT * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'"#);
}

#[test]
fn convert_with_format_timescaledb() {
    let rule = temp_file(".yml", SIMPLE_DETECTION);
    let output = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "--target",
            "postgres",
            "--format",
            "timescaledb",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r#"SELECT time_bucket('1 hour', time) AS bucket, * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'"#);
}

#[test]
fn convert_simple_rule_to_fibratus_expr_format() {
    let rule = temp_file(".yml", SIMPLE_DETECTION);
    let output = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "--target",
            "fibratus",
            "--format",
            "expr",
            "-p",
            "fibratus_windows",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // `evt.name: CreateProcess` injected by the `fibratus_windows`
    // pipeline is recognized as the `spawn_process` macro under the
    // default `-O use_macros=true`.
    assert!(
        stdout.contains("spawn_process"),
        "stdout missing spawn_process: {stdout}",
    );
    // Sigma `process_creation.CommandLine` maps to
    // `ps.sibling.cmdline` (the spawned process's cmdline) because
    // on a Fibratus `CreateProcess` event the new process lives
    // under the `ps.sibling.*` namespace.
    assert!(
        stdout.contains("ps.sibling.cmdline icontains 'whoami'"),
        "stdout missing renamed field: {stdout}",
    );
}

#[test]
fn convert_simple_rule_to_fibratus_yaml_envelope() {
    let rule = temp_file(".yml", SIMPLE_DETECTION);
    let output = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "--target",
            "fibratus",
            "-p",
            "fibratus_windows",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("name: Detect Whoami\n"));
    assert!(stdout.contains("id: 00000000-0000-0000-0000-000000000100\n"));
    assert!(stdout.contains("condition: "));
    assert!(stdout.contains("min-engine-version: 3.0.0\n"));
}

#[test]
fn convert_fibratus_action_option_appends_action_block() {
    let rule = temp_file(".yml", SIMPLE_DETECTION);
    let output = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "--target",
            "fibratus",
            "-p",
            "fibratus_windows",
            "-O",
            "action=kill",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("action:\n  - name: kill\n"),
        "stdout missing action block: {stdout}",
    );
}

#[test]
fn convert_directory_of_rules() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("rule_a.yml"), SIMPLE_DETECTION).unwrap();

    let second_rule = r#"
title: Detect Ipconfig
id: 00000000-0000-0000-0000-000000000101
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'ipconfig'
    condition: selection
level: low
"#;
    std::fs::write(dir.path().join("rule_b.yml"), second_rule).unwrap();

    let output = rsigma()
        .args([
            "backend",
            "convert",
            dir.path().to_str().unwrap(),
            "--target",
            "postgres",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("whoami"), "should contain whoami rule");
    assert!(stdout.contains("ipconfig"), "should contain ipconfig rule");
}

#[test]
fn convert_with_pipeline() {
    let pipeline = temp_file(
        ".yml",
        r#"
name: test-pipeline
priority: 10
transformations:
  - type: field_name_mapping
    mapping:
      CommandLine: process.command_line
"#,
    );
    let rule = temp_file(".yml", SIMPLE_DETECTION);

    let output = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "--target",
            "postgres",
            "-p",
            pipeline.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r#"SELECT * FROM security_events WHERE "process.command_line" ILIKE '%whoami%'"#);
}

#[test]
fn convert_skip_unsupported() {
    let rule = temp_file(".yml", SIMPLE_DETECTION);
    let output = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "--target",
            "postgres",
            "--skip-unsupported",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r#"SELECT * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'"#);
}

#[test]
fn convert_requires_pipeline_error() {
    let rule = temp_file(".yml", SIMPLE_DETECTION);
    rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "--target",
            "test_mandatory_pipeline",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("requires a pipeline"));
}

#[test]
fn convert_invalid_target() {
    let rule = temp_file(".yml", SIMPLE_DETECTION);
    let output = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "--target",
            "nonexistent_backend",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stderr), @"
    Unknown target: nonexistent_backend
    Available targets: postgres, lynxdb, fibratus, test
    ");
}

#[test]
fn convert_invalid_format() {
    let rule = temp_file(".yml", SIMPLE_DETECTION);
    let output = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "--target",
            "postgres",
            "--format",
            "nonexistent_format",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stderr), @"
    Unknown format 'nonexistent_format' for backend 'postgres'
    Available: default (Plain PostgreSQL SQL), view (CREATE OR REPLACE VIEW for each rule), timescaledb (TimescaleDB-optimized queries with time_bucket()), continuous_aggregate (CREATE MATERIALIZED VIEW ... WITH (timescaledb.continuous)), sliding_window (Correlation queries using window functions for per-row sliding detection)
    ");
}

#[test]
fn convert_correlation_rule() {
    let rule = temp_file(".yml", CORRELATION_RULES);
    let output = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "--target",
            "postgres",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @r#"
    SELECT * FROM security_events WHERE "EventType" = 'login_failure'
    WITH combined_events AS (SELECT * FROM security_events WHERE "EventType" = 'login_failure') SELECT src_ip, COUNT(*) AS event_count FROM combined_events GROUP BY src_ip HAVING COUNT(*) >= 5
    "#);
}

#[test]
fn convert_to_file_output() {
    let rule = temp_file(".yml", SIMPLE_DETECTION);
    let dir = TempDir::new().unwrap();
    let out_path = dir.path().join("output.sql");

    rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "--target",
            "postgres",
            "--output",
            out_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let content = std::fs::read_to_string(&out_path).unwrap();
    assert_snapshot!(content, @r#"SELECT * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'"#);
}

// ---------------------------------------------------------------------------
// list-targets / list-formats
// ---------------------------------------------------------------------------

#[test]
fn list_targets() {
    let output = rsigma().args(["backend", "targets"]).output().unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @"
    Available conversion targets:
      postgres  - PostgreSQL/TimescaleDB (aliases: postgresql, pg)
      lynxdb    - LynxDB log analytics engine
      fibratus  - Fibratus Windows kernel-event detection engine
      test      - Backend-neutral test backend
    ");
}

#[test]
fn list_formats_postgres() {
    let output = rsigma()
        .args(["backend", "formats", "postgres"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stdout), @"
    Available formats for 'postgres':
      default  - Plain PostgreSQL SQL
      view  - CREATE OR REPLACE VIEW for each rule
      timescaledb  - TimescaleDB-optimized queries with time_bucket()
      continuous_aggregate  - CREATE MATERIALIZED VIEW ... WITH (timescaledb.continuous)
      sliding_window  - Correlation queries using window functions for per-row sliding detection

    Correlation methods for 'postgres' (select with -O correlation_method=NAME, default: sliding):
      sliding  - Trailing per-event window (default; preserves existing SQL)
      tumbling  - Fixed boundary-aligned buckets (time_bucket/date_bin)
      session  - Gaps-and-islands sessionization (requires a gap)
    ");
}

#[test]
fn list_formats_invalid_target() {
    let output = rsigma()
        .args(["backend", "formats", "nonexistent"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_snapshot!(String::from_utf8_lossy(&output.stderr), @"
    Unknown target: nonexistent
    Available targets: postgres, lynxdb, fibratus, test
    ");
}
