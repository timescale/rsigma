//! Integration tests for the `engine explain` subcommand.

mod common;

use common::{rsigma, temp_file};
use predicates::prelude::*;

const RULE: &str = r#"
title: Suspicious PowerShell
id: ps-1
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: '-enc'
    filter:
        User: SYSTEM
    condition: selection and not filter
level: high
"#;

fn rule_file() -> tempfile::NamedTempFile {
    temp_file(".yml", RULE)
}

#[test]
fn explains_a_match_as_human_tree() {
    let f = rule_file();
    rsigma()
        .args([
            "engine",
            "explain",
            "-r",
            f.path().to_str().unwrap(),
            "--color",
            "never",
            "-e",
            r#"{"Image":"C:\\Windows\\powershell.exe","CommandLine":"powershell -enc AAAA","User":"alice"}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Suspicious PowerShell (ps-1): MATCH"))
        .stdout(predicate::str::contains("PASS selection"));
}

#[test]
fn near_miss_reports_value_mismatch_with_actual() {
    let f = rule_file();
    rsigma()
        .args([
            "engine",
            "explain",
            "-r",
            f.path().to_str().unwrap(),
            "--color",
            "never",
            "-e",
            r#"{"Image":"C:\\Windows\\cmd.exe","CommandLine":"powershell -enc AAAA","User":"SYSTEM"}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("NO MATCH"))
        .stdout(predicate::str::contains("value mismatch"))
        .stdout(predicate::str::contains("actual=\"C:\\\\Windows\\\\cmd.exe\""));
}

#[test]
fn absent_field_reports_field_absent() {
    let f = rule_file();
    rsigma()
        .args([
            "engine",
            "explain",
            "-r",
            f.path().to_str().unwrap(),
            "--color",
            "never",
            "-e",
            r#"{"Image":"C:\\Windows\\powershell.exe"}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("field absent"));
}

#[test]
fn case_only_difference_reports_case_mismatch() {
    let rule = temp_file(
        ".yml",
        r#"
title: Cased
id: cased-1
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|endswith|cased: '\powershell.exe'
    condition: selection
"#,
    );
    rsigma()
        .args([
            "engine",
            "explain",
            "-r",
            rule.path().to_str().unwrap(),
            "--color",
            "never",
            "-e",
            r#"{"CommandLine":"C:\\Windows\\POWERSHELL.EXE"}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("case mismatch"));
}

#[test]
fn negation_node_is_rendered() {
    let f = rule_file();
    rsigma()
        .args([
            "engine",
            "explain",
            "-r",
            f.path().to_str().unwrap(),
            "--color",
            "never",
            "-e",
            r#"{"Image":"C:\\Windows\\powershell.exe","CommandLine":"-enc","User":"SYSTEM"}"#,
        ])
        .assert()
        .success()
        // filter matches (User=SYSTEM) so `not filter` is FAIL, no overall match.
        .stdout(predicate::str::contains("not:"))
        .stdout(predicate::str::contains("NO MATCH"));
}

#[test]
fn quantified_selector_reports_counts() {
    let rule = temp_file(
        ".yml",
        r#"
title: One Of
id: oneof-1
logsource:
    category: test
detection:
    selection_a:
        CommandLine|contains: powershell
    selection_b:
        CommandLine|contains: whoami
    condition: 1 of selection_*
"#,
    );
    rsigma()
        .args([
            "engine",
            "explain",
            "-r",
            rule.path().to_str().unwrap(),
            "--color",
            "never",
            "-e",
            r#"{"CommandLine":"run powershell"}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1/1 matched)"))
        .stdout(predicate::str::contains("MATCH"));
}

#[test]
fn json_output_serializes_the_trace() {
    let f = rule_file();
    rsigma()
        .args([
            "engine",
            "explain",
            "-r",
            f.path().to_str().unwrap(),
            "--output-format",
            "json",
            "-e",
            r#"{"Image":"C:\\Windows\\cmd.exe"}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"matched\":false"))
        .stdout(predicate::str::contains("\"reason\":\"value_mismatch\""))
        .stdout(predicate::str::contains("\"type\":\"selection\""));
}

#[test]
fn pipeline_rename_is_reflected_in_the_trace() {
    let rule = temp_file(
        ".yml",
        r#"
title: CmdLine
id: cl-1
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: mimikatz
    condition: selection
"#,
    );
    let pipeline = temp_file(
        ".yml",
        r#"
name: ecs-ish
priority: 10
transformations:
  - type: field_name_mapping
    mapping:
      CommandLine: process.command_line
"#,
    );
    rsigma()
        .args([
            "engine",
            "explain",
            "-r",
            rule.path().to_str().unwrap(),
            "-p",
            pipeline.path().to_str().unwrap(),
            "--color",
            "never",
            "-e",
            r#"{"process":{"command_line":"mimikatz.exe"}}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("process.command_line"))
        .stdout(predicate::str::contains("MATCH"));
}

#[test]
fn rule_id_filter_selects_one_rule() {
    let rule = temp_file(
        ".yml",
        r#"
title: First
id: first
logsource: {category: test}
detection:
    selection:
        A: 1
    condition: selection
---
title: Second
id: second
logsource: {category: test}
detection:
    selection:
        B: 2
    condition: selection
"#,
    );
    rsigma()
        .args([
            "engine",
            "explain",
            "-r",
            rule.path().to_str().unwrap(),
            "--rule-id",
            "second",
            "--color",
            "never",
            "-e",
            r#"{"B":2}"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Second (second): MATCH"))
        .stdout(predicate::str::contains("First").not());
}

#[test]
fn invalid_inline_json_exits_nonzero() {
    let f = rule_file();
    rsigma()
        .args([
            "engine",
            "explain",
            "-r",
            f.path().to_str().unwrap(),
            "-e",
            "not json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid JSON event"));
}
