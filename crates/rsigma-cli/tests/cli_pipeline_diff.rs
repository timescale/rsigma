//! Integration tests for the `pipeline diff` subcommand.

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
    condition: selection
level: high
"#;

#[test]
fn one_to_one_rename_shows_before_and_after() {
    let rule = temp_file(".yml", RULE);
    let pipe = temp_file(
        ".yml",
        r#"
name: ecs-ish
priority: 10
transformations:
  - id: rename_image
    type: field_name_mapping
    mapping:
      Image: process.executable
"#,
    );
    rsigma()
        .args([
            "pipeline",
            "diff",
            "-r",
            rule.path().to_str().unwrap(),
            "-p",
            pipe.path().to_str().unwrap(),
            "--color",
            "never",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "transformations applied: rename_image",
        ))
        .stdout(predicate::str::contains(
            "-              \"name\": \"Image\"",
        ))
        .stdout(predicate::str::contains(
            "+              \"name\": \"process.executable\"",
        ));
}

#[test]
fn one_to_many_mapping_expands_to_anyof() {
    let rule = temp_file(".yml", RULE);
    let pipe = temp_file(
        ".yml",
        r#"
name: fan-out
priority: 10
transformations:
  - id: fan_out_cmdline
    type: field_name_mapping
    mapping:
      CommandLine:
        - process.command_line
        - process.args
"#,
    );
    rsigma()
        .args([
            "pipeline",
            "diff",
            "-r",
            rule.path().to_str().unwrap(),
            "-p",
            pipe.path().to_str().unwrap(),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"changed\":true"))
        .stdout(predicate::str::contains("process.command_line"))
        .stdout(predicate::str::contains("process.args"))
        // The Cartesian expansion introduces an AnyOf node in the AST.
        .stdout(predicate::str::contains("AnyOf"));
}

#[test]
fn no_op_pipeline_reports_no_change() {
    let rule = temp_file(".yml", RULE);
    let pipe = temp_file(
        ".yml",
        r#"
name: irrelevant
priority: 10
transformations:
  - id: rename_absent
    type: field_name_mapping
    mapping:
      ThisFieldIsNotInTheRule: something.else
"#,
    );
    rsigma()
        .args([
            "pipeline",
            "diff",
            "-r",
            rule.path().to_str().unwrap(),
            "-p",
            pipe.path().to_str().unwrap(),
            "--color",
            "never",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(no change)"));
}

#[test]
fn json_output_carries_before_after_and_applied_items() {
    let rule = temp_file(".yml", RULE);
    let pipe = temp_file(
        ".yml",
        r#"
name: ecs-ish
priority: 10
transformations:
  - id: rename_image
    type: field_name_mapping
    mapping:
      Image: process.executable
"#,
    );
    rsigma()
        .args([
            "pipeline",
            "diff",
            "-r",
            rule.path().to_str().unwrap(),
            "-p",
            pipe.path().to_str().unwrap(),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"changed\":true"))
        .stdout(predicate::str::contains(
            "\"applied_items\":[\"rename_image\"]",
        ))
        .stdout(predicate::str::contains("\"before\":"))
        .stdout(predicate::str::contains("\"after\":"));
}

#[test]
fn rule_id_filter_selects_one_rule() {
    let rules = temp_file(
        ".yml",
        r#"
title: First
id: first
logsource: {category: test}
detection:
    selection:
        Image: a
    condition: selection
---
title: Second
id: second
logsource: {category: test}
detection:
    selection:
        Image: b
    condition: selection
"#,
    );
    let pipe = temp_file(
        ".yml",
        r#"
name: ecs-ish
priority: 10
transformations:
  - id: rename_image
    type: field_name_mapping
    mapping:
      Image: process.executable
"#,
    );
    rsigma()
        .args([
            "pipeline",
            "diff",
            "-r",
            rules.path().to_str().unwrap(),
            "-p",
            pipe.path().to_str().unwrap(),
            "--rule-id",
            "second",
            "--color",
            "never",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Second (second)"))
        .stdout(predicate::str::contains("First").not());
}
