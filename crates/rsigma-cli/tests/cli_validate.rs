//! Integration tests for the validate subcommand.

mod common;

use common::{PIPELINE_YAML, SIMPLE_RULE, rsigma, temp_file};
use predicates::prelude::*;

const SIMPLE_RULE_WINDASH: &str = r#"
title: Test Windash
id: 00000000-0000-0000-0000-000000000002
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|windash|contains: "-exec"
    condition: selection
level: medium
"#;

#[test]
fn validate_directory_with_valid_rules() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rule1.yml"), SIMPLE_RULE).unwrap();
    std::fs::write(dir.path().join("rule2.yml"), SIMPLE_RULE_WINDASH).unwrap();

    rsigma()
        .args(["validate", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Detection rules:"))
        .stdout(predicate::str::contains("Compiled OK:"));
}

#[test]
fn validate_directory_with_errors() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bad.yml"), "42").unwrap();

    rsigma()
        .args(["validate", dir.path().to_str().unwrap(), "--verbose"])
        .assert()
        .stdout(predicate::str::contains("Parsed"));
}

#[test]
fn validate_nonexistent_directory() {
    rsigma()
        .args(["validate", "/tmp/nonexistent_rsigma_dir"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn validate_with_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rule.yml"), SIMPLE_RULE).unwrap();
    let pipeline = temp_file(".yml", PIPELINE_YAML);

    rsigma()
        .args([
            "validate",
            dir.path().to_str().unwrap(),
            "-p",
            pipeline.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Pipeline applied:"));
}
