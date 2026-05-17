//! Integration tests for parse, condition, and stdin subcommands.

mod common;

use common::{SIMPLE_RULE, rsigma, temp_file};
use predicates::prelude::*;

// ---------------------------------------------------------------------------
// parse subcommand
// ---------------------------------------------------------------------------

#[test]
fn parse_valid_rule() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args(["rule", "parse", rule.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Test Rule"))
        .stdout(predicate::str::contains("malware"));
}

#[test]
fn parse_nonexistent_file() {
    rsigma()
        .args(["rule", "parse", "/tmp/nonexistent_rsigma_test.yml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn parse_invalid_yaml() {
    let bad = temp_file(".yml", "42");
    rsigma()
        .args(["rule", "parse", bad.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Warning"));
}

// ---------------------------------------------------------------------------
// condition subcommand
// ---------------------------------------------------------------------------

#[test]
fn condition_valid() {
    rsigma()
        .args(["rule", "condition", "selection1 and not filter"])
        .assert()
        .success()
        .stdout(predicate::str::contains("And"))
        .stdout(predicate::str::contains("selection1"))
        .stdout(predicate::str::contains("filter"));
}

#[test]
fn condition_complex() {
    rsigma()
        .args([
            "rule",
            "condition",
            "1 of selection* or (filter1 and filter2)",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("selection*"));
}

#[test]
fn condition_invalid() {
    rsigma()
        .args(["rule", "condition", "invalid !!! syntax"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

// ---------------------------------------------------------------------------
// stdin subcommand
// ---------------------------------------------------------------------------

#[test]
fn stdin_valid_rule() {
    rsigma()
        .args(["rule", "stdin"])
        .write_stdin(SIMPLE_RULE)
        .assert()
        .success()
        .stdout(predicate::str::contains("Test Rule"));
}

#[test]
fn stdin_invalid_yaml() {
    rsigma()
        .args(["rule", "stdin"])
        .write_stdin("12345")
        .assert()
        .success()
        .stderr(predicate::str::contains("Warning"));
}
