//! Integration tests for the `engine discover-schemas` subcommand.

mod common;

use common::{rsigma, temp_file};
use predicates::prelude::*;

const MIXED_CORPUS: &str = concat!(
    r#"{"vendor":"acme","event_type":"alert","severity":5}"#,
    "\n",
    r#"{"vendor":"acme","event_type":"alert","severity":3}"#,
    "\n",
    r#"{"vendor":"acme","event_type":"alert","severity":8}"#,
    "\n",
    r#"{"vendor":"acme","event_type":"alert","severity":2}"#,
    "\n",
    // An ECS event: recognized by a built-in, so it must never be mined.
    r#"{"ecs.version":"8.11.0","process":{"command_line":"whoami"}}"#,
    "\n",
);

#[test]
fn discovers_candidate_from_ndjson_stdin() {
    rsigma()
        .args(["engine", "discover-schemas", "--output-format", "json"])
        .write_stdin(MIXED_CORPUS)
        .assert()
        .success()
        // The four vendor events are mined; the ECS event is excluded.
        .stdout(predicate::str::contains("\"events_mined\": 4"))
        .stdout(predicate::str::contains("\"discovered_alert\""))
        .stdout(predicate::str::contains("\"signatures_yaml\""));
}

#[test]
fn emit_yaml_prints_only_the_schemas_block() {
    let out = rsigma()
        .args(["engine", "discover-schemas", "--emit", "yaml"])
        .write_stdin(MIXED_CORPUS)
        .output()
        .expect("run discover");
    assert!(out.status.success());
    let yaml = String::from_utf8(out.stdout).expect("utf8");
    assert!(yaml.trim_start().starts_with("schemas:"), "got: {yaml}");
    assert!(yaml.contains("event_type"));
    // The report chrome must be absent in yaml-only mode.
    assert!(!yaml.contains("SUPPORT"));
    assert!(!yaml.contains("Paste into"));
}

#[test]
fn dry_run_reports_before_and_after_counts() {
    rsigma()
        .args([
            "engine",
            "discover-schemas",
            "--dry-run",
            "--output-format",
            "table",
        ])
        .write_stdin(MIXED_CORPUS)
        .assert()
        .success()
        .stdout(predicate::str::contains("Dry run (classification impact)"))
        // Before mining everything is generic_json; the proposals drain it.
        .stdout(predicate::str::contains("generic_json: 4 -> 0"));
}

#[test]
fn emitted_yaml_round_trips_through_classify() {
    // Discover proposals, then feed them back to `engine classify` and confirm
    // the previously-unknown events now classify under a discovered schema.
    let out = rsigma()
        .args(["engine", "discover-schemas", "--emit", "yaml"])
        .write_stdin(MIXED_CORPUS)
        .output()
        .expect("run discover");
    assert!(out.status.success());
    let yaml = String::from_utf8(out.stdout).expect("utf8");
    let config = temp_file(".yml", &yaml);

    rsigma()
        .args([
            "engine",
            "classify",
            "-e",
            r#"{"vendor":"acme","event_type":"alert","severity":9}"#,
            "--schema-config",
            config.path().to_str().unwrap(),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema\": \"discovered_alert\""));
}

#[test]
fn no_value_markers_yields_presence_predicates() {
    let out = rsigma()
        .args([
            "engine",
            "discover-schemas",
            "--emit",
            "yaml",
            "--no-value-markers",
        ])
        .write_stdin(MIXED_CORPUS)
        .output()
        .expect("run discover");
    assert!(out.status.success());
    let yaml = String::from_utf8(out.stdout).expect("utf8");
    assert!(yaml.contains("field_present:"), "got: {yaml}");
    assert!(
        !yaml.contains("equals:"),
        "value markers should be off: {yaml}"
    );
}

#[test]
fn evtx_path_is_rejected() {
    rsigma()
        .args(["engine", "discover-schemas", "-e", "@evidence.evtx"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(".evtx"));
}
