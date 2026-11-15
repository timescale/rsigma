//! Integration tests for `rsigma ruleset list` and `rsigma ruleset show`.
//!
//! The fixture directory carries a copy of the parser ruleset fixtures plus
//! two config files: `rsigma.yaml` declares a working ruleset and a broken
//! one, and `vendor-only.yaml` declares only the working ruleset.

mod common;

use std::path::{Path, PathBuf};

use common::{assert_golden, rsigma};
use predicates::prelude::*;

const W1: &str = "aaaaaaaa-0000-4000-8000-000000000001";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rulesets")
}

#[test]
fn list_table_reports_a_working_ruleset() {
    rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "list",
            "--config",
            "vendor-only.yaml",
            "--output-format",
            "table",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("vendor"))
        .stdout(predicate::str::contains("sysmon"))
        .stdout(predicate::str::contains("ok"));
}

#[test]
fn list_json_reports_counts() {
    let output = rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "list",
            "--config",
            "vendor-only.yaml",
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let envelope: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let rulesets = envelope["rulesets"].as_array().unwrap();
    assert_eq!(rulesets.len(), 1);
    assert_eq!(rulesets[0]["name"], serde_json::json!("vendor"));
    assert_eq!(rulesets[0]["detection"], serde_json::json!(4));
    assert_eq!(rulesets[0]["correlation"], serde_json::json!(2));
    assert_eq!(rulesets[0]["filter"], serde_json::json!(1));
    assert_eq!(rulesets[0]["overlays"], serde_json::json!(3));
    assert_eq!(rulesets[0]["pipelines"], serde_json::json!("sysmon"));
    assert_eq!(rulesets[0]["status"], serde_json::json!("ok"));
    assert_eq!(rulesets[0]["error"], serde_json::json!(""));
}

#[test]
fn show_all_golden_table() {
    let output = rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "show",
            "vendor",
            "--all",
            "--config",
            "vendor-only.yaml",
            "--output-format",
            "table",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_golden("ruleset_show_all.txt", &String::from_utf8(output).unwrap());
}

#[test]
fn show_all_golden_json() {
    let output = rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "show",
            "vendor",
            "--all",
            "--config",
            "vendor-only.yaml",
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_golden("ruleset_show.json", &String::from_utf8(output).unwrap());
}

#[test]
fn show_defaults_to_kept_documents_only() {
    let output = rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "show",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--output-format",
            "table",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.contains("Windows whoami execution"), "{stdout}");
    assert!(stdout.contains("Linux SSH login"), "{stdout}");
    assert!(
        !stdout.contains("Windows curl download"),
        "excluded documents must be hidden by default: {stdout}"
    );
    assert!(
        !stdout.contains("Linux sudo elevation"),
        "unselected documents must be hidden by default: {stdout}"
    );
}

#[test]
fn show_id_yaml_emits_the_overlaid_document() {
    rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "show",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--id",
            W1,
            "--yaml",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("level: critical"))
        .stdout(predicate::str::contains("rsigma.exemplars"))
        .stdout(predicate::str::contains("name: windows_whoami"));
}

#[test]
fn show_id_detail_lists_applied_overlays() {
    let output = rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "show",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--id",
            &W1.to_uppercase(),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let envelope: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let document = &envelope["document"];
    assert_eq!(document["kind"], serde_json::json!("detection"));
    assert_eq!(document["decision"], serde_json::json!("included:0"));
    assert_eq!(
        document["origin"],
        serde_json::json!("s0:windows/proc_creation.yml#0")
    );
    let overlays = document["overlays"].as_array().unwrap();
    assert_eq!(overlays.len(), 3);
    assert_eq!(
        overlays[0]["origin"],
        serde_json::json!("overlays/levels.yml:0")
    );
    assert_eq!(overlays[0]["set"], serde_json::json!(["level"]));
    assert_eq!(overlays[1]["origin"], serde_json::json!("inline:1"));
    assert_eq!(
        overlays[2]["appended"],
        serde_json::json!(["custom_attributes.rsigma.exemplars"])
    );
}

#[test]
fn unknown_name_exits_three_and_lists_defined_names() {
    rsigma()
        .current_dir(fixtures())
        .args(["ruleset", "show", "nope", "--config", "vendor-only.yaml"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("unknown ruleset 'nope'"))
        .stderr(predicate::str::contains("defined rulesets: vendor"));
}

#[test]
fn broken_ruleset_is_reported_without_hiding_other_rows() {
    let output = rsigma()
        .current_dir(fixtures())
        .args(["ruleset", "list", "--output-format", "table"])
        .assert()
        .failure()
        .code(3)
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.contains("broken"), "{stdout}");
    assert!(stdout.contains("missing"), "{stdout}");
    assert!(stdout.contains("vendor"), "{stdout}");
    assert!(stdout.contains("error"), "{stdout}");
}

#[test]
fn empty_config_prints_a_hint() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("rsigma.yaml");
    std::fs::write(&cfg, "version: 1\n").unwrap();

    rsigma()
        .args(["ruleset", "list", "--config", cfg.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("No rulesets defined"))
        .stderr(predicate::str::contains("rsigma.yaml"));
}

#[test]
fn yaml_requires_an_id() {
    rsigma()
        .current_dir(fixtures())
        .args([
            "ruleset",
            "show",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--yaml",
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("--id"));
}
