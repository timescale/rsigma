//! Integration tests for `rsigma backend build`.
//!
//! Every test works on a writable copy of the ruleset fixtures and appends a
//! `convert:` section, so a group's output and manifest can be compared with
//! committed goldens.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{assert_golden, assert_json_golden, rsigma_isolated as rsigma};
use serde_json::Value;

const UNSUPPORTED_RULE: &str = r#"title: Cased field reference
id: eeeeeeee-0000-4000-8000-000000000001
status: stable
description: Image equals CommandLine, compared case-sensitively.
author: Test Author
level: low
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|fieldref|cased: CommandLine
    condition: selection
"#;

const CONVERT_CONFIG: &str = r#"
convert:
  defaults:
    format: default
    options:
      gap: 5m
    skip_unsupported: true
    metadata:
      rule_group: windows
      time_window: 5m
  groups:
    vendor_default:
      ruleset: vendor
      target: test
      output: build/vendor-default.txt
      metadata:
        rule_group: windows
        time_window: 5m
        nested:
          owner: soc
          window: 1h
    vendor_sysmon:
      ruleset: vendor
      target: test
      pipelines: [sysmon]
      output: build/vendor-sysmon.txt
    unsupported_test:
      ruleset: unsupported
      target: test
      skip_unsupported: false
      output: build/unsupported.txt
    missing_ruleset:
      ruleset: nope
      target: test
      output: build/missing.txt
"#;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rulesets")
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A writable copy of the fixtures with a `convert:` section appended.
fn fixture_copy() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    copy_tree(&fixtures(), dir.path());
    let config = dir.path().join("rsigma.yaml");
    let mut body = fs::read_to_string(&config).unwrap();
    body = body.replacen(
        "rulesets:\n",
        "rulesets:\n  unsupported:\n    sources:\n      - unsupported\n",
        1,
    );
    body.push_str(CONVERT_CONFIG);
    fs::write(&config, body).unwrap();
    fs::create_dir_all(dir.path().join("unsupported")).unwrap();
    fs::write(dir.path().join("unsupported/regex.yml"), UNSUPPORTED_RULE).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    let mut command = rsigma();
    command.current_dir(dir).args(args);
    command.output().expect("run rsigma")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_str(stdout(output).trim()).unwrap()
}

/// Read a manifest and replace its generator line, so the golden does not
/// change with the crate version.
fn normalized_manifest(path: &Path) -> String {
    let mut value: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    value["generator"] = serde_json::json!("rsigma test");
    let mut text = serde_json::to_string_pretty(&value).unwrap();
    text.push('\n');
    text
}

#[test]
fn build_writes_only_the_selected_group() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "backend",
            "build",
            "--config",
            "rsigma.yaml",
            "--group",
            "vendor_default",
            "--output-format",
            "json",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let envelope = json_stdout(&output);
    let groups = envelope["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1, "{envelope}");
    assert_eq!(groups[0]["group"], serde_json::json!("vendor_default"));
    assert_eq!(groups[0]["status"], serde_json::json!("written"));

    assert!(!dir.path().join("build/vendor-sysmon.txt").exists());
    assert_golden(
        "backend_build/vendor_default.txt",
        &fs::read_to_string(dir.path().join("build/vendor-default.txt")).unwrap(),
    );
    assert_json_golden(
        "backend_build/vendor_default.txt.manifest.json",
        &normalized_manifest(&dir.path().join("build/vendor-default.txt.manifest.json")),
    );
}

#[test]
fn build_runs_every_group_in_name_order() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "backend",
            "build",
            "--config",
            "rsigma.yaml",
            "--group",
            "vendor_sysmon",
            "--group",
            "vendor_default",
            "--output-format",
            "json",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let envelope = json_stdout(&output);
    let names: Vec<&str> = envelope["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["group"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["vendor_default", "vendor_sysmon"]);
    assert_golden(
        "backend_build/vendor_sysmon.txt",
        &fs::read_to_string(dir.path().join("build/vendor-sysmon.txt")).unwrap(),
    );
    assert_json_golden(
        "backend_build/vendor_sysmon.txt.manifest.json",
        &normalized_manifest(&dir.path().join("build/vendor-sysmon.txt.manifest.json")),
    );
}

#[test]
fn check_is_clean_then_reports_drift() {
    let dir = fixture_copy();
    let build = run(
        dir.path(),
        &[
            "backend",
            "build",
            "--config",
            "rsigma.yaml",
            "--group",
            "vendor_default",
        ],
    );
    assert!(build.status.success(), "{}", stderr(&build));

    let clean = run(
        dir.path(),
        &[
            "backend",
            "build",
            "--config",
            "rsigma.yaml",
            "--group",
            "vendor_default",
            "--check",
        ],
    );
    assert!(clean.status.success(), "{}", stderr(&clean));
    assert!(stderr(&clean).contains("No drift"));

    fs::write(dir.path().join("build/vendor-default.txt"), "drifted\n").unwrap();
    let dirty = run(
        dir.path(),
        &[
            "backend",
            "build",
            "--config",
            "rsigma.yaml",
            "--group",
            "vendor_default",
            "--check",
            "--output-format",
            "json",
        ],
    );
    assert_eq!(dirty.status.code(), Some(1), "{}", stderr(&dirty));
    let envelope = json_stdout(&dirty);
    let drifted = envelope["drifted"].as_array().unwrap();
    assert_eq!(drifted.len(), 1, "{envelope}");
    assert_eq!(drifted[0]["group"], serde_json::json!("vendor_default"));
    assert_eq!(
        drifted[0]["path"],
        serde_json::json!("build/vendor-default.txt")
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("build/vendor-default.txt")).unwrap(),
        "drifted\n",
        "check must not rewrite the file"
    );
}

#[test]
fn a_failing_group_does_not_stop_the_others() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "backend",
            "build",
            "--config",
            "rsigma.yaml",
            "--group",
            "vendor_default",
            "--group",
            "unsupported_test",
            "--output-format",
            "json",
        ],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let envelope = json_stdout(&output);
    let groups = envelope["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 2, "{envelope}");
    assert_eq!(groups[0]["group"], serde_json::json!("unsupported_test"));
    assert_eq!(groups[0]["status"], serde_json::json!("failed"));
    assert_eq!(groups[1]["group"], serde_json::json!("vendor_default"));
    assert_eq!(groups[1]["status"], serde_json::json!("written"));
    assert!(dir.path().join("build/vendor-default.txt").exists());

    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(dir.path().join("build/unsupported.txt.manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["rules"][0]["status"], serde_json::json!("failed"));
    assert_eq!(manifest["queries"], serde_json::json!(0));
}

#[test]
fn an_unknown_ruleset_exits_three_without_stopping_other_groups() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "backend",
            "build",
            "--config",
            "rsigma.yaml",
            "--group",
            "missing_ruleset",
            "--group",
            "vendor_default",
            "--output-format",
            "json",
        ],
    );
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("unknown ruleset 'nope'"));
    let envelope = json_stdout(&output);
    let groups = envelope["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 2, "{envelope}");
    assert_eq!(groups[0]["group"], serde_json::json!("missing_ruleset"));
    assert_eq!(groups[0]["status"], serde_json::json!("failed"));
    assert_eq!(groups[1]["status"], serde_json::json!("written"));
    assert!(dir.path().join("build/vendor-default.txt").exists());
}

#[test]
fn an_unknown_group_exits_three() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "backend",
            "build",
            "--config",
            "rsigma.yaml",
            "--group",
            "nope",
        ],
    );
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("unknown convert group 'nope'"));
}

#[test]
fn metadata_round_trips_verbatim() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "backend",
            "build",
            "--config",
            "rsigma.yaml",
            "--group",
            "vendor_default",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(dir.path().join("build/vendor-default.txt.manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["metadata"],
        serde_json::json!({
            "rule_group": "windows",
            "time_window": "5m",
            "nested": {"owner": "soc", "window": "1h"}
        })
    );
    assert_eq!(manifest["manifest_version"], serde_json::json!(1));
    assert_eq!(manifest["target"], serde_json::json!("test"));
    assert_eq!(manifest["format"], serde_json::json!("default"));
    let detection = manifest["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["kind"] == serde_json::json!("detection"))
        .expect("a detection rule");
    assert_eq!(detection["sha256"].as_str().unwrap().len(), 64);
}
