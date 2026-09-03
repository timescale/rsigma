//! Integration tests for `rsigma rule test`.

mod common;

use std::path::{Path, PathBuf};

use common::rsigma;
use predicates::prelude::*;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test")
}

fn fixture(name: &str) -> String {
    fixtures().join(name).to_string_lossy().into_owned()
}

fn mask_source(json: &str) -> String {
    const KEY: &str = "\"source\":\"";
    let Some(start) = json.find(KEY) else {
        return json.to_string();
    };
    let value_start = start + KEY.len();
    let Some(rel_end) = json[value_start..].find('"') else {
        return json.to_string();
    };
    let end = value_start + rel_end;
    format!("{}FIXTURE{}", &json[..value_start], &json[end..])
}

#[test]
fn test_json_report_passes() {
    let out = rsigma()
        .args([
            "rule",
            "test",
            "--rules",
            &fixture("whoami.yml"),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let actual = mask_source(&String::from_utf8(out).unwrap());
    let value: serde_json::Value = serde_json::from_str(&actual).unwrap();
    assert_eq!(value["summary"]["passed"], 2);
    assert_eq!(value["summary"]["failed"], 0);
    assert_eq!(value["results"].as_array().unwrap().len(), 2);
    assert_eq!(value["results"][0]["passed"], true);
    assert_eq!(value["source"], "FIXTURE");
}

#[test]
fn test_table_default_contains_headers() {
    rsigma()
        .args(["rule", "test", "--rules", &fixture("whoami.yml")])
        .assert()
        .success()
        .stdout(predicate::str::contains("RULE"))
        .stdout(predicate::str::contains("whoami fires"))
        .stdout(predicate::str::contains("pass"));
}

#[test]
fn test_csv_and_tsv_and_ndjson() {
    for format in ["csv", "tsv", "ndjson"] {
        rsigma()
            .args([
                "rule",
                "test",
                "--rules",
                &fixture("whoami.yml"),
                "--output-format",
                format,
            ])
            .assert()
            .success();
    }
}

#[test]
fn test_failed_assertion_exits_findings() {
    rsigma()
        .args([
            "rule",
            "test",
            "--rules",
            &fixture("failing.yml"),
            "--output-format",
            "json",
        ])
        .assert()
        .failure()
        .code(1);
}

#[test]
fn test_fail_on_missing() {
    rsigma()
        .args([
            "rule",
            "test",
            "--rules",
            &fixture("no_exemplars.yml"),
            "--fail-on-missing",
        ])
        .assert()
        .failure()
        .code(1);
}

#[test]
fn test_missing_without_flag_succeeds() {
    rsigma()
        .args(["rule", "test", "--rules", &fixture("no_exemplars.yml")])
        .assert()
        .success();
}

#[test]
fn test_multi_path_loading() {
    rsigma()
        .args([
            "rule",
            "test",
            "--rules",
            &fixture("whoami.yml"),
            "--rules",
            &fixture("no_exemplars.yml"),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"passed\":2"));
}

#[test]
fn test_malformed_exits_config() {
    let yaml = common::temp_file(
        ".yml",
        r#"
title: Bad
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
custom_attributes:
    rsigma.exemplars: []
"#,
    );
    rsigma()
        .args(["rule", "test", "--rules", yaml.path().to_str().unwrap()])
        .assert()
        .failure()
        .code(3);
}

#[test]
fn test_missing_path_exits_rule_error() {
    rsigma()
        .args(["rule", "test", "--rules", "/no/such/rule.yml"])
        .assert()
        .failure()
        .code(2);
}
