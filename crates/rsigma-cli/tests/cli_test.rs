//! Integration tests for `rsigma rule test`.

mod common;

use std::path::{Path, PathBuf};

use common::rsigma;
use predicates::prelude::*;

const JSON_GOLDEN: &str = include_str!("golden/test_report.json");
const FAILING_JSON_GOLDEN: &str = include_str!("golden/test_failing.json");
const NDJSON_GOLDEN: &str = include_str!("golden/test_report.ndjson");
const CSV_GOLDEN: &str = include_str!("golden/test_report.csv");
const TSV_GOLDEN: &str = include_str!("golden/test_report.tsv");
const TABLE_GOLDEN: &str = include_str!("golden/test_table.txt");

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test")
}

fn fixture(name: &str) -> String {
    fixtures().join(name).to_string_lossy().into_owned()
}

/// Normalize line endings (CRLF -> LF) so the committed goldens compare equal
/// regardless of checkout: on Windows, git may rewrite the LF golden files to
/// CRLF, which `include_str!` then embeds, while the binary always writes LF.
fn normalize_eol(s: &str) -> String {
    s.replace("\r\n", "\n")
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

fn run_format(rules: &str, format: Option<&str>) -> String {
    let mut cmd = rsigma();
    cmd.args(["rule", "test", "--rules", rules]);
    if let Some(format) = format {
        cmd.args(["--output-format", format]);
    }
    let out = cmd.assert().success().get_output().stdout.clone();
    String::from_utf8(out).unwrap()
}

#[test]
fn test_json_report_matches_golden() {
    let actual = mask_source(&run_format(&fixture("whoami.yml"), Some("json")));
    assert_eq!(
        actual.trim_end(),
        normalize_eol(JSON_GOLDEN).trim_end(),
        "JSON report drifted from golden"
    );
}

#[test]
fn test_table_default_matches_golden() {
    let actual = run_format(&fixture("whoami.yml"), None);
    assert_eq!(
        normalize_eol(&actual).trim_end(),
        normalize_eol(TABLE_GOLDEN).trim_end(),
        "table output drifted from golden"
    );
}

#[test]
fn test_ndjson_csv_tsv_match_goldens() {
    for (format, golden) in [
        ("ndjson", NDJSON_GOLDEN),
        ("csv", CSV_GOLDEN),
        ("tsv", TSV_GOLDEN),
    ] {
        let actual = run_format(&fixture("whoami.yml"), Some(format));
        assert_eq!(
            normalize_eol(&actual).trim_end(),
            normalize_eol(golden).trim_end(),
            "{format} output drifted from golden"
        );
    }
}

#[test]
fn test_failed_assertion_exits_findings_with_diagnostic() {
    let out = rsigma()
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
        .code(1)
        .get_output()
        .stdout
        .clone();
    let actual = mask_source(&String::from_utf8(out).unwrap());
    assert_eq!(
        actual.trim_end(),
        normalize_eol(FAILING_JSON_GOLDEN).trim_end(),
        "failing JSON report drifted from golden"
    );
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
