//! Integration tests for `rsigma rule doc`: the golden JSON report, Markdown
//! ADS document, and scaffold template, plus boundary and error paths (exit
//! codes, `--missing-only` filtering, the `--fail-on-missing` gate, and the
//! in-place scaffold merge). Per-section assembly and scaffold logic is
//! unit-tested in the command and parser modules; these tests cover the
//! end-to-end CLI surface only.

mod common;

use std::path::{Path, PathBuf};

use common::{rsigma, temp_file};
use predicates::prelude::*;

const REPORT_GOLDEN: &str = include_str!("golden/doc_report.json");
const MARKDOWN_GOLDEN: &str = include_str!("golden/doc_markdown.md");
const SCAFFOLD_GOLDEN: &str = include_str!("golden/doc_scaffold.yaml");

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/doc")
}

fn fixture(name: &str) -> String {
    fixtures().join(name).to_string_lossy().into_owned()
}

fn normalize_eol(s: &str) -> String {
    s.replace("\r\n", "\n")
}

/// Replace the volatile `"source":"<path>"` value in a JSON report with a fixed
/// marker. The path is the checkout/temp location, which varies by runner and
/// OS, and serde_json escapes a Windows path's backslashes (`\` -> `\\`), so a
/// raw path-string replace would miss it. A file path never contains an
/// unescaped `"`, so the next quote terminates the value.
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
fn doc_json_report_matches_golden() {
    let documented = fixture("documented.yml");
    let out = rsigma()
        .args(["rule", "doc", &documented, "--output-format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let actual = mask_source(&String::from_utf8(out).unwrap());
    assert_eq!(
        normalize_eol(&actual).trim_end(),
        normalize_eol(REPORT_GOLDEN).trim_end(),
        "JSON report drifted from golden"
    );
}

#[test]
fn doc_markdown_matches_golden() {
    let out = rsigma()
        .args([
            "rule",
            "doc",
            &fixture("documented.yml"),
            "--format",
            "markdown",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let actual = String::from_utf8(out).unwrap();
    assert_eq!(
        normalize_eol(&actual).trim_end(),
        normalize_eol(MARKDOWN_GOLDEN).trim_end(),
        "Markdown ADS document drifted from golden"
    );
}

#[test]
fn doc_scaffold_matches_golden() {
    let out = rsigma()
        .args(["rule", "doc", "--scaffold", &fixture("bare.yml")])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let actual = String::from_utf8(out).unwrap();
    assert_eq!(
        normalize_eol(&actual).trim_end(),
        normalize_eol(SCAFFOLD_GOLDEN).trim_end(),
        "scaffold template drifted from golden"
    );
}

#[test]
fn fail_on_missing_exits_one_for_bare_rule() {
    rsigma()
        .args(["rule", "doc", &fixture("bare.yml"), "--fail-on-missing"])
        .assert()
        .code(1);
}

#[test]
fn fail_on_missing_exits_zero_for_documented_rule() {
    rsigma()
        .args([
            "rule",
            "doc",
            &fixture("documented.yml"),
            "--fail-on-missing",
        ])
        .assert()
        .success();
}

#[test]
fn missing_only_filters_documented_rule_out() {
    // A fully documented rule is above the bar, so --missing-only shows zero
    // rules in the JSON report.
    rsigma()
        .args([
            "rule",
            "doc",
            &fixture("documented.yml"),
            "--missing-only",
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"rules\":[]"));
}

#[test]
fn scaffold_on_directory_is_config_error() {
    rsigma()
        .args(["rule", "doc", "--scaffold", fixtures().to_str().unwrap()])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("single rule file"));
}

#[test]
fn unreadable_rules_path_is_rule_error() {
    rsigma()
        .args(["rule", "doc", "/tmp/nonexistent_rsigma_doc_rule.yml"])
        .assert()
        .code(2);
}

#[test]
fn in_place_scaffold_fills_custom_sections() {
    // A rule with the reused fields (goal/categorization/false_positives) but
    // none of the rsigma.ads.* sections: scaffolding in place fills the gap, so
    // a follow-up gate passes.
    let rule = temp_file(
        ".yml",
        r#"title: Partial Rule
id: 99999999-8888-7777-6666-555555555555
status: stable
description: Has a goal already.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: medium
tags:
    - attack.execution
falsepositives:
    - Known benign tooling
"#,
    );
    let path = rule.path().to_str().unwrap();

    rsigma()
        .args(["rule", "doc", "--scaffold", path, "--in-place"])
        .assert()
        .success();

    // After the merge every required section is present, so the gate passes.
    rsigma()
        .args(["rule", "doc", path, "--fail-on-missing"])
        .assert()
        .success();
}

#[test]
fn explicit_missing_lint_config_is_config_error() {
    // An explicit --lint-config that cannot be read is a hard error, matching
    // `rule lint`, rather than silently falling back to the default ADS bar.
    rsigma()
        .args([
            "rule",
            "doc",
            &fixture("documented.yml"),
            "--lint-config",
            "/tmp/nonexistent_rsigma_lint_config.yml",
        ])
        .assert()
        .code(3);
}

#[test]
fn in_place_scaffold_does_not_duplicate_a_blank_key() {
    // A rule with a present-but-blank rsigma.ads.strategy: the scaffold must
    // not prepend a second `rsigma.ads.strategy:` key (a duplicate the YAML
    // parser would silently collapse back to the empty value).
    let rule = temp_file(
        ".yml",
        r#"title: Blank Section Rule
id: 12121212-3434-5656-7878-909090909090
status: stable
description: Has a goal already.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: medium
tags:
    - attack.execution
falsepositives:
    - Known benign tooling
custom_attributes:
    rsigma.ads.strategy: ""
"#,
    );
    let path = rule.path().to_str().unwrap();

    rsigma()
        .args(["rule", "doc", "--scaffold", path, "--in-place"])
        .assert()
        .success();

    let merged = std::fs::read_to_string(rule.path()).unwrap();
    let strategy_keys = merged.matches("rsigma.ads.strategy:").count();
    assert_eq!(
        strategy_keys, 1,
        "blank key must not be duplicated:\n{merged}"
    );
    // The genuinely-absent sections were still added.
    assert!(merged.contains("rsigma.ads.validation:"));

    // The merged file still parses (no duplicate-key breakage).
    rsigma().args(["rule", "doc", path]).assert().success();
}

#[test]
fn dry_run_prints_config() {
    rsigma()
        .args(["rule", "doc", &fixture("documented.yml"), "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("fail_on_missing"));
}
