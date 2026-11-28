//! Integration tests for `rsigma rule coverage`: the golden Navigator layer and
//! coverage report, plus boundary and error paths (exit codes, cross-reference
//! gaps, config-file layering). Tag extraction and gap computation are
//! unit-tested in the command module; these tests cover the end-to-end CLI
//! surface only and never touch the network.

use crate::common;

use std::path::{Path, PathBuf};

use common::{rsigma, temp_file};
use predicates::prelude::*;

const REPORT_GOLDEN: &str = include_str!("golden/coverage_report.json");
const LAYER_GOLDEN: &str = include_str!("golden/coverage_layer.json");
const PLAN_JSON_GOLDEN: &str = include_str!("golden/coverage_atomics_plan.json");
const PLAN_TABLE_GOLDEN: &str = include_str!("golden/coverage_atomics_plan.txt");

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/coverage")
}

fn fixture(name: &str) -> String {
    fixtures().join(name).to_string_lossy().into_owned()
}

fn normalize_eol(s: &str) -> String {
    s.replace("\r\n", "\n")
}

#[test]
fn coverage_report_matches_golden() {
    // The report goes to stdout. Compare it to the golden as parsed JSON so the
    // assertion is independent of compact-vs-pretty formatting.
    let output = rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--atomics",
            &fixture("atomics.yaml"),
            "--baseline",
            &fixture("baseline.json"),
            "--targets",
            &fixture("targets.txt"),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let actual: serde_json::Value = serde_json::from_slice(&output).expect("stdout is valid JSON");
    let expected: serde_json::Value =
        serde_json::from_str(REPORT_GOLDEN).expect("golden is valid JSON");
    assert_eq!(actual, expected, "coverage report drifted from golden");
}

#[test]
fn coverage_navigator_layer_matches_golden() {
    let layer = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--navigator",
            layer.path().to_str().unwrap(),
            "--output-format",
            "json",
        ])
        .assert()
        .success();

    let actual = std::fs::read_to_string(layer.path()).unwrap();
    assert_eq!(
        normalize_eol(&actual).trim_end(),
        normalize_eol(LAYER_GOLDEN).trim_end(),
        "Navigator layer drifted from golden"
    );
}

#[test]
fn coverage_fail_on_gaps_exits_one_with_uncovered_target() {
    // T1003 is in the targets file but no rule covers it.
    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--targets",
            &fixture("targets.txt"),
            "--fail-on-gaps",
            "--output-format",
            "table",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("uncovered"));
}

#[test]
fn coverage_fail_on_gaps_clean_when_all_targets_covered() {
    let targets = temp_file(".txt", "T1059\nT1047\n");
    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--targets",
            targets.path().to_str().unwrap(),
            "--fail-on-gaps",
        ])
        .assert()
        .success();
}

#[test]
fn coverage_table_is_human_readable() {
    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--output-format",
            "table",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Coverage summary"))
        .stdout(predicate::str::contains("T1059.001"));
}

#[test]
fn coverage_atomics_directory_clone() {
    // A directory is treated as an atomic-red-team `atomics/` checkout.
    let dir = tempfile::tempdir().unwrap();
    let atomics = dir.path().join("atomics");
    std::fs::create_dir_all(atomics.join("T1059")).unwrap();
    std::fs::write(
        atomics.join("T1059").join("T1059.yaml"),
        "attack_technique: T1059\ndisplay_name: Command and Scripting Interpreter\n",
    )
    .unwrap();
    std::fs::create_dir_all(atomics.join("T1566")).unwrap();
    std::fs::write(
        atomics.join("T1566").join("T1566.yaml"),
        "attack_technique: T1566\ndisplay_name: Phishing\n",
    )
    .unwrap();

    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--atomics",
            atomics.to_str().unwrap(),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        // T1566 has an atomic but no rule; T1059 is covered.
        .stdout(predicate::str::contains(
            "\"atomics_without_rule\":[\"T1566\"]",
        ));
}

#[test]
fn coverage_warns_on_parse_errors_but_still_reports_valid_rules() {
    // A directory with one valid rule and one malformed rule (missing the
    // required detection block). Coverage warns about the parse error on
    // stderr but still reports the valid rule's technique.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("good.yml"),
        "title: Good\nid: 00000000-0000-0000-0000-0000000000e1\n\
         logsource: {category: process_creation, product: windows}\n\
         detection: {sel: {Image: a}, condition: sel}\ntags: [attack.t1059]\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("bad.yml"),
        "title: Missing Detection\nid: 00000000-0000-0000-0000-0000000000e2\n\
         logsource: {category: process_creation, product: windows}\n",
    )
    .unwrap();

    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            dir.path().to_str().unwrap(),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("parse errors"))
        .stdout(predicate::str::contains("\"id\":\"T1059\""));
}

#[test]
fn coverage_missing_rules_is_config_error() {
    rsigma()
        .args(["rule", "coverage"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("no rules path"));
}

#[test]
fn coverage_bad_rules_path_is_rule_error() {
    rsigma()
        .args(["rule", "coverage", "--rules", "/no/such/rules/path.yml"])
        .assert()
        .code(2);
}

#[test]
fn coverage_unreadable_atomics_is_config_error() {
    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--atomics",
            "/no/such/atomics/index.yaml",
        ])
        .assert()
        .code(3);
}

#[test]
fn coverage_ndjson_emits_per_technique_rows() {
    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--output-format",
            "ndjson",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"id\":\"T1047\""))
        .stdout(predicate::str::contains("\"id\":\"T1218.001\""));
}

#[test]
fn coverage_config_file_layering() {
    // atomics + targets come from the config file; only --config and --rules
    // are passed on the command line.
    let cfg = temp_file(
        ".yaml",
        &format!(
            "coverage:\n  atomics: {}\n  targets: {}\n  fail_on_gaps: true\n",
            fixture("atomics.yaml"),
            fixture("targets.txt"),
        ),
    );
    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--config",
            cfg.path().to_str().unwrap(),
            "--output-format",
            "table",
        ])
        .assert()
        // fail_on_gaps from config + uncovered T1003 target -> exit 1.
        .code(1)
        .stdout(predicate::str::contains("Atomic Red Team"));
}

#[test]
fn coverage_reads_rules_from_config() {
    // The rules path comes from the config file; no -r on the command line.
    let cfg = temp_file(
        ".yaml",
        &format!("coverage:\n  rules:\n    - {}\n", fixture("rules.yml")),
    );
    rsigma()
        .args([
            "rule",
            "coverage",
            "--config",
            cfg.path().to_str().unwrap(),
            "--output-format",
            "table",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Coverage summary"));
}

#[test]
fn coverage_atomics_plan_json_matches_golden() {
    let output = rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--atomics",
            &fixture("atomics_plan.yaml"),
            "--emit",
            "atomics-plan",
            "--output-format",
            "json",
            "--no-stats",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let actual: serde_json::Value = serde_json::from_slice(&output).expect("stdout is valid JSON");
    let expected: serde_json::Value =
        serde_json::from_str(PLAN_JSON_GOLDEN).expect("golden is valid JSON");
    assert_eq!(actual, expected, "atomics plan JSON drifted from golden");
}

#[test]
fn coverage_atomics_plan_table_matches_golden() {
    let output = rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--atomics",
            &fixture("atomics_plan.yaml"),
            "--emit",
            "atomics-plan",
            "--output-format",
            "table",
            "--color",
            "never",
            "--quiet",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let actual = String::from_utf8(output).unwrap();
    assert_eq!(
        normalize_eol(&actual).trim_end(),
        normalize_eol(PLAN_TABLE_GOLDEN).trim_end(),
        "atomics plan table drifted from golden"
    );
}

#[test]
fn coverage_atomics_plan_tsv_is_one_row_per_test() {
    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--atomics",
            &fixture("atomics_plan.yaml"),
            "--emit",
            "atomics-plan",
            "--output-format",
            "tsv",
            "--no-stats",
        ])
        .assert()
        .success()
        .stdout(predicate::str::starts_with(
            "TECHNIQUE\tTEST\tGUID\tPLATFORMS\tINVOCATION",
        ))
        .stdout(predicate::str::contains(
            "T1003\tDump LSASS\t33333333-3333-3333-3333-333333333333\twindows\tInvoke-AtomicTest T1003 -TestGuids 33333333-3333-3333-3333-333333333333",
        ))
        .stdout(predicate::str::contains(
            "T1566\tGUID-less phishing\t-\tmacos\tInvoke-AtomicTest T1566",
        ));
}

#[test]
fn coverage_atomics_plan_platforms_narrows_tests() {
    let output = rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--atomics",
            &fixture("atomics_plan.yaml"),
            "--emit",
            "atomics-plan",
            "--platforms",
            "linux",
            "--output-format",
            "json",
            "--no-stats",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(v["summary"]["uncovered_testable"], 2);
    assert_eq!(v["summary"]["techniques_in_plan"], 1);
    assert_eq!(v["summary"]["tests_in_plan"], 1);
    assert_eq!(v["summary"]["platforms"][0], "linux");
    assert_eq!(v["techniques"][0]["technique"], "T1566");
    assert_eq!(v["techniques"][0]["tests"][0]["name"], "Phishing via curl");
}

#[test]
fn coverage_atomics_plan_without_atomics_is_config_error() {
    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--emit",
            "atomics-plan",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "--emit atomics-plan requires --atomics",
        ));
}

#[test]
fn coverage_atomics_plan_flag_error_beats_bad_rules_path() {
    // Flag validation runs before rule loading: a misconfigured emit gets the
    // pointed config error (3), not the rules exit (2).
    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            "/no/such/rules/path.yml",
            "--emit",
            "atomics-plan",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "--emit atomics-plan requires --atomics",
        ));
}

#[test]
fn coverage_platforms_with_report_emit_warns_and_is_ignored() {
    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--platforms",
            "windows",
            "--output-format",
            "table",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "--platforms only applies to --emit atomics-plan",
        ))
        .stdout(predicate::str::contains("Coverage summary"));
}

#[test]
fn coverage_atomics_plan_ndjson_omits_guid_when_absent() {
    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--atomics",
            &fixture("atomics_plan.yaml"),
            "--emit",
            "atomics-plan",
            "--output-format",
            "ndjson",
            "--no-stats",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "{\"technique\":\"T1566\",\"test\":\"GUID-less phishing\",\"platforms\":\"macos\",\"invocation\":\"Invoke-AtomicTest T1566\"}",
        ))
        .stdout(predicate::str::contains(
            "\"guid\":\"33333333-3333-3333-3333-333333333333\"",
        ));
}

#[test]
fn coverage_atomics_plan_reads_atomics_from_config() {
    let cfg = temp_file(
        ".yaml",
        &format!("coverage:\n  atomics: {}\n", fixture("atomics_plan.yaml")),
    );
    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--config",
            cfg.path().to_str().unwrap(),
            "--emit",
            "atomics-plan",
            "--output-format",
            "json",
            "--no-stats",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"technique\":\"T1566\""));
}

#[test]
fn coverage_fail_on_gaps_exit_parity_across_emit_modes() {
    // T1566 is uncovered in the plan fixture; both emit modes must exit 1.
    for emit in ["report", "atomics-plan"] {
        rsigma()
            .args([
                "rule",
                "coverage",
                "--rules",
                &fixture("rules.yml"),
                "--atomics",
                &fixture("atomics_plan.yaml"),
                "--emit",
                emit,
                "--fail-on-gaps",
                "--output-format",
                "json",
                "--no-stats",
            ])
            .assert()
            .code(1);
    }
}

#[test]
fn coverage_dry_run_prints_config_section() {
    rsigma()
        .args([
            "rule",
            "coverage",
            "--rules",
            &fixture("rules.yml"),
            "--dry-run",
        ])
        .assert()
        .success();
}
