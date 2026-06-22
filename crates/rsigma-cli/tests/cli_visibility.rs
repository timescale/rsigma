//! Integration tests for `rsigma rule visibility`: the golden DeTT&CT
//! administration files and visibility Navigator layer, plus boundary and
//! error paths (exit codes, the no-`--observed` baseline, stdin ingestion,
//! config-file layering). Mapping and scoring are unit-tested in the command
//! module; these tests cover the end-to-end CLI surface only and never touch
//! the network (a miniature fixture mapping table stands in for the bundled
//! default).

mod common;

use std::path::{Path, PathBuf};

use common::{rsigma, temp_file};
use predicates::prelude::*;

const REPORT_GOLDEN: &str = include_str!("golden/visibility_report.json");
const DATA_SOURCES_GOLDEN: &str = include_str!("golden/visibility_data_sources.yml");
const TECHNIQUES_GOLDEN: &str = include_str!("golden/visibility_techniques.yml");
const LAYER_GOLDEN: &str = include_str!("golden/visibility_layer.json");

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/visibility")
}

fn fixture(name: &str) -> String {
    fixtures().join(name).to_string_lossy().into_owned()
}

fn normalize_eol(s: &str) -> String {
    s.replace("\r\n", "\n")
}

#[test]
fn visibility_report_matches_golden() {
    let output = rsigma()
        .args([
            "rule",
            "visibility",
            "--rules",
            &fixture("rules.yml"),
            "--observed",
            &fixture("observed.json"),
            "--mapping",
            &fixture("mapping.json"),
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
    assert_eq!(actual, expected, "visibility report drifted from golden");
}

#[test]
fn visibility_dettect_data_sources_matches_golden() {
    let out = tempfile::Builder::new().suffix(".yml").tempfile().unwrap();
    rsigma()
        .args([
            "rule",
            "visibility",
            "--rules",
            &fixture("rules.yml"),
            "--observed",
            &fixture("observed.json"),
            "--mapping",
            &fixture("mapping.json"),
            "--dettect-data-sources",
            out.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    let actual = std::fs::read_to_string(out.path()).unwrap();
    assert_eq!(
        normalize_eol(&actual).trim_end(),
        normalize_eol(DATA_SOURCES_GOLDEN).trim_end(),
        "DeTT&CT data-source administration drifted from golden"
    );
}

#[test]
fn visibility_dettect_techniques_matches_golden() {
    let out = tempfile::Builder::new().suffix(".yml").tempfile().unwrap();
    rsigma()
        .args([
            "rule",
            "visibility",
            "--rules",
            &fixture("rules.yml"),
            "--observed",
            &fixture("observed.json"),
            "--mapping",
            &fixture("mapping.json"),
            "--dettect-techniques",
            out.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    let actual = std::fs::read_to_string(out.path()).unwrap();
    assert_eq!(
        normalize_eol(&actual).trim_end(),
        normalize_eol(TECHNIQUES_GOLDEN).trim_end(),
        "DeTT&CT technique administration drifted from golden"
    );
}

#[test]
fn visibility_navigator_layer_matches_golden() {
    let layer = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    rsigma()
        .args([
            "rule",
            "visibility",
            "--rules",
            &fixture("rules.yml"),
            "--observed",
            &fixture("observed.json"),
            "--mapping",
            &fixture("mapping.json"),
            "--navigator",
            layer.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    let actual = std::fs::read_to_string(layer.path()).unwrap();
    assert_eq!(
        normalize_eol(&actual).trim_end(),
        normalize_eol(LAYER_GOLDEN).trim_end(),
        "visibility Navigator layer drifted from golden"
    );
}

#[test]
fn visibility_fail_on_blind_spots_exits_one() {
    // TargetObject (Windows Registry) is missing in the observed report, so the
    // Windows Registry data source is a blind spot.
    rsigma()
        .args([
            "rule",
            "visibility",
            "--rules",
            &fixture("rules.yml"),
            "--observed",
            &fixture("observed.json"),
            "--mapping",
            &fixture("mapping.json"),
            "--fail-on-blind-spots",
            "--output-format",
            "table",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("blind spots"));
}

#[test]
fn visibility_baseline_without_observed_succeeds() {
    // With no --observed signal the command still runs and reports the
    // rule-expected baseline (every source unobserved).
    rsigma()
        .args([
            "rule",
            "visibility",
            "--rules",
            &fixture("rules.yml"),
            "--mapping",
            &fixture("mapping.json"),
            "--output-format",
            "table",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("baseline"))
        .stdout(predicate::str::contains("Process"));
}

#[test]
fn visibility_reads_observed_from_stdin() {
    let observed = std::fs::read_to_string(fixture("observed.json")).unwrap();
    rsigma()
        .args([
            "rule",
            "visibility",
            "--rules",
            &fixture("rules.yml"),
            "--observed",
            "-",
            "--mapping",
            &fixture("mapping.json"),
            "--output-format",
            "json",
        ])
        .write_stdin(observed)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "\"blind_spots\":[\"Windows Registry\"]",
        ));
}

#[test]
fn visibility_ndjson_emits_per_data_source_rows() {
    rsigma()
        .args([
            "rule",
            "visibility",
            "--rules",
            &fixture("rules.yml"),
            "--observed",
            &fixture("observed.json"),
            "--mapping",
            &fixture("mapping.json"),
            "--output-format",
            "ndjson",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"data_source\":\"Process\""))
        .stdout(predicate::str::contains(
            "\"data_source\":\"Windows Registry\"",
        ));
}

#[test]
fn visibility_config_file_layering() {
    // mapping + fail_on_blind_spots come from the config file; only --config,
    // --rules, and --observed are passed on the command line.
    let cfg = temp_file(
        ".yaml",
        &format!(
            "visibility:\n  mapping: {}\n  fail_on_blind_spots: true\n",
            fixture("mapping.json"),
        ),
    );
    rsigma()
        .args([
            "rule",
            "visibility",
            "--rules",
            &fixture("rules.yml"),
            "--observed",
            &fixture("observed.json"),
            "--config",
            cfg.path().to_str().unwrap(),
            "--output-format",
            "table",
        ])
        .assert()
        // fail_on_blind_spots from config + the Windows Registry blind spot -> 1.
        .code(1)
        .stdout(predicate::str::contains("blind spots"));
}

#[test]
fn visibility_missing_rules_is_config_error() {
    rsigma()
        .args(["rule", "visibility"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("no rules path"));
}

#[test]
fn visibility_bad_rules_path_is_rule_error() {
    rsigma()
        .args(["rule", "visibility", "--rules", "/no/such/rules/path.yml"])
        .assert()
        .code(2);
}

#[test]
fn visibility_malformed_observed_is_config_error() {
    let bad = temp_file(".json", "{ not valid json");
    rsigma()
        .args([
            "rule",
            "visibility",
            "--rules",
            &fixture("rules.yml"),
            "--observed",
            bad.path().to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("observed field report"));
}

#[test]
fn visibility_unreadable_mapping_is_config_error() {
    rsigma()
        .args([
            "rule",
            "visibility",
            "--rules",
            &fixture("rules.yml"),
            "--mapping",
            "/no/such/mapping/table.json",
        ])
        .assert()
        .code(3);
}

#[test]
fn visibility_dry_run_prints_config_section() {
    rsigma()
        .args([
            "rule",
            "visibility",
            "--rules",
            &fixture("rules.yml"),
            "--dry-run",
        ])
        .assert()
        .success();
}

#[test]
fn visibility_default_bundled_mapping_resolves_data_sources() {
    // Without --mapping the bundled default table is used; process_creation +
    // registry_set still resolve to Process and Windows Registry.
    rsigma()
        .args([
            "rule",
            "visibility",
            "--rules",
            &fixture("rules.yml"),
            "--observed",
            &fixture("observed.json"),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"data_source\":\"Process\""))
        .stdout(predicate::str::contains(
            "\"data_source\":\"Windows Registry\"",
        ));
}
