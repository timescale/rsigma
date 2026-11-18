//! Golden tests for the LynxDB backend.
//!
//! Each test case consists of a `.yml` Sigma rule and a `.expected` output
//! file in `tests/golden/lynxdb/`. The test parses the YAML, drives the
//! conversion through the same `convert_collection` entry point the CLI uses,
//! and asserts exact string equality with the expected output.
//!
//! Routing through `convert_collection` (rather than calling
//! `Backend::convert_rule` directly) keeps detection-rule goldens covering
//! the same code path the `rsigma backend convert` CLI takes. Goldens that
//! only contain detection rules and no pipelines flatten to the same output
//! as the previous direct dispatch, so existing `.expected` files are
//! unchanged.

use rsigma_convert::backends::lynxdb::LynxDbBackend;
use rsigma_convert::convert_collection;
use rsigma_parser::parse_sigma_yaml;
use std::fs;
use std::path::Path;

fn run_golden(name: &str) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/lynxdb");
    let yaml_path = base.join(format!("{name}.yml"));
    let expected_path = base.join(format!("{name}.expected"));

    let yaml = fs::read_to_string(&yaml_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", yaml_path.display()));
    let expected = fs::read_to_string(&expected_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", expected_path.display()));
    let expected = expected.trim_end();

    let collection = parse_sigma_yaml(&yaml)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", yaml_path.display()));
    let backend = LynxDbBackend::new();

    let output = convert_collection(&backend, &collection, &[], "default")
        .unwrap_or_else(|e| panic!("conversion failed for {name}: {e}"));
    assert!(
        output.errors.is_empty(),
        "\n\nper-rule errors for '{name}':\n  {:#?}",
        output.errors
    );

    let actual = output
        .queries
        .iter()
        .flat_map(|r| r.queries.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        actual, expected,
        "\n\nGolden test mismatch for '{name}':\n  actual:   {actual}\n  expected: {expected}\n"
    );
}

#[test]
fn golden_simple_eq() {
    run_golden("simple_eq");
}

#[test]
fn golden_and_or_not() {
    run_golden("and_or_not");
}

#[test]
fn golden_not_one_of_filters() {
    run_golden("not_one_of_filters");
}

#[test]
fn golden_not_nested_or() {
    run_golden("not_nested_or");
}

#[test]
fn golden_wildcards() {
    run_golden("wildcards");
}

#[test]
fn golden_regex() {
    run_golden("regex");
}

#[test]
fn golden_cidr() {
    run_golden("cidr");
}

#[test]
fn golden_keywords() {
    run_golden("keywords");
}

#[test]
fn golden_exists_null_bool() {
    run_golden("exists_null_bool");
}

#[test]
fn golden_numeric_compare() {
    run_golden("numeric_compare");
}

#[test]
fn golden_brute_force() {
    run_golden("brute_force");
}

#[test]
fn golden_encodings() {
    run_golden("encodings");
}

#[test]
fn golden_large_integers() {
    run_golden("large_integers");
}

#[test]
fn golden_placeholders_in_values() {
    run_golden("placeholders_in_values");
}
