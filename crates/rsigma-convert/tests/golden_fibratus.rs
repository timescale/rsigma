//! Golden tests for the Fibratus backend.
//!
//! Each case is a `.yml` Sigma rule in `tests/golden/fibratus/` paired with an
//! expected-output file named `{name}.{format}.expected`. The test parses the
//! YAML, drives conversion through the same `convert_collection` entry point
//! the CLI uses, and asserts exact string equality.
//!
//! Most cases use the bare `expr` format (the filter expression, which is what
//! the item/condition conversion produces); a couple use the `default` YAML
//! envelope so the rule wrapper is covered too.
//!
//! To regenerate expected files after an intentional change, run with
//! `RSIGMA_UPDATE_GOLDEN=1`:
//!
//! ```sh
//! RSIGMA_UPDATE_GOLDEN=1 cargo test -p rsigma-convert --test golden_fibratus
//! ```

use rsigma_convert::backends::fibratus::FibratusBackend;
use rsigma_convert::convert_collection;
use rsigma_parser::parse_sigma_yaml;
use std::fs;
use std::path::Path;

fn run_golden(name: &str, format: &str) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/fibratus");
    let yaml_path = base.join(format!("{name}.yml"));
    let expected_path = base.join(format!("{name}.{format}.expected"));

    let yaml = fs::read_to_string(&yaml_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", yaml_path.display()));

    let collection = parse_sigma_yaml(&yaml)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", yaml_path.display()));
    let backend = FibratusBackend::new();

    let output = convert_collection(&backend, &collection, &[], format)
        .unwrap_or_else(|e| panic!("conversion failed for {name} ({format}): {e}"));
    assert!(
        output.errors.is_empty(),
        "\n\nper-rule errors for '{name}' ({format}):\n  {:#?}",
        output.errors
    );

    let actual = output
        .queries
        .iter()
        .flat_map(|r| r.queries.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    let actual = actual.trim_end();

    if std::env::var_os("RSIGMA_UPDATE_GOLDEN").is_some() {
        fs::write(&expected_path, format!("{actual}\n"))
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", expected_path.display()));
        return;
    }

    let expected = fs::read_to_string(&expected_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", expected_path.display()));
    let expected = expected.trim_end();

    assert_eq!(
        actual, expected,
        "\n\nGolden mismatch for '{name}' ({format}):\n  actual:   {actual}\n  expected: {expected}\n"
    );
}

#[test]
fn golden_field_eq() {
    run_golden("field_eq", "expr");
}

#[test]
fn golden_cased() {
    run_golden("cased", "expr");
}

#[test]
fn golden_substring_ops() {
    run_golden("substring_ops", "expr");
}

#[test]
fn golden_wildcards() {
    run_golden("wildcards", "expr");
}

#[test]
fn golden_string_list_in() {
    run_golden("string_list_in", "expr");
}

#[test]
fn golden_multi_re() {
    run_golden("multi_re", "expr");
}

#[test]
fn golden_multi_cidr() {
    run_golden("multi_cidr", "expr");
}

#[test]
fn golden_single_re() {
    run_golden("single_re", "expr");
}

#[test]
fn golden_numeric_compare() {
    run_golden("numeric_compare", "expr");
}

#[test]
fn golden_exists_null() {
    run_golden("exists_null", "expr");
}

#[test]
fn golden_fieldref() {
    run_golden("fieldref", "expr");
}

#[test]
fn golden_and_or_not() {
    run_golden("and_or_not", "expr");
}

#[test]
fn golden_evt_name() {
    run_golden("evt_name", "expr");
}

#[test]
fn golden_all_modifier() {
    run_golden("all_modifier", "expr");
}

#[test]
fn golden_envelope_yaml() {
    run_golden("envelope", "default");
}
