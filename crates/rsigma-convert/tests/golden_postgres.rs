//! Golden tests for the PostgreSQL backend.
//!
//! Each test case consists of a `.yml` Sigma rule and a `.sql` expected output
//! file in `tests/golden/postgres/`. The test parses the YAML, drives the
//! conversion through the same `convert_collection` entry point the CLI uses,
//! and asserts exact string equality with the expected SQL.
//!
//! Routing through `convert_collection` (rather than calling
//! `Backend::convert_rule` directly) exercises the rule-to-table/schema/query
//! map injection and correlation-aware dispatch that the CLI relies on, so
//! the goldens cover the same code path operators run in production. Goldens
//! that only contain detection rules and no pipelines flatten to the same
//! output as the previous direct dispatch, so existing `.sql` files are
//! unchanged.

use rsigma_convert::backends::postgres::PostgresBackend;
use rsigma_convert::convert_collection;
use rsigma_parser::parse_sigma_yaml;
use std::fs;
use std::path::Path;

fn run_golden(name: &str) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/postgres");
    let yaml_path = base.join(format!("{name}.yml"));
    let sql_path = base.join(format!("{name}.sql"));

    let yaml = fs::read_to_string(&yaml_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", yaml_path.display()));
    let expected = fs::read_to_string(&sql_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", sql_path.display()));
    let expected = expected.trim_end();

    let collection = parse_sigma_yaml(&yaml)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", yaml_path.display()));
    let backend = PostgresBackend::new();

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
fn golden_ilike_contains() {
    run_golden("ilike_contains");
}

#[test]
fn golden_like_cased() {
    run_golden("like_cased");
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
fn golden_keywords_fulltext() {
    run_golden("keywords_fulltext");
}

#[test]
fn golden_wildcard() {
    run_golden("wildcard");
}

#[test]
fn golden_exists_null_bool() {
    run_golden("exists_null_bool");
}

#[test]
fn golden_multi_field_detection() {
    run_golden("multi_field_detection");
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
fn golden_fieldref() {
    run_golden("fieldref");
}

#[test]
fn golden_neq() {
    run_golden("neq");
}

#[test]
fn golden_custom_table() {
    run_golden("custom_table");
}

#[test]
fn golden_temporal_default_condition() {
    run_golden("temporal_default_condition");
}

#[test]
fn golden_temporal_ordered() {
    run_golden("temporal_ordered");
}

#[test]
fn golden_chained_correlation() {
    run_golden("chained_correlation");
}

#[test]
fn golden_chained_correlation_generate() {
    run_golden("chained_correlation_generate");
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
fn golden_quoted_identifiers() {
    run_golden("quoted_identifiers");
}
