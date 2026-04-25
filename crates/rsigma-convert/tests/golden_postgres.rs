//! Golden tests for the PostgreSQL backend.
//!
//! Each test case consists of a `.yml` Sigma rule and a `.sql` expected output
//! file in `tests/golden/postgres/`. The test parses the YAML, converts through
//! the PostgreSQL backend, and asserts exact string equality with the expected SQL.

use rsigma_convert::Backend;
use rsigma_convert::backends::postgres::PostgresBackend;
use rsigma_eval::pipeline::state::PipelineState;
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

    let mut results = Vec::new();
    for rule in &collection.rules {
        let queries = backend
            .convert_rule(rule, "default", &PipelineState::default())
            .unwrap_or_else(|e| panic!("conversion failed for {name}: {e}"));
        results.extend(queries);
    }

    let actual = results.join("\n");
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
