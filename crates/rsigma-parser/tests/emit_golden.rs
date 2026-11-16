//! Golden tests for the correlation and filter emitters.
//!
//! Each case is an input file and the exact canonical output in
//! `tests/emit/`. The test also asserts that emitting the output again is a
//! no-op, so every golden is a fixed point. Set `RSIGMA_UPDATE_GOLDEN=1` to
//! rewrite the expected files.

use std::fs;
use std::path::Path;

use rsigma_parser::{emit_correlation_yaml, emit_filter_yaml, parse_sigma_yaml};

fn run_golden(name: &str) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/emit");
    let input_path = base.join(format!("{name}.in.yml"));
    let expected_path = base.join(format!("{name}.out.yml"));

    let input = fs::read_to_string(&input_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", input_path.display()));

    let collection =
        parse_sigma_yaml(&input).unwrap_or_else(|error| panic!("parsing '{name}' failed: {error}"));
    let emitted = if let Some(rule) = collection.correlations.first() {
        emit_correlation_yaml(rule)
    } else if let Some(rule) = collection.filters.first() {
        emit_filter_yaml(rule)
    } else {
        panic!("'{name}' has no correlation or filter document");
    };

    if std::env::var_os("RSIGMA_UPDATE_GOLDEN").is_some() {
        fs::write(&expected_path, &emitted).expect("write golden");
    }

    let expected = fs::read_to_string(&expected_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", expected_path.display()));
    assert_eq!(
        emitted, expected,
        "\n\nGolden mismatch for '{name}':\n--- actual ---\n{emitted}\n--- expected ---\n{expected}\n"
    );

    let reparsed = parse_sigma_yaml(&expected)
        .unwrap_or_else(|error| panic!("re-parsing '{name}' output failed: {error}"));
    let again = if let Some(rule) = reparsed.correlations.first() {
        emit_correlation_yaml(rule)
    } else if let Some(rule) = reparsed.filters.first() {
        emit_filter_yaml(rule)
    } else {
        panic!("'{name}' output has no correlation or filter document");
    };
    assert_eq!(again, expected, "'{name}' output is not a fixed point");
}

#[test]
fn golden_correlation_event_count() {
    run_golden("correlation_event_count");
}

#[test]
fn golden_correlation_value_count_range() {
    run_golden("correlation_value_count_range");
}

#[test]
fn golden_correlation_temporal_extended() {
    run_golden("correlation_temporal_extended");
}

#[test]
fn golden_correlation_session_gap_aliases() {
    run_golden("correlation_session_gap_aliases");
}

#[test]
fn golden_filter_any() {
    run_golden("filter_any");
}

#[test]
fn golden_filter_specific_logsource() {
    run_golden("filter_specific_logsource");
}
