//! Integration tests for the Validation Pipeline scaffold (`validate` feature).
//!
//! Unit tests in `src/validate/` cover per-check behavior; these tests focus on
//! profile wiring, leniency policy, and cross-module boundaries.

#![cfg(feature = "validate")]

use rstix::{
    Diagnostic, DiagnosticCode, ValidationPhase, Validator,
    validate::{Leniency, ValidationReport},
};

#[test]
fn consumer_permissive_phase_set() {
    let validator = Validator::consumer_permissive();
    let phases = validator.phases();
    assert_eq!(phases.len(), 4);
    assert!(phases.contains(&ValidationPhase::Schema));
    assert!(phases.contains(&ValidationPhase::References));
    assert!(!phases.contains(&ValidationPhase::PatternParse));
}

#[test]
fn producer_strict_skips_references_phase() {
    let validator = Validator::producer_strict();
    let phases = validator.phases();
    assert!(!phases.contains(&ValidationPhase::References));
    assert_eq!(phases.len(), 11);
}

#[test]
fn interop_strict_uses_zero_leniency() {
    assert_eq!(Validator::interop_strict().leniency(), Leniency::Zero);
}

#[test]
fn zero_leniency_treats_warnings_as_invalid() {
    let mut report = ValidationReport::with_leniency(Leniency::Zero);
    report.push(Diagnostic::new(
        DiagnosticCode::W0010,
        "unresolved reference",
    ));
    assert!(!report.is_valid());
}

#[test]
fn standard_leniency_allows_warnings() {
    let mut report = ValidationReport::with_leniency(Leniency::Standard);
    report.push(Diagnostic::new(
        DiagnosticCode::W0010,
        "unresolved reference",
    ));
    assert!(report.is_valid());
}

#[test]
fn builder_selects_custom_phases() {
    let validator = Validator::builder()
        .with_phase(ValidationPhase::Schema)
        .with_phase(ValidationPhase::References)
        .build();
    assert_eq!(
        validator.phases(),
        &[ValidationPhase::Schema, ValidationPhase::References]
    );
}

#[test]
fn validate_json_value_matches_str_entry_for_wellformed_input() {
    let json =
        r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000","objects":[]}"#;
    let value: serde_json::Value = serde_json::from_str(json).expect("json");
    let from_str = Validator::consumer_strict().validate_json_str(json);
    let from_value = Validator::consumer_strict().validate_json_value(&value);
    assert_eq!(from_str.is_valid(), from_value.is_valid());
    assert_eq!(
        from_str.with_code(DiagnosticCode::E0001).count(),
        from_value.with_code(DiagnosticCode::E0001).count()
    );
}

#[test]
fn pipeline_report_distinct_from_model_validation_report() {
    let _: ValidationReport = Validator::consumer_strict().validate_json_str("{}");
    let _model_report = rstix::ValidationReport::default();
}
