//! Integration tests for the Validation Pipeline (`validate` feature).

#![cfg(feature = "validate")]

#[path = "support/fixtures_root.rs"]
mod fixtures_root;

use fixtures_root::load_fixture;
use rstix::{
    DiagnosticCode, ValidationPhase, Validator,
    validate::{Leniency, ValidationReport},
};

fn load_bundle_fixture(relative_path: &str) -> String {
    load_fixture(relative_path)
}

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
    report.push(rstix::Diagnostic::new(
        DiagnosticCode::W0010,
        "unresolved reference",
    ));
    assert!(!report.is_valid());
}

#[test]
fn standard_leniency_allows_warnings() {
    let mut report = ValidationReport::with_leniency(Leniency::Standard);
    report.push(rstix::Diagnostic::new(
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

#[test]
fn all_twelve_checks_implemented() {
    assert_eq!(Validator::implemented_phases().len(), 12);
    assert_eq!(
        Validator::consumer_strict()
            .pending_phases_in_profile()
            .count(),
        0
    );
}

#[test]
fn pipeline_reports_w0031_for_tlp1_marking_ref() {
    let json = load_bundle_fixture("validation/bundle-tlp1-marking-ref.json");
    let report = Validator::consumer_strict().validate_json_str(&json);
    assert!(
        report.with_code(DiagnosticCode::W0031).next().is_some(),
        "expected STIX-W0031"
    );
}

#[test]
fn pipeline_reports_e0024_for_invalid_granular_selector() {
    let json = load_bundle_fixture("validation/bundle-granular-selector-invalid.json");
    let report = Validator::consumer_strict().validate_json_str(&json);
    assert!(
        report.with_code(DiagnosticCode::E0024).next().is_some(),
        "expected STIX-E0024"
    );
}

#[test]
fn pipeline_reports_i0002_for_invalid_relationship_matrix() {
    let json = load_bundle_fixture("validation/bundle-relationship-matrix-invalid.json");
    let report = Validator::consumer_strict().validate_json_str(&json);
    assert!(
        report.with_code(DiagnosticCode::I0002).next().is_some(),
        "expected STIX-I0002"
    );
}

#[test]
fn pipeline_reports_w0010_for_bad_capec_external_reference() {
    let json = load_bundle_fixture("validation/bundle-bad-capec.json");
    let report = Validator::consumer_strict().validate_json_str(&json);
    assert!(
        report.with_code(DiagnosticCode::W0010).next().is_some(),
        "expected STIX-W0010"
    );
}

#[test]
fn pipeline_no_i0020_stub_diagnostics_on_clean_bundle() {
    let json =
        r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000","objects":[]}"#;
    let report = Validator::consumer_strict().validate_json_str(json);
    assert!(report.errors().next().is_none());
}
