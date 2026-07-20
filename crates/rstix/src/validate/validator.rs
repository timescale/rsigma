//! `Validator`, profiles, and validation entry points.

use crate::model::{Bundle, ParseOptions, StixObject};

use super::checks::{ValidationContext, document_root_type, run_checks};
use super::diagnostic::{Diagnostic, DiagnosticCode, SourceSpan};
use super::parse_bridge::diagnostics_from_parse_error;
use super::phase::ValidationPhase;
use super::profiles::{
    Leniency, consumer_permissive_phases, consumer_strict_phases, interop_strict_phases,
    producer_strict_phases,
};
use super::report::ValidationReport;

/// Configures which validation checks run and how strictly results are interpreted.
#[derive(Clone, Debug)]
pub struct ValidatorBuilder {
    phases: Vec<ValidationPhase>,
    leniency: Leniency,
    parse_options: ParseOptions,
}

impl ValidatorBuilder {
    /// Start with no checks selected; add checks with [`with_phase`](Self::with_phase).
    pub fn new() -> Self {
        Self {
            phases: Vec::new(),
            leniency: Leniency::Standard,
            parse_options: ParseOptions::default(),
        }
    }

    /// Append a validation check.
    pub fn with_phase(mut self, phase: ValidationPhase) -> Self {
        self.phases.push(phase);
        self
    }

    /// Set leniency policy (used by [`Validator::interop_strict`](Validator::interop_strict)).
    pub fn with_leniency(mut self, leniency: Leniency) -> Self {
        self.leniency = leniency;
        self
    }

    /// Replace bundle parse options (including [`ParseOptions::allow_custom`]).
    pub fn with_parse_options(mut self, parse_options: ParseOptions) -> Self {
        self.parse_options = parse_options;
        self
    }

    /// Enable or disable permissive custom-object parsing during validation.
    pub fn with_allow_custom(mut self, allow_custom: bool) -> Self {
        self.parse_options.allow_custom = allow_custom;
        self
    }

    /// Build the validator.
    pub fn build(self) -> Validator {
        Validator {
            phases: self.phases,
            leniency: self.leniency,
            parse_options: self.parse_options,
        }
    }
}

impl Default for ValidatorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Profile-driven STIX 2.1 validation pipeline.
#[derive(Clone, Debug)]
pub struct Validator {
    phases: Vec<ValidationPhase>,
    leniency: Leniency,
    parse_options: ParseOptions,
}

impl Validator {
    /// Checks that perform validation logic in the pipeline.
    pub fn implemented_phases() -> &'static [ValidationPhase] {
        &ValidationPhase::IMPLEMENTED
    }

    /// JSON, type, schema, and reference checks — permissive ingest path for mixed-trust feeds.
    pub fn consumer_permissive() -> Self {
        Self {
            phases: consumer_permissive_phases(),
            leniency: Leniency::Standard,
            parse_options: ParseOptions::default(),
        }
    }

    /// Selects all twelve pipeline checks for untrusted input.
    pub fn consumer_strict() -> Self {
        Self {
            phases: consumer_strict_phases(),
            leniency: Leniency::Standard,
            parse_options: ParseOptions::default(),
        }
    }

    /// Output validation; skips reference resolution.
    pub fn producer_strict() -> Self {
        Self {
            phases: producer_strict_phases(),
            leniency: Leniency::Standard,
            parse_options: ParseOptions::default(),
        }
    }

    /// Selects all twelve pipeline checks with zero leniency — OASIS interoperability scenarios.
    pub fn interop_strict() -> Self {
        Self {
            phases: interop_strict_phases(),
            leniency: Leniency::Zero,
            parse_options: ParseOptions::default(),
        }
    }

    /// Start a custom check set.
    pub fn builder() -> ValidatorBuilder {
        ValidatorBuilder::new()
    }

    /// Configured validation checks (in execution order).
    pub fn phases(&self) -> &[ValidationPhase] {
        &self.phases
    }

    /// Subset of [`Self::phases`] that are implemented in this build.
    pub fn implemented_phases_in_profile(&self) -> impl Iterator<Item = ValidationPhase> + '_ {
        self.phases
            .iter()
            .copied()
            .filter(|phase| phase.is_implemented())
    }

    /// Subset of [`Self::phases`] that are not implemented.
    pub fn pending_phases_in_profile(&self) -> impl Iterator<Item = ValidationPhase> + '_ {
        self.phases
            .iter()
            .copied()
            .filter(|phase| !phase.is_implemented())
    }

    /// Profile leniency policy.
    pub fn leniency(&self) -> Leniency {
        self.leniency
    }

    /// Bundle parse options used when resolving typed objects during validation.
    pub fn parse_options(&self) -> &ParseOptions {
        &self.parse_options
    }

    /// Validate a parsed bundle.
    pub fn validate_bundle(&self, bundle: &Bundle) -> ValidationReport {
        let mut report = ValidationReport::with_leniency(self.leniency);
        let value = serde_json::to_value(bundle).ok();
        let ctx = ValidationContext::new(
            Some(bundle),
            value.as_ref(),
            self.leniency,
            &self.parse_options,
        );
        let phases = self.phases_without_json_when_typed();
        run_checks(&phases, &ctx, &mut report);
        report
    }

    /// Validate a single STIX object (no bundle reference resolution).
    pub fn validate_object(&self, object: &StixObject) -> ValidationReport {
        let mut report = ValidationReport::with_leniency(self.leniency);
        let value = serde_json::to_value(object).ok();
        let ctx = ValidationContext::new(None, value.as_ref(), self.leniency, &self.parse_options);
        let phases = self
            .phases_without_json_when_typed()
            .into_iter()
            .filter(|phase| *phase != ValidationPhase::References)
            .collect::<Vec<_>>();
        run_checks(&phases, &ctx, &mut report);
        report
    }

    /// Validate raw JSON text — correct entry point for untrusted input.
    pub fn validate_json_str(&self, json: &str) -> ValidationReport {
        match serde_json::from_str::<serde_json::Value>(json) {
            Err(err) => {
                let mut report = ValidationReport::with_leniency(self.leniency);
                report.push(json_parse_diagnostic(json, &err));
                report.push(json_parse_hint());
                report
            }
            Ok(value) => self.validate_json_value(&value),
        }
    }

    /// Validate a parsed JSON value before typed bundle deserialization.
    pub fn validate_json_value(&self, value: &serde_json::Value) -> ValidationReport {
        let mut report = ValidationReport::with_leniency(self.leniency);
        let bundle = if document_root_type(value) == Some("bundle") {
            serde_json::to_string(value).ok().and_then(|json| {
                match Bundle::parse_with_options(&json, &self.parse_options) {
                    Ok(bundle) => Some(bundle),
                    Err(err) => {
                        for diagnostic in diagnostics_from_parse_error(&err, &self.parse_options) {
                            report.push(diagnostic);
                        }
                        None
                    }
                }
            })
        } else {
            None
        };
        let ctx = ValidationContext::new(
            bundle.as_ref(),
            Some(value),
            self.leniency,
            &self.parse_options,
        );
        run_checks(&self.phases, &ctx, &mut report);
        report
    }

    fn phases_without_json_when_typed(&self) -> Vec<ValidationPhase> {
        self.phases
            .iter()
            .copied()
            .filter(|phase| *phase != ValidationPhase::JsonWellFormedness)
            .collect()
    }
}

fn json_parse_diagnostic(json: &str, err: &serde_json::Error) -> Diagnostic {
    let line = err.line();
    let column = err.column();
    Diagnostic::new(DiagnosticCode::E0001, err.to_string())
        .with_property_path("$")
        .with_fix_suggestion("Fix JSON syntax errors before validating as STIX.")
        .with_span(SourceSpan {
            byte_offset: super::diagnostic::byte_offset_from_line_column(json, line, column),
            line: Some(line),
            column: Some(column),
        })
}

fn json_parse_hint() -> Diagnostic {
    Diagnostic::new(
        DiagnosticCode::H0001,
        "Validate STIX bundles with `Validator::validate_json_str` after fixing JSON syntax.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_bundle;

    #[test]
    fn validate_json_str_emits_e0001_on_malformed_json() {
        let json = "{not-json";
        let report = Validator::consumer_strict().validate_json_str(json);
        assert!(!report.is_valid());
        let diag = report
            .with_code(DiagnosticCode::E0001)
            .next()
            .expect("E0001");
        assert_eq!(diag.severity, crate::validate::Severity::Error);
        assert_eq!(diag.property_path.as_deref(), Some("$"));
        assert!(diag.fix_suggestion.is_some());
        let span = diag.span.as_ref().expect("span");
        assert!(span.line.is_some());
        assert_eq!(
            span.byte_offset,
            super::super::diagnostic::byte_offset_from_line_column(
                json,
                span.line.expect("line"),
                span.column.expect("column")
            )
        );
    }

    #[test]
    fn validate_json_str_emits_e0002_on_non_bundle_root() {
        let report = Validator::consumer_strict().validate_json_str("{}");
        assert!(!report.is_valid());
        let diag = report
            .with_code(DiagnosticCode::E0002)
            .next()
            .expect("E0002");
        assert_eq!(diag.property_path.as_deref(), Some("type"));
        assert!(diag.fix_suggestion.is_some());
    }

    #[test]
    fn validate_json_str_emits_e0002_for_unknown_object_type_when_custom_disabled() {
        let json = r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000","objects":[{"type":"not-a-real-type","id":"x--00000000-0000-0000-0000-000000000001"}]}"#;
        let report = Validator::consumer_strict().validate_json_str(json);
        assert!(!report.is_valid());
        assert!(report.with_code(DiagnosticCode::E0002).next().is_some());
    }

    #[test]
    fn with_allow_custom_permits_unknown_object_types_at_parse_time() {
        let json = r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000","objects":[{"type":"x-custom-type","id":"x-custom-type--00000000-0000-0000-0000-000000000001"}]}"#;
        let report = Validator::builder()
            .with_allow_custom(true)
            .build()
            .validate_json_str(json);
        assert!(report.with_code(DiagnosticCode::E0002).next().is_none());
    }

    #[test]
    fn validate_json_str_accepts_minimal_bundle_json() {
        let json =
            r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000","objects":[]}"#;
        let report = Validator::consumer_strict().validate_json_str(json);
        assert!(report.is_valid());
        assert_eq!(report.infos().count(), 0);
    }

    #[test]
    fn consumer_strict_has_all_phases_implemented() {
        let json =
            r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000","objects":[]}"#;
        let validator = Validator::consumer_strict();
        assert_eq!(validator.implemented_phases_in_profile().count(), 12);
        assert_eq!(validator.pending_phases_in_profile().count(), 0);
        let report = validator.validate_json_str(json);
        assert!(report.is_valid());
        assert_eq!(report.infos().count(), 0);
    }

    #[test]
    fn validate_bundle_matches_parse_then_validate() {
        let json =
            r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000","objects":[]}"#;
        let bundle = parse_bundle(json).expect("parse");
        let from_bundle = Validator::consumer_permissive().validate_bundle(&bundle);
        let from_json = Validator::consumer_permissive().validate_json_str(json);
        assert_eq!(from_bundle.is_valid(), from_json.is_valid());
    }
}
