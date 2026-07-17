//! Bridge [`Bundle::validate`] to the validation pipeline (DD-VP-001).

use crate::model::{Bundle, ValidationCode, ValidationFinding, ValidationReport as ModelReport};
use crate::validate::ValidationReport as PipelineReport;
use crate::validate::diagnostic::{Diagnostic, DiagnosticCode};
use crate::validate::legacy_paths::{
    EXTERNAL_REF_CAPEC, EXTERNAL_REF_CVE, GRANULAR_SELECTOR_UNRESOLVED_PREFIX,
    LANGUAGE_CONTENT_MISMATCH_PREFIX, LANGUAGE_CONTENT_UNKNOWN_PREFIX,
};
use crate::validate::semantic::{run_cross_object_semantics, run_tlp_marking_semantics};

/// Run advisory bundle validation via shared pipeline semantic checks.
pub fn bundle_validate(bundle: &Bundle) -> ModelReport {
    let mut pipeline = PipelineReport::new();
    run_cross_object_semantics(bundle, &mut pipeline);
    run_tlp_marking_semantics(bundle, &mut pipeline);
    pipeline_to_model_report(&pipeline)
}

fn pipeline_to_model_report(pipeline: &PipelineReport) -> ModelReport {
    let mut report = ModelReport::default();
    for diagnostic in pipeline.diagnostics() {
        if let Some(finding) = diagnostic_to_finding(diagnostic) {
            report.warnings.push(finding);
        }
    }
    report
}

/// Map a pipeline diagnostic emitted by shared semantic checks to a legacy code.
///
/// Mapping is structural: [`DiagnosticCode`] plus stable [`legacy_paths`] property
/// paths only — never message substring matching.
pub(crate) fn legacy_validation_code(diagnostic: &Diagnostic) -> Option<ValidationCode> {
    let path = diagnostic.property_path.as_deref();
    match diagnostic.code {
        DiagnosticCode::W0031 => Some(ValidationCode::StixW0031TlpV1Encoding),
        DiagnosticCode::W0002 => Some(ValidationCode::ScoDeterministicIdMismatch),
        DiagnosticCode::I0002 => Some(ValidationCode::RelationshipEndpointMatrixInvalid),
        DiagnosticCode::I0001 if path == Some("region") => {
            Some(ValidationCode::LocationRegionNotInOpenVocab)
        }
        DiagnosticCode::W0010 if path == Some("country") => {
            Some(ValidationCode::LocationCountryNotIso3166)
        }
        DiagnosticCode::W0010 if path == Some("encryption_algorithm") => {
            Some(ValidationCode::EncryptionAlgorithmInvalid)
        }
        DiagnosticCode::W0010 if path == Some(EXTERNAL_REF_CAPEC) => {
            Some(ValidationCode::InvalidCapecExternalReference)
        }
        DiagnosticCode::W0010 if path == Some(EXTERNAL_REF_CVE) => {
            Some(ValidationCode::InvalidCveExternalReference)
        }
        DiagnosticCode::E0024 if path == Some("object_modified") => {
            Some(ValidationCode::LanguageContentObjectModifiedMismatch)
        }
        DiagnosticCode::E0024
            if path.is_some_and(|p| p.starts_with(LANGUAGE_CONTENT_UNKNOWN_PREFIX)) =>
        {
            Some(ValidationCode::LanguageContentFieldUnknown)
        }
        DiagnosticCode::E0024
            if path.is_some_and(|p| p.starts_with(LANGUAGE_CONTENT_MISMATCH_PREFIX)) =>
        {
            Some(ValidationCode::LanguageContentValueMismatch)
        }
        DiagnosticCode::E0024
            if path.is_some_and(|p| p.starts_with(GRANULAR_SELECTOR_UNRESOLVED_PREFIX)) =>
        {
            Some(ValidationCode::GranularSelectorSemanticInvalid)
        }
        _ => None,
    }
}

fn diagnostic_to_finding(diagnostic: &Diagnostic) -> Option<ValidationFinding> {
    let code = legacy_validation_code(diagnostic)?;
    Some(ValidationFinding {
        code,
        object_id: diagnostic
            .object_id
            .as_ref()
            .map(|id| id.as_str().to_owned()),
        message: diagnostic.message.clone(),
        detail: diagnostic.property_path.clone(),
    })
}

#[cfg(all(test, feature = "validate"))]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::model::Bundle;
    use crate::validate::legacy_paths::{
        LANGUAGE_CONTENT_UNKNOWN_PREFIX, language_content_mismatch,
    };

    fn language_content_unknown(lang: &str, field: &str) -> String {
        format!("{LANGUAGE_CONTENT_UNKNOWN_PREFIX}{lang}.{field}")
    }

    #[test]
    fn legacy_validation_code_mapping_is_structural() {
        let cases = [
            (
                Diagnostic::new(DiagnosticCode::W0031, "tlp v1")
                    .with_property_path("definition_type"),
                ValidationCode::StixW0031TlpV1Encoding,
            ),
            (
                Diagnostic::new(DiagnosticCode::W0002, "sco id").with_property_path("id"),
                ValidationCode::ScoDeterministicIdMismatch,
            ),
            (
                Diagnostic::new(DiagnosticCode::I0002, "matrix")
                    .with_property_path("relationship_type[uses]"),
                ValidationCode::RelationshipEndpointMatrixInvalid,
            ),
            (
                Diagnostic::new(DiagnosticCode::I0001, "region").with_property_path("region"),
                ValidationCode::LocationRegionNotInOpenVocab,
            ),
            (
                Diagnostic::new(DiagnosticCode::W0010, "country").with_property_path("country"),
                ValidationCode::LocationCountryNotIso3166,
            ),
            (
                Diagnostic::new(DiagnosticCode::W0010, "encryption")
                    .with_property_path("encryption_algorithm"),
                ValidationCode::EncryptionAlgorithmInvalid,
            ),
            (
                Diagnostic::new(DiagnosticCode::W0010, "capec")
                    .with_property_path(EXTERNAL_REF_CAPEC),
                ValidationCode::InvalidCapecExternalReference,
            ),
            (
                Diagnostic::new(DiagnosticCode::W0010, "cve").with_property_path(EXTERNAL_REF_CVE),
                ValidationCode::InvalidCveExternalReference,
            ),
            (
                Diagnostic::new(DiagnosticCode::E0024, "modified")
                    .with_property_path("object_modified"),
                ValidationCode::LanguageContentObjectModifiedMismatch,
            ),
            (
                Diagnostic::new(DiagnosticCode::E0024, "unknown")
                    .with_property_path(language_content_unknown("en", "name")),
                ValidationCode::LanguageContentFieldUnknown,
            ),
            (
                Diagnostic::new(DiagnosticCode::E0024, "mismatch")
                    .with_property_path(language_content_mismatch("en", "name")),
                ValidationCode::LanguageContentValueMismatch,
            ),
            (
                Diagnostic::new(DiagnosticCode::E0024, "selector")
                    .with_property_path("granular_markings.selectors.unresolved[extensions.'x']"),
                ValidationCode::GranularSelectorSemanticInvalid,
            ),
        ];

        for (diagnostic, expected) in cases {
            assert_eq!(
                legacy_validation_code(&diagnostic),
                Some(expected),
                "unexpected mapping for {:?}",
                diagnostic.property_path
            );
        }
    }

    #[test]
    fn legacy_validation_code_ignores_message_substrings() {
        let diagnostic = Diagnostic::new(DiagnosticCode::W0010, "no CAPEC or CVE tokens here")
            .with_property_path("external_references");
        assert_eq!(legacy_validation_code(&diagnostic), None);
    }

    #[test]
    fn delegated_bundle_validate_covers_all_legacy_codes() {
        macro_rules! assert_code_in_fixture {
            ($code:expr, $path:literal) => {
                let bundle = Bundle::parse(include_str!(concat!("../../tests/fixtures/", $path)))
                    .expect(concat!("parse ", $path));
                assert!(
                    bundle.validate().warnings_with_code($code).next().is_some(),
                    "missing legacy code {:?} in fixture {}",
                    $code,
                    $path
                );
            };
        }

        assert_code_in_fixture!(
            ValidationCode::InvalidCapecExternalReference,
            "validation/bundle-bad-capec.json"
        );
        assert_code_in_fixture!(
            ValidationCode::InvalidCveExternalReference,
            "validation/bundle-bad-cve.json"
        );
        assert_code_in_fixture!(
            ValidationCode::RelationshipEndpointMatrixInvalid,
            "validation/bundle-relationship-matrix-invalid.json"
        );
        assert_code_in_fixture!(
            ValidationCode::EncryptionAlgorithmInvalid,
            "validation/bundle-bad-encryption.json"
        );
        assert_code_in_fixture!(
            ValidationCode::GranularSelectorSemanticInvalid,
            "validation/bundle-granular-selector-invalid.json"
        );
        assert_code_in_fixture!(
            ValidationCode::LocationCountryNotIso3166,
            "validation/bundle-location-bad-country.json"
        );
        assert_code_in_fixture!(
            ValidationCode::LocationRegionNotInOpenVocab,
            "validation/bundle-location-bad-region.json"
        );
        assert_code_in_fixture!(
            ValidationCode::LanguageContentValueMismatch,
            "validation/bundle-language-content-list-length.json"
        );
        assert_code_in_fixture!(
            ValidationCode::LanguageContentObjectModifiedMismatch,
            "validation/bundle-language-content-object-modified-mismatch.json"
        );
        assert_code_in_fixture!(
            ValidationCode::ScoDeterministicIdMismatch,
            "validation/bundle-sco-deterministic-id-mismatch.json"
        );
        assert_code_in_fixture!(
            ValidationCode::StixW0031TlpV1Encoding,
            "validation/bundle-tlp1-marking-ref.json"
        );

        let marking = include_str!(
            "../../tests/fixtures/spec/meta/marking-definition-tlp-v1-white-stix21.json"
        );
        let bundle_json = format!(
            r#"{{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000001","objects":[{marking}]}}"#
        );
        let bundle = Bundle::parse(&bundle_json).expect("parse marking-definition bundle");
        assert!(
            bundle
                .validate()
                .warnings_with_code(ValidationCode::StixW0031TlpV1Encoding)
                .next()
                .is_some(),
            "missing legacy code StixW0031TlpV1Encoding for marking-definition fixture"
        );

        let expected: HashSet<ValidationCode> = [
            ValidationCode::StixW0031TlpV1Encoding,
            ValidationCode::ScoDeterministicIdMismatch,
            ValidationCode::GranularSelectorSemanticInvalid,
            ValidationCode::LanguageContentValueMismatch,
            ValidationCode::LanguageContentObjectModifiedMismatch,
            ValidationCode::LocationCountryNotIso3166,
            ValidationCode::LocationRegionNotInOpenVocab,
            ValidationCode::InvalidCapecExternalReference,
            ValidationCode::InvalidCveExternalReference,
            ValidationCode::RelationshipEndpointMatrixInvalid,
            ValidationCode::EncryptionAlgorithmInvalid,
        ]
        .into_iter()
        .collect();
        assert_eq!(
            expected.len(),
            11,
            "test inventory must cover every legacy code"
        );
    }
}
