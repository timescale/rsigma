//! Bridge [`Bundle::validate`] to the validation pipeline (DD-VP-001).

use crate::model::{Bundle, ValidationCode, ValidationFinding, ValidationReport as ModelReport};
use crate::validate::ValidationReport as PipelineReport;
use crate::validate::diagnostic::{Diagnostic, DiagnosticCode};
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

fn diagnostic_to_finding(diagnostic: &Diagnostic) -> Option<ValidationFinding> {
    let code = match diagnostic.code {
        DiagnosticCode::W0031 => ValidationCode::StixW0031TlpV1Encoding,
        DiagnosticCode::W0002 => ValidationCode::ScoDeterministicIdMismatch,
        DiagnosticCode::E0024
            if diagnostic.property_path.as_deref().is_some_and(|p| {
                p.starts_with("selectors[") || p.contains("granular_markings")
            }) =>
        {
            ValidationCode::GranularSelectorSemanticInvalid
        }
        DiagnosticCode::I0002 => ValidationCode::RelationshipEndpointMatrixInvalid,
        DiagnosticCode::W0010 if diagnostic.message.contains("CAPEC") => {
            ValidationCode::InvalidCapecExternalReference
        }
        DiagnosticCode::W0010 if diagnostic.message.contains("CVE") => {
            ValidationCode::InvalidCveExternalReference
        }
        DiagnosticCode::W0010 if diagnostic.property_path.as_deref() == Some("country") => {
            ValidationCode::LocationCountryNotIso3166
        }
        DiagnosticCode::I0001 if diagnostic.property_path.as_deref() == Some("region") => {
            ValidationCode::LocationRegionNotInOpenVocab
        }
        DiagnosticCode::W0010
            if diagnostic.property_path.as_deref() == Some("encryption_algorithm") =>
        {
            ValidationCode::EncryptionAlgorithmInvalid
        }
        DiagnosticCode::E0024 if diagnostic.property_path.as_deref() == Some("object_modified") => {
            ValidationCode::LanguageContentObjectModifiedMismatch
        }
        DiagnosticCode::E0024
            if diagnostic
                .property_path
                .as_deref()
                .is_some_and(|p| p.starts_with("contents."))
                && diagnostic.message.contains("not a property") =>
        {
            ValidationCode::LanguageContentFieldUnknown
        }
        DiagnosticCode::E0024
            if diagnostic
                .property_path
                .as_deref()
                .is_some_and(|p| p.starts_with("contents.")) =>
        {
            ValidationCode::LanguageContentValueMismatch
        }
        _ => return None,
    };
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
