//! Map [`crate::model::ModelError`] to validation pipeline [`Diagnostic`]s.

use crate::core::StixId;
use crate::model::ModelError;

use super::diagnostic::{Diagnostic, DiagnosticCode};

/// Convert a model error into one structured pipeline diagnostic.
pub(crate) fn diagnostic_from_model_error(
    err: &ModelError,
    object_id: Option<&StixId>,
    property_path: Option<&str>,
) -> Diagnostic {
    let (code, property_path) = map_model_error(err, property_path);
    let mut diagnostic = Diagnostic::new(code, err.to_string());
    if let Some(id) = object_id {
        diagnostic = diagnostic.with_object_id(id.clone());
    }
    if let Some(path) = property_path {
        diagnostic = diagnostic.with_property_path(path);
    }
    diagnostic
}

/// Push all diagnostics from a model error into the report.
pub(crate) fn push_model_error(
    report: &mut super::ValidationReport,
    err: &ModelError,
    object_id: Option<&StixId>,
    property_path: Option<&str>,
) {
    report.push(diagnostic_from_model_error(err, object_id, property_path));
}

fn map_model_error(
    err: &ModelError,
    property_path: Option<&str>,
) -> (DiagnosticCode, Option<String>) {
    match err {
        ModelError::ExtensionDefinitionMissingCreatedByRef => {
            (DiagnosticCode::E0005, Some("created_by_ref".into()))
        }
        ModelError::ObservedDataObjectsXorObjectRefs => {
            (DiagnosticCode::E0007, Some("objects".into()))
        }
        ModelError::ObservedDataMissingScoContent => {
            (DiagnosticCode::E0008, Some("object_refs".into()))
        }
        ModelError::EmailMessageBodyWithMultipart
        | ModelError::EmailMessageMultipartMissing
        | ModelError::EmailMessageMultipartWhenSinglePart => {
            (DiagnosticCode::E0009, Some("body".into()))
        }
        ModelError::MalwareFamilyMissingName => (DiagnosticCode::E0004, Some("name".into())),
        ModelError::GranularMarkingMissingRefAndLang => {
            (DiagnosticCode::E0040, property_path.map(String::from))
        }
        ModelError::GranularMarkingBothRefAndLang => {
            (DiagnosticCode::E0041, property_path.map(String::from))
        }
        ModelError::GranularMarkingEmptySelectors => {
            (DiagnosticCode::E0024, Some("selectors".into()))
        }
        ModelError::GranularSelectorSyntaxInvalid { selector } => (
            DiagnosticCode::E0024,
            Some(format!("selectors[{selector}]")),
        ),
        ModelError::IdTypeMismatch { .. } | ModelError::BundleIdPrefixInvalid => {
            (DiagnosticCode::E0003, Some("id".into()))
        }
        ModelError::ModifiedBeforeCreated
        | ModelError::SdoLastSeenBeforeFirstSeen
        | ModelError::SightingLastSeenBeforeFirstSeen
        | ModelError::ObservedDataLastObservedBeforeFirstObserved
        | ModelError::RelationshipStopTimeBeforeStartTime
        | ModelError::NetworkTrafficEndBeforeStart
        | ModelError::IndicatorValidUntilBeforeValidFrom => {
            (DiagnosticCode::E0015, property_path.map(String::from))
        }
        ModelError::OpinionValueInvalid | ModelError::EncryptionAlgorithmInvalid => {
            (DiagnosticCode::E0013, property_path.map(String::from))
        }
        ModelError::SightingOfRefKindInvalid => {
            (DiagnosticCode::E0020, Some("sighting_of_ref".into()))
        }
        ModelError::InvalidReferenceKind { .. }
        | ModelError::RelationshipEndpointKindInvalid
        | ModelError::MalwareSampleRefInvalid
        | ModelError::MalwareAnalysisSampleRefInvalid
        | ModelError::DomainNameResolvesToRefInvalid
        | ModelError::DirectoryContainsRefInvalid
        | ModelError::NetworkTrafficEndpointRefInvalid
        | ModelError::EmailMimeBodyRawRefInvalid
        | ModelError::SightingWhereSightedRefInvalid => {
            (DiagnosticCode::E0021, property_path.map(String::from))
        }
        ModelError::MarkingDefinitionCircularRef { .. } => {
            (DiagnosticCode::E0022, Some("object_marking_refs".into()))
        }
        ModelError::BundleReferenceMissing { ref_id } => {
            (DiagnosticCode::W0010, Some(format!("references[{ref_id}]")))
        }
        ModelError::PropertyExtensionDefinitionMissing { extension_id } => (
            DiagnosticCode::E0030,
            Some(format!("extensions.{extension_id}")),
        ),
        ModelError::ExtensionDeserializeFailed { key, .. } => {
            (DiagnosticCode::E0030, Some(format!("extensions.{key}")))
        }
        ModelError::ScoDeterministicIdMismatch => (DiagnosticCode::W0002, Some("id".into())),
        ModelError::ScoForbiddenCommonProperty { property } => {
            (DiagnosticCode::W0040, Some(property.clone()))
        }
        ModelError::RelationshipEndpointMatrixInvalid {
            relationship_type, ..
        } => (
            DiagnosticCode::I0002,
            Some(format!("relationship_type[{relationship_type}]")),
        ),
        ModelError::RelationshipTypeInvalid => {
            (DiagnosticCode::I0002, Some("relationship_type".into()))
        }
        ModelError::InvalidCapecExternalReference | ModelError::InvalidCveExternalReference => {
            (DiagnosticCode::W0010, Some("external_references".into()))
        }
        _ => (DiagnosticCode::E0003, property_path.map(String::from)),
    }
}
