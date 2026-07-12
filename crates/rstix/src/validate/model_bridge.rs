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
    let (code, default_path) = super::model_mapping::model_error_pipeline_mapping(err);
    let path = property_path
        .map(String::from)
        .or_else(|| default_path.map(String::from))
        .or_else(|| granular_selector_path(err))
        .or_else(|| extension_path(err))
        .or_else(|| sco_forbidden_property_path(err))
        .or_else(|| bundle_reference_path(err));
    (code, path)
}

fn granular_selector_path(err: &ModelError) -> Option<String> {
    match err {
        ModelError::GranularSelectorSyntaxInvalid { selector } => {
            Some(format!("selectors[{selector}]"))
        }
        _ => None,
    }
}

fn extension_path(err: &ModelError) -> Option<String> {
    match err {
        ModelError::PropertyExtensionDefinitionMissing { extension_id } => {
            Some(format!("extensions.{extension_id}"))
        }
        ModelError::ExtensionDeserializeFailed { key, .. } => Some(format!("extensions.{key}")),
        ModelError::ExtensionDefinitionForbiddenCommonProperty { property } => {
            Some(property.clone())
        }
        ModelError::ExtensionTypeOnPredefinedExtension { key } => Some(format!("extensions.{key}")),
        _ => None,
    }
}

fn sco_forbidden_property_path(err: &ModelError) -> Option<String> {
    match err {
        ModelError::ScoForbiddenCommonProperty { property } => Some(property.clone()),
        _ => None,
    }
}

fn bundle_reference_path(err: &ModelError) -> Option<String> {
    match err {
        ModelError::BundleReferenceMissing { ref_id } => Some(format!("references[{ref_id}]")),
        ModelError::RelationshipEndpointMatrixInvalid {
            relationship_type, ..
        } => Some(format!("relationship_type[{relationship_type}]")),
        _ => None,
    }
}
