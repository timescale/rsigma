//! Map [`crate::ParseError`] to validation pipeline diagnostics.

use crate::ParseError;
use crate::model::ParseOptions;

use super::diagnostic::{Diagnostic, DiagnosticCode};

/// Convert a bundle parse failure into one or more structured diagnostics.
pub(crate) fn diagnostics_from_parse_error(
    err: &ParseError,
    opts: &ParseOptions,
) -> Vec<Diagnostic> {
    match err {
        ParseError::NotABundle { actual_type } => vec![
            Diagnostic::new(
                DiagnosticCode::E0002,
                format!("expected STIX type `bundle`, got `{actual_type}`"),
            )
            .with_property_path("type")
            .with_fix_suggestion("Set the document root `type` to `bundle`."),
        ],
        ParseError::UnknownObjectType(type_name) if !opts.allow_custom => {
            vec![Diagnostic::new(
                DiagnosticCode::E0002,
                format!("unknown STIX object type `{type_name}` with allow_custom disabled"),
            )
            .with_property_path("type")
            .with_fix_suggestion(
                "Use a known STIX type, register a custom type, or enable allow_custom on the validator.",
            )]
        }
        ParseError::MissingBundleId => vec![
            Diagnostic::new(DiagnosticCode::E0003, "bundle missing required id")
                .with_property_path("id")
                .with_fix_suggestion("Add a bundle id in `{type}--{uuid}` form."),
        ],
        ParseError::MissingObjectId => vec![
            Diagnostic::new(DiagnosticCode::E0003, "bundle object missing required id")
                .with_property_path("objects[].id")
                .with_fix_suggestion("Add an `id` property to each object in `objects`."),
        ],
        ParseError::DuplicateObjectId(id) => vec![
            Diagnostic::new(
                DiagnosticCode::E0003,
                format!("duplicate bundle object id `{id}`"),
            )
            .with_property_path("objects[].id")
            .with_fix_suggestion("Ensure every object in the bundle has a unique id."),
        ],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_bundle_id_maps_to_e0003_with_metadata() {
        let diags =
            diagnostics_from_parse_error(&ParseError::MissingBundleId, &ParseOptions::default());
        assert_eq!(diags.len(), 1);
        let diag = &diags[0];
        assert_eq!(diag.code, DiagnosticCode::E0003);
        assert_eq!(diag.property_path.as_deref(), Some("id"));
        assert!(diag.fix_suggestion.is_some());
    }
}
