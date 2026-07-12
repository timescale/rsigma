//! Map [`crate::ParseError`] to validation pipeline diagnostics.

use crate::ParseError;
use crate::model::ParseOptions;

use super::diagnostic::{Diagnostic, DiagnosticCode};
use super::model_bridge::diagnostic_from_model_error;

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
        ParseError::Model(model_err) => vec![diagnostic_from_model_error(model_err, None, None)],
        ParseError::Json(err) => diagnostics_from_json_error(err),
        ParseError::ObjectLimitExceeded { count, max } => vec![
            Diagnostic::new(
                DiagnosticCode::E0001,
                format!("bundle object count {count} exceeds limit {max}"),
            )
            .with_property_path("objects"),
        ],
        ParseError::BundleByteLimitExceeded { max } => vec![Diagnostic::new(
            DiagnosticCode::E0001,
            format!("bundle exceeds max_bundle_bytes limit ({max} bytes)"),
        )],
        ParseError::JsonNestingTooDeep { max } => vec![Diagnostic::new(
            DiagnosticCode::E0001,
            format!("JSON nesting exceeds max_nesting_depth ({max})"),
        )],
        ParseError::JsonStringTooLong { len, max } => vec![Diagnostic::new(
            DiagnosticCode::E0001,
            format!("JSON string length {len} exceeds max_string_length ({max})"),
        )],
        ParseError::UnknownObjectType(type_name) => vec![
            Diagnostic::new(
                DiagnosticCode::E0002,
                format!("unknown STIX object type `{type_name}`"),
            )
            .with_property_path("type"),
        ],
    }
}

fn diagnostics_from_json_error(err: &serde_json::Error) -> Vec<Diagnostic> {
    let message = err.to_string();
    if let Some(model_err) = crate::model::ModelError::from_serde_message(&message) {
        return vec![diagnostic_from_model_error(&model_err, None, None)];
    }
    if err.is_syntax() || err.is_eof() {
        vec![Diagnostic::new(DiagnosticCode::E0001, message)]
    } else {
        vec![
            Diagnostic::new(DiagnosticCode::E0003, message).with_fix_suggestion(
                "Check required fields and value shapes against the STIX 2.1 specification.",
            ),
        ]
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

    #[test]
    fn model_serde_message_maps_to_e0004_not_e0001() {
        let json = r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000","objects":[{"type":"malware","spec_version":"2.1","id":"malware--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","created":"2020-01-01T00:00:00.000Z","modified":"2020-01-01T00:00:00.000Z","is_family":true}]}"#;
        let report = crate::validate::Validator::consumer_strict().validate_json_str(json);
        assert!(
            report.with_code(DiagnosticCode::E0004).next().is_some(),
            "expected STIX-E0004"
        );
        assert!(
            report.with_code(DiagnosticCode::E0001).next().is_none(),
            "model validation must not downgrade to STIX-E0001"
        );
    }

    #[test]
    fn true_json_syntax_error_maps_to_e0001() {
        let report = crate::validate::Validator::consumer_strict().validate_json_str("{not-json");
        assert!(
            report.with_code(DiagnosticCode::E0001).next().is_some(),
            "expected STIX-E0001 for malformed JSON"
        );
    }
}
