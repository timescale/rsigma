//! `type` discrimination and custom type policy.

use super::{ValidationContext, ValidationReport};
use crate::validate::diagnostic::{Diagnostic, DiagnosticCode};

/// Returns the root document `type` string when present.
pub(crate) fn document_root_type(value: &serde_json::Value) -> Option<&str> {
    value.as_object()?.get("type")?.as_str()
}

pub fn run(ctx: &ValidationContext<'_>, report: &mut ValidationReport) {
    let Some(value) = ctx.value else {
        return;
    };

    if !value.is_object() {
        report.push(
            Diagnostic::new(
                DiagnosticCode::E0002,
                "STIX document root must be a JSON object",
            )
            .with_property_path("$")
            .with_fix_suggestion("Wrap the payload in a JSON object with `type`: `bundle`."),
        );
        return;
    }

    match document_root_type(value) {
        Some("bundle") => {}
        Some(actual) => {
            report.push(
                Diagnostic::new(
                    DiagnosticCode::E0002,
                    format!("expected STIX type `bundle`, got `{actual}`"),
                )
                .with_property_path("type")
                .with_fix_suggestion("Set the document root `type` to `bundle`."),
            );
        }
        None => {
            report.push(
                Diagnostic::new(
                    DiagnosticCode::E0002,
                    "document root is missing required property `type`",
                )
                .with_property_path("type")
                .with_fix_suggestion("Add `\"type\": \"bundle\"` at the document root."),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ParseOptions;
    use crate::validate::{Leniency, ValidationReport};

    #[test]
    fn missing_root_type_emits_e0002_with_metadata() {
        let value = serde_json::json!({});
        let opts = ParseOptions::default();
        let ctx = ValidationContext::new(None, Some(&value), Leniency::Standard, &opts);
        let mut report = ValidationReport::new();
        run(&ctx, &mut report);
        let diag = report
            .with_code(DiagnosticCode::E0002)
            .next()
            .expect("E0002");
        assert_eq!(diag.property_path.as_deref(), Some("type"));
        assert!(diag.fix_suggestion.is_some());
    }
}
