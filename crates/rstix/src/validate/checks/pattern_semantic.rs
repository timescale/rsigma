//! Indicator STIX pattern type-check.

use crate::pattern::{PatternError, parse_ast, type_check_ast};

use super::super::diagnostic::{Diagnostic, DiagnosticCode};
use super::{ValidationContext, ValidationReport};

pub fn run(ctx: &ValidationContext<'_>, report: &mut ValidationReport) {
    let Some(value) = ctx.value else {
        return;
    };
    let Some(objects) = value.get("objects").and_then(serde_json::Value::as_array) else {
        return;
    };

    for (index, object) in objects.iter().enumerate() {
        if object.get("type").and_then(serde_json::Value::as_str) != Some("indicator") {
            continue;
        }
        if object
            .get("pattern_type")
            .and_then(serde_json::Value::as_str)
            != Some("stix")
        {
            continue;
        }
        let Some(pattern) = object.get("pattern").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let object_id = object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .and_then(|id| crate::core::StixId::parse(id).ok());
        let property_path = format!("objects[{index}].pattern");
        let Ok(ast) = parse_ast(pattern) else {
            continue;
        };
        if let Err(err) = type_check_ast(&ast) {
            report.push(pattern_semantic_diagnostic(err, property_path, object_id));
        }
    }
}

fn pattern_semantic_diagnostic(
    err: PatternError,
    property_path: String,
    object_id: Option<crate::core::StixId>,
) -> Diagnostic {
    let (message, path) = match err {
        PatternError::TypeError { path, msg } => (msg, path),
        other => (other.to_string(), property_path.clone()),
    };
    let mut diagnostic = Diagnostic::new(
        DiagnosticCode::E0011,
        format!("type error at {path}: {message}"),
    )
    .with_property_path(property_path);
    if let Some(id) = object_id {
        diagnostic = diagnostic.with_object_id(id);
    }
    diagnostic
}
