//! Indicator STIX pattern parse.

use crate::pattern::{PatternError, parse_ast};

use super::super::diagnostic::{Diagnostic, DiagnosticCode, SourceSpan};
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
        if let Err(err) = parse_ast(pattern) {
            report.push(pattern_parse_diagnostic(
                err,
                pattern,
                format!("objects[{index}].pattern"),
                object
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|id| crate::core::StixId::parse(id).ok()),
            ));
        }
    }
}

pub(crate) fn pattern_parse_diagnostic(
    err: PatternError,
    source: &str,
    property_path: String,
    object_id: Option<crate::core::StixId>,
) -> Diagnostic {
    let (message, byte_offset) = match err {
        PatternError::LexError { pos, msg } => (format!("lexer error: {msg}"), Some(pos)),
        PatternError::ParseError { pos, msg } => (format!("parse error: {msg}"), Some(pos)),
        PatternError::DepthExceeded { pos, max } => {
            (format!("AST depth exceeds maximum of {max}"), Some(pos))
        }
        PatternError::ComparisonLimitExceeded { pos, max } => (
            format!("comparison count exceeds maximum of {max}"),
            Some(pos),
        ),
        PatternError::InputTooLarge { max } => {
            (format!("pattern exceeds maximum size of {max} bytes"), None)
        }
        PatternError::TypeError { path, msg } => (format!("type error at {path}: {msg}"), None),
    };
    let mut diagnostic =
        Diagnostic::new(DiagnosticCode::E0010, message).with_property_path(property_path);
    if let Some(id) = object_id {
        diagnostic = diagnostic.with_object_id(id);
    }
    if let Some(byte_offset) = byte_offset {
        diagnostic = diagnostic.with_span(SourceSpan {
            byte_offset: Some(byte_offset),
            line: None,
            column: None,
        });
    }
    let _ = source;
    diagnostic
}
