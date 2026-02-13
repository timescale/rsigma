//! Convert rsigma-parser lint warnings and parse/compile errors into LSP
//! `Diagnostic` objects with resolved source positions.

use rsigma_parser::lint::{LintWarning, Severity as LintSeverity, lint_yaml_str};
use tower_lsp::lsp_types::*;

use crate::position::{LineIndex, resolve_path};

/// Produce LSP diagnostics for a Sigma YAML document.
///
/// This runs three layers of validation:
/// 1. Lint warnings with resolved spans (from `rsigma_parser::lint::lint_yaml_str`)
/// 2. AST parse errors (from `rsigma_parser::parse_sigma_yaml`)
/// 3. Compile errors (from `rsigma_eval::compile_rule`)
pub fn diagnose(text: &str) -> Vec<Diagnostic> {
    let index = LineIndex::new(text);
    let mut diagnostics = Vec::new();

    // ── Layer 1: Lint (includes YAML parse errors) ──────────────────────
    let warnings = lint_yaml_str(text);
    for w in &warnings {
        diagnostics.push(lint_warning_to_diagnostic(w, text, &index));
    }

    // ── Layer 2: AST parse errors ───────────────────────────────────────
    match rsigma_parser::parse_sigma_yaml(text) {
        Ok(collection) => {
            // ── Layer 3: Compile errors ─────────────────────────────
            for rule in &collection.rules {
                if let Err(e) = rsigma_eval::compile_rule(rule) {
                    diagnostics.push(compile_error_to_diagnostic(&e.to_string(), text, &index));
                }
            }
        }
        Err(e) => {
            diagnostics.push(parse_error_to_diagnostic(&e.to_string(), text, &index));
        }
    }

    diagnostics
}

/// Convert a `LintWarning` to an LSP `Diagnostic`.
///
/// Uses the pre-resolved `span` if available, otherwise falls back to
/// resolving the JSON-pointer `path` against the raw text.
fn lint_warning_to_diagnostic(warning: &LintWarning, text: &str, index: &LineIndex) -> Diagnostic {
    let range = if let Some(span) = &warning.span {
        Range::new(
            Position::new(span.start_line, span.start_col),
            Position::new(span.end_line, span.end_col),
        )
    } else {
        resolve_path(text, index, &warning.path)
    };

    let severity = match warning.severity {
        LintSeverity::Error => DiagnosticSeverity::ERROR,
        LintSeverity::Warning => DiagnosticSeverity::WARNING,
    };

    Diagnostic {
        range,
        severity: Some(severity),
        code: Some(NumberOrString::String(warning.rule.to_string())),
        source: Some("rsigma".to_string()),
        message: warning.message.clone(),
        ..Default::default()
    }
}

/// Convert a parse error string to an LSP `Diagnostic`.
fn parse_error_to_diagnostic(message: &str, text: &str, index: &LineIndex) -> Diagnostic {
    let range =
        extract_range_from_error(message, index).unwrap_or_else(|| resolve_path(text, index, "/"));

    Diagnostic {
        range,
        severity: Some(DiagnosticSeverity::ERROR),
        code: Some(NumberOrString::String("parse_error".to_string())),
        source: Some("rsigma".to_string()),
        message: message.to_string(),
        ..Default::default()
    }
}

/// Convert a compile error string to an LSP `Diagnostic`.
///
/// Attempts to resolve a more precise location when the error message contains
/// enough information (e.g. highlighting the unknown identifier within the
/// condition line for "unknown detection identifier" errors).
fn compile_error_to_diagnostic(message: &str, text: &str, index: &LineIndex) -> Diagnostic {
    let range = resolve_compile_error_range(message, text, index);

    Diagnostic {
        range,
        severity: Some(DiagnosticSeverity::ERROR),
        code: Some(NumberOrString::String("compile_error".to_string())),
        source: Some("rsigma".to_string()),
        message: message.to_string(),
        ..Default::default()
    }
}

/// Resolve a more precise location for compile errors when possible.
fn resolve_compile_error_range(message: &str, text: &str, index: &LineIndex) -> Range {
    // "unknown detection identifier: X" — highlight X in the condition line
    if let Some(name) = message.strip_prefix("unknown detection identifier: ") {
        let name = name.trim();
        if !name.is_empty() {
            for (i, line) in text.lines().enumerate() {
                let trimmed = line.trim();
                let indent = line.len() - trimmed.len();
                if indent > 0
                    && trimmed.starts_with("condition:")
                    && let Some(offset) = line.find(name)
                {
                    return Range::new(
                        Position::new(i as u32, offset as u32),
                        Position::new(i as u32, (offset + name.len()) as u32),
                    );
                }
            }
        }
    }

    // Default: point to the condition line
    resolve_path(text, index, "/detection/condition")
}

/// Try to extract line/column from error messages like "at line 5 column 3".
fn extract_range_from_error(message: &str, index: &LineIndex) -> Option<Range> {
    let line_idx = message.find("line ")?;
    let after_line = &message[line_idx + 5..];
    let line_end = after_line
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after_line.len());
    let line: u32 = after_line[..line_end].parse().ok()?;
    let line = line.saturating_sub(1); // 1-indexed -> 0-indexed

    let col = if let Some(col_idx) = message.find("column ") {
        let after_col = &message[col_idx + 7..];
        let col_end = after_col
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after_col.len());
        after_col[..col_end].parse::<u32>().unwrap_or(0)
    } else {
        0
    };

    let (_, line_end_offset) = index.line_range(line as usize);
    Some(Range::new(
        Position::new(line, col),
        index.position_of(line_end_offset),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_range_from_yaml_error() {
        // serde_yaml typical error format
        let msg = "invalid type: string \"foo\", expected a mapping at line 5 column 3";
        let text = "title: Test\nstatus: test\nlevel: high\nlogsource:\n  foo\n";
        let index = LineIndex::new(text);
        let range = extract_range_from_error(msg, &index).unwrap();
        assert_eq!(range.start.line, 4); // line 5 -> 0-indexed line 4
        assert_eq!(range.start.character, 3);
    }

    #[test]
    fn extract_range_line_only() {
        let msg = "unexpected character at line 2";
        let text = "title: Test\nbad\n";
        let index = LineIndex::new(text);
        let range = extract_range_from_error(msg, &index).unwrap();
        assert_eq!(range.start.line, 1); // line 2 -> 0-indexed line 1
        assert_eq!(range.start.character, 0); // no column
    }

    #[test]
    fn extract_range_no_match() {
        let msg = "something went wrong";
        let text = "title: Test\n";
        let index = LineIndex::new(text);
        assert!(extract_range_from_error(msg, &index).is_none());
    }

    #[test]
    fn compile_error_unknown_detection_highlights_name() {
        let text = "\
title: Test
detection:
    selection:
        User: admin
    condition: selecton
";
        let index = LineIndex::new(text);
        let range =
            resolve_compile_error_range("unknown detection identifier: selecton", text, &index);
        // Should point to "selecton" in the condition line (line 4)
        assert_eq!(range.start.line, 4);
        let line = text.lines().nth(4).unwrap();
        let offset = line.find("selecton").unwrap();
        assert_eq!(range.start.character, offset as u32);
        assert_eq!(range.end.character, (offset + "selecton".len()) as u32);
    }

    #[test]
    fn compile_error_fallback_to_condition_line() {
        let text = "\
title: Test
detection:
    selection:
        User: admin
    condition: selection
";
        let index = LineIndex::new(text);
        let range =
            resolve_compile_error_range("invalid modifier combination: something", text, &index);
        // Should point to the condition line (line 4)
        assert_eq!(range.start.line, 4);
    }
}
