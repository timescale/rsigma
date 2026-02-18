use std::collections::HashMap;

use rsigma_parser::lint::{
    self, FixDisposition, FixPatch, LintConfig, LintWarning, lint_yaml_str_with_config,
};
use tower_lsp::lsp_types::*;

use crate::position::{LineIndex, resolve_path};

/// Build code actions for the given document and range.
///
/// Re-lints the document, finds warnings with fixes whose ranges overlap
/// the requested range, and converts each into a `CodeAction` with a
/// `WorkspaceEdit` containing `TextEdit`s.
pub fn code_actions(
    uri: &Url,
    text: &str,
    request_range: &Range,
    config: &LintConfig,
) -> Vec<CodeAction> {
    let index = LineIndex::new(text);
    let warnings = lint_yaml_str_with_config(text, config);

    let mut actions = Vec::new();

    for w in &warnings {
        let Some(fix) = &w.fix else { continue };
        if fix.disposition != FixDisposition::Safe {
            continue;
        }

        let diag_range = warning_range(w, text, &index);
        if !ranges_overlap(&diag_range, request_range) {
            continue;
        }

        let edits = fix_to_text_edits(fix, text, &index);
        if edits.is_empty() {
            continue;
        }

        let diagnostic = Diagnostic {
            range: diag_range,
            severity: Some(severity_to_lsp(w.severity)),
            code: Some(NumberOrString::String(w.rule.to_string())),
            source: Some("rsigma".to_string()),
            message: w.message.clone(),
            ..Default::default()
        };

        let mut changes = HashMap::new();
        changes.insert(uri.clone(), edits);

        actions.push(CodeAction {
            title: fix.title.clone(),
            kind: Some(CodeActionKind::QUICKFIX),
            diagnostics: Some(vec![diagnostic]),
            edit: Some(WorkspaceEdit {
                changes: Some(changes),
                ..Default::default()
            }),
            is_preferred: Some(true),
            ..Default::default()
        });
    }

    actions
}

fn warning_range(w: &LintWarning, text: &str, index: &LineIndex) -> Range {
    if let Some(span) = &w.span {
        Range::new(
            Position::new(span.start_line, span.start_col),
            Position::new(span.end_line, span.end_col),
        )
    } else {
        resolve_path(text, index, &w.path)
    }
}

fn severity_to_lsp(severity: lint::Severity) -> DiagnosticSeverity {
    match severity {
        lint::Severity::Error => DiagnosticSeverity::ERROR,
        lint::Severity::Warning => DiagnosticSeverity::WARNING,
        lint::Severity::Info => DiagnosticSeverity::INFORMATION,
        lint::Severity::Hint => DiagnosticSeverity::HINT,
    }
}

/// Convert a Fix's patches into LSP TextEdits.
///
/// For ReplaceValue: replace the value portion of the line at the path.
/// For ReplaceKey: replace the key portion of the line at the path.
/// For Remove: delete the entire line at the path.
fn fix_to_text_edits(
    fix: &rsigma_parser::lint::Fix,
    text: &str,
    index: &LineIndex,
) -> Vec<TextEdit> {
    let lines: Vec<&str> = text.lines().collect();
    let mut edits = Vec::new();

    for patch in &fix.patches {
        match patch {
            FixPatch::ReplaceValue { path, new_value } => {
                let range = resolve_path(text, index, path);
                let line_idx = range.start.line as usize;
                if let Some(line) = lines.get(line_idx)
                    && let Some(edit) = replace_value_edit(line, line_idx, new_value)
                {
                    edits.push(edit);
                }
            }
            FixPatch::ReplaceKey { path, new_key } => {
                let range = resolve_path(text, index, path);
                let line_idx = range.start.line as usize;
                if let Some(line) = lines.get(line_idx) {
                    let old_key = path.rsplit('/').next().unwrap_or("");
                    if let Some(edit) = replace_key_edit(line, line_idx, old_key, new_key) {
                        edits.push(edit);
                    }
                }
            }
            FixPatch::Remove { path } => {
                let range = resolve_path(text, index, path);
                let line_idx = range.start.line as usize;
                let start = Position::new(line_idx as u32, 0);
                let end = if line_idx + 1 < lines.len() {
                    Position::new((line_idx + 1) as u32, 0)
                } else if let Some(line) = lines.get(line_idx) {
                    Position::new(line_idx as u32, line.len() as u32)
                } else {
                    continue;
                };
                edits.push(TextEdit {
                    range: Range::new(start, end),
                    new_text: String::new(),
                });
            }
        }
    }

    edits
}

/// Build a TextEdit that replaces the value portion of a `key: value` line.
fn replace_value_edit(line: &str, line_idx: usize, new_value: &str) -> Option<TextEdit> {
    let colon_pos = line.find(':')?;
    // Value starts after ": " (colon + space)
    let value_start = if line.as_bytes().get(colon_pos + 1) == Some(&b' ') {
        colon_pos + 2
    } else {
        colon_pos + 1
    };
    let range = Range::new(
        Position::new(line_idx as u32, value_start as u32),
        Position::new(line_idx as u32, line.len() as u32),
    );
    Some(TextEdit {
        range,
        new_text: new_value.to_string(),
    })
}

/// Build a TextEdit that replaces a key name on a line.
fn replace_key_edit(line: &str, line_idx: usize, old_key: &str, new_key: &str) -> Option<TextEdit> {
    let key_start = line.find(old_key)?;
    let key_end = key_start + old_key.len();
    let range = Range::new(
        Position::new(line_idx as u32, key_start as u32),
        Position::new(line_idx as u32, key_end as u32),
    );
    Some(TextEdit {
        range,
        new_text: new_key.to_string(),
    })
}

fn ranges_overlap(a: &Range, b: &Range) -> bool {
    a.start.line <= b.end.line && b.start.line <= a.end.line
}

#[cfg(test)]
mod tests {
    use super::*;
    use insta::assert_snapshot;

    fn full_range() -> Range {
        Range::new(Position::new(0, 0), Position::new(u32::MAX, 0))
    }

    fn test_uri() -> Url {
        Url::parse("file:///test.yml").unwrap()
    }

    fn actions_summary(actions: &[&CodeAction]) -> String {
        let mut lines = Vec::new();
        for a in actions {
            lines.push(format!("=== {} ===", a.title));
            if let Some(edit) = &a.edit
                && let Some(changes) = &edit.changes
            {
                for edits in changes.values() {
                    for e in edits {
                        lines.push(format!(
                            "  {}:{}-{}:{}: {:?}",
                            e.range.start.line,
                            e.range.start.character,
                            e.range.end.line,
                            e.range.end.character,
                            e.new_text,
                        ));
                    }
                }
            }
        }
        lines.join("\n")
    }

    #[test]
    fn replace_value_invalid_status() {
        let yaml = "\
title: Test
status: expreimental
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
";
        let actions = code_actions(&test_uri(), yaml, &full_range(), &LintConfig::default());
        let status_fix: Vec<_> = actions
            .iter()
            .filter(|a| a.title.contains("experimental"))
            .collect();
        assert!(!status_fix.is_empty(), "should have a status fix");
        assert_snapshot!(actions_summary(&status_fix), @r#"
        === replace 'expreimental' with 'experimental' ===
          1:8-1:20: "experimental"
        "#);
    }

    #[test]
    fn replace_key_non_lowercase() {
        let yaml = "\
title: Test
Status: experimental
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
";
        let actions = code_actions(&test_uri(), yaml, &full_range(), &LintConfig::default());
        let key_fix: Vec<_> = actions
            .iter()
            .filter(|a| a.title.contains("rename") && a.title.contains("status"))
            .collect();
        assert!(!key_fix.is_empty(), "should have a key rename fix");
        assert_snapshot!(actions_summary(&key_fix), @r#"
        === rename 'Status' to 'status' ===
          1:0-1:6: "status"
        === rename 'Status' to 'status' ===
          1:0-1:6: "status"
        "#);
    }

    #[test]
    fn remove_duplicate_tag() {
        let yaml = "\
title: Test
status: test
tags:
    - attack.execution
    - attack.execution
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
";
        let actions = code_actions(&test_uri(), yaml, &full_range(), &LintConfig::default());
        let dup_fix: Vec<_> = actions
            .iter()
            .filter(|a| a.title.contains("duplicate tag"))
            .collect();
        assert!(!dup_fix.is_empty(), "should have a remove-duplicate fix");
        assert_snapshot!(actions_summary(&dup_fix), @r#"
        === remove duplicate tag 'attack.execution' ===
          4:0-5:0: ""
        "#);
    }

    #[test]
    fn no_actions_for_clean_rule() {
        let yaml = "\
title: Test
status: test
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
";
        let actions = code_actions(&test_uri(), yaml, &full_range(), &LintConfig::default());
        let fixable: Vec<_> = actions.iter().filter(|a| a.edit.is_some()).collect();
        assert!(
            fixable.is_empty(),
            "clean rule should have no fixable actions"
        );
    }

    #[test]
    fn range_filtering_excludes_unrelated() {
        let yaml = "\
title: Test
Status: experimental
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
";
        let narrow_range = Range::new(Position::new(5, 0), Position::new(7, 0));
        let actions = code_actions(&test_uri(), yaml, &narrow_range, &LintConfig::default());
        let key_fix: Vec<_> = actions
            .iter()
            .filter(|a| a.title.contains("rename") && a.title.contains("status"))
            .collect();
        assert!(
            key_fix.is_empty(),
            "Status fix on line 1 should not appear when range is lines 5-7"
        );
    }

    #[test]
    fn multiple_fixes_on_same_document() {
        let yaml = "\
title: Test
status: expreimental
tags:
    - attack.execution
    - attack.execution
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
";
        let actions = code_actions(&test_uri(), yaml, &full_range(), &LintConfig::default());
        let fixable: Vec<_> = actions.iter().filter(|a| a.edit.is_some()).collect();
        assert!(
            fixable.len() >= 2,
            "should have at least 2 fixes (status + duplicate tag), got {}",
            fixable.len()
        );
        assert_snapshot!(actions_summary(&fixable), @r#"
        === replace 'expreimental' with 'experimental' ===
          1:8-1:20: "experimental"
        === remove duplicate tag 'attack.execution' ===
          4:0-5:0: ""
        "#);
    }
}
