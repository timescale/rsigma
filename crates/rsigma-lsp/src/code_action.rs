use std::collections::HashMap;

use rsigma_parser::lint::fix::apply_fixes_to_source;
use rsigma_parser::lint::{
    self, FixDisposition, LintConfig, LintWarning, lint_yaml_str_with_config,
};
use tower_lsp_server::ls_types::*;

use crate::position::{LineIndex, resolve_path};

/// Build code actions for the given document and range.
///
/// Re-lints the document, finds warnings with fixes whose ranges overlap
/// the requested range, and converts each into a `CodeAction` with a
/// `WorkspaceEdit` containing `TextEdit`s.
pub fn code_actions(
    uri: &Uri,
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

        let edits = fix_to_text_edits(w, text, &index);
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

/// Turn one warning's fix into a single LSP `TextEdit` covering the lines it
/// changes. The fix goes through the shared applier, so the edit is the same
/// verified change `rule lint --fix` makes, and a fix that does not apply
/// cleanly yields no edit.
fn fix_to_text_edits(warning: &LintWarning, text: &str, index: &LineIndex) -> Vec<TextEdit> {
    let outcome = apply_fixes_to_source(text, &[warning]);
    if outcome.applied != 1 || outcome.fixed_source == text {
        return Vec::new();
    }
    let fixed = outcome.fixed_source;
    let (old, new) = (text.as_bytes(), fixed.as_bytes());
    let mut start = old.iter().zip(new).take_while(|(a, b)| a == b).count();
    while start > 0 && old[start - 1] != b'\n' {
        start -= 1;
    }
    let max_suffix = old.len().min(new.len()) - start;
    let mut suffix = old
        .iter()
        .rev()
        .zip(new.iter().rev())
        .take(max_suffix)
        .take_while(|(a, b)| a == b)
        .count();
    while suffix > 0 && old[old.len() - suffix - 1] != b'\n' {
        suffix -= 1;
    }
    let range = Range::new(
        index.position_at(text, start),
        index.position_at(text, old.len() - suffix),
    );
    vec![TextEdit {
        range,
        new_text: fixed[start..new.len() - suffix].to_string(),
    }]
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

    fn test_uri() -> Uri {
        "file:///test.yml".parse().unwrap()
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
          1:0-2:0: "status: experimental\n"
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
          1:0-2:0: "status: experimental\n"
        === rename 'Status' to 'status' ===
          1:0-2:0: "status: experimental\n"
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
          1:0-2:0: "status: experimental\n"
        === remove duplicate tag 'attack.execution' ===
          4:0-5:0: ""
        "#);
    }

    #[test]
    fn quoted_key_fix_keeps_the_key_quoted() {
        let yaml = "\
title: Test
logsource:
    category: test
detection:
    sel:
        'a: b|all': value
    condition: sel
";
        let actions = code_actions(&test_uri(), yaml, &full_range(), &LintConfig::default());
        let fix: Vec<_> = actions
            .iter()
            .filter(|a| a.title.contains("remove |all"))
            .collect();
        assert_snapshot!(actions_summary(&fix), @r#"
        === remove |all from 'a: b|all' ===
          5:0-6:0: "        'a: b': value\n"
        "#);
    }

    #[test]
    fn fix_from_a_later_document_edits_that_document() {
        let yaml = "\
title: One
status: test
logsource:
    category: test
detection:
    sel:
        a: b
    condition: sel
---
title: Two
Status: test
logsource:
    category: test
detection:
    sel:
        a: b
    condition: sel
";
        let actions = code_actions(&test_uri(), yaml, &full_range(), &LintConfig::default());
        let fix: Vec<_> = actions
            .iter()
            .filter(|a| a.title.contains("rename"))
            .take(1)
            .collect();
        assert_snapshot!(actions_summary(&fix), @r#"
        === rename 'Status' to 'status' ===
          10:0-11:0: "status: test\n"
        "#);
    }
}
