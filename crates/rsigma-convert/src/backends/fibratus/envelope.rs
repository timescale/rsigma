//! Fibratus rule-YAML envelope builder.
//!
//! Each Sigma rule produces one YAML document. The envelope wraps a
//! pre-rendered Fibratus filter expression in the metadata Fibratus
//! expects on disk (`name`, `id`, `description`, `labels`, `condition`,
//! `min-engine-version`, optional `action`).
//!
//! YAML is hand-rolled rather than routed through [`yaml_serde`] so the
//! emitter has full control over field ordering, block-scalar style for
//! long `condition:` and `description:` values, and golden-test
//! determinism. Fibratus rule files in the upstream library use a
//! consistent block style that hand-rolling reproduces exactly; the
//! generic YAML serializer would re-flow lines and break golden diffs.

use std::collections::BTreeMap;
use std::fmt::Write;

use rsigma_parser::{CorrelationRule, SigmaRule};

use super::config::FibratusConfig;
use super::shared::labels_from_tags;

/// Render one Sigma detection rule as a Fibratus YAML rule document.
///
/// `condition_expr` is the already-converted Fibratus filter expression
/// (the output of the `Backend::convert_condition` walk). The envelope
/// emits one top-level key per line and uses block-scalar indicators for
/// the multi-line `description` and `condition` fields so the output
/// matches upstream's hand-authored rule style.
pub fn render_rule_yaml(rule: &SigmaRule, condition_expr: &str, cfg: &FibratusConfig) -> String {
    render_envelope(
        &rule.title,
        rule.id.as_deref(),
        rule.description.as_deref(),
        &rule.tags,
        condition_expr,
        cfg,
    )
}

/// Render one Sigma correlation rule as a Fibratus YAML rule document.
///
/// The body of `condition_expr` is the already-built `sequence`/`maxspan`
/// DSL produced by [`super::correlation`]. The envelope shape is
/// identical to a detection rule (`name`/`id`/`description`/`labels`/
/// `condition`/`min-engine-version`/`action`); only the condition body
/// differs.
pub fn render_correlation_yaml(
    rule: &CorrelationRule,
    condition_expr: &str,
    cfg: &FibratusConfig,
) -> String {
    render_envelope(
        &rule.title,
        rule.id.as_deref(),
        rule.description.as_deref(),
        &rule.tags,
        condition_expr,
        cfg,
    )
}

/// Inner envelope builder shared by [`render_rule_yaml`] and
/// [`render_correlation_yaml`]. Hand-rolling rather than routing through
/// [`yaml_serde`] keeps field ordering, block-scalar style for long
/// `condition:` values, and folding behavior deterministic so golden
/// tests do not flap on serializer-internal whitespace changes.
fn render_envelope(
    title: &str,
    id: Option<&str>,
    description: Option<&str>,
    tags: &[String],
    condition_expr: &str,
    cfg: &FibratusConfig,
) -> String {
    let mut out = String::with_capacity(condition_expr.len() + 256);

    let _ = writeln!(out, "name: {}", yaml_inline_str(title));

    if let Some(id) = id
        && !id.is_empty()
    {
        let _ = writeln!(out, "id: {}", yaml_inline_str(id));
    }

    if cfg.emit_metadata {
        if let Some(desc) = description
            && !desc.is_empty()
        {
            out.push_str("description: |\n");
            for line in desc.lines() {
                let _ = writeln!(out, "  {line}");
            }
        }

        let labels = labels_from_tags(tags);
        write_labels(&mut out, &labels);
    }

    write_condition(&mut out, condition_expr);

    let _ = writeln!(
        out,
        "min-engine-version: {}",
        yaml_inline_str(&cfg.min_engine_version)
    );

    if let Some(actions) = &cfg.action
        && !actions.is_empty()
    {
        out.push_str("action:\n");
        for a in actions {
            let _ = writeln!(out, "  - name: {}", yaml_inline_str(a));
        }
    }

    out
}

/// Render the `condition:` block.
///
/// - Single short single-line conditions use a plain flow scalar.
/// - Author-provided multi-line conditions (the `sequence`/`maxspan` DSL
///   the correlation builder emits) are wrapped in the folded `>`
///   indicator with line breaks preserved verbatim.
/// - Long single-line conditions are soft-wrapped on top-level
///   `and`/`or` boundaries, again under the folded indicator.
fn write_condition(out: &mut String, expr: &str) {
    if expr.len() <= 100 && !expr.contains('\n') {
        let _ = writeln!(out, "condition: {expr}");
        return;
    }
    out.push_str("condition: >\n");
    if expr.contains('\n') {
        for line in expr.lines() {
            let _ = writeln!(out, "  {line}");
        }
    } else {
        for line in soft_wrap(expr, 100) {
            let _ = writeln!(out, "  {line}");
        }
    }
}

/// Wrap a Fibratus filter expression at `width` columns by breaking on
/// the outermost ` and `/` or ` boundaries. Preserves grouping
/// parentheses; if no top-level boolean separator fits, the expression
/// is emitted on a single line so the loader never sees a re-flowed
/// sub-expression.
fn soft_wrap(expr: &str, width: usize) -> Vec<String> {
    let pieces = split_top_level(expr);
    if pieces.len() == 1 {
        return vec![pieces.into_iter().next().unwrap()];
    }

    let mut lines = Vec::new();
    let mut current = String::new();
    for piece in pieces {
        if current.is_empty() {
            current = piece;
            continue;
        }
        if current.len() + 1 + piece.len() <= width {
            current.push(' ');
            current.push_str(&piece);
        } else {
            lines.push(std::mem::take(&mut current));
            current = piece;
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// Split an expression on its top-level ` and `/` or ` separators while
/// respecting parenthesis and single-quote-string nesting. The separator
/// tokens are kept attached to the right-hand side so a re-join with `' '`
/// reproduces the input verbatim.
fn split_top_level(expr: &str) -> Vec<String> {
    let bytes = expr.as_bytes();
    let mut pieces: Vec<String> = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut in_str = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'\'' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' => in_str = true,
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && (matches_keyword(bytes, i, b" and ") || matches_keyword(bytes, i, b" or "))
        {
            let piece = expr[start..i].trim_end().to_string();
            if !piece.is_empty() {
                pieces.push(piece);
            }
            start = i + 1;
            i += 1;
            continue;
        }
        i += 1;
    }
    let tail = expr[start..].trim().to_string();
    if !tail.is_empty() {
        pieces.push(tail);
    }
    pieces
}

fn matches_keyword(bytes: &[u8], i: usize, kw: &[u8]) -> bool {
    if i + kw.len() > bytes.len() {
        return false;
    }
    bytes[i..i + kw.len()].eq_ignore_ascii_case(kw)
}

fn write_labels(out: &mut String, labels: &BTreeMap<String, String>) {
    if labels.is_empty() {
        return;
    }
    out.push_str("labels:\n");
    for (k, v) in labels {
        let _ = writeln!(out, "  {k}: {}", yaml_inline_str(v));
    }
}

/// Quote a value for a YAML inline scalar.
///
/// Strings that look like YAML reserved tokens (`true`, `false`, `null`,
/// numeric literals) and strings containing characters that would break
/// flow syntax (`:`, `#`, leading `-`, leading whitespace) are wrapped in
/// single quotes with internal single quotes doubled. Other strings are
/// emitted bare so the result reads naturally.
fn yaml_inline_str(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if needs_yaml_quoting(s) {
        format!("'{}'", s.replace('\'', "''"))
    } else {
        s.to_string()
    }
}

fn needs_yaml_quoting(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    let lower = s.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "true" | "false" | "null" | "yes" | "no" | "on" | "off" | "~"
    ) {
        return true;
    }
    if s.parse::<i64>().is_ok() || s.parse::<f64>().is_ok() {
        return true;
    }
    let first = s.chars().next().unwrap();
    if matches!(
        first,
        '-' | '?'
            | ':'
            | ','
            | '['
            | ']'
            | '{'
            | '}'
            | '#'
            | '&'
            | '*'
            | '!'
            | '|'
            | '>'
            | '\''
            | '"'
            | '%'
            | '@'
            | '`'
    ) || first.is_whitespace()
    {
        return true;
    }
    // Strings containing internal quotes, colons, sharps, tabs, or
    // newlines confuse YAML flow scalars. Force quoting in those cases
    // so the loader sees the literal value verbatim.
    s.contains(':')
        || s.contains(" #")
        || s.contains('\n')
        || s.contains('\t')
        || s.contains('\'')
        || s.contains('"')
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::parse_sigma_yaml;

    fn rule(yaml: &str) -> SigmaRule {
        parse_sigma_yaml(yaml)
            .unwrap()
            .rules
            .into_iter()
            .next()
            .unwrap()
    }

    fn cfg() -> FibratusConfig {
        FibratusConfig::default()
    }

    #[test]
    fn render_minimal_rule() {
        let r = rule(
            r#"
title: Test Rule
id: 12345678-1234-1234-1234-1234567890ab
detection:
  selection:
    ps.name: cmd.exe
  condition: selection
"#,
        );
        let out = render_rule_yaml(&r, "ps.name = 'cmd.exe'", &cfg());
        let expected = "\
name: Test Rule
id: 12345678-1234-1234-1234-1234567890ab
condition: ps.name = 'cmd.exe'
min-engine-version: 3.0.0
";
        assert_eq!(out, expected);
    }

    #[test]
    fn render_rule_with_description_and_labels() {
        let r = rule(
            r#"
title: Test
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
description: |
  First line.
  Second line.
tags:
  - attack.defense_evasion
  - attack.t1055
detection:
  selection:
    ps.name: rundll32.exe
  condition: selection
"#,
        );
        let out = render_rule_yaml(&r, "ps.name = 'rundll32.exe'", &cfg());
        assert!(out.contains("description: |\n  First line.\n  Second line.\n"));
        assert!(out.contains("tactic.id: TA0005"));
        assert!(out.contains("technique.id: T1055"));
        assert!(out.contains("condition: ps.name = 'rundll32.exe'"));
        assert!(out.contains("min-engine-version: 3.0.0"));
    }

    #[test]
    fn render_rule_with_action() {
        let r = rule(
            r#"
title: Drop me
detection:
  selection:
    ps.name: malware.exe
  condition: selection
"#,
        );
        let mut c = cfg();
        c.action = Some(vec!["kill".to_string(), "isolate".to_string()]);
        let out = render_rule_yaml(&r, "ps.name = 'malware.exe'", &c);
        assert!(out.ends_with("action:\n  - name: kill\n  - name: isolate\n"));
    }

    #[test]
    fn long_condition_uses_folded_block_with_soft_wrap() {
        let r = rule(
            r#"
title: Long
detection:
  s:
    ps.name: a
  condition: s
"#,
        );
        let long = "spawn_process and ps.exe icontains 'cmd.exe' and ps.cmdline icontains 'powershell.exe' and ps.parent.exe icontains 'explorer.exe'";
        let out = render_rule_yaml(&r, long, &cfg());
        assert!(out.contains("condition: >\n"));
        // Should be split across multiple lines.
        let condition_block: Vec<&str> = out
            .lines()
            .skip_while(|l| !l.starts_with("condition:"))
            .skip(1)
            .take_while(|l| l.starts_with("  "))
            .collect();
        assert!(
            condition_block.len() >= 2,
            "expected wrapped lines, got: {condition_block:?}"
        );
    }

    #[test]
    fn yaml_inline_str_quotes_reserved_words() {
        assert_eq!(yaml_inline_str("true"), "'true'");
        assert_eq!(yaml_inline_str("False"), "'False'");
        assert_eq!(yaml_inline_str("null"), "'null'");
        assert_eq!(yaml_inline_str("42"), "'42'");
    }

    #[test]
    fn yaml_inline_str_quotes_colon_and_leading_dash() {
        assert_eq!(yaml_inline_str("a: b"), "'a: b'");
        assert_eq!(yaml_inline_str("- hi"), "'- hi'");
        assert_eq!(yaml_inline_str("Tom's"), "'Tom''s'");
    }

    #[test]
    fn yaml_inline_str_leaves_normal_strings_bare() {
        assert_eq!(yaml_inline_str("Hello world"), "Hello world");
        assert_eq!(yaml_inline_str("kill"), "kill");
    }

    #[test]
    fn emit_metadata_off_skips_description_and_labels() {
        let r = rule(
            r#"
title: Test
description: ignore me
tags:
  - attack.execution
detection:
  selection:
    ps.name: x
  condition: selection
"#,
        );
        let mut c = cfg();
        c.emit_metadata = false;
        let out = render_rule_yaml(&r, "ps.name = 'x'", &c);
        assert!(!out.contains("description:"));
        assert!(!out.contains("labels:"));
        assert!(!out.contains("tactic.id"));
    }
}
