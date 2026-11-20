//! Backend-local helpers for the Fibratus conversion backend.
//!
//! Functions here are intentionally narrow: each one solves a single mapping
//! problem (string quoting, regex compatibility, ATT&CK tag flattening) so
//! that the `Backend` impl in [`super::mod`](super) reads as a thin dispatch
//! layer.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use rsigma_parser::{SigmaString, StringPart};

use crate::error::{ConvertError, Result};

// =============================================================================
// String quoting
// =============================================================================

/// Quote a [`SigmaString`] for use inside a Fibratus filter expression.
///
/// Fibratus string literals are single-quoted, and the lexer accepts only
/// the `\\`, `\'`, `\"`, and `\n` escapes, with no raw line break. Sigma
/// wildcard tokens are emitted as `*` and `?` so they participate in
/// `matches`/`imatches` evaluation. A glob has no escape for a literal `*`
/// or `?`, so callers route such patterns to `regex()`; elsewhere the
/// characters are literal and stay verbatim.
pub fn quote_sigma_string(value: &SigmaString) -> String {
    let mut out = String::with_capacity(value.original.len() + 2);
    out.push('\'');
    for part in &value.parts {
        match part {
            StringPart::Plain(s) => push_escaped(&mut out, s),
            StringPart::Special(rsigma_parser::SpecialChar::WildcardMulti) => out.push('*'),
            StringPart::Special(rsigma_parser::SpecialChar::WildcardSingle) => out.push('?'),
        }
    }
    out.push('\'');
    out
}

/// Quote a plain `&str` (no Sigma wildcard parsing) for a Fibratus filter
/// expression. Used by the in-list path where the value already arrived as a
/// raw string and by the YAML envelope builder.
pub fn quote_plain_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    push_escaped(&mut out, s);
    out.push('\'');
    out
}

fn push_escaped(out: &mut String, s: &str) {
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
}

/// Whether a [`SigmaString`] contains any wildcard tokens.
pub fn has_wildcards(value: &SigmaString) -> bool {
    value
        .parts
        .iter()
        .any(|p| matches!(p, StringPart::Special(_)))
}

// =============================================================================
// Field identifiers
// =============================================================================

static FIBRATUS_FIELD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_][A-Za-z0-9_.$]*(?:\[[A-Za-z0-9_.$]+\][A-Za-z0-9_.$]*)*$").unwrap()
});

/// Return the field name as a bare Fibratus identifier.
///
/// Fibratus identifiers are dotted paths of letters, digits, `_`, `.`, and
/// `$` (`ps.exe`, `thread.callstack.symbols`), optionally indexed with
/// `[...]` segments (`evt.arg[exe]`, `ps.ancestor[0].name`). The backend never
/// invents field names on its own: pipelines like `fibratus_windows` rename
/// `Image` → `ps.exe`, `TargetFilename` → `file.path`, and friends before the
/// value reaches conversion. Unmapped names such as `Image` pass, so the
/// Fibratus loader still reports them as unknown fields. A name the filter
/// lexer would not read as one identifier fails conversion, because it would
/// change the structure of the filter expression.
pub fn field_ident(name: &str) -> Result<&str> {
    if FIBRATUS_FIELD_RE.is_match(name) {
        Ok(name)
    } else {
        Err(ConvertError::RuleConversion(format!(
            "invalid Fibratus field name: {name}"
        )))
    }
}

// =============================================================================
// Regex compatibility
// =============================================================================

static PCRE_LOOKAROUND_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\(\?[=!<]").unwrap());

static PCRE_NAMED_BACKREF_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\(\?P=").unwrap());

static PCRE_NUMERIC_BACKREF_RE: LazyLock<Regex> = LazyLock::new(|| {
    // `\1`..`\9`, but only when not part of a longer escape; tolerate
    // `\\1` (literal `\` followed by digit) by checking the prefix.
    Regex::new(r"(?:^|[^\\])\\[1-9]").unwrap()
});

/// Return `true` if `pattern` is expressible with Go's RE2 engine (the regex
/// engine behind Fibratus's `regex()` filter function).
///
/// Rejection list mirrors the constructs RE2 explicitly does not implement:
/// lookarounds (`(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`) and
/// backreferences (`\1`..`\9`, `(?P=name)`). Patterns that use only
/// character classes, alternation, quantifiers, anchors, capture groups,
/// and Unicode classes pass through; the Fibratus loader is the final
/// arbiter of whether the pattern compiles.
pub fn is_re2_compatible(pattern: &str) -> bool {
    if PCRE_LOOKAROUND_RE.is_match(pattern) {
        return false;
    }
    if PCRE_NAMED_BACKREF_RE.is_match(pattern) {
        return false;
    }
    if PCRE_NUMERIC_BACKREF_RE.is_match(pattern) {
        return false;
    }
    true
}

// =============================================================================
// ATT&CK tag flattening
// =============================================================================

/// MITRE ATT&CK tactic IDs that may appear in Sigma `tags:` entries
/// (`attack.<tactic_short_name>`). The tactic short name is the Sigma
/// convention; the tactic ID + display name are what Fibratus rule labels
/// carry.
const ATTACK_TACTICS: &[(&str, &str, &str)] = &[
    // (sigma short name, tactic id, display name)
    ("reconnaissance", "TA0043", "Reconnaissance"),
    ("resource_development", "TA0042", "Resource Development"),
    ("initial_access", "TA0001", "Initial Access"),
    ("execution", "TA0002", "Execution"),
    ("persistence", "TA0003", "Persistence"),
    ("privilege_escalation", "TA0004", "Privilege Escalation"),
    ("defense_evasion", "TA0005", "Defense Evasion"),
    ("credential_access", "TA0006", "Credential Access"),
    ("discovery", "TA0007", "Discovery"),
    ("lateral_movement", "TA0008", "Lateral Movement"),
    ("collection", "TA0009", "Collection"),
    ("command_and_control", "TA0011", "Command and Control"),
    ("exfiltration", "TA0010", "Exfiltration"),
    ("impact", "TA0040", "Impact"),
];

/// Convert Sigma `tags:` into the flat Fibratus `labels:` block.
///
/// The mapping is best-effort and mirrors how the upstream
/// [Fibratus rules library](https://github.com/rabbitstack/fibratus/tree/master/rules)
/// names ATT&CK labels:
///
/// - `attack.<tactic_short_name>` → `tactic.id`, `tactic.name`,
///   `tactic.ref`, looked up from a small static `ATTACK_TACTICS`
///   table (kept private; expand it here if a new MITRE tactic ships).
/// - `attack.t<NNNN>` (base technique) → `technique.id`,
///   `technique.ref`.
/// - `attack.t<NNNN>.<sub>` (sub-technique) → `subtechnique.id`,
///   `subtechnique.ref`. The parent `technique.*` keys are only set
///   if the rule *also* carries the base-technique tag, mirroring
///   the upstream convention that techniques and sub-techniques live
///   in separate namespaces rather than overwriting one another.
/// - Anything else is preserved verbatim as `tag.<original>:
///   <original>` so downstream YAML loaders see a string value, not
///   a typed bool.
///
/// Tag iteration order is the rule's source order; the BTreeMap
/// values are written by key, which gives stable golden-test output.
pub fn labels_from_tags(tags: &[String]) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    for tag in tags {
        let lower = tag.to_lowercase();
        if let Some(rest) = lower.strip_prefix("attack.") {
            if let Some(stripped) = rest.strip_prefix('t')
                && stripped.chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                // ATT&CK technique or sub-technique. The presence of a
                // `.` in the stripped tail distinguishes the two:
                // `t1055`     → technique  `T1055`
                // `t1055.001` → sub-tech.  `T1055.001`
                let upper = format!("T{}", stripped.to_uppercase());
                let url_path = upper.replace('.', "/");
                let ref_url = format!("https://attack.mitre.org/techniques/{url_path}/");
                if upper.contains('.') {
                    labels.insert("subtechnique.id".to_string(), upper);
                    labels.insert("subtechnique.ref".to_string(), ref_url);
                } else {
                    labels.insert("technique.id".to_string(), upper);
                    labels.insert("technique.ref".to_string(), ref_url);
                }
                continue;
            }
            if let Some((_, id, name)) = ATTACK_TACTICS.iter().find(|(s, ..)| *s == rest) {
                labels.insert("tactic.id".to_string(), (*id).to_string());
                labels.insert("tactic.name".to_string(), (*name).to_string());
                labels.insert(
                    "tactic.ref".to_string(),
                    format!("https://attack.mitre.org/tactics/{id}/"),
                );
                continue;
            }
        }
        labels.insert(format!("tag.{tag}"), tag.clone());
    }
    labels
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::{SigmaString, SpecialChar, StringPart};

    fn s(parts: Vec<StringPart>) -> SigmaString {
        let original: String = parts
            .iter()
            .map(|p| match p {
                StringPart::Plain(s) => s.clone(),
                StringPart::Special(SpecialChar::WildcardMulti) => "*".to_string(),
                StringPart::Special(SpecialChar::WildcardSingle) => "?".to_string(),
            })
            .collect();
        SigmaString { parts, original }
    }

    #[test]
    fn quote_sigma_string_escapes_quote_and_backslash() {
        let value = s(vec![StringPart::Plain(r"a\b'c".to_string())]);
        assert_eq!(quote_sigma_string(&value), r"'a\\b\'c'");
    }

    #[test]
    fn quote_sigma_string_preserves_wildcards() {
        let value = s(vec![
            StringPart::Special(SpecialChar::WildcardMulti),
            StringPart::Plain("cmd".to_string()),
            StringPart::Special(SpecialChar::WildcardSingle),
        ]);
        assert_eq!(quote_sigma_string(&value), "'*cmd?'");
    }

    #[test]
    fn quote_sigma_string_keeps_literal_glob_chars() {
        let value = s(vec![StringPart::Plain("a*b?c".to_string())]);
        assert_eq!(quote_sigma_string(&value), "'a*b?c'");
    }

    #[test]
    fn quote_escapes_line_breaks() {
        let value = s(vec![StringPart::Plain("a\nb".to_string())]);
        assert_eq!(quote_sigma_string(&value), r"'a\nb'");
        assert_eq!(quote_plain_str("a\nb"), r"'a\nb'");
    }

    #[test]
    fn quote_plain_str_basic() {
        assert_eq!(quote_plain_str("hello"), "'hello'");
        assert_eq!(quote_plain_str(r"a\b'c"), r"'a\\b\'c'");
    }

    #[test]
    fn has_wildcards_detects_specials() {
        let plain = s(vec![StringPart::Plain("cmd.exe".to_string())]);
        let glob = s(vec![
            StringPart::Plain("cmd".to_string()),
            StringPart::Special(SpecialChar::WildcardMulti),
        ]);
        assert!(!has_wildcards(&plain));
        assert!(has_wildcards(&glob));
    }

    #[test]
    fn field_ident_accepts_fibratus_idents() {
        for name in [
            "ps.exe",
            "thread.callstack.symbols",
            "evt.arg[exe]",
            "ps.ancestor[0].name",
            "file.pe.sections[.debug$].entropy",
            "_private",
        ] {
            assert_eq!(field_ident(name).unwrap(), name);
        }
    }

    #[test]
    fn field_ident_accepts_unmapped_sigma_fields() {
        // The loader reports unknown fields, so an unmapped Sigma-style
        // name still converts.
        assert_eq!(field_ident("Image").unwrap(), "Image");
        assert_eq!(field_ident("Custom.Field").unwrap(), "Custom.Field");
    }

    #[test]
    fn field_ident_rejects_names_outside_identifier_syntax() {
        for name in [
            "ps.name = evil or 1 = 1 or ps.name",
            "ps.name) = true or regex(ps.name",
            "ps.name\naction:",
            "ps.name\raction:",
            "cs-uri-query",
            "1field",
            "evt.arg[exe",
            "evt.arg[]",
            "evt.arg[a b]",
            "",
        ] {
            let err = field_ident(name).expect_err(name);
            assert!(
                err.to_string().contains("invalid Fibratus field name"),
                "{err}"
            );
        }
    }

    #[test]
    fn is_re2_compatible_accepts_basic_patterns() {
        assert!(is_re2_compatible(r"power.*(shell|hell)\.dll"));
        assert!(is_re2_compatible(r"^[A-Z]+$"));
        assert!(is_re2_compatible(r"\d{4}-\d{2}-\d{2}"));
        assert!(is_re2_compatible(r"(?i)cmd\.exe"));
    }

    #[test]
    fn is_re2_compatible_rejects_lookarounds() {
        assert!(!is_re2_compatible(r"foo(?=bar)"));
        assert!(!is_re2_compatible(r"foo(?!bar)"));
        assert!(!is_re2_compatible(r"(?<=foo)bar"));
        assert!(!is_re2_compatible(r"(?<!foo)bar"));
    }

    #[test]
    fn is_re2_compatible_rejects_backreferences() {
        assert!(!is_re2_compatible(r"(\w+) \1"));
        assert!(!is_re2_compatible(r"(?P<name>\w+) (?P=name)"));
    }

    #[test]
    fn labels_from_tags_maps_tactic_technique_and_subtechnique_separately() {
        let tags = vec![
            "attack.defense_evasion".to_string(),
            "attack.t1055".to_string(),
            "attack.t1055.001".to_string(),
        ];
        let labels = labels_from_tags(&tags);

        assert_eq!(labels.get("tactic.id").map(String::as_str), Some("TA0005"));
        assert_eq!(
            labels.get("tactic.name").map(String::as_str),
            Some("Defense Evasion")
        );
        assert_eq!(
            labels.get("tactic.ref").map(String::as_str),
            Some("https://attack.mitre.org/tactics/TA0005/"),
        );

        // Base technique and sub-technique live in separate label
        // namespaces (matching the upstream Fibratus rules library
        // convention) so the sub-technique tag no longer overwrites
        // the parent technique tag.
        assert_eq!(
            labels.get("technique.id").map(String::as_str),
            Some("T1055"),
        );
        assert_eq!(
            labels.get("technique.ref").map(String::as_str),
            Some("https://attack.mitre.org/techniques/T1055/"),
        );
        assert_eq!(
            labels.get("subtechnique.id").map(String::as_str),
            Some("T1055.001"),
        );
        assert_eq!(
            labels.get("subtechnique.ref").map(String::as_str),
            Some("https://attack.mitre.org/techniques/T1055/001/"),
        );
    }

    #[test]
    fn labels_from_tags_subtechnique_only_does_not_synthesize_parent_technique() {
        // A rule that tags only `attack.t1055.001` (no `attack.t1055`)
        // emits `subtechnique.*` only. The backend does not invent a
        // parent-technique label because doing so would diverge from
        // the rule author's stated tags.
        let labels = labels_from_tags(&["attack.t1055.001".to_string()]);
        assert!(!labels.contains_key("technique.id"));
        assert_eq!(
            labels.get("subtechnique.id").map(String::as_str),
            Some("T1055.001"),
        );
        assert_eq!(
            labels.get("subtechnique.ref").map(String::as_str),
            Some("https://attack.mitre.org/techniques/T1055/001/"),
        );
    }

    #[test]
    fn labels_from_tags_base_technique_only_does_not_emit_subtechnique() {
        let labels = labels_from_tags(&["attack.t1055".to_string()]);
        assert_eq!(
            labels.get("technique.id").map(String::as_str),
            Some("T1055"),
        );
        assert!(!labels.contains_key("subtechnique.id"));
    }

    #[test]
    fn labels_from_tags_preserves_unknown_tags() {
        let tags = vec!["cve.2023.1234".to_string(), "custom".to_string()];
        let labels = labels_from_tags(&tags);
        assert_eq!(
            labels.get("tag.cve.2023.1234").map(String::as_str),
            Some("cve.2023.1234")
        );
        assert_eq!(labels.get("tag.custom").map(String::as_str), Some("custom"));
    }
}
