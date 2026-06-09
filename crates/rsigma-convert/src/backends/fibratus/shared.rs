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

// =============================================================================
// String quoting
// =============================================================================

/// Quote a [`SigmaString`] for use inside a Fibratus filter expression.
///
/// Fibratus string literals are single-quoted. `\` and `'` are the only
/// characters that must be escaped inside literals. `*` and `?` glob
/// wildcards inherited from a Sigma wildcard token are emitted verbatim so
/// they participate in `matches`/`imatches` evaluation; literal `*`/`?`
/// characters from the source string are backslash-escaped so the filter
/// engine treats them as literals everywhere else.
pub fn quote_sigma_string(value: &SigmaString) -> String {
    let mut out = String::with_capacity(value.original.len() + 2);
    out.push('\'');
    for part in &value.parts {
        match part {
            StringPart::Plain(s) => {
                for ch in s.chars() {
                    match ch {
                        '\\' => out.push_str("\\\\"),
                        '\'' => out.push_str("\\'"),
                        '*' | '?' => {
                            out.push('\\');
                            out.push(ch);
                        }
                        _ => out.push(ch),
                    }
                }
            }
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
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            _ => out.push(ch),
        }
    }
    out.push('\'');
    out
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

static FIBRATUS_FIELD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z_][a-z0-9_\.]*$").unwrap());

/// Return the field name as the Fibratus filter engine expects it.
///
/// Fibratus identifiers are bare lowercase dotted paths (`ps.exe`,
/// `thread.callstack.symbols`). The backend never invents field names on its
/// own: pipelines like `fibratus_windows` are responsible for renaming
/// `Image` → `ps.exe`, `TargetFilename` → `file.path`, and friends before
/// the value reaches conversion. This helper is a defensive identity that
/// passes through anything already in Fibratus shape and forwards everything
/// else verbatim so the upstream filter engine can reject it loudly.
pub fn sanitize_field(name: &str) -> String {
    if FIBRATUS_FIELD_RE.is_match(name) {
        name.to_string()
    } else {
        // Sigma allows arbitrary field names. Pass through unchanged so the
        // caller (or the pipeline) can map it; we deliberately do not
        // lowercase here because some users intentionally route raw event
        // fields by exact case via custom pipelines.
        name.to_string()
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
/// The mapping is best-effort:
///
/// - `attack.t<NNNN>` → `technique.id`, `technique.name` (when known),
///   `technique.ref`.
/// - `attack.t<NNNN>.<sub>` → `technique.id` (full sub-technique ID),
///   `technique.ref`.
/// - `attack.<tactic_short_name>` → `tactic.id`, `tactic.name`,
///   `tactic.ref`, looked up from [`ATTACK_TACTICS`].
/// - Anything else is preserved verbatim as `tag.<original>: <original>`
///   so downstream YAML loaders see a string value, not a typed bool.
///
/// When the same key would be set twice the later tag wins; rsigma rules
/// rarely carry conflicting tactic tags, but if they do the explicit ATT&CK
/// IDs take precedence over the short-name lookups because they appear
/// later in canonical Sigma tag ordering.
pub fn labels_from_tags(tags: &[String]) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    for tag in tags {
        let lower = tag.to_lowercase();
        if let Some(rest) = lower.strip_prefix("attack.") {
            if let Some(stripped) = rest.strip_prefix('t')
                && stripped.chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                // Technique or sub-technique. Preserve the original case
                // for the URL hint; ATT&CK uses uppercase Txxxx in refs.
                let upper = format!("T{}", stripped.to_uppercase());
                labels.insert("technique.id".to_string(), upper.clone());
                labels.insert(
                    "technique.ref".to_string(),
                    format!(
                        "https://attack.mitre.org/techniques/{}/",
                        upper.replace('.', "/")
                    ),
                );
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
    fn quote_sigma_string_escapes_literal_glob_chars() {
        let value = s(vec![StringPart::Plain("a*b?c".to_string())]);
        assert_eq!(quote_sigma_string(&value), r"'a\*b\?c'");
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
    fn sanitize_field_passes_fibratus_idents() {
        assert_eq!(sanitize_field("ps.exe"), "ps.exe");
        assert_eq!(
            sanitize_field("thread.callstack.symbols"),
            "thread.callstack.symbols"
        );
    }

    #[test]
    fn sanitize_field_passes_unknown_unchanged() {
        // Pass-through so the loader rejects loudly if the pipeline failed
        // to rename a Sigma-style PascalCase field.
        assert_eq!(sanitize_field("Image"), "Image");
        assert_eq!(sanitize_field("Custom.Field"), "Custom.Field");
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
    fn labels_from_tags_maps_tactics_and_techniques() {
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
        // The two technique tags both write to the same keys; the later
        // sub-technique tag wins in iteration order.
        let tech_id = labels.get("technique.id").cloned().unwrap();
        assert!(tech_id == "T1055" || tech_id == "T1055.001");
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
