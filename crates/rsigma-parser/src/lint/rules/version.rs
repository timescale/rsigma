//! Lints for the `sigma-version` attribute and its interaction with
//! version-gated syntax (array-matching brackets).

use yaml_serde::Value;

use super::super::{DocType, LintRule, LintWarning, err, key, warning};
use crate::fieldpath::{ends_with_unescaped, first_unescaped};
use crate::version::{
    SPEC_VERSION_ARRAY_MATCHING, SPEC_VERSION_SUPPORTED, major_from_value, resolve_major,
};

/// Lint the `sigma-version` attribute:
///
/// - `unsupported_sigma_version` (error): the declared major is newer than the
///   highest specification major this build implements, so the rule cannot be
///   interpreted correctly and should be skipped or the tool upgraded.
/// - `array_matching_without_version` (warning): the document uses array-matching
///   selector syntax (`field[any]`, `args[0]`, ...) but resolves to a major below
///   the one that enables it, so the brackets are read as literal field-name
///   characters rather than selectors.
pub(crate) fn lint_sigma_version(
    m: &yaml_serde::Mapping,
    doc_type: DocType,
    warnings: &mut Vec<LintWarning>,
) {
    let declared = m.get(key("sigma-version")).and_then(major_from_value);

    if let Some(major) = declared
        && major > SPEC_VERSION_SUPPORTED
    {
        warnings.push(err(
            LintRule::UnsupportedSigmaVersion,
            format!(
                "sigma-version {major} is newer than the supported specification major \
                 {SPEC_VERSION_SUPPORTED}; upgrade the tool or target a supported version"
            ),
            "/sigma-version",
        ));
    }

    if resolve_major(declared) < SPEC_VERSION_ARRAY_MATCHING {
        let section_key = match doc_type {
            DocType::Detection => "detection",
            DocType::Filter => "filter",
            DocType::Correlation => return,
        };
        if let Some(section) = m.get(key(section_key))
            && let Some(offending) = section_has_selector(section)
        {
            warnings.push(warning(
                LintRule::ArrayMatchingWithoutVersion,
                format!(
                    "key '{offending}' uses array-matching selector syntax, but this document \
                     targets specification major {} where brackets are literal field-name \
                     characters; add `sigma-version: {SPEC_VERSION_ARRAY_MATCHING}` to read them \
                     as array selectors, or escape the brackets (`\\[` / `\\]`) to keep them \
                     literal",
                    resolve_major(declared)
                ),
                format!("/{section_key}"),
            ));
        }
    }
}

/// Walk a detection/filter section and return the first field key that carries
/// an array selector, or `None` if there is none.
fn section_has_selector(value: &Value) -> Option<String> {
    match value {
        Value::Mapping(m) => {
            for (k, v) in m {
                if let Some(ks) = k.as_str() {
                    let field_part = ks.split('|').next().unwrap_or(ks);
                    if field_part_has_selector(field_part) {
                        return Some(ks.to_string());
                    }
                }
                if let Some(found) = section_has_selector(v) {
                    return Some(found);
                }
            }
            None
        }
        Value::Sequence(seq) => seq.iter().find_map(section_has_selector),
        _ => None,
    }
}

/// Whether a dotted field path carries an array selector on any segment: a
/// trailing unescaped `[any]`/`[all]`/`[all_or_empty]`/`[none]` quantifier or a
/// `[N]` integer index. Mirrors the parser's selector recognition.
fn field_part_has_selector(field_part: &str) -> bool {
    field_part.split('.').any(segment_has_selector)
}

fn segment_has_selector(seg: &str) -> bool {
    let Some(open) = first_unescaped(seg, b'[') else {
        return false;
    };
    // A selector needs a field name before the bracket and a closing `]`.
    if open == 0 || !ends_with_unescaped(seg, b']') {
        return false;
    }
    let token = &seg[open + 1..seg.len() - 1];
    matches!(token, "any" | "all" | "all_or_empty" | "none") || token.parse::<i64>().is_ok()
}

#[cfg(test)]
mod tests {
    use crate::lint::lint_yaml_str;

    fn rule_ids(yaml: &str) -> Vec<String> {
        lint_yaml_str(yaml)
            .iter()
            .map(|w| w.rule.to_string())
            .collect()
    }

    #[test]
    fn unsupported_major_is_error() {
        let yaml = "title: T\nsigma-version: 99\nlogsource:\n    category: test\ndetection:\n    selection:\n        a: b\n    condition: selection\n";
        assert!(rule_ids(yaml).contains(&"unsupported_sigma_version".to_string()));
    }

    #[test]
    fn supported_major_no_version_findings() {
        let yaml = "title: T\nsigma-version: 3\nlogsource:\n    category: test\ndetection:\n    selection:\n        connections[any]:\n            protocol: TCP\n    condition: selection\n";
        let ids = rule_ids(yaml);
        assert!(!ids.contains(&"unsupported_sigma_version".to_string()));
        assert!(!ids.contains(&"array_matching_without_version".to_string()));
    }

    #[test]
    fn array_selector_without_version_warns() {
        let yaml = "title: T\nlogsource:\n    category: test\ndetection:\n    selection:\n        connections[any]:\n            protocol: TCP\n    condition: selection\n";
        assert!(rule_ids(yaml).contains(&"array_matching_without_version".to_string()));
    }

    #[test]
    fn no_selector_no_warning() {
        let yaml = "title: T\nlogsource:\n    category: test\ndetection:\n    selection:\n        CommandLine: whoami\n    condition: selection\n";
        assert!(!rule_ids(yaml).contains(&"array_matching_without_version".to_string()));
    }

    #[test]
    fn sigma_version_is_a_known_key() {
        let yaml = "title: T\nsigma-version: 3\nlogsource:\n    category: test\ndetection:\n    selection:\n        a: b\n    condition: selection\n";
        assert!(!rule_ids(yaml).contains(&"unknown_key".to_string()));
    }
}
