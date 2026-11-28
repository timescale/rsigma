use std::collections::HashSet;

use yaml_serde::Value;

use super::super::{
    FixPatch, LintRule, LintWarning, err, get_mapping, get_seq, get_str, key, safe_fix, warning,
};
use crate::condition::parse_condition;
use crate::lint::pointer_segment;
use crate::parser::parse_field_spec;
use crate::validate::{check_modifiers, unresolved_references};

/// Valid related types.
const VALID_RELATED_TYPES: &[&str] = &[
    "correlation",
    "derived",
    "obsolete",
    "merged",
    "renamed",
    "similar",
];

/// Known tag namespaces from the spec.
const KNOWN_TAG_NAMESPACES: &[&str] =
    &["attack", "car", "cve", "d3fend", "detection", "stp", "tlp"];

/// Tag pattern: `^[a-z0-9_-]+\.[a-z0-9._-]+$`
fn is_valid_tag(s: &str) -> bool {
    let parts: Vec<&str> = s.splitn(2, '.').collect();
    if parts.len() != 2 {
        return false;
    }
    let ns_ok = !parts[0].is_empty()
        && parts[0]
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    let rest_ok = !parts[1].is_empty()
        && parts[1].chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-'
        });
    ns_ok && rest_ok
}

/// Check if a logsource value is lowercase with valid chars.
fn is_valid_logsource_value(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.' || c == '-'
        })
}

pub(crate) fn lint_detection_rule(
    m: &yaml_serde::Mapping,
    warnings: &mut Vec<LintWarning>,
    extra_namespaces: &[String],
) {
    // ── level ─────────────────────────────────────────────────────────────
    if !m.contains_key(key("level")) {
        warnings.push(warning(
            LintRule::MissingLevel,
            "missing recommended field 'level'",
            "/level",
        ));
    }

    // ── logsource ────────────────────────────────────────────────────────
    if !m.contains_key(key("logsource")) {
        warnings.push(err(
            LintRule::MissingLogsource,
            "missing required field 'logsource'",
            "/logsource",
        ));
    } else {
        lint_logsource(m, warnings);
    }

    // ── detection ────────────────────────────────────────────────────────
    if let Some(det_val) = m.get(key("detection")) {
        if let Some(det) = det_val.as_mapping() {
            let det_keys: HashSet<&str> = det
                .keys()
                .filter_map(|k| k.as_str())
                .filter(|k| *k != "condition" && *k != "timeframe")
                .collect();

            if det.contains_key(key("timeframe")) {
                warnings.push(warning(
                    LintRule::DeprecatedDetectionTimeframe,
                    "'timeframe' inside detection is deprecated Sigma v1.x syntax and has no \
                     effect; use a correlation rule with a timespan instead",
                    "/detection/timeframe",
                ));
            }

            if !det.contains_key(key("condition")) {
                warnings.push(err(
                    LintRule::MissingCondition,
                    "detection section is missing required 'condition'",
                    "/detection/condition",
                ));
            } else if let Some(cond_str) = get_str(det, "condition") {
                if has_deprecated_aggregation(cond_str) {
                    warnings.push(warning(
                        LintRule::DeprecatedAggregationSyntax,
                        "condition uses deprecated Sigma v1.x aggregation syntax \
                         (| count/min/max/avg/sum/near); use a correlation rule instead",
                        "/detection/condition",
                    ));
                } else {
                    match parse_condition(cond_str) {
                        Ok(expr) => {
                            let names: Vec<&str> = det_keys.iter().copied().collect();
                            for unresolved in unresolved_references(&expr, &names) {
                                warnings.push(err(
                                    LintRule::ConditionReferencesUnknown,
                                    unresolved.to_string(),
                                    "/detection/condition",
                                ));
                            }
                        }
                        Err(e) => warnings.push(err(
                            LintRule::InvalidCondition,
                            e.to_string(),
                            "/detection/condition",
                        )),
                    }
                }
            }

            if det_keys.is_empty() {
                warnings.push(warning(
                    LintRule::EmptyDetection,
                    "detection section has no named search identifiers",
                    "/detection",
                ));
            }

            lint_detection_logic(det, warnings);
        }
    } else {
        warnings.push(err(
            LintRule::MissingDetection,
            "missing required field 'detection'",
            "/detection",
        ));
    }

    // ── related ──────────────────────────────────────────────────────────
    if let Some(related) = get_seq(m, "related") {
        for (i, item) in related.iter().enumerate() {
            let path_prefix = format!("/related/{i}");
            if let Some(item_map) = item.as_mapping() {
                let has_id = item_map.contains_key(key("id"));
                let has_type = item_map.contains_key(key("type"));

                if !has_id || !has_type {
                    warnings.push(err(
                        LintRule::RelatedMissingRequired,
                        "related entry must have both 'id' and 'type'",
                        &path_prefix,
                    ));
                }

                if let Some(id) = get_str(item_map, "id")
                    && !super::metadata::is_valid_uuid(id)
                {
                    warnings.push(warning(
                        LintRule::InvalidRelatedId,
                        format!("related id \"{id}\" is not a valid UUID"),
                        format!("{path_prefix}/id"),
                    ));
                }

                if let Some(type_val) = get_str(item_map, "type")
                    && !VALID_RELATED_TYPES.contains(&type_val)
                {
                    warnings.push(err(
                        LintRule::InvalidRelatedType,
                        format!(
                            "invalid related type \"{type_val}\", expected one of: {}",
                            VALID_RELATED_TYPES.join(", ")
                        ),
                        format!("{path_prefix}/type"),
                    ));
                }
            }
        }
    }

    // ── deprecated + related consistency ─────────────────────────────────
    if get_str(m, "status") == Some("deprecated") {
        let has_related = get_seq(m, "related")
            .map(|seq| !seq.is_empty())
            .unwrap_or(false);
        if !has_related {
            warnings.push(warning(
                LintRule::DeprecatedWithoutRelated,
                "deprecated rule should have a 'related' entry linking to its replacement",
                "/status",
            ));
        }
    }

    // ── tags ─────────────────────────────────────────────────────────────
    if let Some(tags) = get_seq(m, "tags") {
        let mut seen_tags: HashSet<String> = HashSet::new();
        for (i, tag_val) in tags.iter().enumerate() {
            if let Some(tag) = tag_val.as_str() {
                if !is_valid_tag(tag) {
                    warnings.push(warning(
                        LintRule::InvalidTag,
                        format!(
                            "tag \"{tag}\" does not match required pattern (lowercase, dotted namespace)"
                        ),
                        format!("/tags/{i}"),
                    ));
                } else if let Some(ns) = tag.split('.').next()
                    && !KNOWN_TAG_NAMESPACES.contains(&ns)
                    && !extra_namespaces.iter().any(|n| n.as_str() == ns)
                {
                    let mut seen = std::collections::HashSet::new();
                    let known_list: Vec<&str> = KNOWN_TAG_NAMESPACES
                        .iter()
                        .copied()
                        .chain(extra_namespaces.iter().map(String::as_str))
                        .filter(|n| seen.insert(*n))
                        .collect();
                    warnings.push(warning(
                        LintRule::UnknownTagNamespace,
                        format!(
                            "unknown tag namespace \"{ns}\", known namespaces: {}",
                            known_list.join(", ")
                        ),
                        format!("/tags/{i}"),
                    ));
                }

                if !seen_tags.insert(tag.to_string()) {
                    let mut w = warning(
                        LintRule::DuplicateTags,
                        format!("duplicate tag \"{tag}\""),
                        format!("/tags/{i}"),
                    );
                    w.fix = safe_fix(
                        format!("remove duplicate tag '{tag}'"),
                        vec![FixPatch::Remove {
                            path: format!("/tags/{i}"),
                        }],
                    );
                    warnings.push(w);
                }
            }
        }
    }

    // ── references (unique) ──────────────────────────────────────────────
    if let Some(refs) = get_seq(m, "references") {
        let mut seen: HashSet<String> = HashSet::new();
        for (i, r) in refs.iter().enumerate() {
            if let Some(s) = r.as_str()
                && !seen.insert(s.to_string())
            {
                let mut w = warning(
                    LintRule::DuplicateReferences,
                    format!("duplicate reference \"{s}\""),
                    format!("/references/{i}"),
                );
                w.fix = safe_fix(
                    "remove duplicate reference",
                    vec![FixPatch::Remove {
                        path: format!("/references/{i}"),
                    }],
                );
                warnings.push(w);
            }
        }
    }

    // ── fields (unique) ──────────────────────────────────────────────────
    if let Some(fields) = get_seq(m, "fields") {
        let mut seen: HashSet<String> = HashSet::new();
        for (i, f) in fields.iter().enumerate() {
            if let Some(s) = f.as_str()
                && !seen.insert(s.to_string())
            {
                let mut w = warning(
                    LintRule::DuplicateFields,
                    format!("duplicate field \"{s}\""),
                    format!("/fields/{i}"),
                );
                w.fix = safe_fix(
                    "remove duplicate field",
                    vec![FixPatch::Remove {
                        path: format!("/fields/{i}"),
                    }],
                );
                warnings.push(w);
            }
        }
    }

    // ── falsepositives (minLength 2) ─────────────────────────────────────
    if let Some(fps) = get_seq(m, "falsepositives") {
        for (i, fp) in fps.iter().enumerate() {
            if let Some(s) = fp.as_str()
                && s.len() < 2
            {
                warnings.push(warning(
                    LintRule::FalsepositiveTooShort,
                    format!("falsepositive entry \"{s}\" must be at least 2 characters"),
                    format!("/falsepositives/{i}"),
                ));
            }
        }
    }

    // ── scope (minLength 2) ──────────────────────────────────────────────
    if let Some(scope) = get_seq(m, "scope") {
        for (i, s_val) in scope.iter().enumerate() {
            if let Some(s) = s_val.as_str()
                && s.len() < 2
            {
                warnings.push(warning(
                    LintRule::ScopeTooShort,
                    format!("scope entry \"{s}\" must be at least 2 characters"),
                    format!("/scope/{i}"),
                ));
            }
        }
    }
}

pub(crate) fn lint_logsource(m: &yaml_serde::Mapping, warnings: &mut Vec<LintWarning>) {
    if let Some(ls) = get_mapping(m, "logsource") {
        for field in &["category", "product", "service"] {
            if let Some(val) = get_str(ls, field)
                && !is_valid_logsource_value(val)
            {
                let lower = val.to_ascii_lowercase();
                let mut w = warning(
                    LintRule::LogsourceValueNotLowercase,
                    format!("logsource {field} \"{val}\" should be lowercase (a-z, 0-9, _, ., -)"),
                    format!("/logsource/{field}"),
                );
                w.fix = safe_fix(
                    format!("lowercase '{val}' to '{lower}'"),
                    vec![FixPatch::ReplaceValue {
                        path: format!("/logsource/{field}"),
                        new_value: lower,
                    }],
                );
                warnings.push(w);
            }
        }
    }
}

/// Detect deprecated Sigma v1.x pipe-aggregation syntax in a condition string.
fn has_deprecated_aggregation(condition: &str) -> bool {
    let pipe_pos = match condition.find('|') {
        Some(p) => p,
        None => return false,
    };
    let after_pipe = condition[pipe_pos + 1..].trim_start();
    let agg_keyword = after_pipe
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .next()
        .unwrap_or("");
    matches!(
        agg_keyword,
        "count" | "min" | "max" | "avg" | "sum" | "near"
    )
}

/// Checks detection logic: null in value lists, single-value |all, empty value lists.
fn lint_detection_logic(det: &yaml_serde::Mapping, warnings: &mut Vec<LintWarning>) {
    for (det_key, det_val) in det {
        let det_key_str = det_key.as_str().unwrap_or("");
        if det_key_str == "condition" || det_key_str == "timeframe" {
            continue;
        }

        lint_detection_value(det_val, det_key_str, warnings);
    }
}

/// The JSON-pointer path of one field key in one named detection, for a fix.
fn fix_path(det_name: &str, field_key: &str) -> String {
    format!(
        "/detection/{}/{}",
        pointer_segment(det_name),
        pointer_segment(field_key)
    )
}

fn lint_detection_value(value: &Value, det_name: &str, warnings: &mut Vec<LintWarning>) {
    match value {
        Value::Mapping(m) => {
            check_flattened_array_correlation(m, det_name, warnings);
            for (field_key, field_val) in m {
                let field_key_str = field_key.as_str().unwrap_or("");

                if field_key_str.contains("|all") && field_key_str.contains("|re") {
                    let new_key = field_key_str.replace("|all", "");
                    let mut w = warning(
                        LintRule::AllWithRe,
                        format!(
                            "'{field_key_str}' in '{det_name}' combines |all with |re; \
                             regex alternation (|) already handles multi-match — \
                             |all is redundant or misleading here"
                        ),
                        format!("/detection/{det_name}/{field_key_str}"),
                    );
                    w.fix = safe_fix(
                        format!("remove |all from '{field_key_str}'"),
                        vec![FixPatch::ReplaceKey {
                            path: fix_path(det_name, field_key_str),
                            new_key,
                        }],
                    );
                    warnings.push(w);
                }

                if field_key_str.contains("|all") {
                    let needs_fix = if let Value::Sequence(seq) = field_val {
                        seq.len() <= 1
                    } else {
                        true
                    };
                    if needs_fix {
                        let new_key = field_key_str.replace("|all", "");
                        let count = if let Value::Sequence(seq) = field_val {
                            seq.len().to_string()
                        } else {
                            "a single".into()
                        };
                        let mut w = warning(
                            LintRule::SingleValueAllModifier,
                            format!(
                                "'{field_key_str}' in '{det_name}' uses |all modifier with {count} value(s); |all requires multiple values"
                            ),
                            format!("/detection/{det_name}/{field_key_str}"),
                        );
                        w.fix = safe_fix(
                            format!("remove |all from '{field_key_str}'"),
                            vec![FixPatch::ReplaceKey {
                                path: fix_path(det_name, field_key_str),
                                new_key,
                            }],
                        );
                        warnings.push(w);
                    }
                }

                if let Some(msg) = check_modifier_compatibility(field_key_str) {
                    warnings.push(err(
                        LintRule::IncompatibleModifiers,
                        format!("'{field_key_str}' in '{det_name}': {msg}"),
                        format!("/detection/{det_name}/{field_key_str}"),
                    ));
                }

                if let Value::Sequence(seq) = field_val {
                    if seq.is_empty() {
                        warnings.push(warning(
                            LintRule::EmptyValueList,
                            format!("'{field_key_str}' in '{det_name}' has an empty value list"),
                            format!("/detection/{det_name}/{field_key_str}"),
                        ));
                    } else {
                        let has_null = seq.iter().any(|v| v.is_null());
                        let has_non_null = seq.iter().any(|v| !v.is_null());
                        if has_null && has_non_null {
                            warnings.push(warning(
                                LintRule::NullInValueList,
                                format!(
                                    "'{field_key_str}' in '{det_name}' mixes null with other values; null should be in its own selection"
                                ),
                                format!("/detection/{det_name}/{field_key_str}"),
                            ));
                        }
                    }
                }

                let base_field = field_key_str.split('|').next().unwrap_or(field_key_str);
                let is_wildcard_only = match field_val {
                    Value::String(s) => s == "*",
                    Value::Sequence(seq) => seq.len() == 1 && seq[0].as_str() == Some("*"),
                    _ => false,
                };
                if is_wildcard_only && !field_key_str.contains("|re") {
                    let new_key = format!("{base_field}|exists");
                    let mut w = warning(
                        LintRule::WildcardOnlyValue,
                        format!(
                            "'{field_key_str}' in '{det_name}' uses a lone wildcard '*'; \
                             consider '{base_field}|exists: true' instead"
                        ),
                        format!("/detection/{det_name}/{field_key_str}"),
                    );
                    w.fix = safe_fix(
                        format!("replace with '{new_key}: true'"),
                        vec![
                            FixPatch::ReplaceKey {
                                path: fix_path(det_name, field_key_str),
                                new_key,
                            },
                            FixPatch::ReplaceBool {
                                path: fix_path(det_name, &format!("{base_field}|exists")),
                                new_value: true,
                            },
                        ],
                    );
                    warnings.push(w);
                }
            }
        }
        Value::Sequence(seq) => {
            for item in seq {
                if item.is_mapping() {
                    lint_detection_value(item, det_name, warnings);
                }
            }
        }
        _ => {}
    }
}

/// Warn on the declined flattened array-correlation form: two or more sibling
/// keys that share a quantified array prefix (e.g. `connections[any].protocol`
/// and `connections[any].ip`).
///
/// These keys do NOT bind to the same array element, which is almost always
/// what the author intends. The portable, same-element construct is an
/// object-scope block (`connections[any]:` with the fields nested under it).
fn check_flattened_array_correlation(
    m: &yaml_serde::Mapping,
    det_name: &str,
    warnings: &mut Vec<LintWarning>,
) {
    use std::collections::BTreeMap;

    let mut by_prefix: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for field_key in m.keys() {
        let field_key_str = field_key.as_str().unwrap_or("");
        let field_part = field_key_str.split('|').next().unwrap_or(field_key_str);
        if let Some(prefix) = flattened_array_prefix(field_part) {
            by_prefix
                .entry(prefix)
                .or_default()
                .push(field_key_str.to_string());
        }
    }

    for (prefix, keys) in &by_prefix {
        if keys.len() > 1 {
            warnings.push(warning(
                LintRule::FlattenedArrayCorrelation,
                format!(
                    "keys {keys:?} in '{det_name}' share the array prefix '{prefix}' but each \
                     opens an independent scope, so they do not correlate on the same array \
                     element; rewrite as an object-scope block (`{prefix}:` with the fields \
                     nested under it) to require one element to satisfy all of them"
                ),
                format!("/detection/{det_name}"),
            ));
        }
    }
}

/// Return the path up to and including the first array-quantified segment, but
/// only when at least one more path segment follows it (the flattened
/// correlation shape). Returns `None` for plain fields, trailing quantifiers
/// (`tags[all]`), and single-predicate shorthands.
fn flattened_array_prefix(field_part: &str) -> Option<String> {
    let segments: Vec<&str> = field_part.split('.').collect();
    for (i, seg) in segments.iter().enumerate() {
        if (seg.ends_with("[any]") || seg.ends_with("[all]")) && i + 1 < segments.len() {
            return Some(segments[..=i].join("."));
        }
    }
    None
}

/// The modifier conflict the parser rejects for a detection key, if any. A
/// chain the parser cannot read (an unknown or repeated modifier, or `not`) is
/// left to the parser's own error.
fn check_modifier_compatibility(field_key: &str) -> Option<String> {
    let spec = parse_field_spec(field_key).ok()?;
    check_modifiers(&spec.modifiers).err()
}

#[cfg(test)]
mod tests {
    use super::super::super::{Fix, FixPatch, LintRule, LintWarning, Severity, lint_yaml_value};
    use super::*;

    fn yaml_value(yaml: &str) -> yaml_serde::Value {
        yaml_serde::from_str(yaml).unwrap()
    }

    fn lint(yaml: &str) -> Vec<LintWarning> {
        lint_yaml_value(&yaml_value(yaml))
    }

    fn has_rule(warnings: &[LintWarning], rule: LintRule) -> bool {
        warnings.iter().any(|w| w.rule == rule)
    }

    fn has_no_rule(warnings: &[LintWarning], rule: LintRule) -> bool {
        !has_rule(warnings, rule)
    }

    fn find_fix(warnings: &[LintWarning], rule: LintRule) -> Option<&Fix> {
        warnings
            .iter()
            .find(|w| w.rule == rule)
            .and_then(|w| w.fix.as_ref())
    }

    fn fix_summary(fix: &Fix) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        writeln!(s, "title: {}", fix.title).unwrap();
        writeln!(s, "disposition: {:?}", fix.disposition).unwrap();
        for (i, p) in fix.patches.iter().enumerate() {
            match p {
                FixPatch::ReplaceValue { path, new_value } => {
                    writeln!(s, "patch[{i}]: ReplaceValue {path} -> {new_value}").unwrap();
                }
                FixPatch::ReplaceBool { path, new_value } => {
                    writeln!(s, "patch[{i}]: ReplaceBool {path} -> {new_value}").unwrap();
                }
                FixPatch::ReplaceKey { path, new_key } => {
                    writeln!(s, "patch[{i}]: ReplaceKey {path} -> {new_key}").unwrap();
                }
                FixPatch::Remove { path } => {
                    writeln!(s, "patch[{i}]: Remove {path}").unwrap();
                }
            }
        }
        s
    }

    #[test]
    fn missing_logsource() {
        let w = lint(
            r#"
title: Test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::MissingLogsource));
    }

    #[test]
    fn missing_detection() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
"#,
        );
        assert!(has_rule(&w, LintRule::MissingDetection));
    }

    #[test]
    fn missing_condition() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
"#,
        );
        assert!(has_rule(&w, LintRule::MissingCondition));
    }

    #[test]
    fn empty_detection() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::EmptyDetection));
    }

    #[test]
    fn invalid_related_type() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
related:
    - id: 929a690e-bef0-4204-a928-ef5e620d6fcc
      type: invalid_type
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidRelatedType));
    }

    #[test]
    fn related_missing_required_fields() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
related:
    - id: 929a690e-bef0-4204-a928-ef5e620d6fcc
"#,
        );
        assert!(has_rule(&w, LintRule::RelatedMissingRequired));
    }

    #[test]
    fn deprecated_without_related() {
        let w = lint(
            r#"
title: Test
status: deprecated
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::DeprecatedWithoutRelated));
    }

    #[test]
    fn invalid_tag_pattern() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
tags:
    - 'Invalid Tag'
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidTag));
    }

    #[test]
    fn unknown_tag_namespace() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
tags:
    - custom.something
"#,
        );
        assert!(has_rule(&w, LintRule::UnknownTagNamespace));
    }

    #[test]
    fn duplicate_tags() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
tags:
    - attack.execution
    - attack.execution
"#,
        );
        assert!(has_rule(&w, LintRule::DuplicateTags));
    }

    #[test]
    fn logsource_not_lowercase() {
        let w = lint(
            r#"
title: Test
logsource:
    category: Process_Creation
    product: Windows
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::LogsourceValueNotLowercase));
    }

    #[test]
    fn missing_level() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::MissingLevel));
    }

    #[test]
    fn valid_level_no_missing_warning() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::MissingLevel));
    }

    #[test]
    fn single_value_all_modifier() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|contains|all: 'single'
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::SingleValueAllModifier));
    }

    #[test]
    fn flattened_array_correlation_warns() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        connections[any].protocol: 'TCP'
        connections[any].ip: '1.2.3.1'
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::FlattenedArrayCorrelation));
    }

    #[test]
    fn single_array_shorthand_is_not_flagged() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        connections[any].ip: '1.2.3.1'
        EventName: 'x'
    condition: selection
"#,
        );
        assert!(has_no_rule(&w, LintRule::FlattenedArrayCorrelation));
    }

    #[test]
    fn object_scope_block_is_not_flagged() {
        // The block form nests fields under the quantified key, so they are not
        // sibling keys and must not trigger the flattened-correlation warning.
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        connections[any]:
            protocol: 'TCP'
            ip: '1.2.3.1'
    condition: selection
"#,
        );
        assert!(has_no_rule(&w, LintRule::FlattenedArrayCorrelation));
    }

    #[test]
    fn null_in_value_list() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        FieldA:
            - 'value1'
            - null
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::NullInValueList));
    }

    #[test]
    fn condition_references_unknown() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: sel_main
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::ConditionReferencesUnknown));
    }

    #[test]
    fn condition_references_valid() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::ConditionReferencesUnknown));
    }

    #[test]
    fn condition_references_complex_valid() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    sel_main:
        field: value
    filter_fp:
        User: admin
    condition: sel_main and not filter_fp
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::ConditionReferencesUnknown));
    }

    #[test]
    fn condition_reports_every_unknown_identifier() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection and not (filter_a or filter_b)
level: medium
"#,
        );
        let messages: Vec<&str> = w
            .iter()
            .filter(|w| w.rule == LintRule::ConditionReferencesUnknown)
            .map(|w| w.message.as_str())
            .collect();
        assert_eq!(
            messages,
            [
                "condition references unknown detection identifier 'filter_a'",
                "condition references unknown detection identifier 'filter_b'",
            ]
        );
    }

    #[test]
    fn condition_selector_matching_nothing_is_unknown() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection and not 1 of filter_*
level: medium
"#,
        );
        let finding = w
            .iter()
            .find(|w| w.rule == LintRule::ConditionReferencesUnknown)
            .expect("unmatched selector is flagged");
        assert_eq!(
            finding.message,
            "selector '1 of filter_*' matches no detection identifier"
        );
        assert_eq!(finding.severity, Severity::Error);
    }

    #[test]
    fn condition_selector_matching_a_detection_is_valid() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection_a:
        field: value
    selection_b:
        other: value
    condition: 1 of selection_* or all of them
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::ConditionReferencesUnknown));
    }

    #[test]
    fn unparsable_condition_is_invalid() {
        for condition in [
            "0 of missing_*",
            "selection andd filter",
            "selection and (filter",
        ] {
            let w = lint(&format!(
                "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        field: value\n    condition: {condition}\nlevel: medium\n"
            ));
            let finding = w
                .iter()
                .find(|w| w.rule == LintRule::InvalidCondition)
                .unwrap_or_else(|| panic!("'{condition}' is flagged"));
            assert_eq!(finding.severity, Severity::Error);
            assert_eq!(finding.path, "/detection/condition");
            let parser_error = parse_condition(condition).unwrap_err().to_string();
            assert_eq!(finding.message, parser_error);
            assert!(
                has_no_rule(&w, LintRule::ConditionReferencesUnknown),
                "{condition}"
            );
        }
    }

    #[test]
    fn valid_condition_is_not_invalid() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    filter:
        other: value
    condition: selection and not filter
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::InvalidCondition));
    }

    #[test]
    fn empty_value_list() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: []
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::EmptyValueList));
    }

    #[test]
    fn all_with_re_warning() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|all|re:
            - '(?i)whoami'
            - '(?i)net user'
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::AllWithRe));
    }

    #[test]
    fn all_without_re_no_all_with_re() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|contains|all:
            - 'whoami'
            - 'net user'
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::AllWithRe));
    }

    #[test]
    fn re_without_all_no_all_with_re() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine|re: '(?i)whoami|net user'
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::AllWithRe));
    }

    #[test]
    fn incompatible_contains_startswith() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|contains|startswith: 'test'
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::IncompatibleModifiers));
    }

    #[test]
    fn incompatible_endswith_startswith() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|endswith|startswith: 'test'
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::IncompatibleModifiers));
    }

    #[test]
    fn incompatible_contains_endswith() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|contains|endswith: 'test'
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::IncompatibleModifiers));
    }

    #[test]
    fn incompatible_re_with_contains() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|re|contains: '.*test.*'
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::IncompatibleModifiers));
    }

    #[test]
    fn incompatible_cidr_with_startswith() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|cidr|startswith: '192.168.0.0/16'
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::IncompatibleModifiers));
    }

    #[test]
    fn incompatible_exists_with_contains() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|exists|contains: true
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::IncompatibleModifiers));
    }

    #[test]
    fn incompatible_gt_with_contains() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|gt|contains: 100
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::IncompatibleModifiers));
    }

    #[test]
    fn fieldref_contains_is_compatible() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|fieldref|contains: Other
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::IncompatibleModifiers));
    }

    #[test]
    fn fieldref_neq_is_compatible() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|fieldref|neq: Other
        CommandLine|contains|neq: 'test'
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::IncompatibleModifiers));
    }

    #[test]
    fn contains_before_fieldref_is_incompatible() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|contains|fieldref: Other
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::IncompatibleModifiers));
    }

    #[test]
    fn fieldref_with_re_is_incompatible() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|fieldref|re: Other
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::IncompatibleModifiers));
    }

    #[test]
    fn incompatible_regex_flags_without_re() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|i|m: 'test'
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::IncompatibleModifiers));
    }

    #[test]
    fn compatible_re_with_regex_flags() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|re|i|m|s: '(?i)test'
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::IncompatibleModifiers));
    }

    #[test]
    fn compatible_contains_all() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|contains|all:
            - 'val1'
            - 'val2'
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::IncompatibleModifiers));
    }

    #[test]
    fn compatible_base64offset_contains() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|base64offset|contains: 'test'
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::IncompatibleModifiers));
    }

    #[test]
    fn compatible_wide_base64() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Field|wide|base64: 'test'
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::IncompatibleModifiers));
    }

    fn field_rule(key: &str, value: &str) -> String {
        format!(
            "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        {key}: {value}\n    condition: selection\nlevel: medium\n"
        )
    }

    fn lint_field(key: &str, value: &str) -> Vec<LintWarning> {
        lint(&field_rule(key, value))
    }

    fn incompatible_message(key: &str, value: &str) -> Option<String> {
        lint_field(key, value)
            .into_iter()
            .find(|w| w.rule == LintRule::IncompatibleModifiers)
            .map(|w| w.message)
    }

    #[test]
    fn incompatible_modifiers_is_an_error() {
        let w = lint_field("Field|contains|startswith", "'test'");
        let finding = w
            .iter()
            .find(|w| w.rule == LintRule::IncompatibleModifiers)
            .expect("conflicting operators are flagged");
        assert_eq!(finding.severity, Severity::Error);
        assert_eq!(
            finding.message,
            "'Field|contains|startswith' in 'selection': at most one operator may be set per field; got |contains, |startswith"
        );
    }

    #[test]
    fn two_utf16_encodings_are_incompatible() {
        let msg = incompatible_message("Field|wide|utf16be|base64", "'test'")
            .expect("two encodings are flagged");
        assert!(msg.contains("mutually exclusive UTF-16 encodings"), "{msg}");
    }

    #[test]
    fn base64_with_base64offset_is_incompatible() {
        let msg = incompatible_message("Field|base64|base64offset|contains", "'test'")
            .expect("two base64 strategies are flagged");
        assert!(
            msg.contains("mutually exclusive base64 strategies"),
            "{msg}"
        );
    }

    #[test]
    fn transform_with_non_string_operator_is_incompatible() {
        let msg = incompatible_message("Field|base64|re", "'test'")
            .expect("transform with a regex is flagged");
        assert!(msg.contains("value transformations |base64"), "{msg}");
    }

    #[test]
    fn regex_flag_before_re_is_incompatible() {
        let msg =
            incompatible_message("Field|i|re", "'test'").expect("a flag before re is flagged");
        assert!(msg.contains("must follow |re"), "{msg}");
    }

    #[test]
    fn exists_with_cased_is_incompatible() {
        assert!(incompatible_message("Field|exists|cased", "true").is_some());
    }

    #[test]
    fn unreadable_modifier_chain_is_not_reported_as_incompatible() {
        assert!(incompatible_message("Field|contains|bogus|startswith", "'test'").is_none());
        assert!(incompatible_message("Field|contains|contains", "'test'").is_none());
    }

    /// Lint flags a modifier chain exactly when the parser rejects it.
    #[test]
    fn incompatible_modifiers_matches_parser() {
        let cases = [
            ("Field|contains|all", "['a', 'b']"),
            ("Field|contains|startswith", "'test'"),
            ("Field|re|i|m|s", "'test'"),
            ("Field|i|re", "'test'"),
            ("Field|m", "'test'"),
            ("Field|cidr", "'10.0.0.0/8'"),
            ("Field|cidr|contains", "'10.0.0.0/8'"),
            ("Field|gt", "100"),
            ("Field|gt|lt", "100"),
            ("Field|exists", "true"),
            ("Field|exists|cased", "true"),
            ("Field|fieldref", "Other"),
            ("Field|fieldref|endswith", "Other"),
            ("Field|endswith|fieldref", "Other"),
            ("Field|fieldref|re", "Other"),
            ("Field|wide|base64offset|contains", "'test'"),
            ("Field|utf16le|utf16be|base64", "'test'"),
            ("Field|base64|base64offset", "'test'"),
            ("Field|windash|contains", "'-test'"),
            ("Field|windash|cidr", "'10.0.0.0/8'"),
            ("Field|expand", "'%var%'"),
            ("Field|expand|gt", "100"),
            ("Field|cased|contains", "'test'"),
            ("Field|cased|re", "'test'"),
            ("Field|hour", "10"),
            ("Field|hour|cased", "10"),
        ];
        for (key, value) in cases {
            let yaml = field_rule(key, value);
            let parser_rejects = crate::parse_sigma_yaml(&yaml)
                .map(|c| c.has_errors())
                .unwrap_or(true);
            let lint_rejects = has_rule(&lint(&yaml), LintRule::IncompatibleModifiers);
            assert_eq!(lint_rejects, parser_rejects, "{key}: {value}");
        }
    }

    #[test]
    fn wildcard_only_value_string() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        TargetFilename: '*'
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::WildcardOnlyValue));
    }

    #[test]
    fn wildcard_only_value_list() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        TargetFilename:
            - '*'
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::WildcardOnlyValue));
    }

    #[test]
    fn wildcard_with_other_values_no_warning() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        TargetFilename:
            - '*temp*'
            - '*cache*'
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::WildcardOnlyValue));
    }

    #[test]
    fn wildcard_regex_no_warning() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        TargetFilename|re: '*'
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::WildcardOnlyValue));
    }

    #[test]
    fn deprecated_aggregation_count() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        EventID: 4625
    condition: selection | count(TargetUserName) by IpAddress > 5
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::DeprecatedAggregationSyntax));
        assert!(has_no_rule(&w, LintRule::ConditionReferencesUnknown));
        let dag = w
            .iter()
            .find(|w| w.rule == LintRule::DeprecatedAggregationSyntax)
            .unwrap();
        assert_eq!(dag.severity, Severity::Warning);
    }

    #[test]
    fn deprecated_aggregation_near() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection | near(field) by host
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::DeprecatedAggregationSyntax));
        assert!(has_no_rule(&w, LintRule::ConditionReferencesUnknown));
    }

    #[test]
    fn deprecated_detection_timeframe() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
    timeframe: 5m
level: medium
"#,
        );
        let finding = w
            .iter()
            .find(|w| w.rule == LintRule::DeprecatedDetectionTimeframe)
            .expect("timeframe is flagged");
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.path, "/detection/timeframe");
        assert!(has_no_rule(&w, LintRule::ConditionReferencesUnknown));
    }

    #[test]
    fn no_deprecated_detection_timeframe_without_timeframe() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::DeprecatedDetectionTimeframe));
    }

    #[test]
    fn no_deprecated_aggregation_for_normal_condition() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::DeprecatedAggregationSyntax));
    }

    #[test]
    fn no_deprecated_aggregation_for_pipe_in_field_modifier() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    selection:
        field|contains: value
    condition: selection
level: medium
"#,
        );
        assert!(has_no_rule(&w, LintRule::DeprecatedAggregationSyntax));
        assert!(has_no_rule(&w, LintRule::ConditionReferencesUnknown));
    }

    #[test]
    fn has_deprecated_aggregation_function() {
        assert!(has_deprecated_aggregation(
            "selection | count(User) by SourceIP > 5"
        ));
        assert!(has_deprecated_aggregation(
            "selection |  sum(Amount) by Account > 1000"
        ));
        assert!(has_deprecated_aggregation(
            "selection | near(field) by host"
        ));
        assert!(has_deprecated_aggregation(
            "selection | min(score) by host > 0"
        ));
        assert!(has_deprecated_aggregation(
            "selection | max(score) by host > 100"
        ));
        assert!(has_deprecated_aggregation(
            "selection | avg(score) by host > 50"
        ));
        assert!(!has_deprecated_aggregation("selection and not filter"));
        assert!(!has_deprecated_aggregation("1 of selection*"));
        assert!(!has_deprecated_aggregation("all of them"));
    }

    #[test]
    fn fix_logsource_value_not_lowercase() {
        let w = lint(
            r#"
title: Test
logsource:
    category: Test
detection:
    sel:
        field: value
    condition: sel
"#,
        );
        let fix = find_fix(&w, LintRule::LogsourceValueNotLowercase).expect("should have fix");
        insta::assert_snapshot!(fix_summary(fix), @r"
        title: lowercase 'Test' to 'test'
        disposition: Safe
        patch[0]: ReplaceValue /logsource/category -> test
        ");
    }

    #[test]
    fn fix_duplicate_tags() {
        let w = lint(
            r#"
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
"#,
        );
        let fix = find_fix(&w, LintRule::DuplicateTags).expect("should have fix");
        insta::assert_snapshot!(fix_summary(fix), @r"
        title: remove duplicate tag 'attack.execution'
        disposition: Safe
        patch[0]: Remove /tags/1
        ");
    }

    #[test]
    fn fix_duplicate_references() {
        let w = lint(
            r#"
title: Test
references:
    - https://example.com
    - https://example.com
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"#,
        );
        let fix = find_fix(&w, LintRule::DuplicateReferences).expect("should have fix");
        insta::assert_snapshot!(fix_summary(fix), @r"
        title: remove duplicate reference
        disposition: Safe
        patch[0]: Remove /references/1
        ");
    }

    #[test]
    fn fix_duplicate_fields() {
        let w = lint(
            r#"
title: Test
fields:
    - CommandLine
    - CommandLine
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"#,
        );
        let fix = find_fix(&w, LintRule::DuplicateFields).expect("should have fix");
        insta::assert_snapshot!(fix_summary(fix), @r"
        title: remove duplicate field
        disposition: Safe
        patch[0]: Remove /fields/1
        ");
    }

    #[test]
    fn fix_all_with_re() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    sel:
        Cmd|all|re:
            - foo.*
            - bar.*
    condition: sel
"#,
        );
        let fix = find_fix(&w, LintRule::AllWithRe).expect("should have fix");
        insta::assert_snapshot!(fix_summary(fix), @r"
        title: remove |all from 'Cmd|all|re'
        disposition: Safe
        patch[0]: ReplaceKey /detection/sel/Cmd|all|re -> Cmd|re
        ");
    }

    #[test]
    fn fix_single_value_all_modifier() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    sel:
        Cmd|all|contains:
            - only_one
    condition: sel
"#,
        );
        let fix = find_fix(&w, LintRule::SingleValueAllModifier).expect("should have fix");
        insta::assert_snapshot!(fix_summary(fix), @r"
        title: remove |all from 'Cmd|all|contains'
        disposition: Safe
        patch[0]: ReplaceKey /detection/sel/Cmd|all|contains -> Cmd|contains
        ");
    }

    #[test]
    fn fix_wildcard_only_value() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    sel:
        CommandLine: '*'
    condition: sel
"#,
        );
        let fix = find_fix(&w, LintRule::WildcardOnlyValue).expect("should have fix");
        insta::assert_snapshot!(fix_summary(fix), @r"
        title: replace with 'CommandLine|exists: true'
        disposition: Safe
        patch[0]: ReplaceKey /detection/sel/CommandLine -> CommandLine|exists
        patch[1]: ReplaceBool /detection/sel/CommandLine|exists -> true
        ");
    }

    #[test]
    fn fix_paths_escape_slashes_in_names() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
detection:
    sel/a:
        dir/name~x|all: one
    condition: all of them
"#,
        );
        let fix = find_fix(&w, LintRule::SingleValueAllModifier).expect("should have fix");
        insta::assert_snapshot!(fix_summary(fix), @r"
        title: remove |all from 'dir/name~x|all'
        disposition: Safe
        patch[0]: ReplaceKey /detection/sel~1a/dir~1name~0x|all -> dir/name~x
        ");
    }
}
