use std::collections::HashSet;

use serde_yaml::Value;

use super::super::{
    FixPatch, LintRule, LintWarning, err, get_mapping, get_seq, get_str, key, safe_fix, warning,
};

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

pub(crate) fn lint_detection_rule(m: &serde_yaml::Mapping, warnings: &mut Vec<LintWarning>) {
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
                    for ident in extract_condition_identifiers(cond_str) {
                        if !det_keys.contains(ident.as_str()) {
                            warnings.push(err(
                                LintRule::ConditionReferencesUnknown,
                                format!(
                                    "condition references '{ident}' but no such detection identifier exists"
                                ),
                                "/detection/condition",
                            ));
                        }
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
                } else {
                    if let Some(ns) = tag.split('.').next()
                        && !KNOWN_TAG_NAMESPACES.contains(&ns)
                    {
                        warnings.push(warning(
                            LintRule::UnknownTagNamespace,
                            format!(
                                "unknown tag namespace \"{ns}\", known namespaces: {}",
                                KNOWN_TAG_NAMESPACES.join(", ")
                            ),
                            format!("/tags/{i}"),
                        ));
                    }
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

pub(crate) fn lint_logsource(m: &serde_yaml::Mapping, warnings: &mut Vec<LintWarning>) {
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

/// Extract bare identifiers from a condition expression (excluding keywords
/// and wildcard patterns) so we can check they exist in the detection section.
fn extract_condition_identifiers(condition: &str) -> Vec<String> {
    const KEYWORDS: &[&str] = &["and", "or", "not", "of", "all", "them"];
    condition
        .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '*')
        .filter(|s| !s.is_empty())
        .filter(|s| !KEYWORDS.contains(s))
        .filter(|s| !s.chars().all(|c| c.is_ascii_digit()))
        .filter(|s| !s.contains('*'))
        .map(|s| s.to_string())
        .collect()
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
fn lint_detection_logic(det: &serde_yaml::Mapping, warnings: &mut Vec<LintWarning>) {
    for (det_key, det_val) in det {
        let det_key_str = det_key.as_str().unwrap_or("");
        if det_key_str == "condition" || det_key_str == "timeframe" {
            continue;
        }

        lint_detection_value(det_val, det_key_str, warnings);
    }
}

fn lint_detection_value(value: &Value, det_name: &str, warnings: &mut Vec<LintWarning>) {
    match value {
        Value::Mapping(m) => {
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
                            path: format!("/detection/{det_name}/{field_key_str}"),
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
                                path: format!("/detection/{det_name}/{field_key_str}"),
                                new_key,
                            }],
                        );
                        warnings.push(w);
                    }
                }

                if let Some(msg) = check_modifier_compatibility(field_key_str) {
                    warnings.push(warning(
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
                                path: format!("/detection/{det_name}/{field_key_str}"),
                                new_key,
                            },
                            FixPatch::ReplaceValue {
                                path: format!("/detection/{det_name}/{base_field}|exists"),
                                new_value: "true".into(),
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

/// Check field modifier compatibility and return a diagnostic message if
/// the combination is invalid.
fn check_modifier_compatibility(field_key: &str) -> Option<String> {
    let parts: Vec<&str> = field_key.split('|').collect();
    if parts.len() < 2 {
        return None;
    }
    let modifiers = &parts[1..];

    let string_match: &[&str] = &["contains", "startswith", "endswith"];
    let pattern_match: &[&str] = &["re", "cidr"];
    let numeric_compare: &[&str] = &["gt", "gte", "lt", "lte", "neq"];
    let regex_flags: &[&str] = &["i", "ignorecase", "m", "multiline", "s", "dotall"];

    let has_string = modifiers
        .iter()
        .filter(|m| string_match.contains(m))
        .count();
    let has_pattern: Vec<&&str> = modifiers
        .iter()
        .filter(|m| pattern_match.contains(m))
        .collect();
    let has_numeric = modifiers.iter().any(|m| numeric_compare.contains(m));
    let has_exists = modifiers.contains(&"exists");
    let has_re = modifiers.contains(&"re");
    let has_regex_flags = modifiers.iter().any(|m| regex_flags.contains(m));

    if has_string > 1 {
        return Some(
            "multiple string-match modifiers (contains, startswith, endswith) \
             are mutually exclusive"
                .to_string(),
        );
    }

    if !has_pattern.is_empty() && has_string > 0 {
        return Some(format!(
            "pattern modifier '{}' is incompatible with string-match modifiers \
             (contains, startswith, endswith)",
            has_pattern
                .iter()
                .map(|m| **m)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    if has_numeric && (has_string > 0 || !has_pattern.is_empty()) {
        return Some(
            "numeric comparison modifiers (gt, gte, lt, lte, neq) are incompatible \
             with string-match and pattern modifiers"
                .to_string(),
        );
    }

    if has_exists && modifiers.len() > 1 {
        let others: Vec<&&str> = modifiers
            .iter()
            .filter(|m| **m != "exists" && **m != "all" && **m != "cased")
            .collect();
        if !others.is_empty() {
            return Some(format!(
                "'exists' modifier is incompatible with: {}",
                others.iter().map(|m| **m).collect::<Vec<_>>().join(", ")
            ));
        }
    }

    if has_regex_flags && !has_re {
        return Some("regex flag modifiers (i, m, s) require the 're' modifier".to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::super::super::{Fix, FixPatch, LintRule, LintWarning, Severity, lint_yaml_value};
    use super::*;

    fn yaml_value(yaml: &str) -> serde_yaml::Value {
        serde_yaml::from_str(yaml).unwrap()
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
        patch[1]: ReplaceValue /detection/sel/CommandLine|exists -> true
        ");
    }
}
