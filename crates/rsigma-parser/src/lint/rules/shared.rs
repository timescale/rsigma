use super::super::{
    DocType, FixPatch, LintRule, LintWarning, TYPO_MAX_EDIT_DISTANCE, edit_distance, info, safe_fix,
};

/// Known top-level keys shared across all Sigma document types.
pub(crate) const KNOWN_KEYS_SHARED: &[&str] = &[
    "title",
    "id",
    "name",
    "status",
    "description",
    "author",
    "date",
    "modified",
    "related",
    "taxonomy",
    "action",
    "license",
    "references",
    "tags",
];

/// Extra top-level keys valid for detection rules.
pub(crate) const KNOWN_KEYS_DETECTION: &[&str] = &[
    "logsource",
    "detection",
    "fields",
    "falsepositives",
    "level",
    "scope",
    "custom_attributes",
];

/// Extra top-level keys valid for correlation rules.
pub(crate) const KNOWN_KEYS_CORRELATION: &[&str] = &[
    "correlation",
    "custom_attributes",
    "falsepositives",
    "fields",
    "generate",
    "level",
    "license",
    "related",
    "scope",
];

/// Extra top-level keys valid for filter rules.
pub(crate) const KNOWN_KEYS_FILTER: &[&str] = &[
    "custom_attributes",
    "falsepositives",
    "fields",
    "filter",
    "level",
    "license",
    "logsource",
    "references",
    "related",
    "scope",
    "tags",
    "taxonomy",
];

/// Check for unknown top-level keys that are likely typos of known keys.
pub(crate) fn lint_unknown_keys(
    m: &serde_yaml::Mapping,
    doc_type: DocType,
    warnings: &mut Vec<LintWarning>,
) {
    let type_keys = doc_type.known_keys();
    let all_known: Vec<&str> = KNOWN_KEYS_SHARED
        .iter()
        .chain(type_keys.iter())
        .copied()
        .collect();

    for k in m.keys() {
        let Some(ks) = k.as_str() else { continue };
        if KNOWN_KEYS_SHARED.contains(&ks) || type_keys.contains(&ks) {
            continue;
        }
        if let Some(closest) = all_known
            .iter()
            .filter(|known| edit_distance(ks, known) <= TYPO_MAX_EDIT_DISTANCE)
            .min_by_key(|known| edit_distance(ks, known))
        {
            let mut w = info(
                LintRule::UnknownKey,
                format!("unknown top-level key \"{ks}\"; did you mean \"{closest}\"?"),
                format!("/{ks}"),
            );
            w.fix = safe_fix(
                format!("rename '{ks}' to '{closest}'"),
                vec![FixPatch::ReplaceKey {
                    path: format!("/{ks}"),
                    new_key: closest.to_string(),
                }],
            );
            warnings.push(w);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{Fix, FixPatch, LintRule, LintWarning, Severity, lint_yaml_value};

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
    fn unknown_key_typo_detected() {
        let w = lint(
            r#"
title: Test
desciption: Typo field
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
"#,
        );
        assert!(has_rule(&w, LintRule::UnknownKey));
        let unk = w.iter().find(|w| w.rule == LintRule::UnknownKey).unwrap();
        assert!(unk.message.contains("desciption"));
        assert!(unk.message.contains("description"));
        assert_eq!(unk.severity, Severity::Info);
    }

    #[test]
    fn known_keys_no_unknown_warning() {
        let w = lint(
            r#"
title: Test Rule
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
status: test
description: A valid description
author: tester
date: '2025-01-01'
modified: '2025-06-01'
license: MIT
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
tags:
    - attack.execution
references:
    - https://example.com
fields:
    - CommandLine
falsepositives:
    - Legitimate admin
"#,
        );
        assert!(has_no_rule(&w, LintRule::UnknownKey));
    }

    #[test]
    fn custom_fields_allowed_by_spec() {
        let w = lint(
            r#"
title: Test Rule
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: medium
simulation:
    action: scan
regression_tests_path: tests/
custom_metadata: hello
"#,
        );
        assert!(has_no_rule(&w, LintRule::UnknownKey));
    }

    #[test]
    fn unknown_key_typo_correlation() {
        let w = lint(
            r#"
title: Correlation Test
name: test_correlation
correlation:
    type: event_count
    rules:
        - rule1
    group-by:
        - src_ip
    timespan: 5m
    condition:
        gte: 10
lvel: high
"#,
        );
        assert!(has_rule(&w, LintRule::UnknownKey));
        let unk = w.iter().find(|w| w.rule == LintRule::UnknownKey).unwrap();
        assert!(unk.message.contains("lvel"));
        assert!(unk.message.contains("level"));
    }

    #[test]
    fn unknown_key_custom_field_filter() {
        let w = lint(
            r#"
title: Filter Test
logsource:
    category: test
filter:
    rules:
        - rule1
    selection:
        User: admin
    condition: selection
badkey: foo
"#,
        );
        assert!(has_no_rule(&w, LintRule::UnknownKey));
    }

    #[test]
    fn fix_unknown_key_typo() {
        let w = lint(
            r#"
title: Test
desciption: Typo field
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
level: medium
"#,
        );
        let fix = find_fix(&w, LintRule::UnknownKey).expect("should have fix");
        insta::assert_snapshot!(fix_summary(fix), @r"
        title: rename 'desciption' to 'description'
        disposition: Safe
        patch[0]: ReplaceKey /desciption -> description
        ");
    }
}
