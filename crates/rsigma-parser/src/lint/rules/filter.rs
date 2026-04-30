use super::super::{FixPatch, LintRule, LintWarning, err, key, safe_fix, warning};
use super::detection::lint_logsource;

pub(crate) fn lint_filter_rule(m: &serde_yaml::Mapping, warnings: &mut Vec<LintWarning>) {
    // ── filter section ───────────────────────────────────────────────────
    let Some(filter_val) = m.get(key("filter")) else {
        warnings.push(err(
            LintRule::MissingFilter,
            "missing required field 'filter'",
            "/filter",
        ));
        return;
    };

    let Some(filter) = filter_val.as_mapping() else {
        warnings.push(err(
            LintRule::MissingFilter,
            "'filter' must be a mapping",
            "/filter",
        ));
        return;
    };

    // ── filter.rules ─────────────────────────────────────────────────────
    if let Some(rules_val) = filter.get(key("rules")) {
        match rules_val {
            serde_yaml::Value::Sequence(_) => {}
            serde_yaml::Value::String(s) if s.eq_ignore_ascii_case("any") => {}
            serde_yaml::Value::String(_) => {}
            _ => {
                warnings.push(err(
                    LintRule::MissingFilterRules,
                    "filter.rules must be a sequence of rule IDs, a single rule ID string, or 'any'",
                    "/filter/rules",
                ));
            }
        }
    }

    // ── filter.selection ─────────────────────────────────────────────────
    if !filter.contains_key(key("selection")) {
        warnings.push(err(
            LintRule::MissingFilterSelection,
            "missing required field 'filter.selection'",
            "/filter/selection",
        ));
    }

    // ── filter.condition ─────────────────────────────────────────────────
    if !filter.contains_key(key("condition")) {
        warnings.push(err(
            LintRule::MissingFilterCondition,
            "missing required field 'filter.condition'",
            "/filter/condition",
        ));
    }

    // ── logsource required for filters ───────────────────────────────────
    if !m.contains_key(key("logsource")) {
        warnings.push(err(
            LintRule::MissingFilterLogsource,
            "missing required field 'logsource' for filter rule",
            "/logsource",
        ));
    } else {
        lint_logsource(m, warnings);
    }

    // ── Filters should NOT have level or status ──────────────────────────
    if m.contains_key(key("level")) {
        let mut w = warning(
            LintRule::FilterHasLevel,
            "filter rules should not have a 'level' field",
            "/level",
        );
        w.fix = safe_fix(
            "remove 'level' from filter rule",
            vec![FixPatch::Remove {
                path: "/level".into(),
            }],
        );
        warnings.push(w);
    }

    if m.contains_key(key("status")) {
        let mut w = warning(
            LintRule::FilterHasStatus,
            "filter rules should not have a 'status' field",
            "/status",
        );
        w.fix = safe_fix(
            "remove 'status' from filter rule",
            vec![FixPatch::Remove {
                path: "/status".into(),
            }],
        );
        warnings.push(w);
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
    fn valid_filter_no_errors() {
        let w = lint(
            r#"
title: Filter Admin
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - 929a690e-bef0-4204-a928-ef5e620d6fcc
    selection:
        User|startswith: 'adm_'
    condition: selection
"#,
        );
        let errors: Vec<_> = w.iter().filter(|w| w.severity == Severity::Error).collect();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn filter_without_rules_is_valid() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
filter:
    selection:
        User: admin
    condition: selection
"#,
        );
        assert!(!has_rule(&w, LintRule::MissingFilterRules));
    }

    #[test]
    fn filter_rules_invalid_type() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
filter:
    rules: 123
    selection:
        User: admin
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::MissingFilterRules));
    }

    #[test]
    fn filter_rules_any_string_is_valid() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
filter:
    rules: any
    selection:
        User: admin
    condition: selection
"#,
        );
        assert!(!has_rule(&w, LintRule::MissingFilterRules));
    }

    #[test]
    fn filter_rules_empty_sequence_is_valid() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
filter:
    rules: []
    selection:
        User: admin
    condition: selection
"#,
        );
        assert!(!has_rule(&w, LintRule::EmptyFilterRules));
    }

    #[test]
    fn missing_filter_selection() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
filter:
    rules:
        - some-rule
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::MissingFilterSelection));
    }

    #[test]
    fn missing_filter_condition() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
filter:
    rules:
        - some-rule
    selection:
        User: admin
"#,
        );
        assert!(has_rule(&w, LintRule::MissingFilterCondition));
    }

    #[test]
    fn filter_has_level_warning() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
level: high
filter:
    rules:
        - some-rule
    selection:
        User: admin
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::FilterHasLevel));
    }

    #[test]
    fn filter_has_status_warning() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
status: test
filter:
    rules:
        - some-rule
    selection:
        User: admin
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::FilterHasStatus));
    }

    #[test]
    fn missing_filter_logsource() {
        let w = lint(
            r#"
title: Test
filter:
    rules:
        - some-rule
    selection:
        User: admin
    condition: selection
"#,
        );
        assert!(has_rule(&w, LintRule::MissingFilterLogsource));
    }

    #[test]
    fn fix_filter_has_level() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
level: high
filter:
    rules:
        - rule1
    selection:
        User: admin
    condition: selection
"#,
        );
        let fix = find_fix(&w, LintRule::FilterHasLevel).expect("should have fix");
        insta::assert_snapshot!(fix_summary(fix), @r"
        title: remove 'level' from filter rule
        disposition: Safe
        patch[0]: Remove /level
        ");
    }

    #[test]
    fn fix_filter_has_status() {
        let w = lint(
            r#"
title: Test
logsource:
    category: test
status: test
filter:
    rules:
        - rule1
    selection:
        User: admin
    condition: selection
"#,
        );
        let fix = find_fix(&w, LintRule::FilterHasStatus).expect("should have fix");
        insta::assert_snapshot!(fix_summary(fix), @r"
        title: remove 'status' from filter rule
        disposition: Safe
        patch[0]: Remove /status
        ");
    }
}
