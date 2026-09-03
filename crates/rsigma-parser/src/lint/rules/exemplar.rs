//! Static shape checks for `rsigma.exemplars`.
//!
//! Lint never executes events. It inspects both the nested
//! `custom_attributes:` map and a top-level dotted key, and it also
//! runs on `action: global`/`repeat` fragments so inherited templates
//! are not silently skipped.

use yaml_serde::Value;

use crate::exemplar::{ExemplarRuleKind, parse_exemplars, raw_exemplar_values};

use super::super::{DocType, LintRule, LintWarning, Severity, warn};

pub(crate) fn lint_exemplars(
    m: &yaml_serde::Mapping,
    doc_type: Option<DocType>,
    warnings: &mut Vec<LintWarning>,
) {
    let kind = doc_type.map(doc_kind);
    for (path, value) in raw_exemplar_values(m) {
        lint_one(value, kind, path, warnings);
    }
}

fn lint_one(
    value: &Value,
    kind: Option<ExemplarRuleKind>,
    path: String,
    warnings: &mut Vec<LintWarning>,
) {
    match kind {
        Some(kind) => emit_parse(value, kind, path, true, warnings),
        None => {
            emit_parse(
                value,
                ExemplarRuleKind::Detection,
                path.clone(),
                false,
                warnings,
            );
            emit_parse(value, ExemplarRuleKind::Correlation, path, false, warnings);
        }
    }
}

fn emit_parse(
    value: &Value,
    kind: ExemplarRuleKind,
    path: String,
    report_wrong_kind: bool,
    warnings: &mut Vec<LintWarning>,
) {
    let Err(errors) = parse_exemplars(value, kind, path) else {
        return;
    };
    for error in errors {
        if error.is_wrong_rule_kind() {
            if report_wrong_kind {
                warnings.push(warn(
                    LintRule::ExemplarWrongRuleKind,
                    Severity::Warning,
                    error.message,
                    error.path,
                ));
            }
        } else if !warnings.iter().any(|w| {
            w.rule == LintRule::ExemplarShape && w.path == error.path && w.message == error.message
        }) {
            warnings.push(warn(
                LintRule::ExemplarShape,
                Severity::Warning,
                error.message,
                error.path,
            ));
        }
    }
}

fn doc_kind(doc_type: DocType) -> ExemplarRuleKind {
    match doc_type {
        DocType::Detection => ExemplarRuleKind::Detection,
        DocType::Correlation => ExemplarRuleKind::Correlation,
        DocType::Filter => ExemplarRuleKind::Filter,
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{LintRule, lint_yaml_value};

    fn lint(yaml: &str) -> Vec<LintRule> {
        let value: yaml_serde::Value = yaml_serde::from_str(yaml).unwrap();
        lint_yaml_value(&value)
            .into_iter()
            .map(|w| w.rule)
            .collect()
    }

    const BASE: &str = "title: T\nlogsource:\n    category: test\ndetection:\n    selection:\n        field: value\n    condition: selection\n";

    #[test]
    fn well_formed_detection_exemplars_are_silent() {
        let yaml = format!(
            "{BASE}custom_attributes:\n    rsigma.exemplars:\n        - expect: match\n          event:\n              field: value\n"
        );
        assert!(!lint(&yaml).contains(&LintRule::ExemplarShape));
        assert!(!lint(&yaml).contains(&LintRule::ExemplarWrongRuleKind));
    }

    #[test]
    fn empty_list_is_shape() {
        let yaml = format!("{BASE}custom_attributes:\n    rsigma.exemplars: []\n");
        assert!(lint(&yaml).contains(&LintRule::ExemplarShape));
    }

    #[test]
    fn events_on_detection_is_wrong_kind() {
        let yaml = format!(
            "{BASE}custom_attributes:\n    rsigma.exemplars:\n        - expect: match\n          events:\n              - offset: 0s\n                event:\n                    field: value\n"
        );
        assert!(lint(&yaml).contains(&LintRule::ExemplarWrongRuleKind));
    }

    #[test]
    fn filter_exemplars_are_wrong_kind() {
        let yaml = r#"
title: F
logsource:
    category: test
filter:
    rules:
        - some-id
    selection:
        field: skip
    condition: selection
custom_attributes:
    rsigma.exemplars:
        - expect: match
          event:
              field: skip
"#;
        assert!(lint(yaml).contains(&LintRule::ExemplarWrongRuleKind));
    }

    #[test]
    fn action_fragment_exemplars_are_linted() {
        let yaml = r#"
action: global
custom_attributes:
    rsigma.exemplars: []
"#;
        assert!(lint(yaml).contains(&LintRule::ExemplarShape));
        assert!(!lint(yaml).contains(&LintRule::ExemplarWrongRuleKind));
    }

    #[test]
    fn action_fragment_does_not_flag_kind() {
        let yaml = r#"
action: global
custom_attributes:
    rsigma.exemplars:
        - expect: match
          events:
              - offset: 0s
                event:
                    field: value
"#;
        assert!(!lint(yaml).contains(&LintRule::ExemplarWrongRuleKind));
        assert!(!lint(yaml).contains(&LintRule::ExemplarShape));
    }
}
