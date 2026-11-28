use super::super::{LintRule, LintWarning, err, get_str, info, key, reference_list, warning};
use crate::ast::{CorrelationType, WindowMode};

/// Valid correlation types.
const VALID_CORRELATION_TYPES: &[&str] = &[
    "event_count",
    "value_count",
    "temporal",
    "temporal_ordered",
    "value_sum",
    "value_avg",
    "value_percentile",
    "value_median",
];

/// Valid condition operators.
const VALID_CONDITION_OPERATORS: &[&str] = &["gt", "gte", "lt", "lte", "eq", "neq"];

/// Valid window modes.
const VALID_WINDOW_MODES: &[&str] = &["sliding", "tumbling", "session"];

/// Correlation types that require a condition section.
const TYPES_REQUIRING_CONDITION: &[&str] = &[
    "event_count",
    "value_count",
    "value_sum",
    "value_avg",
    "value_percentile",
];

/// Correlation types that require condition.field.
const TYPES_REQUIRING_FIELD: &[&str] = &[
    "value_count",
    "value_sum",
    "value_avg",
    "value_percentile",
    "value_median",
];

fn is_valid_timespan(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let last = s.as_bytes()[s.len() - 1];
    if !matches!(last, b's' | b'm' | b'h' | b'd' | b'w' | b'M' | b'y') {
        return false;
    }
    let num_part = &s[..s.len() - 1];
    !num_part.is_empty()
        && num_part.chars().all(|c| c.is_ascii_digit())
        && num_part.parse::<u64>().is_ok_and(|n| n > 0)
}

/// Resolve the winning spelling of an `rsigma.*` attribute: the
/// `custom_attributes:` block, then the top level, then the first-class
/// `correlation.*` key. Returns the value, whether any spelling is present, and
/// the diagnostic path of the winning spelling.
fn attribute_spelling<'a>(
    m: &'a yaml_serde::Mapping,
    corr: &'a yaml_serde::Mapping,
    attribute: &str,
    first_class: &str,
) -> (Option<&'a str>, bool, String) {
    let block = m.get(key("custom_attributes")).and_then(|v| v.as_mapping());
    if let Some(v) = block.and_then(|b| b.get(key(attribute))) {
        (v.as_str(), true, format!("/custom_attributes/{attribute}"))
    } else if let Some(v) = m.get(key(attribute)) {
        (v.as_str(), true, format!("/{attribute}"))
    } else if let Some(v) = corr.get(key(first_class)) {
        (v.as_str(), true, format!("/correlation/{first_class}"))
    } else {
        (None, false, format!("/correlation/{first_class}"))
    }
}

pub(crate) fn lint_correlation_rule(m: &yaml_serde::Mapping, warnings: &mut Vec<LintWarning>) {
    let Some(corr_val) = m.get(key("correlation")) else {
        warnings.push(err(
            LintRule::MissingCorrelation,
            "missing required field 'correlation'",
            "/correlation",
        ));
        return;
    };

    let Some(corr) = corr_val.as_mapping() else {
        warnings.push(err(
            LintRule::MissingCorrelation,
            "'correlation' must be a mapping",
            "/correlation",
        ));
        return;
    };

    // ── type ─────────────────────────────────────────────────────────────
    let corr_type = get_str(corr, "type");
    match corr_type {
        None => {
            warnings.push(err(
                LintRule::MissingCorrelationType,
                "missing required field 'correlation.type'",
                "/correlation/type",
            ));
        }
        Some(t) if !VALID_CORRELATION_TYPES.contains(&t) => {
            warnings.push(err(
                LintRule::InvalidCorrelationType,
                format!(
                    "invalid correlation type \"{t}\", expected one of: {}",
                    VALID_CORRELATION_TYPES.join(", ")
                ),
                "/correlation/type",
            ));
        }
        _ => {}
    }

    // ── rules ────────────────────────────────────────────────────────────
    let rules = reference_list(corr.get(key("rules")));
    let rules_present = corr.contains_key(key("rules"));
    let condition_is_string = corr
        .get(key("condition"))
        .and_then(|v| v.as_str())
        .is_some();
    if let Some(rules_val) = corr.get(key("rules")) {
        if rules_val.as_sequence().is_some_and(|seq| seq.is_empty()) {
            warnings.push(warning(
                LintRule::EmptyCorrelationRules,
                "correlation.rules should not be empty",
                "/correlation/rules",
            ));
        }
    } else if !condition_is_string {
        warnings.push(err(
            LintRule::MissingCorrelationRules,
            "missing required field 'correlation.rules'",
            "/correlation/rules",
        ));
    }

    // ── string condition references ──────────────────────────────────────
    // A string condition names the rules it aggregates. Every name must be in
    // `rules:`, and every listed rule should be used. Selectors are skipped:
    // their identifiers come from the detection set, not the condition.
    if condition_is_string
        && rules_present
        && let Some(cond) = get_str(corr, "condition")
        && let Ok(expr) = crate::condition::parse_condition(cond)
        && let Ok(identifiers) = crate::parser::condition_identifiers(&expr)
    {
        for name in &identifiers {
            if !rules.contains(name) {
                warnings.push(err(
                    LintRule::ExtendedConditionUndefinedRule,
                    format!("condition references '{name}', which is not in correlation.rules"),
                    "/correlation/condition",
                ));
            }
        }
        for rule in &rules {
            if !identifiers.iter().any(|name| name == rule) {
                warnings.push(warning(
                    LintRule::ExtendedConditionUnreferencedRule,
                    format!(
                        "correlation.rules lists '{rule}', which the condition never references"
                    ),
                    "/correlation/rules",
                ));
            }
        }
    }

    // ── timespan ─────────────────────────────────────────────────────────
    if let Some(ts) = get_str(corr, "timespan").or_else(|| get_str(corr, "timeframe")) {
        if !is_valid_timespan(ts) {
            warnings.push(err(
                LintRule::InvalidTimespanFormat,
                format!(
                    "invalid timespan \"{ts}\", expected format like 5m, 1h, 30s, 7d, 1w, 1M, 1y"
                ),
                "/correlation/timespan",
            ));
        }
    } else {
        warnings.push(err(
            LintRule::MissingCorrelationTimespan,
            "missing required field 'correlation.timespan'",
            "/correlation/timespan",
        ));
    }

    // ── window + gap ──────────────────────────────────────────────────────
    // Accept every spelling the parser reads: the `rsigma.*` custom
    // attributes, in the `custom_attributes:` block or at the top level, and
    // the first-class `correlation.window` / `correlation.gap` keys. The
    // parser's precedence applies (block, then top level, then
    // `correlation.*`), and the diagnostic points at the winning key.
    // Presence is checked before type so a key set to a non-string value (e.g.
    // an unquoted `gap: 300`) is reported as invalid instead of missing.
    let (window, window_present, window_ptr) =
        attribute_spelling(m, corr, "rsigma.window", "window");
    let (gap, gap_present, gap_ptr) = attribute_spelling(m, corr, "rsigma.gap", "gap");
    let (window_ptr, gap_ptr) = (window_ptr.as_str(), gap_ptr.as_str());

    let window_known = match (window_present, window) {
        (false, _) => true,
        (true, Some(w)) => VALID_WINDOW_MODES.contains(&w),
        (true, None) => false,
    };
    if window_present {
        match window {
            Some(w) if !VALID_WINDOW_MODES.contains(&w) => {
                warnings.push(err(
                    LintRule::InvalidWindowMode,
                    format!(
                        "invalid window mode \"{w}\", expected one of: {}",
                        VALID_WINDOW_MODES.join(", ")
                    ),
                    window_ptr,
                ));
            }
            None => {
                warnings.push(err(
                    LintRule::InvalidWindowMode,
                    "window must be a string: sliding, tumbling, or session",
                    window_ptr,
                ));
            }
            _ => {}
        }
    }

    if gap_present {
        match gap {
            Some(g) if !is_valid_timespan(g) => {
                warnings.push(err(
                    LintRule::InvalidGapFormat,
                    format!("invalid gap \"{g}\", expected format like 5m, 1h, 30s, 7d"),
                    gap_ptr,
                ));
            }
            None => {
                warnings.push(err(
                    LintRule::InvalidGapFormat,
                    "gap must be a string duration like \"5m\" (quote numeric values)",
                    gap_ptr,
                ));
            }
            _ => {}
        }
    }

    // Only reason about the gap/window relationship when the window is a known
    // value; an invalid mode is already reported by InvalidWindowMode. A gap of
    // the wrong type still counts as present (the author did set one).
    if window_known {
        let is_session = window == Some("session");
        if is_session && !gap_present {
            warnings.push(err(
                LintRule::MissingSessionGap,
                "window: session requires a 'gap' (e.g. gap: 5m)",
                gap_ptr,
            ));
        } else if !is_session && gap_present {
            warnings.push(err(
                LintRule::GapWithoutSession,
                "'gap' is only valid with window: session",
                gap_ptr,
            ));
        }
    }

    // ── absence semantics ────────────────────────────────────────────────
    // The engine evaluates negated rule references at a deadline. The linter
    // resolves the window from raw YAML using the parser's precedence, so a
    // document without pipelines or overlays is rejected at load exactly when
    // it is flagged here.
    let mut is_absence = false;
    if let Some(ct) = corr_type.and_then(|t| t.parse::<CorrelationType>().ok())
        && let Some(cond) = get_str(corr, "condition")
        && let Ok(expr) = crate::condition::parse_condition(cond)
    {
        let window_mode = match (window_present, window) {
            (false, _) => Some(WindowMode::Sliding),
            (true, Some(w)) => w.parse::<WindowMode>().ok(),
            (true, None) => None,
        };
        if let Some(window_mode) = window_mode {
            let condition_rules = if rules_present {
                rules.clone()
            } else {
                crate::parser::condition_identifiers(&expr).unwrap_or_default()
            };
            let has_group_by = corr.contains_key(key("group-by"));
            match crate::absence::analyze_absence_parts(
                &expr,
                ct,
                window_mode,
                &condition_rules,
                has_group_by,
            ) {
                Ok(Some(_)) => {
                    is_absence = true;
                    warnings.push(info(
                        LintRule::AbsenceSemantics,
                        "this correlation is evaluated at a deadline by the rsigma engine; that \
                         evaluation is an rsigma extension, and the PostgreSQL and Fibratus \
                         backends reject it",
                        "/correlation/condition",
                    ));
                }
                Ok(None) => {}
                Err(error) => warnings.push(err(
                    LintRule::AbsenceConditionUnsupported,
                    error.to_string(),
                    "/correlation/condition",
                )),
            }
        }
    }

    // ── rsigma.absence_grace ─────────────────────────────────────────────
    let (grace, grace_present, grace_ptr) =
        attribute_spelling(m, corr, "rsigma.absence_grace", "absence_grace");
    if grace_present {
        match grace {
            Some(g) if crate::value::Timespan::parse(g).is_ok() => {
                if !is_absence {
                    warnings.push(warning(
                        LintRule::AbsenceGraceWithoutAbsence,
                        "rsigma.absence_grace has no effect on a correlation that is not an \
                         absence correlation",
                        grace_ptr,
                    ));
                }
            }
            _ => warnings.push(err(
                LintRule::InvalidAbsenceGrace,
                "rsigma.absence_grace must be a duration like 30s (0s is allowed)",
                grace_ptr,
            )),
        }
    }

    // ── Conditional requirements per correlation type ─────────────────────
    if let Some(ct) = corr_type {
        if !corr.contains_key(key("group-by")) {
            warnings.push(err(
                LintRule::MissingGroupBy,
                format!("{ct} correlation requires 'group-by'"),
                "/correlation/group-by",
            ));
        }

        if TYPES_REQUIRING_CONDITION.contains(&ct) {
            if let Some(cond_val) = corr.get(key("condition")) {
                if let Some(cond_map) = cond_val.as_mapping() {
                    lint_correlation_condition(cond_map, ct, warnings);
                }
            } else {
                warnings.push(err(
                    LintRule::MissingCorrelationCondition,
                    format!("{ct} correlation requires a 'condition'"),
                    "/correlation/condition",
                ));
            }
        }
    }

    // ── generate ─────────────────────────────────────────────────────────
    for (path, val) in [
        ("/generate", m.get(key("generate"))),
        ("/correlation/generate", corr.get(key("generate"))),
    ] {
        if let Some(gen_val) = val
            && !gen_val.is_bool()
        {
            warnings.push(err(
                LintRule::GenerateNotBoolean,
                "'generate' must be a boolean (true/false)",
                path,
            ));
        }
    }

    let generate = m.get(key("generate")).or_else(|| corr.get(key("generate")));
    if generate.is_none_or(|value| value.as_bool() == Some(false)) {
        warnings.push(info(
            LintRule::CorrelationOnlyReferences,
            "referenced rules produce no standalone output; set 'generate: true' to emit them",
            "/generate",
        ));
    }
}

fn lint_correlation_condition(
    cond: &yaml_serde::Mapping,
    corr_type: &str,
    warnings: &mut Vec<LintWarning>,
) {
    if TYPES_REQUIRING_FIELD.contains(&corr_type) && !cond.contains_key(key("field")) {
        warnings.push(err(
            LintRule::MissingConditionField,
            format!("{corr_type} correlation condition requires 'field'"),
            "/correlation/condition/field",
        ));
    }

    for (k, v) in cond {
        let ks = k.as_str().unwrap_or("");
        if ks == "field" || ks == "percentile" {
            continue;
        }
        if !VALID_CONDITION_OPERATORS.contains(&ks) {
            warnings.push(err(
                LintRule::InvalidConditionOperator,
                format!(
                    "invalid condition operator \"{ks}\", expected one of: {}",
                    VALID_CONDITION_OPERATORS.join(", ")
                ),
                format!("/correlation/condition/{ks}"),
            ));
        } else if !v.is_i64() && !v.is_u64() && !v.is_f64() {
            warnings.push(err(
                LintRule::ConditionValueNotNumeric,
                format!("condition operator '{ks}' requires a numeric value"),
                format!("/correlation/condition/{ks}"),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{LintRule, LintWarning, Severity, lint_yaml_value};
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

    #[test]
    fn valid_correlation_no_errors() {
        let w = lint(
            r#"
title: Brute Force
correlation:
    type: event_count
    rules:
        - 929a690e-bef0-4204-a928-ef5e620d6fcc
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 100
level: high
"#,
        );
        let errors: Vec<_> = w.iter().filter(|w| w.severity == Severity::Error).collect();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn invalid_correlation_type() {
        let w = lint(
            r#"
title: Test
correlation:
    type: invalid_type
    rules:
        - some-rule
    timespan: 1h
    group-by:
        - User
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidCorrelationType));
    }

    #[test]
    fn missing_correlation_timespan() {
        let w = lint(
            r#"
title: Test
correlation:
    type: event_count
    rules:
        - some-rule
    group-by:
        - User
    condition:
        gte: 10
"#,
        );
        assert!(has_rule(&w, LintRule::MissingCorrelationTimespan));
    }

    #[test]
    fn invalid_timespan_format() {
        let w = lint(
            r#"
title: Test
correlation:
    type: event_count
    rules:
        - some-rule
    group-by:
        - User
    timespan: 1hour
    condition:
        gte: 10
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidTimespanFormat));
    }

    #[test]
    fn missing_group_by() {
        let w = lint(
            r#"
title: Test
correlation:
    type: event_count
    rules:
        - some-rule
    timespan: 1h
    condition:
        gte: 10
"#,
        );
        assert!(has_rule(&w, LintRule::MissingGroupBy));
    }

    #[test]
    fn missing_condition_field_for_value_count() {
        let w = lint(
            r#"
title: Test
correlation:
    type: value_count
    rules:
        - some-rule
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 10
"#,
        );
        assert!(has_rule(&w, LintRule::MissingConditionField));
    }

    #[test]
    fn invalid_condition_operator() {
        let w = lint(
            r#"
title: Test
correlation:
    type: event_count
    rules:
        - some-rule
    group-by:
        - User
    timespan: 1h
    condition:
        bigger: 10
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidConditionOperator));
    }

    #[test]
    fn generate_not_boolean() {
        let w = lint(
            r#"
title: Test
correlation:
    type: event_count
    rules:
        - some-rule
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 10
    generate: 'yes'
"#,
        );
        assert!(has_rule(&w, LintRule::GenerateNotBoolean));
    }

    #[test]
    fn absent_generate_reports_correlation_only_output() {
        let w = lint(
            r#"
title: Test
correlation:
    type: event_count
    rules: [some-rule]
    group-by: [User]
    timespan: 1h
    condition:
        gte: 10
"#,
        );
        assert!(has_rule(&w, LintRule::CorrelationOnlyReferences));
    }

    #[test]
    fn generate_true_has_no_correlation_only_hint() {
        let w = lint(
            r#"
title: Test
generate: true
correlation:
    type: event_count
    rules: [some-rule]
    group-by: [User]
    timespan: 1h
    condition:
        gte: 10
"#,
        );
        assert!(!has_rule(&w, LintRule::CorrelationOnlyReferences));
    }

    #[test]
    fn timespan_zero_seconds() {
        assert!(!is_valid_timespan("0s"));
    }

    #[test]
    fn timespan_no_digits() {
        assert!(!is_valid_timespan("s"));
    }

    #[test]
    fn timespan_no_unit() {
        assert!(!is_valid_timespan("123"));
    }

    #[test]
    fn timespan_invalid_unit() {
        assert!(!is_valid_timespan("5x"));
    }

    #[test]
    fn timespan_valid_variants() {
        assert!(is_valid_timespan("30s"));
        assert!(is_valid_timespan("5m"));
        assert!(is_valid_timespan("1h"));
        assert!(is_valid_timespan("7d"));
        assert!(is_valid_timespan("1w"));
        assert!(is_valid_timespan("1M"));
        assert!(is_valid_timespan("1y"));
    }

    #[test]
    fn invalid_window_mode() {
        let w = lint(
            r#"
title: Test
correlation:
    type: event_count
    rules:
        - some-rule
    group-by:
        - User
    timespan: 1h
    window: rolling
    condition:
        gte: 10
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidWindowMode));
    }

    #[test]
    fn missing_session_gap() {
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules:
        - a
        - b
    group-by:
        - User
    timespan: 2h
    window: session
"#,
        );
        assert!(has_rule(&w, LintRule::MissingSessionGap));
    }

    #[test]
    fn gap_without_session() {
        let w = lint(
            r#"
title: Test
correlation:
    type: event_count
    rules:
        - some-rule
    group-by:
        - User
    timespan: 1h
    gap: 5m
    condition:
        gte: 10
"#,
        );
        assert!(has_rule(&w, LintRule::GapWithoutSession));
    }

    #[test]
    fn invalid_gap_format() {
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules:
        - a
        - b
    group-by:
        - User
    timespan: 2h
    window: session
    gap: 5minutes
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidGapFormat));
    }

    #[test]
    fn valid_session_window_no_errors() {
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules:
        - a
        - b
    group-by:
        - User
    timespan: 2h
    window: session
    gap: 5m
"#,
        );
        assert!(!has_rule(&w, LintRule::InvalidWindowMode));
        assert!(!has_rule(&w, LintRule::MissingSessionGap));
        assert!(!has_rule(&w, LintRule::GapWithoutSession));
        assert!(!has_rule(&w, LintRule::InvalidGapFormat));
    }

    #[test]
    fn rsigma_namespace_session_missing_gap() {
        // The lint also reasons about the rsigma.* extension spelling.
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules:
        - a
        - b
    group-by:
        - User
    timespan: 2h
rsigma.window: session
"#,
        );
        assert!(has_rule(&w, LintRule::MissingSessionGap));
    }

    #[test]
    fn non_string_gap_is_invalid_format_not_missing() {
        // An unquoted numeric gap is a type error, not a missing gap.
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules:
        - a
        - b
    group-by:
        - User
    timespan: 2h
    window: session
    gap: 300
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidGapFormat));
        assert!(!has_rule(&w, LintRule::MissingSessionGap));
    }

    #[test]
    fn non_string_window_is_invalid_mode() {
        let w = lint(
            r#"
title: Test
correlation:
    type: event_count
    rules:
        - some-rule
    group-by:
        - User
    timespan: 1h
    window: 5
    condition:
        gte: 10
"#,
        );
        assert!(has_rule(&w, LintRule::InvalidWindowMode));
    }

    #[test]
    fn rsigma_namespace_valid_session_no_errors() {
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules:
        - a
        - b
    group-by:
        - User
    timespan: 2h
rsigma.window: session
rsigma.gap: 5m
"#,
        );
        assert!(!has_rule(&w, LintRule::InvalidWindowMode));
        assert!(!has_rule(&w, LintRule::MissingSessionGap));
        assert!(!has_rule(&w, LintRule::GapWithoutSession));
        assert!(!has_rule(&w, LintRule::InvalidGapFormat));
    }

    #[test]
    fn custom_attributes_block_window_is_checked() {
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules:
        - a
        - b
    group-by:
        - User
    timespan: 2h
custom_attributes:
    rsigma.window: hopping
"#,
        );
        let invalid = w
            .iter()
            .find(|w| w.rule == LintRule::InvalidWindowMode)
            .expect("invalid window mode in the block");
        assert_eq!(invalid.path, "/custom_attributes/rsigma.window");
    }

    #[test]
    fn custom_attributes_block_session_missing_gap() {
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules:
        - a
        - b
    group-by:
        - User
    timespan: 2h
custom_attributes:
    rsigma.window: session
"#,
        );
        assert!(has_rule(&w, LintRule::MissingSessionGap));
    }

    #[test]
    fn custom_attributes_block_wins_over_top_level() {
        // The block's valid session window and gap win over an invalid
        // top-level mode, as in the parser.
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules:
        - a
        - b
    group-by:
        - User
    timespan: 2h
rsigma.window: hopping
custom_attributes:
    rsigma.window: session
    rsigma.gap: 5m
"#,
        );
        assert!(!has_rule(&w, LintRule::InvalidWindowMode));
        assert!(!has_rule(&w, LintRule::MissingSessionGap));
    }

    #[test]
    fn extended_condition_undefined_rule_is_an_error() {
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules: [a]
    group-by: [User]
    timespan: 5m
    condition: a and not b
"#,
        );
        assert!(has_rule(&w, LintRule::ExtendedConditionUndefinedRule));
    }

    #[test]
    fn extended_condition_unreferenced_rule_is_a_warning() {
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules: [a, b]
    group-by: [User]
    timespan: 5m
    condition: a
"#,
        );
        assert!(has_rule(&w, LintRule::ExtendedConditionUnreferencedRule));
    }

    #[test]
    fn string_condition_does_not_report_missing_rules() {
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    group-by: [User]
    timespan: 5m
    condition: a and not b
"#,
        );
        assert!(!has_rule(&w, LintRule::MissingCorrelationRules));
        assert!(!has_rule(&w, LintRule::ExtendedConditionUndefinedRule));
    }

    #[test]
    fn selector_condition_skips_identifier_checks() {
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules: [a]
    group-by: [User]
    timespan: 5m
    condition: a and 1 of login_*
"#,
        );
        assert!(!has_rule(&w, LintRule::ExtendedConditionUndefinedRule));
        assert!(!has_rule(&w, LintRule::ExtendedConditionUnreferencedRule));
    }

    #[test]
    fn absence_semantics_is_reported_for_negated_conditions() {
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal_ordered
    rules: [login, mfa]
    group-by: [User]
    timespan: 5m
    condition: login and not mfa
"#,
        );
        assert!(has_rule(&w, LintRule::AbsenceSemantics));
        assert!(!has_rule(&w, LintRule::AbsenceConditionUnsupported));
    }

    #[test]
    fn absence_condition_under_or_is_unsupported() {
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules: [a, b]
    group-by: [User]
    timespan: 5m
    condition: a or not b
"#,
        );
        assert!(has_rule(&w, LintRule::AbsenceConditionUnsupported));
        assert!(!has_rule(&w, LintRule::AbsenceSemantics));
    }

    #[test]
    fn absence_condition_in_a_session_window_is_unsupported() {
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules: [a, b]
    group-by: [User]
    timespan: 5m
    condition: a and not b
custom_attributes:
    rsigma.window: session
    rsigma.gap: 1m
"#,
        );
        let unsupported = w
            .iter()
            .find(|w| w.rule == LintRule::AbsenceConditionUnsupported)
            .expect("session window is unsupported");
        assert!(
            unsupported.message.contains("session"),
            "{}",
            unsupported.message
        );
    }

    #[test]
    fn invalid_absence_grace_is_reported_at_its_winning_spelling() {
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules: [a, b]
    group-by: [User]
    timespan: 5m
    condition: a and not b
rsigma.absence_grace: 30seconds
custom_attributes:
    rsigma.absence_grace: 30seconds
"#,
        );
        let invalid = w
            .iter()
            .find(|w| w.rule == LintRule::InvalidAbsenceGrace)
            .expect("invalid grace");
        assert_eq!(invalid.path, "/custom_attributes/rsigma.absence_grace");
    }

    #[test]
    fn block_grace_wins_over_a_top_level_value() {
        let w = lint(
            r#"
title: Test
correlation:
    type: temporal
    rules: [a, b]
    group-by: [User]
    timespan: 5m
    condition: a and not b
rsigma.absence_grace: bogus
custom_attributes:
    rsigma.absence_grace: 30s
"#,
        );
        assert!(!has_rule(&w, LintRule::InvalidAbsenceGrace));
        assert!(has_rule(&w, LintRule::AbsenceSemantics));
    }

    #[test]
    fn absence_grace_without_absence_is_a_warning() {
        let w = lint(
            r#"
title: Test
correlation:
    type: event_count
    rules: [a]
    group-by: [User]
    timespan: 5m
    condition:
        gte: 3
rsigma.absence_grace: 30s
"#,
        );
        assert!(has_rule(&w, LintRule::AbsenceGraceWithoutAbsence));
        assert!(!has_rule(&w, LintRule::InvalidAbsenceGrace));
    }
}
