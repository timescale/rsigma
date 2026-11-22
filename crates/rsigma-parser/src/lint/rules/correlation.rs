use crate::ast::ConditionExpr;
use crate::condition::parse_condition;

use super::super::{LintRule, LintWarning, err, get_str, info, key};

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
    if let Some(rules) = corr.get(key("rules")) {
        if let Some(seq) = rules.as_sequence()
            && seq.is_empty()
        {
            warnings.push(super::super::warning(
                LintRule::EmptyCorrelationRules,
                "correlation.rules should not be empty",
                "/correlation/rules",
            ));
        }
    } else {
        warnings.push(err(
            LintRule::MissingCorrelationRules,
            "missing required field 'correlation.rules'",
            "/correlation/rules",
        ));
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
    // Accept both spellings: the `rsigma.*` extension namespace (top-level
    // `rsigma.window` / `rsigma.gap`) is primary, and the first-class
    // `correlation.window` / `correlation.gap` keys are aliases. The `rsigma.*`
    // spelling wins when both are present, and the diagnostic points at it.
    // Presence is checked before type so a key set to a non-string value (e.g.
    // an unquoted `gap: 300`) is reported as invalid instead of missing.
    let (window, window_present, window_ptr) = match m.get(key("rsigma.window")) {
        Some(v) => (v.as_str(), true, "/rsigma.window"),
        None => match corr.get(key("window")) {
            Some(v) => (v.as_str(), true, "/correlation/window"),
            None => (None, false, "/correlation/window"),
        },
    };
    let (gap, gap_present, gap_ptr) = match m.get(key("rsigma.gap")) {
        Some(v) => (v.as_str(), true, "/rsigma.gap"),
        None => match corr.get(key("gap")) {
            Some(v) => (v.as_str(), true, "/correlation/gap"),
            None => (None, false, "/correlation/gap"),
        },
    };

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

    // ── absence semantics ────────────────────────────────────────────────
    if matches!(corr_type, Some("temporal" | "temporal_ordered"))
        && let Some(condition) = get_str(corr, "condition")
        && let Ok(expr) = parse_condition(condition)
        && has_negated_identifier(&expr)
    {
        warnings.push(info(
            LintRule::AbsenceSemantics,
            "negated temporal references use deferred absence semantics (an rsigma extension): the window fires at its deadline if the negated rule never arrives; static conversion backends reject it",
            "/correlation/condition",
        ));
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

fn has_negated_identifier(expr: &ConditionExpr) -> bool {
    match expr {
        ConditionExpr::Not(inner) => contains_identifier(inner) || has_negated_identifier(inner),
        ConditionExpr::And(children) | ConditionExpr::Or(children) => {
            children.iter().any(has_negated_identifier)
        }
        ConditionExpr::Identifier(_) | ConditionExpr::Selector { .. } => false,
    }
}

fn contains_identifier(expr: &ConditionExpr) -> bool {
    match expr {
        ConditionExpr::Identifier(_) => true,
        ConditionExpr::Not(inner) => contains_identifier(inner),
        ConditionExpr::And(children) | ConditionExpr::Or(children) => {
            children.iter().any(contains_identifier)
        }
        ConditionExpr::Selector { .. } => false,
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
    fn negated_temporal_condition_warns_about_absence_semantics() {
        let w = lint(
            r#"
title: Login without MFA
correlation:
    type: temporal
    rules:
        - login-success
        - mfa-success
    group-by:
        - User
    timespan: 5m
    condition: login-success and not mfa-success
"#,
        );
        assert!(has_rule(&w, LintRule::AbsenceSemantics));
        assert!(w.iter().any(|warning| {
            warning.rule == LintRule::AbsenceSemantics && warning.severity == Severity::Info
        }));
    }

    #[test]
    fn positive_temporal_or_condition_has_no_absence_warning() {
        let w = lint(
            r#"
title: Either Login
correlation:
    type: temporal
    rules:
        - ssh-login
        - vpn-login
    group-by:
        - User
    timespan: 5m
    condition: ssh-login or vpn-login
"#,
        );
        assert!(!has_rule(&w, LintRule::AbsenceSemantics));
    }
}
