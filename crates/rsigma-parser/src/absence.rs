//! Analysis of negated rule references in temporal correlation conditions.
//!
//! A string `condition:` such as `login and not mfa` names the rules a
//! correlation aggregates. Negating one of them means the correlation must
//! fire when that rule did *not* match in the window, which the rsigma engine
//! evaluates at a deadline instead of the moment the positive rule matches.
//! This module decides whether a condition has that shape, and rejects the
//! shapes a deadline cannot decide.
//!
//! The parser already requires every identifier to appear in
//! `correlation.rules`; the engine calls [`analyze_absence`] on the compiled
//! rule so a pipeline or overlay that changes the window cannot introduce an
//! unsupported shape.

use std::fmt;

use crate::ast::{
    ConditionExpr, CorrelationCondition, CorrelationRule, CorrelationType, WindowMode,
};
use crate::condition::MAX_CONDITION_TREE_DEPTH;

/// Whether an absence correlation opens an obligation from a positive match or
/// watches a single heartbeat rule for silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsenceKind {
    /// A positive condition matched and one or more negated rules must stay
    /// absent until the deadline.
    Obligation,
    /// A single heartbeat rule stopped arriving.
    Deadman,
}

/// The normalized shape of an absence correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbsenceShape {
    /// Whether this is an obligation or a deadman correlation.
    pub kind: AbsenceKind,
    /// The positive part of the condition, in negation normal form, or `None`
    /// for the deadman form.
    pub positive: Option<ConditionExpr>,
    /// Distinct positive identifiers in `rules:` order, for the ordered
    /// matcher to use as stages.
    pub positive_refs: Vec<String>,
    /// Negated identifiers in order of first appearance.
    pub negated: Vec<String>,
}

/// Why a condition cannot be evaluated as an absence correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbsenceShapeError {
    /// A negation appears under an `or`, where it cannot be decided at one
    /// deadline.
    NegationUnderOr,
    /// A selector (`1 of ...`, `all of ...`) appears in the condition.
    Selector,
    /// The same rule is used both positively and negated.
    RefBothWays(String),
    /// A `session` window cannot be decided at a deadline.
    SessionWindow,
    /// A `temporal_ordered` positive part is not a conjunction of identifiers.
    OrderedDisjunction,
    /// The deadman form names more than one heartbeat rule.
    DeadmanMultipleRefs,
    /// The deadman form needs a non-empty `group-by`.
    DeadmanWithoutGroupBy,
    /// The deadman form requires `temporal`, not `temporal_ordered`.
    DeadmanOrdered,
    /// The deadman form requires a `sliding` window.
    DeadmanNotSliding,
    /// The condition tree is deeper than [`MAX_CONDITION_TREE_DEPTH`].
    TooDeep,
}

impl fmt::Display for AbsenceShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbsenceShapeError::NegationUnderOr => write!(
                f,
                "a negation under `or` cannot be decided at a deadline; negated rules may only \
                 appear in the top-level `and`"
            ),
            AbsenceShapeError::Selector => write!(
                f,
                "selectors (`1 of ...`, `all of ...`) are not supported in an absence condition; \
                 name the rules explicitly"
            ),
            AbsenceShapeError::RefBothWays(name) => write!(
                f,
                "rule `{name}` is used both positively and negated; a rule may appear on one \
                 side only"
            ),
            AbsenceShapeError::SessionWindow => write!(
                f,
                "a `session` window cannot be decided at a deadline; use `sliding` or `tumbling`"
            ),
            AbsenceShapeError::OrderedDisjunction => write!(
                f,
                "a `temporal_ordered` absence condition must be a conjunction of rules; \
                 move any `or` into the negated part or use `temporal`"
            ),
            AbsenceShapeError::DeadmanMultipleRefs => write!(
                f,
                "a deadman condition watches one heartbeat rule; negate exactly one rule"
            ),
            AbsenceShapeError::DeadmanWithoutGroupBy => write!(
                f,
                "a deadman condition needs a `group-by` so it can tell which entity went silent"
            ),
            AbsenceShapeError::DeadmanOrdered => write!(
                f,
                "a deadman condition requires `type: temporal`; `temporal_ordered` has no \
                 positive stage to order"
            ),
            AbsenceShapeError::DeadmanNotSliding => write!(
                f,
                "a deadman condition requires a `sliding` window; a bucket end would not match \
                 the heartbeat interval"
            ),
            AbsenceShapeError::TooDeep => write!(
                f,
                "the condition tree is deeper than {MAX_CONDITION_TREE_DEPTH}; simplify the \
                 condition"
            ),
        }
    }
}

impl std::error::Error for AbsenceShapeError {}

/// Analyze a correlation rule's condition for absence semantics.
///
/// Returns `Ok(None)` when the rule is not a `temporal` or `temporal_ordered`
/// correlation, when its condition is a threshold, or when the condition has
/// no negated rule reference after normalization. Returns `Ok(Some(shape))`
/// when the engine must evaluate it at a deadline.
///
/// ```
/// use rsigma_parser::{analyze_absence, parse_sigma_yaml, AbsenceKind};
///
/// let yaml = r#"
/// title: Host stopped sending heartbeats
/// correlation:
///     type: temporal
///     group-by:
///         - host.id
///     timespan: 10m
///     condition: not host_heartbeat
/// "#;
/// let collection = parse_sigma_yaml(yaml).unwrap();
/// let shape = analyze_absence(&collection.correlations[0]).unwrap().unwrap();
/// assert_eq!(shape.kind, AbsenceKind::Deadman);
/// assert_eq!(shape.negated, ["host_heartbeat"]);
/// assert!(shape.positive.is_none());
/// ```
pub fn analyze_absence(rule: &CorrelationRule) -> Result<Option<AbsenceShape>, AbsenceShapeError> {
    let CorrelationCondition::Extended(expr) = &rule.condition else {
        return Ok(None);
    };
    analyze_absence_parts(
        expr,
        rule.correlation_type,
        rule.window,
        &rule.rules,
        !rule.group_by.is_empty(),
    )
}

/// Analyze an extended condition expression with the correlation's type,
/// window mode, `rules:` list, and whether it has a `group-by`.
///
/// This is the lower-level entry point for the linter, which resolves the
/// window from raw YAML before the parser's pipeline and overlay steps.
pub fn analyze_absence_parts(
    expr: &ConditionExpr,
    correlation_type: CorrelationType,
    window: WindowMode,
    rules: &[String],
    has_group_by: bool,
) -> Result<Option<AbsenceShape>, AbsenceShapeError> {
    if !matches!(
        correlation_type,
        CorrelationType::Temporal | CorrelationType::TemporalOrdered
    ) {
        return Ok(None);
    }

    let normalized = normalize(expr, false, 1)?;

    // A negation around a selector does not make an absence condition: its
    // identifiers come from the detection set, not from `rules:`.
    if !has_negated_identifier(&normalized) {
        return Ok(None);
    }

    if window == WindowMode::Session {
        return Err(AbsenceShapeError::SessionWindow);
    }

    let mut conjuncts: Vec<&ConditionExpr> = Vec::new();
    flatten_top_level_and(&normalized, &mut conjuncts);

    let mut negated: Vec<String> = Vec::new();
    let mut positive: Vec<&ConditionExpr> = Vec::new();
    for conjunct in conjuncts {
        if let ConditionExpr::Not(child) = conjunct
            && let ConditionExpr::Identifier(name) = child.as_ref()
        {
            if !negated.iter().any(|seen| seen == name) {
                negated.push(name.clone());
            }
            continue;
        }
        if contains_selector(conjunct) {
            return Err(AbsenceShapeError::Selector);
        }
        if contains_negation(conjunct) {
            return Err(AbsenceShapeError::NegationUnderOr);
        }
        positive.push(conjunct);
    }

    let mut positive_ids: Vec<String> = Vec::new();
    for conjunct in &positive {
        collect_identifiers(conjunct, &mut positive_ids);
    }
    for name in &negated {
        if positive_ids.iter().any(|seen| seen == name) {
            return Err(AbsenceShapeError::RefBothWays(name.clone()));
        }
    }

    if positive.is_empty() {
        if negated.len() != 1 {
            return Err(AbsenceShapeError::DeadmanMultipleRefs);
        }
        if !has_group_by {
            return Err(AbsenceShapeError::DeadmanWithoutGroupBy);
        }
        if correlation_type == CorrelationType::TemporalOrdered {
            return Err(AbsenceShapeError::DeadmanOrdered);
        }
        if window != WindowMode::Sliding {
            return Err(AbsenceShapeError::DeadmanNotSliding);
        }
        return Ok(Some(AbsenceShape {
            kind: AbsenceKind::Deadman,
            positive: None,
            positive_refs: Vec::new(),
            negated,
        }));
    }

    if correlation_type == CorrelationType::TemporalOrdered
        && positive
            .iter()
            .any(|conjunct| !matches!(conjunct, ConditionExpr::Identifier(_)))
    {
        return Err(AbsenceShapeError::OrderedDisjunction);
    }

    let positive_expr = match positive.as_slice() {
        [single] => (*single).clone(),
        many => ConditionExpr::And(many.iter().map(|node| (*node).clone()).collect()),
    };
    let mut positive_refs: Vec<String> = Vec::new();
    for rule in rules {
        if positive_ids.contains(rule) && !positive_refs.contains(rule) {
            positive_refs.push(rule.clone());
        }
    }

    Ok(Some(AbsenceShape {
        kind: AbsenceKind::Obligation,
        positive: Some(positive_expr),
        positive_refs,
        negated,
    }))
}

/// Push negations down to identifiers. A negation around a selector is
/// dropped, since selectors never take part in an absence condition.
fn normalize(
    expr: &ConditionExpr,
    negated: bool,
    depth: usize,
) -> Result<ConditionExpr, AbsenceShapeError> {
    if depth > MAX_CONDITION_TREE_DEPTH {
        return Err(AbsenceShapeError::TooDeep);
    }
    match expr {
        ConditionExpr::Identifier(name) => {
            let identifier = ConditionExpr::Identifier(name.clone());
            if negated {
                Ok(ConditionExpr::Not(Box::new(identifier)))
            } else {
                Ok(identifier)
            }
        }
        ConditionExpr::Not(child) => normalize(child, !negated, depth + 1),
        ConditionExpr::And(children) => {
            let children = children
                .iter()
                .map(|child| normalize(child, negated, depth + 1))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(if negated {
                ConditionExpr::Or(children)
            } else {
                ConditionExpr::And(children)
            })
        }
        ConditionExpr::Or(children) => {
            let children = children
                .iter()
                .map(|child| normalize(child, negated, depth + 1))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(if negated {
                ConditionExpr::And(children)
            } else {
                ConditionExpr::Or(children)
            })
        }
        ConditionExpr::Selector { .. } => Ok(expr.clone()),
    }
}

/// Whether any `not <identifier>` remains in a normalized expression.
fn has_negated_identifier(expr: &ConditionExpr) -> bool {
    let mut stack = vec![expr];
    while let Some(node) = stack.pop() {
        match node {
            ConditionExpr::Not(child) => {
                if matches!(child.as_ref(), ConditionExpr::Identifier(_)) {
                    return true;
                }
                stack.push(child);
            }
            ConditionExpr::And(children) | ConditionExpr::Or(children) => {
                stack.extend(children.iter());
            }
            ConditionExpr::Identifier(_) | ConditionExpr::Selector { .. } => {}
        }
    }
    false
}

/// Flatten nested top-level `and` nodes into their conjuncts.
fn flatten_top_level_and<'a>(expr: &'a ConditionExpr, out: &mut Vec<&'a ConditionExpr>) {
    match expr {
        ConditionExpr::And(children) => {
            for child in children {
                flatten_top_level_and(child, out);
            }
        }
        other => out.push(other),
    }
}

/// Whether any selector appears anywhere under `expr`.
fn contains_selector(expr: &ConditionExpr) -> bool {
    let mut stack = vec![expr];
    while let Some(node) = stack.pop() {
        match node {
            ConditionExpr::Selector { .. } => return true,
            ConditionExpr::And(children) | ConditionExpr::Or(children) => {
                stack.extend(children.iter());
            }
            ConditionExpr::Not(child) => stack.push(child),
            ConditionExpr::Identifier(_) => {}
        }
    }
    false
}

/// Whether any negation remains anywhere under `expr`.
fn contains_negation(expr: &ConditionExpr) -> bool {
    let mut stack = vec![expr];
    while let Some(node) = stack.pop() {
        match node {
            ConditionExpr::Not(_) => return true,
            ConditionExpr::And(children) | ConditionExpr::Or(children) => {
                stack.extend(children.iter());
            }
            ConditionExpr::Identifier(_) | ConditionExpr::Selector { .. } => {}
        }
    }
    false
}

/// Collect every identifier under `expr`, in order of first appearance.
fn collect_identifiers(expr: &ConditionExpr, out: &mut Vec<String>) {
    let mut stack = vec![expr];
    while let Some(node) = stack.pop() {
        match node {
            ConditionExpr::Identifier(name) => {
                if !out.iter().any(|seen| seen == name) {
                    out.push(name.clone());
                }
            }
            ConditionExpr::And(children) | ConditionExpr::Or(children) => {
                stack.extend(children.iter().rev());
            }
            ConditionExpr::Not(child) => stack.push(child),
            ConditionExpr::Selector { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_condition;

    fn analyze(
        condition: &str,
        correlation_type: CorrelationType,
        window: WindowMode,
        rules: &[&str],
        has_group_by: bool,
    ) -> Result<Option<AbsenceShape>, AbsenceShapeError> {
        let expr = parse_condition(condition).unwrap();
        let rules: Vec<String> = rules.iter().map(|rule| (*rule).to_string()).collect();
        analyze_absence_parts(&expr, correlation_type, window, &rules, has_group_by)
    }

    fn obligation(condition: &str) -> AbsenceShape {
        analyze(
            condition,
            CorrelationType::Temporal,
            WindowMode::Sliding,
            &["a", "b", "c", "d"],
            true,
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn single_negation_is_an_obligation() {
        let shape = obligation("a and not b");
        assert_eq!(shape.kind, AbsenceKind::Obligation);
        assert_eq!(shape.negated, ["b"]);
        assert_eq!(shape.positive_refs, ["a"]);
    }

    #[test]
    fn negated_disjunction_is_accepted() {
        let shape = obligation("a and not (b or d)");
        assert_eq!(shape.kind, AbsenceKind::Obligation);
        assert_eq!(shape.negated, ["b", "d"]);
        assert_eq!(shape.positive_refs, ["a"]);
    }

    #[test]
    fn positive_disjunction_is_accepted_under_temporal() {
        let shape = obligation("(a or c) and not b");
        assert_eq!(shape.kind, AbsenceKind::Obligation);
        assert_eq!(shape.positive_refs, ["a", "c"]);
        assert_eq!(shape.negated, ["b"]);
    }

    #[test]
    fn positive_refs_follow_rules_order_and_negated_follow_the_condition() {
        let shape = obligation("(c or a) and not d and not b");
        assert_eq!(shape.positive_refs, ["a", "c"]);
        assert_eq!(shape.negated, ["d", "b"]);
    }

    #[test]
    fn duplicate_rules_entries_count_once() {
        let shape = analyze(
            "a and b and not c",
            CorrelationType::TemporalOrdered,
            WindowMode::Sliding,
            &["a", "a", "b", "c"],
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(shape.positive_refs, ["a", "b"]);
    }

    #[test]
    fn selector_inside_a_negated_disjunction_is_rejected() {
        assert_eq!(
            obligation_error("a and not (b or 1 of x*)"),
            AbsenceShapeError::Selector
        );
    }

    #[test]
    fn rule_used_both_ways_through_a_disjunction_is_rejected() {
        assert_eq!(
            obligation_error("(a or b) and not b"),
            AbsenceShapeError::RefBothWays("b".into())
        );
    }

    fn obligation_error(condition: &str) -> AbsenceShapeError {
        analyze(
            condition,
            CorrelationType::Temporal,
            WindowMode::Sliding,
            &["a", "b", "c", "d"],
            true,
        )
        .unwrap_err()
    }

    #[test]
    fn deadman_shape() {
        let shape = analyze(
            "not host_heartbeat",
            CorrelationType::Temporal,
            WindowMode::Sliding,
            &["host_heartbeat"],
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(shape.kind, AbsenceKind::Deadman);
        assert_eq!(shape.negated, ["host_heartbeat"]);
        assert!(shape.positive.is_none());
        assert!(shape.positive_refs.is_empty());
    }

    #[test]
    fn double_negation_is_not_absence() {
        assert!(
            analyze(
                "not not a",
                CorrelationType::Temporal,
                WindowMode::Sliding,
                &["a"],
                true
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn negated_selector_is_not_absence() {
        assert!(
            analyze(
                "a and not 1 of sel_*",
                CorrelationType::Temporal,
                WindowMode::Sliding,
                &["a"],
                true
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn negation_under_or_is_rejected() {
        assert_eq!(
            analyze(
                "a or not b",
                CorrelationType::Temporal,
                WindowMode::Sliding,
                &["a", "b"],
                true
            )
            .unwrap_err(),
            AbsenceShapeError::NegationUnderOr
        );
        assert_eq!(
            analyze(
                "not (b and d)",
                CorrelationType::Temporal,
                WindowMode::Sliding,
                &["b", "d"],
                true
            )
            .unwrap_err(),
            AbsenceShapeError::NegationUnderOr
        );
    }

    #[test]
    fn selector_in_an_absence_condition_is_rejected() {
        assert_eq!(
            analyze(
                "a and 1 of sel_* and not b",
                CorrelationType::Temporal,
                WindowMode::Sliding,
                &["a", "b"],
                true
            )
            .unwrap_err(),
            AbsenceShapeError::Selector
        );
    }

    #[test]
    fn rule_used_both_ways_is_rejected() {
        assert_eq!(
            analyze(
                "a and not a",
                CorrelationType::Temporal,
                WindowMode::Sliding,
                &["a"],
                true
            )
            .unwrap_err(),
            AbsenceShapeError::RefBothWays("a".to_string())
        );
    }

    #[test]
    fn session_window_is_rejected() {
        assert_eq!(
            analyze(
                "a and not b",
                CorrelationType::Temporal,
                WindowMode::Session,
                &["a", "b"],
                true
            )
            .unwrap_err(),
            AbsenceShapeError::SessionWindow
        );
    }

    #[test]
    fn ordered_disjunction_is_rejected() {
        assert_eq!(
            analyze(
                "(a or c) and not b",
                CorrelationType::TemporalOrdered,
                WindowMode::Sliding,
                &["a", "b", "c"],
                true
            )
            .unwrap_err(),
            AbsenceShapeError::OrderedDisjunction
        );
    }

    #[test]
    fn deadman_restrictions_are_rejected() {
        assert_eq!(
            analyze(
                "not a and not b",
                CorrelationType::Temporal,
                WindowMode::Sliding,
                &["a", "b"],
                true
            )
            .unwrap_err(),
            AbsenceShapeError::DeadmanMultipleRefs
        );
        assert_eq!(
            analyze(
                "not a",
                CorrelationType::Temporal,
                WindowMode::Sliding,
                &["a"],
                false
            )
            .unwrap_err(),
            AbsenceShapeError::DeadmanWithoutGroupBy
        );
        assert_eq!(
            analyze(
                "not a",
                CorrelationType::TemporalOrdered,
                WindowMode::Sliding,
                &["a"],
                true
            )
            .unwrap_err(),
            AbsenceShapeError::DeadmanOrdered
        );
        assert_eq!(
            analyze(
                "not a",
                CorrelationType::Temporal,
                WindowMode::Tumbling,
                &["a"],
                true
            )
            .unwrap_err(),
            AbsenceShapeError::DeadmanNotSliding
        );
    }

    #[test]
    fn non_temporal_types_are_ignored() {
        assert!(
            analyze(
                "a and not b",
                CorrelationType::EventCount,
                WindowMode::Sliding,
                &["a", "b"],
                true
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn too_deep_tree_is_rejected() {
        let mut expr = ConditionExpr::Identifier("a".into());
        for _ in 0..MAX_CONDITION_TREE_DEPTH {
            expr = ConditionExpr::Not(Box::new(expr));
        }
        assert_eq!(
            analyze_absence_parts(
                &expr,
                CorrelationType::Temporal,
                WindowMode::Sliding,
                &["a".to_string()],
                true
            )
            .unwrap_err(),
            AbsenceShapeError::TooDeep
        );
    }
}
