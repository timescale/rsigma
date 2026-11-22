use std::collections::HashMap;
use std::sync::Arc;

use rsigma_parser::{
    ConditionExpr, ConditionOperator, CorrelationCondition, CorrelationRule, CorrelationType,
    FieldAlias, WindowMode,
};

use crate::error::{EvalError, Result};

use super::{AbsenceMode, CompiledAbsence, CompiledCondition, CompiledCorrelation, GroupByField};

// =============================================================================
// Compilation
// =============================================================================

/// Compile a parsed `CorrelationRule` into a `CompiledCorrelation`.
pub fn compile_correlation(rule: &CorrelationRule) -> Result<CompiledCorrelation> {
    // Build group-by fields, resolving aliases
    let alias_map: HashMap<&str, &FieldAlias> =
        rule.aliases.iter().map(|a| (a.alias.as_str(), a)).collect();

    let group_by: Vec<GroupByField> = rule
        .group_by
        .iter()
        .map(|field_name| {
            if let Some(alias) = alias_map.get(field_name.as_str()) {
                GroupByField::Aliased {
                    alias: field_name.clone(),
                    mapping: alias.mapping.clone(),
                }
            } else {
                GroupByField::Direct(field_name.clone())
            }
        })
        .collect();

    // Compile condition
    let (condition, extended_expr) = compile_condition(&rule.condition, rule.correlation_type)?;
    let absence = compile_absence(rule, extended_expr.as_ref())?;

    // Window mode and session gap. The parser already enforces this invariant,
    // but re-validate here so correlations built directly through the API (not
    // via the parser) cannot reach the engine in an inconsistent state.
    let gap_secs = rule.gap.as_ref().map(|t| t.seconds);
    match rule.window {
        WindowMode::Session if gap_secs.is_none() => {
            return Err(EvalError::CorrelationError(
                "session window requires a 'gap'".to_string(),
            ));
        }
        WindowMode::Sliding | WindowMode::Tumbling if gap_secs.is_some() => {
            return Err(EvalError::CorrelationError(
                "'gap' is only valid with a session window".to_string(),
            ));
        }
        _ => {}
    }

    // Resolve per-correlation overrides from custom attributes.
    // These mirror the engine-level `rsigma.*` attributes but apply only
    // to this correlation rule, taking precedence over engine defaults.
    let suppress_secs = rule
        .custom_attributes
        .get("rsigma.suppress")
        .and_then(|v| v.as_str())
        .and_then(|s| rsigma_parser::Timespan::parse(s).ok())
        .map(|ts| ts.seconds);

    let action = rule
        .custom_attributes
        .get("rsigma.action")
        .and_then(|v| v.as_str())
        .and_then(|s| {
            s.parse::<crate::correlation_engine::CorrelationAction>()
                .ok()
        });

    let event_mode = rule
        .custom_attributes
        .get("rsigma.correlation_event_mode")
        .and_then(|v| v.as_str())
        .and_then(|s| {
            s.parse::<crate::correlation_engine::CorrelationEventMode>()
                .ok()
        });

    let max_events = rule
        .custom_attributes
        .get("rsigma.max_correlation_events")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<usize>().ok());

    let max_group_entries = rule
        .custom_attributes
        .get("rsigma.max_group_entries")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<usize>().ok());

    let custom_attributes = Arc::new(crate::compiler::yaml_to_json_map(&rule.custom_attributes));

    Ok(CompiledCorrelation {
        id: rule.id.clone(),
        name: rule.name.clone(),
        title: rule.title.clone(),
        level: rule.level,
        tags: rule.tags.clone(),
        description: rule.description.clone(),
        falsepositives: rule.falsepositives.clone(),
        correlation_type: rule.correlation_type,
        rule_refs: rule.rules.clone(),
        group_by,
        timespan_secs: rule.timespan.seconds,
        window_mode: rule.window,
        gap_secs,
        condition,
        extended_expr,
        absence,
        generate: rule.generate,
        suppress_secs,
        action,
        event_mode,
        max_events,
        max_group_entries,
        custom_attributes,
    })
}

/// Compile absence semantics from an extended temporal condition.
///
/// Absence is expressed with the existing extended-condition grammar. This
/// keeps the Sigma correlation type unchanged and mirrors pySigma's SQLite
/// backend, where `a and not b` opens a forward window from `a` and fires at
/// the deadline if `b` never arrives.
///
/// v1 accepts a conjunction of positive and negated rule references. `OR`
/// branches are rejected because "which branch opens the timer" would be
/// ambiguous. `not heartbeat` is the deadman form: the heartbeat anchors the
/// timer, and the window fires after `timespan` of silence.
fn compile_absence(
    rule: &CorrelationRule,
    expr: Option<&ConditionExpr>,
) -> Result<Option<CompiledAbsence>> {
    let Some(expr) = expr else {
        return Ok(None);
    };
    if !matches!(
        rule.correlation_type,
        CorrelationType::Temporal | CorrelationType::TemporalOrdered
    ) {
        return Ok(None);
    }

    let nnf = to_nnf(expr, false);
    if !has_negated_identifier(&nnf) {
        return Ok(None);
    }

    let mut positive_refs = Vec::new();
    let mut negative_refs = Vec::new();
    collect_absence_conjunction(&nnf, &mut positive_refs, &mut negative_refs)?;

    if negative_refs.is_empty() {
        return Ok(None);
    }

    dedup_preserving_order(&mut positive_refs);
    dedup_preserving_order(&mut negative_refs);

    if positive_refs
        .iter()
        .any(|reference| negative_refs.contains(reference))
    {
        return Err(EvalError::CorrelationError(format!(
            "correlation '{}' references the same rule as both positive and negated",
            rule.title
        )));
    }

    for reference in positive_refs.iter().chain(negative_refs.iter()) {
        if !rule.rules.iter().any(|candidate| candidate == reference) {
            return Err(EvalError::CorrelationError(format!(
                "absence condition in correlation '{}' references '{reference}', which is not listed in correlation.rules",
                rule.title
            )));
        }
    }

    if rule.window != WindowMode::Sliding || rule.gap.is_some() {
        return Err(EvalError::CorrelationError(format!(
            "absence correlation '{}' uses a forward fixed window and cannot use window modes or gap",
            rule.title
        )));
    }

    let mode = if positive_refs.is_empty() {
        if negative_refs.len() != 1 {
            return Err(EvalError::CorrelationError(format!(
                "pure-negative absence correlation '{}' must reference exactly one heartbeat rule",
                rule.title
            )));
        }
        if rule.correlation_type == CorrelationType::TemporalOrdered {
            return Err(EvalError::CorrelationError(format!(
                "temporal_ordered absence correlation '{}' must have at least one positive rule",
                rule.title
            )));
        }
        if rule.group_by.is_empty() {
            return Err(EvalError::CorrelationError(format!(
                "pure-negative absence correlation '{}' requires group-by so the deadman timer is scoped to an entity",
                rule.title
            )));
        }
        AbsenceMode::LastNegative
    } else {
        // temporal_ordered orders positive references in the order declared by
        // correlation.rules, not the order they appear in the condition.
        let order: HashMap<&str, usize> = rule
            .rules
            .iter()
            .enumerate()
            .map(|(index, reference)| (reference.as_str(), index))
            .collect();
        positive_refs
            .sort_by_key(|reference| order.get(reference.as_str()).copied().unwrap_or(usize::MAX));
        AbsenceMode::FirstPositive
    };

    Ok(Some(CompiledAbsence {
        mode,
        positive_refs,
        negative_refs,
    }))
}

/// Push negations down to identifiers so conjunctions and disjunctions can be
/// classified consistently.
fn to_nnf(expr: &ConditionExpr, negated: bool) -> ConditionExpr {
    match expr {
        ConditionExpr::Identifier(identifier) => {
            if negated {
                ConditionExpr::Not(Box::new(ConditionExpr::Identifier(identifier.clone())))
            } else {
                ConditionExpr::Identifier(identifier.clone())
            }
        }
        ConditionExpr::Not(inner) => to_nnf(inner, !negated),
        ConditionExpr::And(children) => {
            let mapped = children
                .iter()
                .map(|child| to_nnf(child, negated))
                .collect();
            if negated {
                ConditionExpr::Or(mapped)
            } else {
                ConditionExpr::And(mapped)
            }
        }
        ConditionExpr::Or(children) => {
            let mapped = children
                .iter()
                .map(|child| to_nnf(child, negated))
                .collect();
            if negated {
                ConditionExpr::And(mapped)
            } else {
                ConditionExpr::Or(mapped)
            }
        }
        ConditionExpr::Selector { .. } => expr.clone(),
    }
}

fn has_negated_identifier(expr: &ConditionExpr) -> bool {
    match expr {
        ConditionExpr::Not(inner) => {
            matches!(inner.as_ref(), ConditionExpr::Identifier(_)) || has_negated_identifier(inner)
        }
        ConditionExpr::And(children) | ConditionExpr::Or(children) => {
            children.iter().any(has_negated_identifier)
        }
        ConditionExpr::Identifier(_) | ConditionExpr::Selector { .. } => false,
    }
}

fn collect_absence_conjunction(
    expr: &ConditionExpr,
    positive: &mut Vec<String>,
    negative: &mut Vec<String>,
) -> Result<()> {
    match expr {
        ConditionExpr::Identifier(identifier) => {
            positive.push(identifier.clone());
            Ok(())
        }
        ConditionExpr::Not(inner) => match inner.as_ref() {
            ConditionExpr::Identifier(identifier) => {
                negative.push(identifier.clone());
                Ok(())
            }
            _ => Err(EvalError::CorrelationError(
                "absence conditions only support negated rule references".to_string(),
            )),
        },
        ConditionExpr::And(children) => {
            for child in children {
                collect_absence_conjunction(child, positive, negative)?;
            }
            Ok(())
        }
        ConditionExpr::Or(_) => Err(EvalError::CorrelationError(
            "absence conditions do not support OR branches; use a conjunction of positive and negated rule references".to_string(),
        )),
        ConditionExpr::Selector { .. } => Err(EvalError::CorrelationError(
            "absence conditions do not support selectors".to_string(),
        )),
    }
}

fn dedup_preserving_order(values: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

/// Compile a `CorrelationCondition` into a `CompiledCondition` and optional expression.
fn compile_condition(
    cond: &CorrelationCondition,
    corr_type: CorrelationType,
) -> Result<(CompiledCondition, Option<ConditionExpr>)> {
    match cond {
        CorrelationCondition::Threshold {
            predicates,
            field,
            percentile,
        } => {
            // Numeric aggregations operate on a single numeric field. The
            // Sigma specification does not define how to combine several
            // numeric fields under sum/avg/percentile/median, so reject the
            // multi-field case at compile time rather than silently using
            // only the first field (the historical behavior of this engine,
            // which dropped data without warning).
            if matches!(
                corr_type,
                CorrelationType::ValueSum
                    | CorrelationType::ValueAvg
                    | CorrelationType::ValuePercentile
                    | CorrelationType::ValueMedian
            ) && let Some(fields) = field
                && fields.len() > 1
            {
                return Err(EvalError::CorrelationError(format!(
                    "{:?} correlation requires a single numeric field, but {} were declared: {:?}",
                    corr_type,
                    fields.len(),
                    fields
                )));
            }
            Ok((
                CompiledCondition {
                    field: field.clone(),
                    predicates: predicates
                        .iter()
                        .map(|(op, count)| (*op, *count as f64))
                        .collect(),
                    percentile: *percentile,
                },
                None,
            ))
        }
        CorrelationCondition::Extended(expr) => {
            match corr_type {
                CorrelationType::Temporal | CorrelationType::TemporalOrdered => {
                    // For extended conditions, the threshold is a dummy (gte: 1)
                    // since the actual evaluation is done via the expression tree.
                    Ok((
                        CompiledCondition {
                            field: None,
                            predicates: vec![(ConditionOperator::Gte, 1.0)],
                            percentile: None,
                        },
                        Some(expr.clone()),
                    ))
                }
                _ => Err(EvalError::CorrelationError(
                    "Extended conditions are only supported for temporal correlation types"
                        .to_string(),
                )),
            }
        }
    }
}
