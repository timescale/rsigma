use std::collections::HashMap;
use std::sync::Arc;

use rsigma_parser::{
    ConditionExpr, ConditionOperator, CorrelationCondition, CorrelationRule, CorrelationType,
    FieldAlias,
};

use crate::error::{EvalError, Result};

use super::{CompiledCondition, CompiledCorrelation, GroupByField};

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

    let custom_attributes = Arc::new(crate::compiler::yaml_to_json_map(&rule.custom_attributes));

    Ok(CompiledCorrelation {
        id: rule.id.clone(),
        name: rule.name.clone(),
        title: rule.title.clone(),
        level: rule.level,
        tags: rule.tags.clone(),
        correlation_type: rule.correlation_type,
        rule_refs: rule.rules.clone(),
        group_by,
        timespan_secs: rule.timespan.seconds,
        condition,
        extended_expr,
        generate: rule.generate,
        suppress_secs,
        action,
        event_mode,
        max_events,
        custom_attributes,
    })
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
        } => Ok((
            CompiledCondition {
                field: field.clone(),
                predicates: predicates
                    .iter()
                    .map(|(op, count)| (*op, *count as f64))
                    .collect(),
                percentile: *percentile,
            },
            None,
        )),
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
