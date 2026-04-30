use std::collections::HashMap;

use serde_yaml::Value;

use crate::ast::*;
use crate::condition::parse_condition;
use crate::error::{Result, SigmaParserError};
use crate::value::Timespan;

use super::{collect_custom_attributes, get_str, get_str_list, parse_related, val_key};

// =============================================================================
// Correlation Rule Parsing
// =============================================================================

/// Parse a correlation rule from a YAML value.
///
/// Reference: pySigma correlations.py SigmaCorrelationRule.from_dict
pub(super) fn parse_correlation_rule(value: &Value) -> Result<CorrelationRule> {
    let m = value
        .as_mapping()
        .ok_or_else(|| SigmaParserError::InvalidCorrelation("Expected a YAML mapping".into()))?;

    let title = get_str(m, "title")
        .ok_or_else(|| SigmaParserError::MissingField("title".into()))?
        .to_string();

    let corr_val = m
        .get(val_key("correlation"))
        .ok_or_else(|| SigmaParserError::MissingField("correlation".into()))?;
    let corr = corr_val.as_mapping().ok_or_else(|| {
        SigmaParserError::InvalidCorrelation("correlation must be a mapping".into())
    })?;

    // Correlation type (required)
    let type_str = get_str(corr, "type")
        .ok_or_else(|| SigmaParserError::InvalidCorrelation("Missing correlation type".into()))?;
    let correlation_type: CorrelationType = type_str.parse().map_err(|_| {
        SigmaParserError::InvalidCorrelation(format!("Unknown correlation type: {type_str}"))
    })?;

    // Rules references
    let rules = match corr.get(val_key("rules")) {
        Some(Value::Sequence(seq)) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    };

    // Group-by
    let group_by = match corr.get(val_key("group-by")) {
        Some(Value::Sequence(seq)) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    };

    // Timespan (required) — accept both "timeframe" (Sigma standard) and "timespan"
    let timespan_str = get_str(corr, "timeframe")
        .or_else(|| get_str(corr, "timespan"))
        .ok_or_else(|| SigmaParserError::InvalidCorrelation("Missing timeframe".into()))?;
    let timespan = Timespan::parse(timespan_str)?;

    // Generate flag - Sigma correlation schema defines `generate` at document root.
    // Nested `correlation.generate` is accepted for backward compatibility.
    let generate = m
        .get(val_key("generate"))
        .and_then(|v| v.as_bool())
        .or_else(|| corr.get(val_key("generate")).and_then(|v| v.as_bool()))
        .unwrap_or(false);

    // Condition
    let condition = parse_correlation_condition(corr, correlation_type)?;

    // Aliases
    let aliases = parse_correlation_aliases(corr);

    // Top-level keys from the Sigma correlation-rules JSON schema plus keys this
    // parser reads from the document root (including common extensions).
    let standard_correlation_keys: &[&str] = &[
        "author",
        "correlation",
        "custom_attributes",
        "date",
        "description",
        "falsepositives",
        "fields",
        "generate",
        "id",
        "level",
        "license",
        "modified",
        "name",
        "references",
        "related",
        "scope",
        "status",
        "tags",
        "taxonomy",
        "title",
    ];
    let custom_attributes = collect_custom_attributes(m, standard_correlation_keys);

    Ok(CorrelationRule {
        title,
        id: get_str(m, "id").map(|s| s.to_string()),
        name: get_str(m, "name").map(|s| s.to_string()),
        status: get_str(m, "status").and_then(|s| s.parse().ok()),
        description: get_str(m, "description").map(|s| s.to_string()),
        author: get_str(m, "author").map(|s| s.to_string()),
        date: get_str(m, "date").map(|s| s.to_string()),
        modified: get_str(m, "modified").map(|s| s.to_string()),
        related: parse_related(m.get(val_key("related"))),
        references: get_str_list(m, "references"),
        taxonomy: get_str(m, "taxonomy").map(|s| s.to_string()),
        license: get_str(m, "license").map(|s| s.to_string()),
        tags: get_str_list(m, "tags"),
        fields: get_str_list(m, "fields"),
        falsepositives: get_str_list(m, "falsepositives"),
        level: get_str(m, "level").and_then(|s| s.parse().ok()),
        scope: get_str_list(m, "scope"),
        correlation_type,
        rules,
        group_by,
        timespan,
        condition,
        aliases,
        generate,
        custom_attributes,
    })
}

/// Parse a correlation condition (either threshold dict or extended string).
///
/// Reference: pySigma correlations.py SigmaCorrelationCondition.from_dict
fn parse_correlation_condition(
    corr: &serde_yaml::Mapping,
    correlation_type: CorrelationType,
) -> Result<CorrelationCondition> {
    let condition_val = corr.get(val_key("condition"));

    match condition_val {
        Some(Value::Mapping(cm)) => {
            // Threshold condition: { gte: 100 } or range { gt: 100, lte: 200, field: "username" }
            let operators = ["lt", "lte", "gt", "gte", "eq", "neq"];
            let mut predicates = Vec::new();

            for &op_str in &operators {
                if let Some(val) = cm.get(val_key(op_str))
                    && let Ok(parsed_op) = op_str.parse::<ConditionOperator>()
                {
                    let count = val
                        .as_u64()
                        .or_else(|| val.as_i64().map(|i| i as u64))
                        .ok_or_else(|| {
                            SigmaParserError::InvalidCorrelation(format!(
                                "correlation condition operator '{op_str}' requires a numeric value, got: {val:?}"
                            ))
                        })?;
                    predicates.push((parsed_op, count));
                }
            }

            if predicates.is_empty() {
                return Err(SigmaParserError::InvalidCorrelation(
                    "Correlation condition must have an operator (lt, lte, gt, gte, eq, neq)"
                        .into(),
                ));
            }

            let field = match cm.get(val_key("field")) {
                Some(Value::String(s)) => Some(vec![s.clone()]),
                Some(Value::Sequence(seq)) => {
                    let fields: Vec<String> = seq
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                    if fields.is_empty() {
                        None
                    } else {
                        Some(fields)
                    }
                }
                _ => None,
            };

            let percentile = cm.get(val_key("percentile")).and_then(|v| v.as_u64());

            Ok(CorrelationCondition::Threshold {
                predicates,
                field,
                percentile,
            })
        }
        Some(Value::String(expr_str)) => {
            // Extended condition for temporal types: "rule_a and rule_b"
            let expr = parse_condition(expr_str)?;
            Ok(CorrelationCondition::Extended(expr))
        }
        None => {
            // Default for temporal types: all rules must match
            match correlation_type {
                CorrelationType::Temporal | CorrelationType::TemporalOrdered => {
                    Ok(CorrelationCondition::Threshold {
                        predicates: vec![(ConditionOperator::Gte, 1)],
                        field: None,
                        percentile: None,
                    })
                }
                _ => Err(SigmaParserError::InvalidCorrelation(
                    "Non-temporal correlation rule requires a condition".into(),
                )),
            }
        }
        _ => Err(SigmaParserError::InvalidCorrelation(
            "Correlation condition must be a mapping or string".into(),
        )),
    }
}

/// Parse correlation field aliases.
fn parse_correlation_aliases(corr: &serde_yaml::Mapping) -> Vec<FieldAlias> {
    let Some(Value::Mapping(aliases_map)) = corr.get(val_key("aliases")) else {
        return Vec::new();
    };

    aliases_map
        .iter()
        .filter_map(|(alias_key, alias_val)| {
            let alias = alias_key.as_str()?.to_string();
            let mapping_map = alias_val.as_mapping()?;
            let mapping: HashMap<String, String> = mapping_map
                .iter()
                .filter_map(|(k, v)| Some((k.as_str()?.to_string(), v.as_str()?.to_string())))
                .collect();
            Some(FieldAlias { alias, mapping })
        })
        .collect()
}
