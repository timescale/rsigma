use std::collections::{HashMap, HashSet};

use yaml_serde::Value;

use crate::ast::*;
use crate::condition::parse_condition;
use crate::diagnostic::CollectionDiagnostic;
use crate::error::{Result, SigmaParserError};
use crate::value::Timespan;

use super::{
    collect_custom_attributes, get_str, get_str_list, parse_enum_with_warn, parse_related,
    parse_sigma_version, val_key,
};

/// Top-level keys from the Sigma correlation-rules JSON schema plus keys this
/// parser reads from the document root (including common extensions).
pub(crate) const STANDARD_CORRELATION_KEYS: &[&str] = &[
    "author",
    "correlation",
    "sigma-version",
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

// =============================================================================
// Correlation Rule Parsing
// =============================================================================

/// Parse a correlation rule from a YAML value.
///
/// `warnings` receives non-fatal issues (invalid `status` / `level`
/// values, malformed `related:` entries); see
/// [`parse_detection_rule`](super::detection::parse_detection_rule).
///
/// Reference: pySigma correlations.py SigmaCorrelationRule.from_dict
pub(super) fn parse_correlation_rule(
    value: &Value,
    warnings: &mut Vec<CollectionDiagnostic>,
) -> Result<CorrelationRule> {
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
    let rules_present = corr.contains_key(val_key("rules"));
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
    if timespan.seconds == 0 {
        return Err(SigmaParserError::InvalidCorrelation(
            "Correlation timeframe must be greater than zero".into(),
        ));
    }

    // Window mode (optional, defaults to sliding) and the session `gap` from
    // the first-class `correlation.window` / `correlation.gap` keys. The
    // `rsigma.window` / `rsigma.gap` custom attributes override them below,
    // once the custom attributes are collected.
    let window = match corr.get(val_key("window")) {
        Some(v) => parse_window_value("window", v)?,
        None => WindowMode::default(),
    };
    let gap = corr
        .get(val_key("gap"))
        .map(|v| parse_gap_value("gap", v))
        .transpose()?;

    // Generate flag - Sigma correlation schema defines `generate` at document root.
    // Nested `correlation.generate` is accepted for backward compatibility.
    let generate = m
        .get(val_key("generate"))
        .and_then(|v| v.as_bool())
        .or_else(|| corr.get(val_key("generate")).and_then(|v| v.as_bool()))
        .unwrap_or(false);

    // Condition
    let condition = parse_correlation_condition(corr, correlation_type, &rules)?;
    let rules = resolve_condition_rules(&condition, rules, rules_present)?;

    // Aliases
    let aliases = parse_correlation_aliases(corr);

    let custom_attributes = collect_custom_attributes(m, STANDARD_CORRELATION_KEYS);

    let mut rule = CorrelationRule {
        title,
        sigma_version: parse_sigma_version(m, warnings),
        id: get_str(m, "id").map(|s| s.to_string()),
        name: get_str(m, "name").map(|s| s.to_string()),
        status: parse_enum_with_warn(get_str(m, "status"), "status", warnings),
        description: get_str(m, "description").map(|s| s.to_string()),
        author: get_str(m, "author").map(|s| s.to_string()),
        date: get_str(m, "date").map(|s| s.to_string()),
        modified: get_str(m, "modified").map(|s| s.to_string()),
        related: parse_related(m.get(val_key("related")), warnings),
        references: get_str_list(m, "references"),
        taxonomy: get_str(m, "taxonomy").map(|s| s.to_string()),
        license: get_str(m, "license").map(|s| s.to_string()),
        tags: get_str_list(m, "tags"),
        fields: get_str_list(m, "fields"),
        falsepositives: get_str_list(m, "falsepositives"),
        level: parse_enum_with_warn(get_str(m, "level"), "level", warnings),
        scope: get_str_list(m, "scope"),
        correlation_type,
        rules,
        group_by,
        timespan,
        window,
        gap,
        condition,
        aliases,
        generate,
        custom_attributes,
    };
    rule.resolve_window_attributes(true)?;
    Ok(rule)
}

/// Custom attribute that sets a correlation's window mode, overriding
/// `correlation.window`.
pub(crate) const WINDOW_ATTRIBUTE: &str = "rsigma.window";

/// Custom attribute that sets a session window's gap, overriding
/// `correlation.gap`.
pub(crate) const GAP_ATTRIBUTE: &str = "rsigma.gap";

impl CorrelationRule {
    /// Set `window` and `gap` from the `rsigma.window` and `rsigma.gap`
    /// custom attributes after the attributes change, for example after
    /// processing pipelines or ruleset overlays.
    ///
    /// The attributes override `correlation.window` and `correlation.gap`.
    /// A resulting window other than `session` drops the gap, field and
    /// attribute both, since only session windows use one; this lets an
    /// override switch a session rule to `sliding` or `tumbling`. A `session`
    /// window without a gap is an error. Without either attribute, the rule
    /// is left as it is.
    ///
    /// The parser already resolves the attributes, more strictly: a rule
    /// that sets a gap on a non-session window does not parse.
    pub fn apply_window_attributes(&mut self) -> Result<()> {
        if !self.custom_attributes.contains_key(WINDOW_ATTRIBUTE)
            && !self.custom_attributes.contains_key(GAP_ATTRIBUTE)
        {
            return Ok(());
        }
        self.resolve_window_attributes(false)
    }

    /// Resolve the window attributes. `strict` rejects a gap on a
    /// non-session window instead of dropping it.
    pub(crate) fn resolve_window_attributes(&mut self, strict: bool) -> Result<()> {
        if let Some(v) = self.custom_attributes.get(WINDOW_ATTRIBUTE) {
            self.window = parse_window_value(WINDOW_ATTRIBUTE, v)?;
        }
        if let Some(v) = self.custom_attributes.get(GAP_ATTRIBUTE) {
            self.gap = Some(parse_gap_value(GAP_ATTRIBUTE, v)?);
        }
        match self.window {
            WindowMode::Session if self.gap.is_none() => Err(SigmaParserError::InvalidCorrelation(
                "window: session requires a gap (gap: or rsigma.gap:, e.g. 5m)".into(),
            )),
            WindowMode::Sliding | WindowMode::Tumbling if self.gap.is_some() => {
                if strict {
                    return Err(SigmaParserError::InvalidCorrelation(format!(
                        "'gap' is only valid with window: session, not window: {}",
                        self.window.as_str()
                    )));
                }
                self.gap = None;
                self.custom_attributes.remove(GAP_ATTRIBUTE);
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// Parse a window mode value. A non-string value (an unquoted number, say)
/// is a type error rather than an absent key.
fn parse_window_value(key: &str, v: &Value) -> Result<WindowMode> {
    let w = v.as_str().ok_or_else(|| {
        SigmaParserError::InvalidCorrelation(format!(
            "'{key}' must be a string: sliding, tumbling, or session"
        ))
    })?;
    w.parse::<WindowMode>().map_err(|_| {
        SigmaParserError::InvalidCorrelation(format!(
            "Unknown window mode: {w} (expected sliding, tumbling, or session)"
        ))
    })
}

/// Parse a session gap value. An unquoted number is a type error with a hint
/// rather than an absent key.
fn parse_gap_value(key: &str, v: &Value) -> Result<Timespan> {
    let g = v.as_str().ok_or_else(|| {
        SigmaParserError::InvalidCorrelation(format!(
            "'{key}' must be a string duration like \"5m\" (quote numeric values)"
        ))
    })?;
    Timespan::parse(g)
}

/// Parse a correlation condition (either threshold dict or extended string).
///
/// Reference: pySigma correlations.py SigmaCorrelationCondition.from_dict
fn parse_correlation_condition(
    corr: &yaml_serde::Mapping,
    correlation_type: CorrelationType,
    rules: &[String],
) -> Result<CorrelationCondition> {
    let condition_val = corr.get(val_key("condition"));

    match condition_val {
        Some(Value::Mapping(cm)) => {
            // Threshold condition: { gte: 100 } or range { gt: 100, lte: 200, field: "username" }
            let operators = ["lt", "lte", "gt", "gte", "eq", "neq"];
            let allowed_keys = ["lt", "lte", "gt", "gte", "eq", "neq", "field", "percentile"];
            for key in cm.keys() {
                let Some(key) = key.as_str() else {
                    return Err(SigmaParserError::InvalidCorrelation(
                        "Correlation condition keys must be strings".into(),
                    ));
                };
                if !allowed_keys.contains(&key) {
                    return Err(SigmaParserError::InvalidCorrelation(format!(
                        "Unknown correlation condition key: {key}"
                    )));
                }
            }
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

            if matches!(
                correlation_type,
                CorrelationType::ValueCount
                    | CorrelationType::ValueSum
                    | CorrelationType::ValueAvg
                    | CorrelationType::ValuePercentile
                    | CorrelationType::ValueMedian
            ) && field.is_none()
            {
                return Err(SigmaParserError::InvalidCorrelation(format!(
                    "{} correlation condition requires 'field'",
                    correlation_type.as_str()
                )));
            }

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
            // Default for temporal types: every distinct referenced rule must match.
            match correlation_type {
                CorrelationType::Temporal | CorrelationType::TemporalOrdered => {
                    let distinct = rules.iter().collect::<HashSet<_>>().len();
                    if distinct == 0 {
                        return Err(SigmaParserError::InvalidCorrelation(
                            "Temporal correlation without a condition requires at least one rule in 'rules'".into(),
                        ));
                    }
                    Ok(CorrelationCondition::Threshold {
                        predicates: vec![(ConditionOperator::Gte, distinct as u64)],
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

/// Identifiers a condition references, in order of first appearance, and
/// whether it also uses a selector, whose identifiers cannot be enumerated
/// without the detection set.
///
/// Iterative, so a tree built through the API cannot overflow the stack.
pub(crate) fn condition_identifiers(expr: &ConditionExpr) -> (Vec<String>, bool) {
    let mut out: Vec<String> = Vec::new();
    let mut selector = false;
    let mut stack: Vec<&ConditionExpr> = vec![expr];
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
            ConditionExpr::Selector { .. } => selector = true,
        }
    }
    (out, selector)
}

/// Resolve `rules:` against a string condition: derive the references when the
/// key is absent, and reject an identifier the list does not carry.
fn resolve_condition_rules(
    condition: &CorrelationCondition,
    mut rules: Vec<String>,
    rules_present: bool,
) -> Result<Vec<String>> {
    let CorrelationCondition::Extended(expr) = condition else {
        return Ok(rules);
    };
    let (identifiers, selector) = condition_identifiers(expr);
    if !rules_present {
        if selector {
            return Err(SigmaParserError::InvalidCorrelation(
                "rules is required when the condition uses a selector".into(),
            ));
        }
        rules = identifiers;
        return Ok(rules);
    }
    for name in identifiers {
        if !rules.contains(&name) {
            return Err(SigmaParserError::InvalidCorrelation(format!(
                "condition references '{name}', which is not in correlation.rules"
            )));
        }
    }
    Ok(rules)
}

/// Parse correlation field aliases.
fn parse_correlation_aliases(corr: &yaml_serde::Mapping) -> Vec<FieldAlias> {
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
