//! Pipeline transformations that mutate `SigmaRule` AST nodes.
//!
//! All 14 pySigma transformation types are implemented as variants of the
//! [`Transformation`] enum. Each variant carries its configuration parameters
//! and is applied via the [`Transformation::apply`] method.

use std::collections::HashMap;

use regex::Regex;

use rsigma_parser::{
    ConditionExpr, Detection, DetectionItem, FieldSpec, SigmaRule, SigmaString, SigmaValue,
};

use super::conditions::{DetectionItemCondition, FieldNameCondition};
use super::state::PipelineState;
use crate::error::{EvalError, Result};

// =============================================================================
// Transformation enum
// =============================================================================

/// All supported pipeline transformation types.
#[derive(Debug, Clone)]
pub enum Transformation {
    /// Map field names via a lookup table.
    FieldNameMapping { mapping: HashMap<String, String> },

    /// Map field name prefixes.
    FieldNamePrefixMapping { mapping: HashMap<String, String> },

    /// Add a prefix to all matched field names.
    FieldNamePrefix { prefix: String },

    /// Add a suffix to all matched field names.
    FieldNameSuffix { suffix: String },

    /// Remove matching detection items.
    DropDetectionItem,

    /// Add field=value conditions to the rule's detection.
    AddCondition {
        conditions: HashMap<String, SigmaValue>,
        /// If true, negate the added conditions.
        negated: bool,
    },

    /// Replace logsource fields.
    ChangeLogsource {
        category: Option<String>,
        product: Option<String>,
        service: Option<String>,
    },

    /// Regex replacement in string values.
    ReplaceString { regex: String, replacement: String },

    /// Expand `%name%` placeholders with pipeline variables.
    ValuePlaceholders,

    /// Replace unresolved `%name%` placeholders with `*` wildcard.
    WildcardPlaceholders,

    /// Store expression template (no-op for eval, kept for YAML compat).
    QueryExpressionPlaceholders { expression: String },

    /// Set key-value in pipeline state.
    SetState { key: String, value: String },

    /// Fail if rule conditions match.
    RuleFailure { message: String },

    /// Fail if detection item conditions match.
    DetectionItemFailure { message: String },
}

// =============================================================================
// Application logic
// =============================================================================

impl Transformation {
    /// Apply this transformation to a `SigmaRule`, mutating it in place.
    ///
    /// Returns `Ok(true)` if the transformation was applied, `Ok(false)` if skipped.
    pub fn apply(
        &self,
        rule: &mut SigmaRule,
        state: &mut PipelineState,
        detection_item_conditions: &[DetectionItemCondition],
        field_name_conditions: &[FieldNameCondition],
        field_name_cond_not: bool,
    ) -> Result<bool> {
        match self {
            Transformation::FieldNameMapping { mapping } => {
                apply_field_name_transform(
                    rule,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    |name| mapping.get(name).cloned(),
                );
                Ok(true)
            }

            Transformation::FieldNamePrefixMapping { mapping } => {
                apply_field_name_transform(
                    rule,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    |name| {
                        for (prefix, replacement) in mapping {
                            if name.starts_with(prefix.as_str()) {
                                return Some(format!("{}{}", replacement, &name[prefix.len()..]));
                            }
                        }
                        None
                    },
                );
                Ok(true)
            }

            Transformation::FieldNamePrefix { prefix } => {
                apply_field_name_transform(
                    rule,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    |name| Some(format!("{prefix}{name}")),
                );
                Ok(true)
            }

            Transformation::FieldNameSuffix { suffix } => {
                apply_field_name_transform(
                    rule,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    |name| Some(format!("{name}{suffix}")),
                );
                Ok(true)
            }

            Transformation::DropDetectionItem => {
                drop_detection_items(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                );
                Ok(true)
            }

            Transformation::AddCondition {
                conditions,
                negated,
            } => {
                add_conditions(rule, conditions, *negated);
                Ok(true)
            }

            Transformation::ChangeLogsource {
                category,
                product,
                service,
            } => {
                if let Some(cat) = category {
                    rule.logsource.category = Some(cat.clone());
                }
                if let Some(prod) = product {
                    rule.logsource.product = Some(prod.clone());
                }
                if let Some(svc) = service {
                    rule.logsource.service = Some(svc.clone());
                }
                Ok(true)
            }

            Transformation::ReplaceString { regex, replacement } => {
                let re = Regex::new(regex)
                    .map_err(|e| EvalError::InvalidModifiers(format!("bad regex: {e}")))?;
                replace_strings_in_rule(
                    rule,
                    state,
                    detection_item_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                    &re,
                    replacement,
                );
                Ok(true)
            }

            Transformation::ValuePlaceholders => {
                expand_placeholders_in_rule(rule, state, false);
                Ok(true)
            }

            Transformation::WildcardPlaceholders => {
                expand_placeholders_in_rule(rule, state, true);
                Ok(true)
            }

            Transformation::QueryExpressionPlaceholders { .. } => {
                // No-op for eval mode
                Ok(false)
            }

            Transformation::SetState { key, value } => {
                state.set_state(key.clone(), serde_json::Value::String(value.clone()));
                Ok(true)
            }

            Transformation::RuleFailure { message } => Err(EvalError::InvalidModifiers(format!(
                "Pipeline rule failure: {message} (rule: {})",
                rule.title
            ))),

            Transformation::DetectionItemFailure { message } => {
                // Check if any detection item matches the conditions
                let has_match = rule_has_matching_item(rule, state, detection_item_conditions);
                if has_match {
                    Err(EvalError::InvalidModifiers(format!(
                        "Pipeline detection item failure: {message} (rule: {})",
                        rule.title
                    )))
                } else {
                    Ok(false)
                }
            }
        }
    }
}

// =============================================================================
// Field name transformation helper
// =============================================================================

fn apply_field_name_transform<F>(
    rule: &mut SigmaRule,
    state: &PipelineState,
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    transform_fn: F,
) where
    F: Fn(&str) -> Option<String>,
{
    for detection in rule.detection.named.values_mut() {
        transform_detection_fields(
            detection,
            state,
            field_name_conditions,
            field_name_cond_not,
            &transform_fn,
        );
    }
}

fn transform_detection_fields<F>(
    detection: &mut Detection,
    state: &PipelineState,
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    transform_fn: &F,
) where
    F: Fn(&str) -> Option<String>,
{
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                if let Some(ref name) = item.field.name
                    && field_conditions_match(
                        name,
                        state,
                        field_name_conditions,
                        field_name_cond_not,
                    )
                    && let Some(new_name) = transform_fn(name)
                {
                    item.field.name = Some(new_name);
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                transform_detection_fields(
                    sub,
                    state,
                    field_name_conditions,
                    field_name_cond_not,
                    transform_fn,
                );
            }
        }
        Detection::Keywords(_) => {}
    }
}

fn field_conditions_match(
    field_name: &str,
    state: &PipelineState,
    conditions: &[FieldNameCondition],
    negate: bool,
) -> bool {
    if conditions.is_empty() {
        return true;
    }
    let all_match = conditions
        .iter()
        .all(|c| c.matches_field_name(field_name, state));
    if negate { !all_match } else { all_match }
}

// =============================================================================
// Drop detection items
// =============================================================================

fn drop_detection_items(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
) {
    for detection in rule.detection.named.values_mut() {
        drop_from_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            field_name_cond_not,
        );
    }
}

fn drop_from_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
) {
    match detection {
        Detection::AllOf(items) => {
            items.retain(|item| {
                !should_drop_item(
                    item,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                )
            });
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                drop_from_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                );
            }
        }
        Detection::Keywords(_) => {}
    }
}

fn should_drop_item(
    item: &DetectionItem,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
) -> bool {
    // Check detection item conditions
    let det_match = detection_conditions.is_empty()
        || detection_conditions
            .iter()
            .all(|c| c.matches_item(item, state));

    // Check field name conditions
    let field_match = if let Some(ref name) = item.field.name {
        field_conditions_match(name, state, field_name_conditions, field_name_cond_not)
    } else {
        field_name_conditions.is_empty()
    };

    det_match && field_match
}

// =============================================================================
// Add conditions
// =============================================================================

fn add_conditions(rule: &mut SigmaRule, conditions: &HashMap<String, SigmaValue>, negated: bool) {
    // Create a new detection with the given conditions
    let items: Vec<DetectionItem> = conditions
        .iter()
        .map(|(field, value)| DetectionItem {
            field: FieldSpec::new(Some(field.clone()), Vec::new()),
            values: vec![value.clone()],
        })
        .collect();

    let det_name = format!("__pipeline_cond_{}", rule.detection.named.len());
    rule.detection
        .named
        .insert(det_name.clone(), Detection::AllOf(items));

    // Add to existing conditions: AND (or AND NOT if negated)
    let cond_ref = ConditionExpr::Identifier(det_name);
    let cond_expr = if negated {
        ConditionExpr::Not(Box::new(cond_ref))
    } else {
        cond_ref
    };

    rule.detection.conditions = rule
        .detection
        .conditions
        .iter()
        .map(|existing| ConditionExpr::And(vec![existing.clone(), cond_expr.clone()]))
        .collect();
}

// =============================================================================
// Replace strings
// =============================================================================

fn replace_strings_in_rule(
    rule: &mut SigmaRule,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    re: &Regex,
    replacement: &str,
) {
    for detection in rule.detection.named.values_mut() {
        replace_strings_in_detection(
            detection,
            state,
            detection_conditions,
            field_name_conditions,
            field_name_cond_not,
            re,
            replacement,
        );
    }
}

fn replace_strings_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    detection_conditions: &[DetectionItemCondition],
    field_name_conditions: &[FieldNameCondition],
    field_name_cond_not: bool,
    re: &Regex,
    replacement: &str,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                let det_match = detection_conditions.is_empty()
                    || detection_conditions
                        .iter()
                        .all(|c| c.matches_item(item, state));
                let field_match = if let Some(ref name) = item.field.name {
                    field_conditions_match(name, state, field_name_conditions, field_name_cond_not)
                } else {
                    field_name_conditions.is_empty()
                };

                if det_match && field_match {
                    replace_strings_in_values(&mut item.values, re, replacement);
                }
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                replace_strings_in_detection(
                    sub,
                    state,
                    detection_conditions,
                    field_name_conditions,
                    field_name_cond_not,
                    re,
                    replacement,
                );
            }
        }
        Detection::Keywords(values) => {
            replace_strings_in_values(values, re, replacement);
        }
    }
}

fn replace_strings_in_values(values: &mut [SigmaValue], re: &Regex, replacement: &str) {
    for value in values.iter_mut() {
        if let SigmaValue::String(s) = value {
            let replaced = re.replace_all(&s.original, replacement);
            if replaced != s.original {
                *s = SigmaString::new(&replaced);
            }
        }
    }
}

// =============================================================================
// Placeholder expansion
// =============================================================================

fn expand_placeholders_in_rule(rule: &mut SigmaRule, state: &PipelineState, wildcard: bool) {
    for detection in rule.detection.named.values_mut() {
        expand_placeholders_in_detection(detection, state, wildcard);
    }
}

fn expand_placeholders_in_detection(
    detection: &mut Detection,
    state: &PipelineState,
    wildcard: bool,
) {
    match detection {
        Detection::AllOf(items) => {
            for item in items.iter_mut() {
                expand_placeholders_in_values(&mut item.values, state, wildcard);
            }
        }
        Detection::AnyOf(subs) => {
            for sub in subs.iter_mut() {
                expand_placeholders_in_detection(sub, state, wildcard);
            }
        }
        Detection::Keywords(values) => {
            expand_placeholders_in_values(values, state, wildcard);
        }
    }
}

fn expand_placeholders_in_values(
    values: &mut Vec<SigmaValue>,
    state: &PipelineState,
    wildcard: bool,
) {
    let mut expanded_values = Vec::new();
    for value in values.drain(..) {
        if let SigmaValue::String(ref s) = value {
            let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
            if plain.contains('%') {
                // Try to expand %name% patterns
                let result = expand_placeholder_string(&plain, state, wildcard);
                expanded_values.extend(result);
                continue;
            }
        }
        expanded_values.push(value);
    }
    *values = expanded_values;
}

fn expand_placeholder_string(s: &str, state: &PipelineState, wildcard: bool) -> Vec<SigmaValue> {
    // Find %name% patterns
    let mut result = s.to_string();
    let mut has_unresolved = false;

    // Simple regex-free pattern matching for %name%
    loop {
        let start = result.find('%');
        if start.is_none() {
            break;
        }
        let start = start.unwrap();
        let rest = &result[start + 1..];
        let end = rest.find('%');
        if end.is_none() {
            break;
        }
        let end = end.unwrap();
        let placeholder = &rest[..end];

        if let Some(values) = state.vars.get(placeholder) {
            if values.len() == 1 {
                result = format!("{}{}{}", &result[..start], values[0], &rest[end + 1..]);
            } else if values.is_empty() {
                if wildcard {
                    result = format!("{}*{}", &result[..start], &rest[end + 1..]);
                } else {
                    has_unresolved = true;
                    break;
                }
            } else {
                // Multiple values: create one SigmaValue per expansion
                return values
                    .iter()
                    .map(|v| {
                        let expanded = format!("{}{}{}", &result[..start], v, &rest[end + 1..]);
                        SigmaValue::String(SigmaString::new(&expanded))
                    })
                    .collect();
            }
        } else if wildcard {
            result = format!("{}*{}", &result[..start], &rest[end + 1..]);
        } else {
            has_unresolved = true;
            break;
        }
    }

    if has_unresolved && wildcard {
        // Replace remaining unresolved placeholders with *
        // This is a simplistic approach
        vec![SigmaValue::String(SigmaString::new(&result))]
    } else {
        vec![SigmaValue::String(SigmaString::new(&result))]
    }
}

// =============================================================================
// Helper: check if rule has any item matching conditions
// =============================================================================

fn rule_has_matching_item(
    rule: &SigmaRule,
    state: &PipelineState,
    conditions: &[DetectionItemCondition],
) -> bool {
    for detection in rule.detection.named.values() {
        if detection_has_matching_item(detection, state, conditions) {
            return true;
        }
    }
    false
}

fn detection_has_matching_item(
    detection: &Detection,
    state: &PipelineState,
    conditions: &[DetectionItemCondition],
) -> bool {
    match detection {
        Detection::AllOf(items) => items
            .iter()
            .any(|item| conditions.iter().all(|c| c.matches_item(item, state))),
        Detection::AnyOf(subs) => subs
            .iter()
            .any(|sub| detection_has_matching_item(sub, state, conditions)),
        Detection::Keywords(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::{Detections, LogSource, Modifier};

    fn make_test_rule() -> SigmaRule {
        let mut named = HashMap::new();
        named.insert(
            "selection".to_string(),
            Detection::AllOf(vec![
                DetectionItem {
                    field: FieldSpec::new(
                        Some("CommandLine".to_string()),
                        vec![Modifier::Contains],
                    ),
                    values: vec![SigmaValue::String(SigmaString::new("whoami"))],
                },
                DetectionItem {
                    field: FieldSpec::new(
                        Some("ParentImage".to_string()),
                        vec![Modifier::EndsWith],
                    ),
                    values: vec![SigmaValue::String(SigmaString::new("\\cmd.exe"))],
                },
            ]),
        );

        SigmaRule {
            title: "Test Rule".to_string(),
            logsource: LogSource {
                category: Some("process_creation".to_string()),
                product: Some("windows".to_string()),
                service: None,
                definition: None,
                custom: HashMap::new(),
            },
            detection: Detections {
                named,
                conditions: vec![ConditionExpr::Identifier("selection".to_string())],
                condition_strings: vec!["selection".to_string()],
                timeframe: None,
            },
            id: Some("test-001".to_string()),
            name: None,
            related: vec![],
            taxonomy: None,
            status: None,
            description: None,
            license: None,
            author: None,
            references: vec![],
            date: None,
            modified: None,
            fields: vec![],
            falsepositives: vec![],
            level: Some(rsigma_parser::Level::Medium),
            tags: vec![],
            scope: vec![],
        }
    }

    #[test]
    fn test_field_name_mapping() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let mut mapping = HashMap::new();
        mapping.insert(
            "CommandLine".to_string(),
            "process.command_line".to_string(),
        );
        mapping.insert(
            "ParentImage".to_string(),
            "process.parent.executable".to_string(),
        );

        let t = Transformation::FieldNameMapping { mapping };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(
                items[0].field.name,
                Some("process.command_line".to_string())
            );
            assert_eq!(
                items[1].field.name,
                Some("process.parent.executable".to_string())
            );
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_field_name_prefix() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::FieldNamePrefix {
            prefix: "winlog.event_data.".to_string(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(
                items[0].field.name,
                Some("winlog.event_data.CommandLine".to_string())
            );
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_field_name_suffix() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::FieldNameSuffix {
            suffix: ".keyword".to_string(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(items[0].field.name, Some("CommandLine.keyword".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_change_logsource() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::ChangeLogsource {
            category: Some("endpoint".to_string()),
            product: Some("elastic".to_string()),
            service: None,
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        assert_eq!(rule.logsource.category, Some("endpoint".to_string()));
        assert_eq!(rule.logsource.product, Some("elastic".to_string()));
    }

    #[test]
    fn test_replace_string() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::ReplaceString {
            regex: r"whoami".to_string(),
            replacement: "REPLACED".to_string(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            if let SigmaValue::String(s) = &items[0].values[0] {
                assert_eq!(s.original, "REPLACED");
            } else {
                panic!("Expected String value");
            }
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_add_condition() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let mut conds = HashMap::new();
        conds.insert(
            "index".to_string(),
            SigmaValue::String(SigmaString::new("windows-*")),
        );
        let t = Transformation::AddCondition {
            conditions: conds,
            negated: false,
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        // Check that a new detection was added
        assert!(
            rule.detection
                .named
                .keys()
                .any(|k| k.starts_with("__pipeline_cond_"))
        );
        // Check that conditions were wrapped
        assert_eq!(rule.detection.conditions.len(), 1);
        if let ConditionExpr::And(parts) = &rule.detection.conditions[0] {
            assert_eq!(parts.len(), 2);
        } else {
            panic!("Expected And condition");
        }
    }

    #[test]
    fn test_set_state() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::SetState {
            key: "index".to_string(),
            value: "windows".to_string(),
        };
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
        assert!(state.state_matches("index", "windows"));
    }

    #[test]
    fn test_drop_detection_item_with_field_condition() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();

        let field_conds = vec![FieldNameCondition::IncludeFields {
            fields: vec!["ParentImage".to_string()],
            match_type: super::super::conditions::FieldMatchType::Plain,
        }];

        let t = Transformation::DropDetectionItem;
        t.apply(&mut rule, &mut state, &[], &field_conds, false)
            .unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(items.len(), 1); // ParentImage was dropped
            assert_eq!(items[0].field.name, Some("CommandLine".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_field_name_mapping_with_conditions() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();

        // Only map CommandLine, not ParentImage
        let field_conds = vec![FieldNameCondition::IncludeFields {
            fields: vec!["CommandLine".to_string()],
            match_type: super::super::conditions::FieldMatchType::Plain,
        }];

        let mut mapping = HashMap::new();
        mapping.insert("CommandLine".to_string(), "process.args".to_string());
        mapping.insert("ParentImage".to_string(), "process.parent".to_string());

        let t = Transformation::FieldNameMapping { mapping };
        t.apply(&mut rule, &mut state, &[], &field_conds, false)
            .unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            assert_eq!(items[0].field.name, Some("process.args".to_string()));
            // ParentImage should NOT have been mapped (field condition didn't match)
            assert_eq!(items[1].field.name, Some("ParentImage".to_string()));
        } else {
            panic!("Expected AllOf");
        }
    }

    #[test]
    fn test_rule_failure() {
        let mut rule = make_test_rule();
        let mut state = PipelineState::default();
        let t = Transformation::RuleFailure {
            message: "Unsupported rule".to_string(),
        };
        let result = t.apply(&mut rule, &mut state, &[], &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn test_value_placeholders() {
        let mut named = HashMap::new();
        named.insert(
            "selection".to_string(),
            Detection::AllOf(vec![DetectionItem {
                field: FieldSpec::new(Some("User".to_string()), vec![]),
                values: vec![SigmaValue::String(SigmaString::new("%admin_users%"))],
            }]),
        );

        let mut rule = SigmaRule {
            title: "Test".to_string(),
            logsource: LogSource::default(),
            detection: Detections {
                named,
                conditions: vec![ConditionExpr::Identifier("selection".to_string())],
                condition_strings: vec!["selection".to_string()],
                timeframe: None,
            },
            id: None,
            name: None,
            related: vec![],
            taxonomy: None,
            status: None,
            description: None,
            license: None,
            author: None,
            references: vec![],
            date: None,
            modified: None,
            fields: vec![],
            falsepositives: vec![],
            level: None,
            tags: vec![],
            scope: vec![],
        };

        let mut state = PipelineState::default();
        state.vars.insert(
            "admin_users".to_string(),
            vec!["root".to_string(), "admin".to_string()],
        );

        let t = Transformation::ValuePlaceholders;
        t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

        let det = &rule.detection.named["selection"];
        if let Detection::AllOf(items) = det {
            // Should have expanded to 2 values
            assert_eq!(items[0].values.len(), 2);
        } else {
            panic!("Expected AllOf");
        }
    }
}
