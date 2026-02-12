//! Pipeline conditions that gate when transformations are applied.
//!
//! Three levels of conditions:
//! - **Rule conditions**: evaluated against the whole `SigmaRule`
//! - **Detection item conditions**: evaluated against individual `DetectionItem` values
//! - **Field name conditions**: evaluated against field names in detection items

use regex::Regex;

use rsigma_parser::{CorrelationRule, Detection, DetectionItem, LogSource, SigmaRule, SigmaValue};

use super::state::PipelineState;

// =============================================================================
// Rule Conditions
// =============================================================================

/// A condition evaluated against a `SigmaRule` (or `CorrelationRule`).
#[derive(Debug, Clone)]
pub enum RuleCondition {
    /// Match logsource fields (category, product, service). `None` = any.
    Logsource {
        category: Option<String>,
        product: Option<String>,
        service: Option<String>,
    },

    /// Rule contains a detection item matching the given field and value.
    ContainsDetectionItem {
        field: String,
        value: Option<String>,
    },

    /// A specific processing item was applied earlier.
    ProcessingItemApplied { processing_item_id: String },

    /// Check pipeline state key-value.
    ProcessingState { key: String, val: String },

    /// Always true for detection rules.
    IsSigmaRule,

    /// Always true for correlation rules.
    IsSigmaCorrelationRule,

    /// Match a rule attribute (level, status, etc.) against a value.
    RuleAttribute { attribute: String, value: String },

    /// Rule has a specific tag.
    Tag { tag: String },
}

impl RuleCondition {
    /// Check if this condition matches a detection rule.
    pub fn matches_rule(&self, rule: &SigmaRule, state: &PipelineState) -> bool {
        match self {
            RuleCondition::Logsource {
                category,
                product,
                service,
            } => logsource_matches(&rule.logsource, category, product, service),

            RuleCondition::ContainsDetectionItem { field, value } => {
                rule_contains_detection_item(&rule.detection.named, field, value.as_deref())
            }

            RuleCondition::ProcessingItemApplied { processing_item_id } => {
                state.was_applied(processing_item_id)
            }

            RuleCondition::ProcessingState { key, val } => state.state_matches(key, val),

            RuleCondition::IsSigmaRule => true,
            RuleCondition::IsSigmaCorrelationRule => false,

            RuleCondition::RuleAttribute { attribute, value } => {
                rule_attribute_matches(rule, attribute, value)
            }

            RuleCondition::Tag { tag } => rule.tags.iter().any(|t| t == tag),
        }
    }

    /// Check if this condition matches a correlation rule.
    pub fn matches_correlation(&self, _corr: &CorrelationRule, state: &PipelineState) -> bool {
        match self {
            RuleCondition::IsSigmaRule => false,
            RuleCondition::IsSigmaCorrelationRule => true,
            RuleCondition::ProcessingItemApplied { processing_item_id } => {
                state.was_applied(processing_item_id)
            }
            RuleCondition::ProcessingState { key, val } => state.state_matches(key, val),
            _ => false,
        }
    }
}

/// Check if all rule conditions match for a rule.
pub fn all_rule_conditions_match(
    conditions: &[RuleCondition],
    rule: &SigmaRule,
    state: &PipelineState,
) -> bool {
    conditions.iter().all(|c| c.matches_rule(rule, state))
}

// =============================================================================
// Detection Item Conditions
// =============================================================================

/// A condition evaluated against individual detection item values.
#[derive(Debug, Clone)]
pub enum DetectionItemCondition {
    /// String value matches a pre-compiled regex pattern.
    MatchString { regex: Regex, negate: bool },

    /// Detection item value is null.
    IsNull { negate: bool },

    /// A specific processing item was applied.
    ProcessingItemApplied { processing_item_id: String },

    /// Check pipeline state.
    ProcessingState { key: String, val: String },
}

impl DetectionItemCondition {
    /// Check if this condition matches a detection item's values.
    pub fn matches_item(&self, item: &DetectionItem, state: &PipelineState) -> bool {
        match self {
            DetectionItemCondition::MatchString { regex, negate } => {
                let has_match = item.values.iter().any(|v| match v {
                    SigmaValue::String(s) => {
                        let plain = s.as_plain().unwrap_or_else(|| s.original.clone());
                        regex.is_match(&plain)
                    }
                    _ => false,
                });
                if *negate { !has_match } else { has_match }
            }

            DetectionItemCondition::IsNull { negate } => {
                let has_null = item.values.iter().any(|v| matches!(v, SigmaValue::Null));
                if *negate { !has_null } else { has_null }
            }

            DetectionItemCondition::ProcessingItemApplied { processing_item_id } => {
                state.was_applied_to_detection_item(processing_item_id)
            }

            DetectionItemCondition::ProcessingState { key, val } => state.state_matches(key, val),
        }
    }
}

// =============================================================================
// Field Name Conditions
// =============================================================================

/// Pre-compiled field match list — either plain strings or compiled regexes.
#[derive(Debug, Clone)]
pub enum FieldMatcher {
    /// Exact string comparison.
    Plain(Vec<String>),
    /// Pre-compiled regex patterns.
    Regex(Vec<regex::Regex>),
}

/// Legacy enum kept for pipeline parsing compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldMatchType {
    /// Exact string comparison.
    Plain,
    /// Regex pattern matching.
    Regex,
}

/// A condition evaluated against field names in detection items.
#[derive(Debug, Clone)]
pub enum FieldNameCondition {
    /// Field name must be in the include list.
    IncludeFields { matcher: FieldMatcher },

    /// Field name must NOT be in the exclude list.
    ExcludeFields { matcher: FieldMatcher },

    /// A specific processing item was applied.
    ProcessingItemApplied { processing_item_id: String },

    /// Check pipeline state.
    ProcessingState { key: String, val: String },
}

impl FieldNameCondition {
    /// Check if this condition matches a field name.
    pub fn matches_field_name(&self, field_name: &str, state: &PipelineState) -> bool {
        match self {
            FieldNameCondition::IncludeFields { matcher } => field_matches(field_name, matcher),

            FieldNameCondition::ExcludeFields { matcher } => !field_matches(field_name, matcher),

            FieldNameCondition::ProcessingItemApplied { processing_item_id } => {
                state.was_applied(processing_item_id)
            }

            FieldNameCondition::ProcessingState { key, val } => state.state_matches(key, val),
        }
    }
}

// =============================================================================
// Condition expression evaluation
// =============================================================================

/// Evaluate a logical expression string over a map of condition results.
///
/// The expression can use `and`, `or`, `not`, parentheses, and condition IDs.
/// For simplicity, we support a flat `and` / `or` / `not` evaluation over
/// named conditions.
pub fn eval_condition_expr(expr: &str, results: &std::collections::HashMap<String, bool>) -> bool {
    // Simple tokenizer and evaluator for expressions like:
    // "cond1 and not cond2" or "cond1 or cond2"
    let tokens: Vec<&str> = expr.split_whitespace().collect();
    if tokens.is_empty() {
        return true;
    }

    // Parse with simple recursive descent
    eval_or_expr(&tokens, &mut 0, results)
}

fn eval_or_expr(
    tokens: &[&str],
    pos: &mut usize,
    results: &std::collections::HashMap<String, bool>,
) -> bool {
    let mut result = eval_and_expr(tokens, pos, results);
    while *pos < tokens.len() && tokens[*pos].eq_ignore_ascii_case("or") {
        *pos += 1;
        let rhs = eval_and_expr(tokens, pos, results);
        result = result || rhs;
    }
    result
}

fn eval_and_expr(
    tokens: &[&str],
    pos: &mut usize,
    results: &std::collections::HashMap<String, bool>,
) -> bool {
    let mut result = eval_not_expr(tokens, pos, results);
    while *pos < tokens.len() && tokens[*pos].eq_ignore_ascii_case("and") {
        *pos += 1;
        let rhs = eval_not_expr(tokens, pos, results);
        result = result && rhs;
    }
    result
}

fn eval_not_expr(
    tokens: &[&str],
    pos: &mut usize,
    results: &std::collections::HashMap<String, bool>,
) -> bool {
    if *pos < tokens.len() && tokens[*pos].eq_ignore_ascii_case("not") {
        *pos += 1;
        return !eval_primary(tokens, pos, results);
    }
    eval_primary(tokens, pos, results)
}

fn eval_primary(
    tokens: &[&str],
    pos: &mut usize,
    results: &std::collections::HashMap<String, bool>,
) -> bool {
    if *pos >= tokens.len() {
        return false;
    }

    if tokens[*pos] == "(" {
        *pos += 1;
        let result = eval_or_expr(tokens, pos, results);
        if *pos < tokens.len() && tokens[*pos] == ")" {
            *pos += 1;
        }
        return result;
    }

    let id = tokens[*pos];
    *pos += 1;
    *results.get(id).unwrap_or(&false)
}

// =============================================================================
// Helper functions
// =============================================================================

fn logsource_matches(
    ls: &LogSource,
    category: &Option<String>,
    product: &Option<String>,
    service: &Option<String>,
) -> bool {
    if let Some(cat) = category {
        match &ls.category {
            Some(lc) if lc.eq_ignore_ascii_case(cat) => {}
            _ => return false,
        }
    }
    if let Some(prod) = product {
        match &ls.product {
            Some(lp) if lp.eq_ignore_ascii_case(prod) => {}
            _ => return false,
        }
    }
    if let Some(svc) = service {
        match &ls.service {
            Some(ls_svc) if ls_svc.eq_ignore_ascii_case(svc) => {}
            _ => return false,
        }
    }
    true
}

fn rule_contains_detection_item(
    named: &std::collections::HashMap<String, Detection>,
    field: &str,
    value: Option<&str>,
) -> bool {
    for detection in named.values() {
        if detection_contains_item(detection, field, value) {
            return true;
        }
    }
    false
}

fn detection_contains_item(detection: &Detection, field: &str, value: Option<&str>) -> bool {
    match detection {
        Detection::AllOf(items) => items.iter().any(|item| item_matches(item, field, value)),
        Detection::AnyOf(subs) => subs
            .iter()
            .any(|sub| detection_contains_item(sub, field, value)),
        Detection::Keywords(_) => false,
    }
}

fn item_matches(item: &DetectionItem, field: &str, value: Option<&str>) -> bool {
    let field_match = item
        .field
        .name
        .as_ref()
        .is_some_and(|n| n.eq_ignore_ascii_case(field));

    if !field_match {
        return false;
    }

    if let Some(val) = value {
        item.values.iter().any(|v| match v {
            SigmaValue::String(s) => s
                .as_plain()
                .unwrap_or_else(|| s.original.clone())
                .eq_ignore_ascii_case(val),
            SigmaValue::Integer(i) => i.to_string() == val,
            SigmaValue::Float(f) => f.to_string() == val,
            SigmaValue::Bool(b) => b.to_string() == val,
            SigmaValue::Null => val == "null",
        })
    } else {
        true // Just checking field existence, no value constraint
    }
}

fn rule_attribute_matches(rule: &SigmaRule, attribute: &str, value: &str) -> bool {
    match attribute {
        "level" => rule
            .level
            .as_ref()
            .is_some_and(|l| format!("{l:?}").eq_ignore_ascii_case(value)),
        "status" => rule
            .status
            .as_ref()
            .is_some_and(|s| format!("{s:?}").eq_ignore_ascii_case(value)),
        "author" => rule
            .author
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case(value)),
        "title" => rule.title.eq_ignore_ascii_case(value),
        "id" => rule.id.as_deref().is_some_and(|id| id == value),
        "date" => rule.date.as_deref().is_some_and(|d| d == value),
        "description" => rule
            .description
            .as_deref()
            .is_some_and(|d| d.contains(value)),
        _ => false,
    }
}

fn field_matches(field_name: &str, matcher: &FieldMatcher) -> bool {
    match matcher {
        FieldMatcher::Plain(fields) => fields.iter().any(|f| f == field_name),
        FieldMatcher::Regex(regexes) => regexes.iter().any(|re| re.is_match(field_name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_eval_condition_expr_simple() {
        let mut results = HashMap::new();
        results.insert("cond1".to_string(), true);
        results.insert("cond2".to_string(), false);

        assert!(eval_condition_expr("cond1", &results));
        assert!(!eval_condition_expr("cond2", &results));
        assert!(eval_condition_expr("cond1 and not cond2", &results));
        assert!(eval_condition_expr("cond1 or cond2", &results));
        assert!(!eval_condition_expr("cond1 and cond2", &results));
    }

    #[test]
    fn test_logsource_condition() {
        let rule = SigmaRule {
            title: "Test".to_string(),
            logsource: LogSource {
                category: Some("process_creation".to_string()),
                product: Some("windows".to_string()),
                service: None,
                definition: None,
                custom: HashMap::new(),
            },
            detection: rsigma_parser::Detections {
                named: HashMap::new(),
                conditions: vec![],
                condition_strings: vec![],
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
            custom_attributes: HashMap::new(),
        };
        let state = PipelineState::default();

        let cond = RuleCondition::Logsource {
            category: Some("process_creation".to_string()),
            product: Some("windows".to_string()),
            service: None,
        };
        assert!(cond.matches_rule(&rule, &state));

        let cond2 = RuleCondition::Logsource {
            category: Some("network".to_string()),
            product: None,
            service: None,
        };
        assert!(!cond2.matches_rule(&rule, &state));
    }

    #[test]
    fn test_is_sigma_rule_condition() {
        let state = PipelineState::default();
        let rule = SigmaRule {
            title: "Test".to_string(),
            logsource: LogSource::default(),
            detection: rsigma_parser::Detections {
                named: HashMap::new(),
                conditions: vec![],
                condition_strings: vec![],
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
            custom_attributes: HashMap::new(),
        };

        assert!(RuleCondition::IsSigmaRule.matches_rule(&rule, &state));
        assert!(!RuleCondition::IsSigmaCorrelationRule.matches_rule(&rule, &state));
    }

    #[test]
    fn test_tag_condition() {
        let state = PipelineState::default();
        let rule = SigmaRule {
            title: "Test".to_string(),
            logsource: LogSource::default(),
            detection: rsigma_parser::Detections {
                named: HashMap::new(),
                conditions: vec![],
                condition_strings: vec![],
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
            tags: vec!["attack.execution".to_string(), "attack.t1059".to_string()],
            scope: vec![],
            custom_attributes: HashMap::new(),
        };

        assert!(
            RuleCondition::Tag {
                tag: "attack.execution".to_string()
            }
            .matches_rule(&rule, &state)
        );
        assert!(
            !RuleCondition::Tag {
                tag: "attack.persistence".to_string()
            }
            .matches_rule(&rule, &state)
        );
    }

    #[test]
    fn test_field_name_include() {
        let state = PipelineState::default();
        let cond = FieldNameCondition::IncludeFields {
            matcher: FieldMatcher::Plain(vec![
                "CommandLine".to_string(),
                "ParentImage".to_string(),
            ]),
        };
        assert!(cond.matches_field_name("CommandLine", &state));
        assert!(!cond.matches_field_name("User", &state));
    }

    #[test]
    fn test_field_name_exclude() {
        let state = PipelineState::default();
        let cond = FieldNameCondition::ExcludeFields {
            matcher: FieldMatcher::Plain(vec!["Hostname".to_string()]),
        };
        assert!(cond.matches_field_name("CommandLine", &state));
        assert!(!cond.matches_field_name("Hostname", &state));
    }

    #[test]
    fn test_field_name_regex() {
        let state = PipelineState::default();
        let cond = FieldNameCondition::IncludeFields {
            matcher: FieldMatcher::Regex(vec![Regex::new("Event.*").unwrap()]),
        };
        assert!(cond.matches_field_name("EventType", &state));
        assert!(cond.matches_field_name("EventID", &state));
        assert!(!cond.matches_field_name("CommandLine", &state));
    }

    #[test]
    fn test_processing_item_applied() {
        let mut state = PipelineState::default();
        let cond = RuleCondition::ProcessingItemApplied {
            processing_item_id: "my_transform".to_string(),
        };
        let rule = SigmaRule {
            title: "Test".to_string(),
            logsource: LogSource::default(),
            detection: rsigma_parser::Detections {
                named: HashMap::new(),
                conditions: vec![],
                condition_strings: vec![],
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
            custom_attributes: HashMap::new(),
        };

        assert!(!cond.matches_rule(&rule, &state));
        state.mark_applied("my_transform");
        assert!(cond.matches_rule(&rule, &state));
    }
}
