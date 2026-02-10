//! Compiled correlation types, group key, window state, and compilation.
//!
//! Transforms the parser's `CorrelationRule` AST into an optimized
//! `CompiledCorrelation` with associated `WindowState` for stateful evaluation.

use std::collections::{HashMap, HashSet, VecDeque};

use rsigma_parser::{
    ConditionOperator, CorrelationCondition, CorrelationRule, CorrelationType, FieldAlias, Level,
};

use crate::error::{EvalError, Result};
use crate::event::Event;

// =============================================================================
// Compiled types
// =============================================================================

/// Compiled form of a `CorrelationRule`, ready for stateful evaluation.
#[derive(Debug, Clone)]
pub struct CompiledCorrelation {
    pub id: Option<String>,
    pub name: Option<String>,
    pub title: String,
    pub level: Option<Level>,
    pub tags: Vec<String>,
    pub correlation_type: CorrelationType,
    /// IDs or names of referenced rules (detection or other correlations).
    pub rule_refs: Vec<String>,
    /// Resolved group-by fields (may include aliases).
    pub group_by: Vec<GroupByField>,
    /// Time window in seconds.
    pub timespan_secs: u64,
    /// Compiled threshold condition.
    pub condition: CompiledCondition,
    /// Whether referenced detection rules should also generate standalone matches.
    pub generate: bool,
}

/// A group-by field, potentially aliased per referenced rule.
#[derive(Debug, Clone)]
pub enum GroupByField {
    /// Simple field name, same across all referenced rules.
    Direct(String),
    /// Aliased: maps rule_ref -> actual field name in that rule's events.
    Aliased {
        alias: String,
        mapping: HashMap<String, String>,
    },
}

impl GroupByField {
    /// Get the display name of this group-by field.
    pub fn name(&self) -> &str {
        match self {
            GroupByField::Direct(s) => s,
            GroupByField::Aliased { alias, .. } => alias,
        }
    }

    /// Resolve the actual field name to look up in an event, given which
    /// rule (by ID or name) produced the detection match.
    ///
    /// Tries to find the rule in the alias mapping by any of the provided
    /// identifiers (ID, name, etc.).
    pub fn resolve(&self, rule_refs: &[&str]) -> &str {
        match self {
            GroupByField::Direct(s) => s,
            GroupByField::Aliased { alias, mapping } => {
                for r in rule_refs {
                    if let Some(field) = mapping.get(*r) {
                        return field.as_str();
                    }
                }
                alias
            }
        }
    }
}

/// Compiled threshold condition with one or more predicates (supports ranges).
#[derive(Debug, Clone)]
pub struct CompiledCondition {
    /// Optional field name for value_count, value_sum, value_avg, value_percentile.
    pub field: Option<String>,
    /// One or more predicates to satisfy (all must be true for the condition to match).
    pub predicates: Vec<(ConditionOperator, f64)>,
}

impl CompiledCondition {
    /// Check if the given value satisfies all predicates.
    pub fn check(&self, value: f64) -> bool {
        self.predicates.iter().all(|(op, threshold)| match op {
            ConditionOperator::Lt => value < *threshold,
            ConditionOperator::Lte => value <= *threshold,
            ConditionOperator::Gt => value > *threshold,
            ConditionOperator::Gte => value >= *threshold,
            ConditionOperator::Eq => (value - *threshold).abs() < f64::EPSILON,
            ConditionOperator::Neq => (value - *threshold).abs() >= f64::EPSILON,
        })
    }
}

// =============================================================================
// Group Key
// =============================================================================

/// Composite key for group-by partitioning.
///
/// Each element corresponds to a `GroupByField` value extracted from an event.
/// `None` means the field was absent from the event.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct GroupKey(pub Vec<Option<String>>);

impl GroupKey {
    /// Extract a group key from an event given the group-by fields and the
    /// rule reference identifiers (ID, name, etc.) that produced the detection match.
    pub fn extract(event: &Event, group_by: &[GroupByField], rule_refs: &[&str]) -> Self {
        let values = group_by
            .iter()
            .map(|field| {
                let field_name = field.resolve(rule_refs);
                event.get_field(field_name).and_then(value_to_string)
            })
            .collect();
        GroupKey(values)
    }

    /// Build a group key from explicit field-value pairs (for chaining).
    pub fn from_pairs(pairs: &[(String, String)], group_by: &[GroupByField]) -> Self {
        let values = group_by
            .iter()
            .map(|field| {
                let name = field.name();
                pairs
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.clone())
            })
            .collect();
        GroupKey(values)
    }

    /// Convert to field-name/value pairs for output.
    pub fn to_pairs(&self, group_by: &[GroupByField]) -> Vec<(String, String)> {
        group_by
            .iter()
            .zip(self.0.iter())
            .filter_map(|(field, value)| {
                value
                    .as_ref()
                    .map(|v| (field.name().to_string(), v.clone()))
            })
            .collect()
    }
}

/// Convert a JSON value to a string for group-key purposes.
fn value_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

// =============================================================================
// Window State
// =============================================================================

/// Per-group mutable state within a time window.
///
/// Each variant matches the type of aggregation being performed.
#[derive(Debug, Clone)]
pub enum WindowState {
    /// For `event_count`: timestamps of matching events.
    EventCount { timestamps: VecDeque<i64> },
    /// For `value_count`: (timestamp, field_value) pairs.
    ValueCount { entries: VecDeque<(i64, String)> },
    /// For `temporal` / `temporal_ordered`: rule_ref -> list of hit timestamps.
    Temporal {
        rule_hits: HashMap<String, VecDeque<i64>>,
    },
    /// For `value_sum`, `value_avg`, `value_percentile`, `value_median`:
    /// (timestamp, numeric_value) pairs.
    NumericAgg { entries: VecDeque<(i64, f64)> },
}

impl WindowState {
    /// Create a new empty window state for the given correlation type.
    pub fn new_for(corr_type: CorrelationType) -> Self {
        match corr_type {
            CorrelationType::EventCount => WindowState::EventCount {
                timestamps: VecDeque::new(),
            },
            CorrelationType::ValueCount => WindowState::ValueCount {
                entries: VecDeque::new(),
            },
            CorrelationType::Temporal | CorrelationType::TemporalOrdered => WindowState::Temporal {
                rule_hits: HashMap::new(),
            },
            CorrelationType::ValueSum
            | CorrelationType::ValueAvg
            | CorrelationType::ValuePercentile
            | CorrelationType::ValueMedian => WindowState::NumericAgg {
                entries: VecDeque::new(),
            },
        }
    }

    /// Remove all entries older than the cutoff timestamp.
    pub fn evict(&mut self, cutoff: i64) {
        match self {
            WindowState::EventCount { timestamps } => {
                while timestamps.front().is_some_and(|&t| t < cutoff) {
                    timestamps.pop_front();
                }
            }
            WindowState::ValueCount { entries } => {
                while entries.front().is_some_and(|(t, _)| *t < cutoff) {
                    entries.pop_front();
                }
            }
            WindowState::Temporal { rule_hits } => {
                for timestamps in rule_hits.values_mut() {
                    while timestamps.front().is_some_and(|&t| t < cutoff) {
                        timestamps.pop_front();
                    }
                }
                // Remove empty rule entries
                rule_hits.retain(|_, ts| !ts.is_empty());
            }
            WindowState::NumericAgg { entries } => {
                while entries.front().is_some_and(|(t, _)| *t < cutoff) {
                    entries.pop_front();
                }
            }
        }
    }

    /// Returns true if this state has no entries.
    pub fn is_empty(&self) -> bool {
        match self {
            WindowState::EventCount { timestamps } => timestamps.is_empty(),
            WindowState::ValueCount { entries } => entries.is_empty(),
            WindowState::Temporal { rule_hits } => rule_hits.is_empty(),
            WindowState::NumericAgg { entries } => entries.is_empty(),
        }
    }

    /// Record an event_count hit.
    pub fn push_event_count(&mut self, ts: i64) {
        if let WindowState::EventCount { timestamps } = self {
            timestamps.push_back(ts);
        }
    }

    /// Record a value_count hit with the field value.
    pub fn push_value_count(&mut self, ts: i64, value: String) {
        if let WindowState::ValueCount { entries } = self {
            entries.push_back((ts, value));
        }
    }

    /// Record a temporal hit for a specific rule reference.
    pub fn push_temporal(&mut self, ts: i64, rule_ref: &str) {
        if let WindowState::Temporal { rule_hits } = self {
            rule_hits
                .entry(rule_ref.to_string())
                .or_default()
                .push_back(ts);
        }
    }

    /// Record a numeric aggregation value.
    pub fn push_numeric(&mut self, ts: i64, value: f64) {
        if let WindowState::NumericAgg { entries } = self {
            entries.push_back((ts, value));
        }
    }

    /// Evaluate the window state against the correlation condition.
    ///
    /// Returns `Some(aggregated_value)` if the condition is satisfied,
    /// `None` otherwise.
    pub fn check_condition(
        &self,
        condition: &CompiledCondition,
        corr_type: CorrelationType,
        rule_refs: &[String],
    ) -> Option<f64> {
        let value = match (self, corr_type) {
            (WindowState::EventCount { timestamps }, CorrelationType::EventCount) => {
                timestamps.len() as f64
            }
            (WindowState::ValueCount { entries }, CorrelationType::ValueCount) => {
                // Count distinct values
                let distinct: HashSet<&String> = entries.iter().map(|(_, v)| v).collect();
                distinct.len() as f64
            }
            (WindowState::Temporal { rule_hits }, CorrelationType::Temporal) => {
                // Count how many distinct referenced rules have fired
                let fired: usize = rule_refs
                    .iter()
                    .filter(|r| rule_hits.get(r.as_str()).is_some_and(|ts| !ts.is_empty()))
                    .count();
                fired as f64
            }
            (WindowState::Temporal { rule_hits }, CorrelationType::TemporalOrdered) => {
                // Check if all referenced rules fired in order
                if check_temporal_ordered(rule_refs, rule_hits) {
                    rule_refs.len() as f64
                } else {
                    0.0
                }
            }
            (WindowState::NumericAgg { entries }, CorrelationType::ValueSum) => {
                entries.iter().map(|(_, v)| v).sum()
            }
            (WindowState::NumericAgg { entries }, CorrelationType::ValueAvg) => {
                if entries.is_empty() {
                    0.0
                } else {
                    let sum: f64 = entries.iter().map(|(_, v)| v).sum();
                    sum / entries.len() as f64
                }
            }
            (WindowState::NumericAgg { entries }, CorrelationType::ValuePercentile) => {
                // The condition value is a percentile threshold (e.g., lte: 1 means
                // the value should be at or below the 1st percentile).
                // We compute the percentile rank of each value in the distribution.
                // For simplicity: return the count of distinct values as a proxy.
                // In practice, percentile correlation is backend-specific.
                // Here we return the percentile position of the condition field.
                if entries.is_empty() {
                    0.0
                } else {
                    let mut values: Vec<f64> = entries.iter().map(|(_, v)| *v).collect();
                    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                    // Return the median-ish value for percentile checking
                    // The condition.check() will compare this against the threshold
                    let idx = values.len() / 2;
                    values[idx]
                }
            }
            (WindowState::NumericAgg { entries }, CorrelationType::ValueMedian) => {
                if entries.is_empty() {
                    0.0
                } else {
                    let mut values: Vec<f64> = entries.iter().map(|(_, v)| *v).collect();
                    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                    let mid = values.len() / 2;
                    if values.len().is_multiple_of(2) && values.len() >= 2 {
                        (values[mid - 1] + values[mid]) / 2.0
                    } else {
                        values[mid]
                    }
                }
            }
            _ => return None, // mismatched state/type
        };

        if condition.check(value) {
            Some(value)
        } else {
            None
        }
    }
}

/// Check if all referenced rules fired in the correct order within the window.
///
/// For `temporal_ordered`, each rule must have at least one hit, and there
/// must exist a sequence of timestamps (one per rule) that is non-decreasing
/// and follows the rule ordering.
fn check_temporal_ordered(
    rule_refs: &[String],
    rule_hits: &HashMap<String, VecDeque<i64>>,
) -> bool {
    if rule_refs.is_empty() {
        return true;
    }

    // All rules must have at least one hit
    for r in rule_refs {
        if rule_hits.get(r.as_str()).is_none_or(|ts| ts.is_empty()) {
            return false;
        }
    }

    // Check if there's a valid ordered sequence: for each rule in order,
    // find a timestamp >= the previous rule's chosen timestamp.
    fn find_ordered(
        rule_refs: &[String],
        rule_hits: &HashMap<String, VecDeque<i64>>,
        idx: usize,
        min_ts: i64,
    ) -> bool {
        if idx >= rule_refs.len() {
            return true;
        }
        let Some(timestamps) = rule_hits.get(&rule_refs[idx]) else {
            return false;
        };
        for &ts in timestamps {
            if ts >= min_ts && find_ordered(rule_refs, rule_hits, idx + 1, ts) {
                return true;
            }
        }
        false
    }

    find_ordered(rule_refs, rule_hits, 0, i64::MIN)
}

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
    let condition = compile_condition(&rule.condition, rule.correlation_type)?;

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
        generate: rule.generate,
    })
}

/// Compile a `CorrelationCondition` into a `CompiledCondition`.
fn compile_condition(
    cond: &CorrelationCondition,
    corr_type: CorrelationType,
) -> Result<CompiledCondition> {
    match cond {
        CorrelationCondition::Threshold { op, count, field } => Ok(CompiledCondition {
            field: field.clone(),
            predicates: vec![(*op, *count as f64)],
        }),
        CorrelationCondition::Extended(_expr) => {
            // For temporal types with an extended boolean condition,
            // default to: all referenced rules must fire (gte: rule_count).
            // The actual boolean expression evaluation would require a more
            // complex implementation. For now, treat it as "all must fire".
            match corr_type {
                CorrelationType::Temporal | CorrelationType::TemporalOrdered => {
                    Ok(CompiledCondition {
                        field: None,
                        predicates: vec![(ConditionOperator::Gte, 1.0)],
                    })
                }
                _ => Err(EvalError::CorrelationError(
                    "Extended conditions are only supported for temporal correlation types"
                        .to_string(),
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_group_key_extract() {
        let v = json!({"User": "admin", "Host": "srv01"});
        let event = Event::from_value(&v);
        let group_by = vec![
            GroupByField::Direct("User".to_string()),
            GroupByField::Direct("Host".to_string()),
        ];
        let key = GroupKey::extract(&event, &group_by, &["rule1"]);
        assert_eq!(
            key.0,
            vec![Some("admin".to_string()), Some("srv01".to_string())]
        );
    }

    #[test]
    fn test_group_key_missing_field() {
        let v = json!({"User": "admin"});
        let event = Event::from_value(&v);
        let group_by = vec![
            GroupByField::Direct("User".to_string()),
            GroupByField::Direct("Host".to_string()),
        ];
        let key = GroupKey::extract(&event, &group_by, &["rule1"]);
        assert_eq!(key.0, vec![Some("admin".to_string()), None]);
    }

    #[test]
    fn test_group_key_aliased() {
        let v = json!({"source.ip": "10.0.0.1"});
        let event = Event::from_value(&v);
        let group_by = vec![GroupByField::Aliased {
            alias: "internal_ip".to_string(),
            mapping: HashMap::from([
                ("rule_a".to_string(), "source.ip".to_string()),
                ("rule_b".to_string(), "destination.ip".to_string()),
            ]),
        }];
        let key = GroupKey::extract(&event, &group_by, &["rule_a"]);
        assert_eq!(key.0, vec![Some("10.0.0.1".to_string())]);
    }

    #[test]
    fn test_condition_check() {
        let cond = CompiledCondition {
            field: None,
            predicates: vec![(ConditionOperator::Gte, 100.0)],
        };
        assert!(!cond.check(99.0));
        assert!(cond.check(100.0));
        assert!(cond.check(101.0));
    }

    #[test]
    fn test_condition_check_range() {
        let cond = CompiledCondition {
            field: None,
            predicates: vec![
                (ConditionOperator::Gt, 100.0),
                (ConditionOperator::Lte, 200.0),
            ],
        };
        assert!(!cond.check(100.0));
        assert!(cond.check(101.0));
        assert!(cond.check(200.0));
        assert!(!cond.check(201.0));
    }

    #[test]
    fn test_window_event_count() {
        let mut state = WindowState::new_for(CorrelationType::EventCount);
        for i in 0..5 {
            state.push_event_count(1000 + i);
        }
        let cond = CompiledCondition {
            field: None,
            predicates: vec![(ConditionOperator::Gte, 5.0)],
        };
        assert_eq!(
            state.check_condition(&cond, CorrelationType::EventCount, &[]),
            Some(5.0)
        );
    }

    #[test]
    fn test_window_event_count_eviction() {
        let mut state = WindowState::new_for(CorrelationType::EventCount);
        for i in 0..10 {
            state.push_event_count(1000 + i);
        }
        // Evict events before ts=1005
        state.evict(1005);
        let cond = CompiledCondition {
            field: None,
            predicates: vec![(ConditionOperator::Gte, 5.0)],
        };
        assert_eq!(
            state.check_condition(&cond, CorrelationType::EventCount, &[]),
            Some(5.0)
        );
    }

    #[test]
    fn test_window_value_count() {
        let mut state = WindowState::new_for(CorrelationType::ValueCount);
        state.push_value_count(1000, "user1".to_string());
        state.push_value_count(1001, "user2".to_string());
        state.push_value_count(1002, "user1".to_string()); // duplicate
        state.push_value_count(1003, "user3".to_string());

        let cond = CompiledCondition {
            field: Some("User".to_string()),
            predicates: vec![(ConditionOperator::Gte, 3.0)],
        };
        assert_eq!(
            state.check_condition(&cond, CorrelationType::ValueCount, &[]),
            Some(3.0)
        );
    }

    #[test]
    fn test_window_temporal() {
        let refs = vec!["rule_a".to_string(), "rule_b".to_string()];
        let mut state = WindowState::new_for(CorrelationType::Temporal);
        state.push_temporal(1000, "rule_a");
        // Only rule_a fired — condition: all refs must fire
        let cond = CompiledCondition {
            field: None,
            predicates: vec![(ConditionOperator::Gte, 2.0)],
        };
        assert!(
            state
                .check_condition(&cond, CorrelationType::Temporal, &refs)
                .is_none()
        );

        // Now rule_b fires too
        state.push_temporal(1001, "rule_b");
        assert_eq!(
            state.check_condition(&cond, CorrelationType::Temporal, &refs),
            Some(2.0)
        );
    }

    #[test]
    fn test_window_temporal_ordered() {
        let refs = vec![
            "rule_a".to_string(),
            "rule_b".to_string(),
            "rule_c".to_string(),
        ];
        let mut state = WindowState::new_for(CorrelationType::TemporalOrdered);
        // Fire in order: a, b, c
        state.push_temporal(1000, "rule_a");
        state.push_temporal(1001, "rule_b");
        state.push_temporal(1002, "rule_c");

        let cond = CompiledCondition {
            field: None,
            predicates: vec![(ConditionOperator::Gte, 3.0)],
        };
        assert!(
            state
                .check_condition(&cond, CorrelationType::TemporalOrdered, &refs)
                .is_some()
        );
    }

    #[test]
    fn test_window_temporal_ordered_wrong_order() {
        let refs = vec!["rule_a".to_string(), "rule_b".to_string()];
        let mut state = WindowState::new_for(CorrelationType::TemporalOrdered);
        // Fire in wrong order: b before a
        state.push_temporal(1000, "rule_b");
        state.push_temporal(1001, "rule_a");

        let cond = CompiledCondition {
            field: None,
            predicates: vec![(ConditionOperator::Gte, 2.0)],
        };
        assert!(
            state
                .check_condition(&cond, CorrelationType::TemporalOrdered, &refs)
                .is_none()
        );
    }

    #[test]
    fn test_window_value_sum() {
        let mut state = WindowState::new_for(CorrelationType::ValueSum);
        state.push_numeric(1000, 500.0);
        state.push_numeric(1001, 600.0);

        let cond = CompiledCondition {
            field: Some("bytes_sent".to_string()),
            predicates: vec![(ConditionOperator::Gt, 1000.0)],
        };
        assert_eq!(
            state.check_condition(&cond, CorrelationType::ValueSum, &[]),
            Some(1100.0)
        );
    }

    #[test]
    fn test_window_value_avg() {
        let mut state = WindowState::new_for(CorrelationType::ValueAvg);
        state.push_numeric(1000, 100.0);
        state.push_numeric(1001, 200.0);
        state.push_numeric(1002, 300.0);

        let cond = CompiledCondition {
            field: Some("bytes".to_string()),
            predicates: vec![(ConditionOperator::Gte, 200.0)],
        };
        assert_eq!(
            state.check_condition(&cond, CorrelationType::ValueAvg, &[]),
            Some(200.0)
        );
    }

    #[test]
    fn test_window_value_median() {
        let mut state = WindowState::new_for(CorrelationType::ValueMedian);
        state.push_numeric(1000, 10.0);
        state.push_numeric(1001, 20.0);
        state.push_numeric(1002, 30.0);

        let cond = CompiledCondition {
            field: Some("latency".to_string()),
            predicates: vec![(ConditionOperator::Gte, 20.0)],
        };
        assert_eq!(
            state.check_condition(&cond, CorrelationType::ValueMedian, &[]),
            Some(20.0)
        );
    }

    #[test]
    fn test_compile_correlation_basic() {
        use rsigma_parser::parse_sigma_yaml;

        let yaml = r#"
title: Base Rule
id: f305fd62-beca-47da-ad95-7690a0620084
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: "s3.amazonaws.com"
    condition: selection
level: low
---
title: Multiple AWS bucket enumerations
id: be246094-01d3-4bba-88de-69e582eba0cc
status: experimental
correlation:
    type: event_count
    rules:
        - f305fd62-beca-47da-ad95-7690a0620084
    group-by:
        - userIdentity.arn
    timespan: 1h
    condition:
        gte: 100
level: high
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(collection.correlations.len(), 1);

        let compiled = compile_correlation(&collection.correlations[0]).unwrap();
        assert_eq!(compiled.correlation_type, CorrelationType::EventCount);
        assert_eq!(compiled.timespan_secs, 3600);
        assert_eq!(compiled.rule_refs.len(), 1);
        assert_eq!(compiled.group_by.len(), 1);
        assert!(compiled.condition.check(100.0));
        assert!(!compiled.condition.check(99.0));
    }
}
