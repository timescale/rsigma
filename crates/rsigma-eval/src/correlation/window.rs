use std::collections::{HashMap, HashSet, VecDeque};

use rsigma_parser::{ConditionExpr, CorrelationType};
use serde::Serialize;

use super::CompiledCondition;

// =============================================================================
// Window State
// =============================================================================

/// Per-group mutable state within a time window.
///
/// Each variant matches the type of aggregation being performed.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
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

    /// Returns the most recent timestamp in this window, or `None` if empty.
    pub fn latest_timestamp(&self) -> Option<i64> {
        match self {
            WindowState::EventCount { timestamps } => timestamps.back().copied(),
            WindowState::ValueCount { entries } => entries.back().map(|(t, _)| *t),
            WindowState::Temporal { rule_hits } => {
                rule_hits.values().filter_map(|ts| ts.back().copied()).max()
            }
            WindowState::NumericAgg { entries } => entries.back().map(|(t, _)| *t),
        }
    }

    /// Clear all entries from the window state (used by `CorrelationAction::Reset`).
    pub fn clear(&mut self) {
        match self {
            WindowState::EventCount { timestamps } => timestamps.clear(),
            WindowState::ValueCount { entries } => entries.clear(),
            WindowState::Temporal { rule_hits } => rule_hits.clear(),
            WindowState::NumericAgg { entries } => entries.clear(),
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
    ///
    /// For temporal correlations with an extended expression, the expression
    /// is evaluated against the set of rules that have fired in the window.
    pub fn check_condition(
        &self,
        condition: &CompiledCondition,
        corr_type: CorrelationType,
        rule_refs: &[String],
        extended_expr: Option<&ConditionExpr>,
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
                // If an extended expression is provided, evaluate it
                if let Some(expr) = extended_expr {
                    if eval_temporal_expr(expr, rule_hits) {
                        // Return the count of fired rules as the value
                        let fired: usize = rule_refs
                            .iter()
                            .filter(|r| rule_hits.get(r.as_str()).is_some_and(|ts| !ts.is_empty()))
                            .count();
                        return Some(fired as f64);
                    } else {
                        return None;
                    }
                }
                // Default: count how many distinct referenced rules have fired
                let fired: usize = rule_refs
                    .iter()
                    .filter(|r| rule_hits.get(r.as_str()).is_some_and(|ts| !ts.is_empty()))
                    .count();
                fired as f64
            }
            (WindowState::Temporal { rule_hits }, CorrelationType::TemporalOrdered) => {
                // If an extended expression is provided, evaluate it first
                if let Some(expr) = extended_expr
                    && !eval_temporal_expr(expr, rule_hits)
                {
                    return None;
                }
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
                // Proper percentile calculation using linear interpolation.
                // The condition threshold represents a percentile rank (0-100).
                // We compute the value at that percentile from the window data.
                if entries.is_empty() {
                    return None;
                }
                let mut values: Vec<f64> = entries
                    .iter()
                    .map(|(_, v)| *v)
                    .filter(|v| v.is_finite())
                    .collect();
                if values.is_empty() {
                    return None;
                }
                values.sort_by(|a, b| a.partial_cmp(b).expect("NaN filtered"));
                let percentile_rank = condition.percentile.map(|p| p as f64).unwrap_or(50.0);
                let pval = percentile_linear_interp(&values, percentile_rank);
                return Some(pval);
            }
            (WindowState::NumericAgg { entries }, CorrelationType::ValueMedian) => {
                if entries.is_empty() {
                    0.0
                } else {
                    let mut values: Vec<f64> = entries
                        .iter()
                        .map(|(_, v)| *v)
                        .filter(|v| v.is_finite())
                        .collect();
                    if values.is_empty() {
                        return None;
                    }
                    values.sort_by(|a, b| a.partial_cmp(b).expect("NaN filtered"));
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

/// Evaluate a boolean condition expression against the set of rules that have
/// fired within the temporal window.
///
/// Each `Identifier` in the expression is treated as a rule reference — it's
/// `true` if that rule has at least one hit in `rule_hits`.
pub(super) fn eval_temporal_expr(
    expr: &ConditionExpr,
    rule_hits: &HashMap<String, VecDeque<i64>>,
) -> bool {
    match expr {
        ConditionExpr::Identifier(name) => rule_hits
            .get(name.as_str())
            .is_some_and(|ts| !ts.is_empty()),
        ConditionExpr::And(children) => children.iter().all(|c| eval_temporal_expr(c, rule_hits)),
        ConditionExpr::Or(children) => children.iter().any(|c| eval_temporal_expr(c, rule_hits)),
        ConditionExpr::Not(child) => !eval_temporal_expr(child, rule_hits),
        ConditionExpr::Selector { .. } => {
            // Selectors are not meaningful for temporal condition evaluation
            false
        }
    }
}

/// Compute the value at a given percentile rank using linear interpolation.
///
/// Returns 0.0 if `values` is empty.
/// `values` must be sorted in ascending order.
/// `percentile` is from 0.0 to 100.0.
pub(super) fn percentile_linear_interp(values: &[f64], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let n = values.len();
    if n == 1 {
        return values[0];
    }

    // Clamp percentile to [0, 100]
    let p = percentile.clamp(0.0, 100.0) / 100.0;

    // Use the "C = 1" interpolation method (most common in statistics)
    // rank = p * (n - 1)
    let rank = p * (n - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    let fraction = rank - lower as f64;

    if lower == upper || upper >= n {
        values[lower.min(n - 1)]
    } else {
        values[lower] + fraction * (values[upper] - values[lower])
    }
}
