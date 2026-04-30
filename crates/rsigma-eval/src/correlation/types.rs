use std::collections::HashMap;
use std::sync::Arc;

use rsigma_parser::{ConditionExpr, ConditionOperator, CorrelationType, Level};

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
    /// Extended boolean condition expression for temporal correlations.
    /// When set, evaluates this expression against fired rules instead of
    /// a simple threshold count.
    pub extended_expr: Option<ConditionExpr>,
    /// Whether referenced detection rules should also generate standalone matches.
    pub generate: bool,
    /// Per-correlation suppression window in seconds, resolved from the
    /// `rsigma.suppress` custom attribute. `None` means use engine default.
    pub suppress_secs: Option<u64>,
    /// Per-correlation action on match, resolved from the `rsigma.action`
    /// custom attribute. `None` means use engine default.
    pub action: Option<crate::correlation_engine::CorrelationAction>,
    /// Event inclusion mode for this correlation.
    /// `None` means use the engine default (`CorrelationConfig.correlation_event_mode`).
    pub event_mode: Option<crate::correlation_engine::CorrelationEventMode>,
    /// Maximum events to store per window group for event inclusion.
    /// `None` means use the engine default (`CorrelationConfig.max_correlation_events`).
    pub max_events: Option<usize>,
    /// Custom attributes from the original Sigma correlation rule (merged).
    /// Wrapped in `Arc` so that per-match cloning is a pointer bump.
    pub custom_attributes: Arc<HashMap<String, serde_json::Value>>,
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
    /// Optional field name(s) for value_count, value_sum, value_avg, value_percentile.
    /// When multiple fields are present, value_count counts distinct tuples.
    pub field: Option<Vec<String>>,
    /// One or more predicates to satisfy (all must be true for the condition to match).
    pub predicates: Vec<(ConditionOperator, f64)>,
    /// Percentile rank (0-100) for `value_percentile` type.
    /// `None` means use the default (50).
    pub percentile: Option<u64>,
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
