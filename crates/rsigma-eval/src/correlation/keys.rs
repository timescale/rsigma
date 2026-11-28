use std::borrow::Cow;

use serde::Serialize;

use crate::event::Event;

use super::types::GroupByField;

// =============================================================================
// Group Key
// =============================================================================

/// Composite key for group-by partitioning.
///
/// Each element corresponds to a `GroupByField` value extracted from an event.
#[derive(Debug, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, serde::Deserialize)]
pub struct GroupKey(pub Vec<Option<String>>);

impl GroupKey {
    /// Extract a group key from an event given the group-by fields and the
    /// rule reference identifiers (ID, name, etc.) that produced the detection match.
    ///
    /// Returns `None` when any group-by field is absent, null, or cannot be
    /// represented as a scalar string.
    pub fn extract(
        event: &impl Event,
        group_by: &[GroupByField],
        rule_refs: &[&str],
    ) -> Option<Self> {
        let values: Option<Vec<_>> = group_by
            .iter()
            .map(|field| {
                let field_name = field.resolve(rule_refs);
                event
                    .get_field(field_name)
                    .and_then(|v| v.as_str().map(Cow::into_owned))
                    .map(Some)
            })
            .collect();
        values.map(GroupKey)
    }

    /// Build a group key from explicit field-value pairs (for chaining).
    ///
    /// Returns `None` when the child correlation did not provide every field
    /// required by the parent.
    pub fn from_pairs(pairs: &[(String, String)], group_by: &[GroupByField]) -> Option<Self> {
        let values: Option<Vec<_>> = group_by
            .iter()
            .map(|field| {
                let name = field.name();
                pairs
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.clone())
                    .map(Some)
            })
            .collect();
        values.map(GroupKey)
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
