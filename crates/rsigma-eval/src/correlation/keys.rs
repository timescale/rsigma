use serde::Serialize;

use crate::event::{Event, EventValue};

use super::types::GroupByField;

// =============================================================================
// Group Key
// =============================================================================

/// Composite key for group-by partitioning.
///
/// Each element corresponds to a `GroupByField` value extracted from an event.
/// `None` means the field was absent from the event.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, serde::Deserialize)]
pub struct GroupKey(pub Vec<Option<String>>);

impl GroupKey {
    /// Extract a group key from an event given the group-by fields and the
    /// rule reference identifiers (ID, name, etc.) that produced the detection match.
    pub fn extract(event: &impl Event, group_by: &[GroupByField], rule_refs: &[&str]) -> Self {
        let values = group_by
            .iter()
            .map(|field| {
                let field_name = field.resolve(rule_refs);
                event
                    .get_field(field_name)
                    .and_then(|v| value_to_string(&v))
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

/// Convert an [`EventValue`] to a string for group-key purposes.
fn value_to_string(v: &EventValue) -> Option<String> {
    match v {
        EventValue::Str(s) => Some(s.to_string()),
        EventValue::Int(n) => Some(n.to_string()),
        EventValue::Float(f) => Some(f.to_string()),
        EventValue::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}
