//! Statement marking payloads.

use crate::model::meta::MarkingDefinition;

/// Parsed statement marking text from a marking-definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementMarking {
    /// Statement text when present.
    pub statement: String,
}

impl StatementMarking {
    /// Extract a statement marking from a marking-definition, if encoded as statement type.
    pub fn from_marking_definition(marking: &MarkingDefinition) -> Option<Self> {
        if marking.definition_type.as_deref() != Some("statement") {
            return None;
        }
        let statement = marking
            .definition
            .as_ref()
            .and_then(|def| def.get("statement"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)?;
        Some(Self { statement })
    }
}
