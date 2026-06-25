//! STIX `archive-ext` extension.

use crate::model::ModelError;
use crate::model::common::ExtensionMap;

use crate::model::sco::ref_types::DirectoryContainsRef;

/// Archive file extension (STIX §6.7.2).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ArchiveExt {
    /// Files contained in the archive.
    pub contains_refs: Vec<DirectoryContainsRef>,
    /// Optional archive comment.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub comment: Option<String>,
}

impl ArchiveExt {
    /// Extension dictionary key.
    pub const KEY: &'static str = "archive-ext";

    /// Validate extension invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.contains_refs.is_empty() {
            return Err(ModelError::ArchiveExtContainsRefsEmpty);
        }

        Ok(())
    }

    /// Parse and validate this extension from an [`ExtensionMap`], if present.
    pub fn validate_in_map(map: &ExtensionMap) -> Result<(), ModelError> {
        if let Some(entry) = map.get(Self::KEY) {
            let mut obj = serde_json::Map::new();
            if let Some(t) = &entry.extension_type {
                obj.insert(
                    "extension_type".into(),
                    serde_json::Value::String(t.as_str().into()),
                );
            }
            for (k, v) in &entry.properties {
                obj.insert(k.clone(), v.clone());
            }
            let ext: Self = serde_json::from_value(serde_json::Value::Object(obj))
                .map_err(|_| ModelError::ExtensionDeserializeFailed)?;
            ext.validate()?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn round_trips_fixture() {
        let json =
            include_str!("../../../../tests/fixtures/spec/sco/extensions/archive-ext-minimal.json");
        let parsed: ArchiveExt = serde_json::from_str(json).expect("parse");
        parsed.validate().expect("valid");
        let value = serde_json::to_value(&parsed).expect("serialize");
        let reparsed: ArchiveExt = serde_json::from_value(value).expect("reparse");
        assert_eq!(parsed, reparsed);
    }
}
