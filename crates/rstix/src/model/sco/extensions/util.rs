//! Shared helpers for parsing SCO extensions from [`ExtensionMap`] entries.

use crate::model::ModelError;
use crate::model::common::ExtensionEntry;

/// Deserialize an extension body from a map entry, preserving the serde error detail.
#[cfg(feature = "serde")]
pub(crate) fn deserialize_from_entry<T: serde::de::DeserializeOwned>(
    key: &'static str,
    entry: &ExtensionEntry,
) -> Result<T, ModelError> {
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
    serde_json::from_value(serde_json::Value::Object(obj)).map_err(|err| {
        ModelError::ExtensionDeserializeFailed {
            key,
            detail: err.to_string(),
        }
    })
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::model::common::ExtensionEntry;
    use crate::model::sco::extensions::ArchiveExt;

    #[test]
    fn deserialize_error_includes_extension_key_and_detail() {
        let entry = ExtensionEntry {
            extension_type: None,
            properties: BTreeMap::from([(
                "contains_refs".into(),
                serde_json::Value::String("not-an-array".into()),
            )]),
        };
        let err = deserialize_from_entry::<ArchiveExt>("archive-ext", &entry).unwrap_err();
        let ModelError::ExtensionDeserializeFailed { key, detail } = err else {
            panic!("expected ExtensionDeserializeFailed");
        };
        assert_eq!(key, "archive-ext");
        assert!(!detail.is_empty());
    }
}
