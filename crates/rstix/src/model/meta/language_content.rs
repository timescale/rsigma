//! STIX `language-content` objects (STIX §7.2.4).

use std::collections::BTreeMap;

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::common::SdoSroCommonProps;

/// A STIX language-content object carrying translated field values.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::meta::LanguageContent;
///
/// let json = r#"{
///   "type": "language-content",
///   "spec_version": "2.1",
///   "id": "language-content--a0b0c0d0-e0f0-4a5b-8c9d-0e1f2a3b4c5d",
///   "created": "2016-05-12T08:17:27.000Z",
///   "modified": "2016-05-12T08:17:27.000Z",
///   "object_ref": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
///   "object_modified": false,
///   "contents": { "de": { "name": "Spearphishing" } }
/// }"#;
/// let content: LanguageContent = serde_json::from_str(json)?;
/// assert_eq!(content.object_ref.type_name(), "attack-pattern");
/// assert!(content.contents.contains_key("de"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LanguageContent {
    /// STIX object type (`language-content`).
    #[cfg_attr(
        feature = "serde",
        serde(
            rename = "type",
            deserialize_with = "deserialize_language_content_type"
        )
    )]
    object_type: String,
    /// SDO/SRO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Target object id.
    pub object_ref: StixId,
    /// Whether `object_ref` points at the latest revision of the target object.
    pub object_modified: bool,
    /// Translations keyed by language tag, then by field name.
    ///
    /// Uses [`BTreeMap`] for stable JSON key order on serialization.
    pub contents: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
}

impl LanguageContent {
    /// STIX type name for language-content objects.
    pub const TYPE_NAME: &'static str = "language-content";
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!(
            "../../../tests/fixtures/spec/meta/marking-definition-tlp-v1-white-stix21.json"
        );
        let msg = serde_json::from_str::<LanguageContent>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `language-content`"));
        assert!(msg.contains("got `marking-definition`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/meta/language-content.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err =
            serde_json::from_value::<LanguageContent>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn get_field_exposes_object_ref() {
        let json = include_str!("../../../tests/fixtures/spec/meta/language-content.json");
        let content: LanguageContent = serde_json::from_str(json).expect("parse");
        assert!(matches!(
            content.get_field(&["object_ref"]),
            Some(QueryValue::Id(_))
        ));
    }
}

#[cfg(feature = "serde")]
fn deserialize_language_content_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, LanguageContent::TYPE_NAME)
}

impl QueryableStixObject for LanguageContent {
    fn id(&self) -> &StixId {
        &self.common.id
    }

    fn type_name(&self) -> &'static str {
        Self::TYPE_NAME
    }

    fn spec_version(&self) -> Option<SpecVersion> {
        Some(self.common.spec_version)
    }

    fn created(&self) -> Option<&StixTimestamp> {
        Some(&self.common.created)
    }

    fn modified(&self) -> Option<&StixTimestamp> {
        Some(&self.common.modified)
    }

    fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
        match path {
            ["object_modified"] => Some(QueryValue::Bool(self.object_modified)),
            ["object_ref"] => Some(QueryValue::Id(&self.object_ref)),
            ["created_by_ref"] => self
                .common
                .created_by_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            _ => None,
        }
    }
}
