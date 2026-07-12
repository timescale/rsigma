//! STIX `language-content` objects (STIX §7.2.4).

use std::collections::BTreeMap;

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::SdoSroCommonProps;

/// A STIX language-content object carrying translated field values.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
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
    /// SDO/SRO common properties (`lang` must not be set).
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Target object id.
    pub object_ref: StixId,
    /// Target object revision timestamp when pinning a specific version.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub object_modified: Option<StixTimestamp>,
    /// Translations keyed by language tag, then by field name.
    pub contents: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
}

impl LanguageContent {
    /// STIX type name for language-content objects.
    pub const TYPE_NAME: &'static str = "language-content";

    /// Validate language-content invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)?;
        if self.common.lang.is_some() {
            return Err(ModelError::LanguageContentLangNotAllowed);
        }
        crate::model::validate::validate_language_content_contents(&self.contents)?;
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_language_content_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, LanguageContent::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for LanguageContent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(
                rename = "type",
                deserialize_with = "deserialize_language_content_type"
            )]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            object_ref: StixId,
            #[serde(default)]
            object_modified: Option<StixTimestamp>,
            contents: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let content = Self {
            object_type: raw.object_type,
            common: raw.common,
            object_ref: raw.object_ref,
            object_modified: raw.object_modified,
            contents: raw.contents,
        };
        content
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(content)
    }
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
            ["object_modified"] => self.object_modified.as_ref().map(QueryValue::Timestamp),
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
