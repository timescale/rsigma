//! STIX `note` objects (STIX §4.13).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::SdoSroCommonProps;

/// A STIX note conveying analyst commentary about related objects (STIX §4.13).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Note {
    /// STIX object type (`note`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_note_type")
    )]
    object_type: String,
    /// SDO/SRO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Brief summary of the note content.
    #[cfg_attr(
        feature = "serde",
        serde(default, rename = "abstract", skip_serializing_if = "Option::is_none")
    )]
    pub abstract_: Option<String>,
    /// Note body text.
    pub content: String,
    /// Analyst author names.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub authors: Vec<String>,
    /// STIX objects this note applies to.
    pub object_refs: Vec<StixId>,
}

impl Note {
    /// STIX type name for notes.
    pub const TYPE_NAME: &'static str = "note";

    /// Check note common properties.
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)
    }
}

#[cfg(feature = "serde")]
fn deserialize_note_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Note::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Note {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_note_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            #[serde(default, rename = "abstract")]
            abstract_: Option<String>,
            content: String,
            #[serde(default)]
            authors: Vec<String>,
            object_refs: Vec<StixId>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let note = Self {
            object_type: raw.object_type,
            common: raw.common,
            abstract_: raw.abstract_,
            content: raw.content,
            authors: raw.authors,
            object_refs: raw.object_refs,
        };
        note.validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(note)
    }
}

impl QueryableStixObject for Note {
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
            ["abstract"] => self.abstract_.as_deref().map(QueryValue::Str),
            ["content"] => Some(QueryValue::Str(&self.content)),
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
        let json = include_str!("../../../tests/fixtures/spec/sdo/threat-actor-minimal.json");
        let msg = serde_json::from_str::<Note>(json).unwrap_err().to_string();
        assert!(msg.contains("expected STIX type `note`"));
        assert!(msg.contains("got `threat-actor`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/note-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Note>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
