//! STIX `opinion` objects (STIX §4.15).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::SdoSroCommonProps;
use crate::vocab::OpinionValue;

/// A STIX opinion assessing correctness of related objects (STIX §4.15).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Opinion {
    /// STIX object type (`opinion`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_opinion_type")
    )]
    object_type: String,
    /// SDO/SRO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Explanation for the opinion.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub explanation: Option<String>,
    /// Analyst author names.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub authors: Vec<String>,
    /// Agreement level on a fixed scale.
    pub opinion: OpinionValue,
    /// STIX objects this opinion applies to.
    pub object_refs: Vec<StixId>,
}

impl Opinion {
    /// STIX type name for opinions.
    pub const TYPE_NAME: &'static str = "opinion";

    /// Check opinion common properties.
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)
    }
}

#[cfg(feature = "serde")]
fn deserialize_opinion_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Opinion::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Opinion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_opinion_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            #[serde(default)]
            explanation: Option<String>,
            #[serde(default)]
            authors: Vec<String>,
            opinion: OpinionValue,
            object_refs: Vec<StixId>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let opinion = Self {
            object_type: raw.object_type,
            common: raw.common,
            explanation: raw.explanation,
            authors: raw.authors,
            opinion: raw.opinion,
            object_refs: raw.object_refs,
        };
        opinion
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(opinion)
    }
}

impl QueryableStixObject for Opinion {
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
            ["explanation"] => self.explanation.as_deref().map(QueryValue::Str),
            ["opinion"] => Some(QueryValue::Str(self.opinion.as_str())),
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
        let json = include_str!("../../../tests/fixtures/spec/sdo/identity-minimal.json");
        let msg = serde_json::from_str::<Opinion>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `opinion`"));
        assert!(msg.contains("got `identity`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/opinion-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Opinion>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
