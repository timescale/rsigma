//! STIX `grouping` objects (STIX §4.4).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::SdoSroCommonProps;

/// A STIX grouping asserting shared context among referenced objects (STIX §4.4).
///
/// Required properties per STIX §4.4.1: common SDO fields, `name`, `context`, and
/// `object_refs`. The spec requires non-empty values for those fields; empty strings
/// or lists may still parse (see crate README conformance notes).
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sdo::Grouping;
///
/// let json = r#"{
///   "type": "grouping",
///   "spec_version": "2.1",
///   "id": "grouping--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
///   "created": "2015-12-21T19:59:11.000Z",
///   "modified": "2015-12-21T19:59:11.000Z",
///   "name": "The Black Vine Cyberespionage Group",
///   "context": "suspicious-activity",
///   "object_refs": [
///     "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2"
///   ]
/// }"#;
/// let grouping: Grouping = serde_json::from_str(json)?;
/// assert_eq!(grouping.context, "suspicious-activity");
/// assert_eq!(grouping.object_refs.len(), 1);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Grouping {
    /// STIX object type (`grouping`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_grouping_type")
    )]
    object_type: String,
    /// SDO/SRO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Name identifying the grouping.
    pub name: String,
    /// Human-readable description.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// Short descriptor of the shared context (grouping-context-ov).
    pub context: String,
    /// STIX object identifiers referenced by this grouping.
    pub object_refs: Vec<StixId>,
}

impl Grouping {
    /// STIX type name for groupings.
    pub const TYPE_NAME: &'static str = "grouping";

    /// Check grouping common properties.
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)
    }
}

#[cfg(feature = "serde")]
fn deserialize_grouping_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Grouping::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Grouping {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_grouping_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            name: String,
            #[serde(default)]
            description: Option<String>,
            context: String,
            object_refs: Vec<StixId>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let grouping = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
            description: raw.description,
            context: raw.context,
            object_refs: raw.object_refs,
        };
        grouping
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(grouping)
    }
}

impl QueryableStixObject for Grouping {
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
            ["name"] => Some(QueryValue::Str(&self.name)),
            ["description"] => self.description.as_deref().map(QueryValue::Str),
            ["context"] => Some(QueryValue::Str(&self.context)),
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
        let msg = serde_json::from_str::<Grouping>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `grouping`"));
        assert!(msg.contains("got `identity`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/grouping-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Grouping>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
