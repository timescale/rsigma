//! STIX `incident` objects (STIX §4.6).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::SdoSroCommonProps;

/// A STIX incident stub for basic incident sharing use cases (STIX §4.6).
///
/// Required properties: common SDO fields plus `name`. Optional field: `description`.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sdo::Incident;
///
/// let json = r#"{
///   "type": "incident",
///   "spec_version": "2.1",
///   "id": "incident--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
///   "created": "2016-04-06T20:03:48.000Z",
///   "modified": "2016-04-06T20:03:48.000Z",
///   "name": "Incident 43",
///   "description": "This incident addresses APT 28 ..."
/// }"#;
/// let incident: Incident = serde_json::from_str(json)?;
/// assert_eq!(incident.name, "Incident 43");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Incident {
    /// STIX object type (`incident`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_incident_type")
    )]
    object_type: String,
    /// SDO/SRO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Name identifying the incident.
    pub name: String,
    /// Human-readable description.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
}

impl Incident {
    /// STIX type name for incidents.
    pub const TYPE_NAME: &'static str = "incident";

    /// Check common SDO properties.
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)
    }
}

#[cfg(feature = "serde")]
fn deserialize_incident_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Incident::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Incident {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_incident_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            name: String,
            #[serde(default)]
            description: Option<String>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let incident = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
            description: raw.description,
        };
        incident
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(incident)
    }
}

impl QueryableStixObject for Incident {
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
        let msg = serde_json::from_str::<Incident>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `incident`"));
        assert!(msg.contains("got `threat-actor`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/incident-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Incident>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
