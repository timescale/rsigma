//! STIX `autonomous-system` objects (STIX §6.2).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AutonomousSystem {
    #[cfg_attr(
        feature = "serde",
        serde(
            rename = "type",
            deserialize_with = "deserialize_autonomous_system_type"
        )
    )]
    object_type: String,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    pub number: u32,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub name: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub rir: Option<String>,
}

impl AutonomousSystem {
    pub const TYPE_NAME: &'static str = "autonomous-system";
    pub fn validate(&self) -> Result<(), ModelError> {
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_autonomous_system_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, AutonomousSystem::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AutonomousSystem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(
                rename = "type",
                deserialize_with = "deserialize_autonomous_system_type"
            )]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            number: u32,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            rir: Option<String>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            number: raw.number,
            name: raw.name,
            rir: raw.rir,
        };
        obj.validate().map_err(serde::de::Error::custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for AutonomousSystem {
    fn id(&self) -> &StixId {
        &self.common.id
    }
    fn type_name(&self) -> &'static str {
        Self::TYPE_NAME
    }
    fn spec_version(&self) -> Option<SpecVersion> {
        self.common.spec_version
    }
    fn created(&self) -> Option<&StixTimestamp> {
        None
    }
    fn modified(&self) -> Option<&StixTimestamp> {
        None
    }
    fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
        match path {
            ["number"] => Some(QueryValue::Int(i64::from(self.number))),
            ["name"] => self.name.as_deref().map(QueryValue::Str),
            ["rir"] => self.rir.as_deref().map(QueryValue::Str),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/url.json");
        let msg = serde_json::from_str::<AutonomousSystem>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `autonomous-system`"));
        assert!(msg.contains("got `url`"));
    }
    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/autonomous-system-basic.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err =
            serde_json::from_value::<AutonomousSystem>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
