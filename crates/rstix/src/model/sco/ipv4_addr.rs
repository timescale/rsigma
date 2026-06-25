//! STIX `ipv4-addr` objects (STIX §6.8).

use crate::core::{AutonomousSystemId, MacAddrId};
use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Ipv4Addr {
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_ipv4_addr_type")
    )]
    object_type: String,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    pub value: String,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub resolves_to_refs: Vec<MacAddrId>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub belongs_to_refs: Vec<AutonomousSystemId>,
}

impl Ipv4Addr {
    pub const TYPE_NAME: &'static str = "ipv4-addr";

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.value.is_empty() {
            return Err(ModelError::Ipv4AddrValueEmpty);
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_ipv4_addr_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Ipv4Addr::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Ipv4Addr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_ipv4_addr_type")]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            value: String,
            #[serde(default)]
            resolves_to_refs: Vec<MacAddrId>,
            #[serde(default)]
            belongs_to_refs: Vec<AutonomousSystemId>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            value: raw.value,
            resolves_to_refs: raw.resolves_to_refs,
            belongs_to_refs: raw.belongs_to_refs,
        };
        obj.validate().map_err(serde::de::Error::custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for Ipv4Addr {
    fn id(&self) -> &StixId {
        &self.common.id
    }

    fn type_name(&self) -> &'static str {
        Ipv4Addr::TYPE_NAME
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
            ["value"] => Some(QueryValue::Str(&self.value)),
            ["resolves_to_refs", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.resolves_to_refs.get(i))
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["belongs_to_refs", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.belongs_to_refs.get(i))
                .map(|id| QueryValue::Id(id.as_stix_id())),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::core::QueryValue;

    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/url.json");
        let msg = serde_json::from_str::<Ipv4Addr>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `ipv4-addr`"));
        assert!(msg.contains("got `"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/ipv4-addr-single.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Ipv4Addr>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn get_field_exposes_refs() {
        let json = include_str!("../../../tests/fixtures/spec/sco/ipv4-addr-with-belongs.json");
        let obj: Ipv4Addr = serde_json::from_str(json).expect("parse");
        assert!(matches!(
            obj.get_field(&["belongs_to_refs", "0"]),
            Some(QueryValue::Id(_))
        ));
    }
}
