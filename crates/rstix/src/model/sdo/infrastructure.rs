//! STIX `infrastructure` objects (STIX §4.8).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::{KillChainPhase, SdoSroCommonProps};
use crate::model::sdo::{validate_first_last_seen, validate_kill_chain_phases};

/// Infrastructure supporting adversary operations (STIX §4.8).
///
/// [`name`](Self::name) is required per STIX §4.8.1.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Infrastructure {
    /// STIX object type (`infrastructure`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_infrastructure_type")
    )]
    object_type: String,
    /// SDO common properties (STIX §3.2).
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Name identifying the infrastructure (STIX §4.8.1).
    pub name: String,
    /// Human-readable description (STIX §4.8.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// Infrastructure categories (infrastructure-type-ov) (STIX §4.8.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub infrastructure_types: Vec<String>,
    /// Alternative names for this infrastructure (STIX §4.8.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub aliases: Vec<String>,
    /// Kill chain phases where this infrastructure is used (STIX §4.8.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub kill_chain_phases: Vec<KillChainPhase>,
    /// When this infrastructure was first observed (STIX §4.8.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub first_seen: Option<StixTimestamp>,
    /// When this infrastructure was last observed (STIX §4.8.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub last_seen: Option<StixTimestamp>,
}

impl Infrastructure {
    /// STIX type name for infrastructure objects.
    pub const TYPE_NAME: &'static str = "infrastructure";

    /// Check infrastructure invariants (kill-chain phases, time ordering).
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)?;
        validate_kill_chain_phases(&self.kill_chain_phases)?;
        validate_first_last_seen(&self.first_seen, &self.last_seen)
    }
}

#[cfg(feature = "serde")]
fn deserialize_infrastructure_type<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(d, Infrastructure::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Infrastructure {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_infrastructure_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            name: String,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            infrastructure_types: Vec<String>,
            #[serde(default)]
            aliases: Vec<String>,
            #[serde(default)]
            kill_chain_phases: Vec<KillChainPhase>,
            #[serde(default)]
            first_seen: Option<StixTimestamp>,
            #[serde(default)]
            last_seen: Option<StixTimestamp>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let value = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
            description: raw.description,
            infrastructure_types: raw.infrastructure_types,
            aliases: raw.aliases,
            kill_chain_phases: raw.kill_chain_phases,
            first_seen: raw.first_seen,
            last_seen: raw.last_seen,
        };
        value
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(value)
    }
}

impl QueryableStixObject for Infrastructure {
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
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/location-minimal.json");
        let msg = serde_json::from_str::<Infrastructure>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `infrastructure`"));
        assert!(msg.contains("got `location`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/infrastructure-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err =
            serde_json::from_value::<Infrastructure>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
