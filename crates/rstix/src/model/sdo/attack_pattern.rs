//! STIX `attack-pattern` objects (STIX §4.1).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::{KillChainPhase, SdoSroCommonProps};
use crate::model::sdo::validate_kill_chain_phases;

/// A STIX attack pattern describing adversary TTP behavior (STIX §4.1).
///
/// Required properties: common SDO fields plus `name`. Optional fields include
/// `description`, `aliases`, and `kill_chain_phases`.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sdo::AttackPattern;
///
/// let json = r#"{
///   "type": "attack-pattern",
///   "spec_version": "2.1",
///   "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
///   "created": "2016-05-12T08:17:27.000Z",
///   "modified": "2016-05-12T08:17:27.000Z",
///   "name": "Spear Phishing",
///   "description": "Adversary sends a crafted email to deliver malware.",
///   "external_references": [
///     { "source_name": "capec", "external_id": "CAPEC-163" }
///   ]
/// }"#;
/// let attack_pattern: AttackPattern = serde_json::from_str(json)?;
/// assert_eq!(attack_pattern.name, "Spear Phishing");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AttackPattern {
    /// STIX object type (`attack-pattern`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_attack_pattern_type")
    )]
    object_type: String,
    /// SDO/SRO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Name identifying the attack pattern.
    pub name: String,
    /// Human-readable description.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// Alternative names for this attack pattern.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub aliases: Vec<String>,
    /// Kill chain phases where this pattern applies.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub kill_chain_phases: Vec<KillChainPhase>,
}

impl AttackPattern {
    /// STIX type name for attack patterns.
    pub const TYPE_NAME: &'static str = "attack-pattern";

    /// Check attack-pattern-specific invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)?;
        validate_kill_chain_phases(&self.kill_chain_phases)
    }
}

#[cfg(feature = "serde")]
fn deserialize_attack_pattern_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, AttackPattern::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AttackPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_attack_pattern_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            name: String,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            aliases: Vec<String>,
            #[serde(default)]
            kill_chain_phases: Vec<KillChainPhase>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let attack_pattern = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
            description: raw.description,
            aliases: raw.aliases,
            kill_chain_phases: raw.kill_chain_phases,
        };
        attack_pattern
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(attack_pattern)
    }
}

impl QueryableStixObject for AttackPattern {
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
        let json = include_str!("../../../tests/fixtures/spec/sdo/campaign-minimal.json");
        let msg = serde_json::from_str::<AttackPattern>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `attack-pattern`"));
        assert!(msg.contains("got `campaign`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/attack-pattern-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err =
            serde_json::from_value::<AttackPattern>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
