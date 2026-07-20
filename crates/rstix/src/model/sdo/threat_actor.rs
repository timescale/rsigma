//! STIX `threat-actor` objects (STIX §4.17).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::SdoSroCommonProps;
use crate::model::sdo::validate_first_last_seen;

/// A STIX threat actor representing malicious individuals, groups, or organizations (STIX §4.17).
///
/// Required properties: common SDO fields plus `name`. Optional fields capture
/// actor types, aliases, activity windows, roles, goals, sophistication, resources,
/// and motivations.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sdo::ThreatActor;
///
/// let json = r#"{
///   "type": "threat-actor",
///   "spec_version": "2.1",
///   "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
///   "created": "2016-04-06T20:03:48.000Z",
///   "modified": "2016-04-06T20:03:48.000Z",
///   "name": "Evil Org",
///   "threat_actor_types": ["crime-syndicate"],
///   "primary_motivation": "organizational-gain"
/// }"#;
/// let threat_actor: ThreatActor = serde_json::from_str(json)?;
/// assert_eq!(threat_actor.name, "Evil Org");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ThreatActor {
    /// STIX object type (`threat-actor`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_threat_actor_type")
    )]
    object_type: String,
    /// SDO/SRO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Name identifying the threat actor.
    pub name: String,
    /// Human-readable description.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// Threat actor types (threat-actor-type-ov).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub threat_actor_types: Vec<String>,
    /// Alternative names for this threat actor.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub aliases: Vec<String>,
    /// When this threat actor was first observed.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub first_seen: Option<StixTimestamp>,
    /// When this threat actor was last observed.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub last_seen: Option<StixTimestamp>,
    /// Roles played by this threat actor (threat-actor-role-ov).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub roles: Vec<String>,
    /// High-level goals of this threat actor.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub goals: Vec<String>,
    /// Skill or expertise level (threat-actor-sophistication-ov).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub sophistication: Option<String>,
    /// Organizational resource level (attack-resource-level-ov).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub resource_level: Option<String>,
    /// Primary motivation (attack-motivation-ov).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub primary_motivation: Option<String>,
    /// Secondary motivations (attack-motivation-ov).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub secondary_motivations: Vec<String>,
    /// Personal motivations (attack-motivation-ov).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub personal_motivations: Vec<String>,
}

impl ThreatActor {
    /// STIX type name for threat actors.
    pub const TYPE_NAME: &'static str = "threat-actor";

    /// Check threat-actor-specific invariants (time ordering when both timestamps are set).
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)?;
        validate_first_last_seen(&self.first_seen, &self.last_seen)
    }
}

#[cfg(feature = "serde")]
fn deserialize_threat_actor_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, ThreatActor::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ThreatActor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_threat_actor_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            name: String,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            threat_actor_types: Vec<String>,
            #[serde(default)]
            aliases: Vec<String>,
            #[serde(default)]
            first_seen: Option<StixTimestamp>,
            #[serde(default)]
            last_seen: Option<StixTimestamp>,
            #[serde(default)]
            roles: Vec<String>,
            #[serde(default)]
            goals: Vec<String>,
            #[serde(default)]
            sophistication: Option<String>,
            #[serde(default)]
            resource_level: Option<String>,
            #[serde(default)]
            primary_motivation: Option<String>,
            #[serde(default)]
            secondary_motivations: Vec<String>,
            #[serde(default)]
            personal_motivations: Vec<String>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let threat_actor = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
            description: raw.description,
            threat_actor_types: raw.threat_actor_types,
            aliases: raw.aliases,
            first_seen: raw.first_seen,
            last_seen: raw.last_seen,
            roles: raw.roles,
            goals: raw.goals,
            sophistication: raw.sophistication,
            resource_level: raw.resource_level,
            primary_motivation: raw.primary_motivation,
            secondary_motivations: raw.secondary_motivations,
            personal_motivations: raw.personal_motivations,
        };
        threat_actor
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(threat_actor)
    }
}

impl QueryableStixObject for ThreatActor {
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
            ["sophistication"] => self.sophistication.as_deref().map(QueryValue::Str),
            ["resource_level"] => self.resource_level.as_deref().map(QueryValue::Str),
            ["primary_motivation"] => self.primary_motivation.as_deref().map(QueryValue::Str),
            ["first_seen"] => self.first_seen.as_ref().map(QueryValue::Timestamp),
            ["last_seen"] => self.last_seen.as_ref().map(QueryValue::Timestamp),
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
        let msg = serde_json::from_str::<ThreatActor>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `threat-actor`"));
        assert!(msg.contains("got `campaign`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/threat-actor-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err =
            serde_json::from_value::<ThreatActor>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn validate_rejects_last_seen_before_first_seen() {
        let first = StixTimestamp::parse("2016-05-01T00:00:00.000Z").expect("timestamp");
        let last = StixTimestamp::parse("2016-04-01T00:00:00.000Z").expect("timestamp");
        let threat_actor = ThreatActor {
            object_type: ThreatActor::TYPE_NAME.to_string(),
            common: threat_actor_common(),
            name: "Evil Org".into(),
            description: None,
            threat_actor_types: Vec::new(),
            aliases: Vec::new(),
            first_seen: Some(first),
            last_seen: Some(last),
            roles: Vec::new(),
            goals: Vec::new(),
            sophistication: None,
            resource_level: None,
            primary_motivation: None,
            secondary_motivations: Vec::new(),
            personal_motivations: Vec::new(),
        };
        assert_eq!(
            threat_actor.validate().unwrap_err(),
            ModelError::SdoLastSeenBeforeFirstSeen
        );
    }

    fn threat_actor_common() -> SdoSroCommonProps {
        let ts = StixTimestamp::parse("2016-05-12T08:17:27.000Z").expect("timestamp");
        SdoSroCommonProps::new(StixId::generate("threat-actor"), ts.clone(), ts)
    }
}
