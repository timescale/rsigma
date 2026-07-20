//! STIX `intrusion-set` objects (STIX §4.9).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::SdoSroCommonProps;
use crate::model::sdo::validate_first_last_seen;

/// A grouped set of adversarial behaviors and resources (STIX §4.9).
///
/// [`name`](Self::name) is required per STIX §4.9.1.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sdo::IntrusionSet;
///
/// let json = r#"{
///   "type": "intrusion-set",
///   "spec_version": "2.1",
///   "id": "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
///   "created": "2016-04-06T20:03:48.000Z",
///   "modified": "2016-04-06T20:03:48.000Z",
///   "name": "Bobcat Breakin"
/// }"#;
/// let intrusion_set: IntrusionSet = serde_json::from_str(json)?;
/// assert_eq!(intrusion_set.name, "Bobcat Breakin");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct IntrusionSet {
    /// STIX object type (`intrusion-set`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_intrusion_set_type")
    )]
    object_type: String,
    /// SDO common properties (STIX §3.2).
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Name identifying the intrusion set (STIX §4.9.1).
    pub name: String,
    /// Human-readable description (STIX §4.9.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// Alternative names for this intrusion set (STIX §4.9.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub aliases: Vec<String>,
    /// When this intrusion set was first observed (STIX §4.9.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub first_seen: Option<StixTimestamp>,
    /// When this intrusion set was last observed (STIX §4.9.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub last_seen: Option<StixTimestamp>,
    /// High-level goals of this intrusion set (STIX §4.9.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub goals: Vec<String>,
    /// Organizational resource level (attack-resource-level-ov) (STIX §4.9.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub resource_level: Option<String>,
    /// Primary motivation (attack-motivation-ov) (STIX §4.9.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub primary_motivation: Option<String>,
    /// Secondary motivations (attack-motivation-ov) (STIX §4.9.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub secondary_motivations: Vec<String>,
}

impl IntrusionSet {
    /// STIX type name for intrusion sets.
    pub const TYPE_NAME: &'static str = "intrusion-set";

    /// Check intrusion-set invariants (time ordering when both timestamps are set).
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)?;
        validate_first_last_seen(&self.first_seen, &self.last_seen)
    }
}

#[cfg(feature = "serde")]
fn deserialize_intrusion_set_type<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(d, IntrusionSet::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for IntrusionSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_intrusion_set_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            name: String,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            aliases: Vec<String>,
            #[serde(default)]
            first_seen: Option<StixTimestamp>,
            #[serde(default)]
            last_seen: Option<StixTimestamp>,
            #[serde(default)]
            goals: Vec<String>,
            #[serde(default)]
            resource_level: Option<String>,
            #[serde(default)]
            primary_motivation: Option<String>,
            #[serde(default)]
            secondary_motivations: Vec<String>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let value = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
            description: raw.description,
            aliases: raw.aliases,
            first_seen: raw.first_seen,
            last_seen: raw.last_seen,
            goals: raw.goals,
            resource_level: raw.resource_level,
            primary_motivation: raw.primary_motivation,
            secondary_motivations: raw.secondary_motivations,
        };
        value
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(value)
    }
}

impl QueryableStixObject for IntrusionSet {
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
        let json = include_str!("../../../tests/fixtures/spec/sdo/malware-minimal.json");
        let msg = serde_json::from_str::<IntrusionSet>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `intrusion-set`"));
        assert!(msg.contains("got `malware`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/intrusion-set-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err =
            serde_json::from_value::<IntrusionSet>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
