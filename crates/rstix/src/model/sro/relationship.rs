//! STIX `relationship` objects (STIX §5.1).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::SdoSroCommonProps;

/// Source object reference (STIX §5.1.2 — SDO or SCO; target validation deferred).
pub type RelSourceRef = StixId;
/// Target object reference (STIX §5.1.2 — SDO or SCO; target validation deferred).
pub type RelTargetRef = StixId;

/// A STIX relationship linking a source object to a target object.
///
/// `source_ref` and `target_ref` must reference SDOs or SCOs per STIX §5.1.2.
/// SDO/SCO-only validation is deferred until `StixObject` dispatch lands
/// (follow-up: typed bundle parse).
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sro::Relationship;
///
/// let json = r#"{
///   "type": "relationship",
///   "spec_version": "2.1",
///   "id": "relationship--a2216352-483a-4941-842c-5328ad08abfd",
///   "created": "2016-05-12T08:17:27.000Z",
///   "modified": "2016-05-12T08:17:27.000Z",
///   "relationship_type": "uses",
///   "source_ref": "malware--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
///   "target_ref": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061"
/// }"#;
/// let relationship: Relationship = serde_json::from_str(json)?;
/// assert_eq!(relationship.relationship_type, "uses");
/// assert_eq!(relationship.source_ref.type_name(), "malware");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Relationship {
    /// STIX object type (`relationship`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_relationship_type")
    )]
    object_type: String,
    /// SDO/SRO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Name of the relationship (for example `uses`, `related-to`).
    pub relationship_type: String,
    /// Source object id.
    pub source_ref: RelSourceRef,
    /// Target object id.
    pub target_ref: RelTargetRef,
    /// Human-readable description.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// When the relationship began.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub start_time: Option<StixTimestamp>,
    /// When the relationship ended.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub stop_time: Option<StixTimestamp>,
}

impl Relationship {
    /// STIX type name for relationships.
    pub const TYPE_NAME: &'static str = "relationship";

    /// Check relationship-specific invariants (type charset, time ordering).
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_relationship_type(&self.relationship_type)?;
        if let (Some(start_time), Some(stop_time)) = (&self.start_time, &self.stop_time)
            && stop_time <= start_time
        {
            return Err(ModelError::RelationshipStopTimeBeforeStartTime);
        }
        Ok(())
    }
}

fn validate_relationship_type(relationship_type: &str) -> Result<(), ModelError> {
    if relationship_type.is_empty()
        || !relationship_type
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(ModelError::RelationshipTypeInvalid);
    }
    Ok(())
}

#[cfg(feature = "serde")]
fn deserialize_relationship_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Relationship::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Relationship {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_relationship_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            relationship_type: String,
            source_ref: RelSourceRef,
            target_ref: RelTargetRef,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            start_time: Option<StixTimestamp>,
            #[serde(default)]
            stop_time: Option<StixTimestamp>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let relationship = Self {
            object_type: raw.object_type,
            common: raw.common,
            relationship_type: raw.relationship_type,
            source_ref: raw.source_ref,
            target_ref: raw.target_ref,
            description: raw.description,
            start_time: raw.start_time,
            stop_time: raw.stop_time,
        };
        relationship.validate().map_err(serde::de::Error::custom)?;
        Ok(relationship)
    }
}

impl QueryableStixObject for Relationship {
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
            ["relationship_type"] => Some(QueryValue::Str(&self.relationship_type)),
            ["description"] => self.description.as_deref().map(QueryValue::Str),
            ["start_time"] => self.start_time.as_ref().map(QueryValue::Timestamp),
            ["stop_time"] => self.stop_time.as_ref().map(QueryValue::Timestamp),
            ["source_ref"] => Some(QueryValue::Id(&self.source_ref)),
            ["target_ref"] => Some(QueryValue::Id(&self.target_ref)),
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
        let json = include_str!("../../../tests/fixtures/spec/sro/sighting-minimal.json");
        let msg = serde_json::from_str::<Relationship>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `relationship`"));
        assert!(msg.contains("got `sighting`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sro/relationship.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err =
            serde_json::from_value::<Relationship>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn get_field_exposes_refs() {
        let json = include_str!("../../../tests/fixtures/spec/sro/relationship.json");
        let relationship: Relationship = serde_json::from_str(json).expect("parse");
        assert!(matches!(
            relationship.get_field(&["source_ref"]),
            Some(QueryValue::Id(_))
        ));
        assert!(matches!(
            relationship.get_field(&["target_ref"]),
            Some(QueryValue::Id(_))
        ));
    }

    #[test]
    fn validate_rejects_invalid_relationship_type() {
        let relationship = Relationship {
            object_type: Relationship::TYPE_NAME.to_string(),
            common: relationship_common(),
            relationship_type: "Uses".into(),
            source_ref: StixId::generate("malware"),
            target_ref: StixId::generate("attack-pattern"),
            description: None,
            start_time: None,
            stop_time: None,
        };
        assert_eq!(
            relationship.validate().unwrap_err(),
            ModelError::RelationshipTypeInvalid
        );
    }

    #[test]
    fn validate_rejects_stop_time_before_start_time() {
        let start = StixTimestamp::parse("2016-05-01T00:00:00.000Z").expect("timestamp");
        let stop = StixTimestamp::parse("2016-04-01T00:00:00.000Z").expect("timestamp");
        let relationship = Relationship {
            object_type: Relationship::TYPE_NAME.to_string(),
            common: relationship_common(),
            relationship_type: "related-to".into(),
            source_ref: StixId::generate("malware"),
            target_ref: StixId::generate("attack-pattern"),
            description: None,
            start_time: Some(start),
            stop_time: Some(stop),
        };
        assert_eq!(
            relationship.validate().unwrap_err(),
            ModelError::RelationshipStopTimeBeforeStartTime
        );
    }

    fn relationship_common() -> SdoSroCommonProps {
        let ts = StixTimestamp::parse("2016-05-12T08:17:27.000Z").expect("timestamp");
        SdoSroCommonProps::new(StixId::generate("relationship"), ts.clone(), ts)
    }
}
