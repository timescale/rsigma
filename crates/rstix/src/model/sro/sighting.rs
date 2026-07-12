//! STIX `sighting` objects (STIX §5.2).

use crate::core::{
    IdentityId, LocationId, ObservedDataId, QueryValue, QueryableStixObject, SpecVersion, StixId,
    StixObjectKind, StixTimestamp,
};
use crate::model::ModelError;
use crate::model::common::SdoSroCommonProps;

/// SDO reference for [`Sighting::sighting_of_ref`] (STIX §5.2.1).
pub type SightingOfRef = StixId;

/// Identity or location reference in [`Sighting::where_sighted_refs`] (STIX §5.2.1).
#[derive(Clone, Debug, PartialEq)]
pub enum WhereSightedRef {
    /// An identity that observed the sighting.
    Identity(IdentityId),
    /// A location where the sighting was observed.
    Location(LocationId),
}

impl WhereSightedRef {
    /// Borrow the underlying STIX id.
    pub fn as_stix_id(&self) -> &StixId {
        match self {
            Self::Identity(id) => id.as_stix_id(),
            Self::Location(id) => id.as_stix_id(),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for WhereSightedRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_stix_id().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for WhereSightedRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let id = <StixId as serde::Deserialize>::deserialize(deserializer)?;
        match id.type_name() {
            "identity" => IdentityId::from_stix_id(id)
                .map(Self::Identity)
                .map_err(serde::de::Error::custom),
            "location" => LocationId::from_stix_id(id)
                .map(Self::Location)
                .map_err(serde::de::Error::custom),
            _ => Err(ModelError::SightingWhereSightedRefInvalid.into_de_custom()),
        }
    }
}

/// A STIX sighting of an SDO in an external organization or environment.
///
/// `sighting_of_ref` must reference an SDO per STIX §5.2.1. Reference kind is
/// validated from the id prefix at deserialize time.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sro::Sighting;
///
/// let json = r#"{
///   "type": "sighting",
///   "spec_version": "2.1",
///   "id": "sighting--a2216352-483a-4941-842c-5328ad08abfd",
///   "created": "2016-05-12T08:17:27.000Z",
///   "modified": "2016-05-12T08:17:27.000Z",
///   "sighting_of_ref": "indicator--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
///   "where_sighted_refs": ["identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"]
/// }"#;
/// let sighting: Sighting = serde_json::from_str(json)?;
/// assert_eq!(sighting.sighting_of_ref.type_name(), "indicator");
/// assert_eq!(sighting.where_sighted_refs.len(), 1);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Sighting {
    /// STIX object type (`sighting`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_sighting_type")
    )]
    object_type: String,
    /// SDO/SRO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Human-readable description.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// Start of the sighting time window.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub first_seen: Option<StixTimestamp>,
    /// End of the sighting time window.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub last_seen: Option<StixTimestamp>,
    /// Number of times the sighted SDO was observed.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub count: Option<u32>,
    /// Whether the sighting is summarized from other data (STIX §5.2.1).
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            deserialize_with = "deserialize_sighting_summary",
            serialize_with = "serialize_sighting_summary",
            skip_serializing_if = "Option::is_none"
        )
    )]
    pub summary: Option<String>,
    /// SDO that was sighted.
    pub sighting_of_ref: SightingOfRef,
    /// Observed-data objects that contributed to the sighting.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub observed_data_refs: Vec<ObservedDataId>,
    /// Identities or locations where the sighting was observed.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub where_sighted_refs: Vec<WhereSightedRef>,
}

impl Sighting {
    /// STIX type name for sightings.
    pub const TYPE_NAME: &'static str = "sighting";

    /// Maximum inclusive value for [`Self::count`] (STIX §5.2.1).
    pub const COUNT_MAX: u32 = 999_999_999;

    /// Check sighting-specific invariants (count range, time window ordering, ref kind).
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)?;
        if let Some(count) = self.count
            && count > Self::COUNT_MAX
        {
            return Err(ModelError::SightingCountOutOfRange);
        }
        if let (Some(first_seen), Some(last_seen)) = (&self.first_seen, &self.last_seen)
            && last_seen < first_seen
        {
            return Err(ModelError::SightingLastSeenBeforeFirstSeen);
        }
        match StixObjectKind::from_type_str(self.sighting_of_ref.type_name()) {
            Some(StixObjectKind::Sdo(_)) => Ok(()),
            _ => Err(ModelError::SightingOfRefKindInvalid),
        }
    }
}

#[cfg(feature = "serde")]
fn serialize_sighting_summary<S>(value: &Option<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value.as_deref() {
        None => serializer.serialize_none(),
        Some("true") => serializer.serialize_bool(true),
        Some("false") => serializer.serialize_bool(false),
        Some(text) => serializer.serialize_str(text),
    }
}

#[cfg(feature = "serde")]
fn deserialize_sighting_summary<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Wire {
        Bool(bool),
        Str(String),
    }
    match Option::<Wire>::deserialize(deserializer)? {
        None => Ok(None),
        Some(Wire::Bool(false)) => Ok(Some("false".into())),
        Some(Wire::Bool(true)) => Ok(Some("true".into())),
        Some(Wire::Str(text)) => Ok(Some(text)),
    }
}

#[cfg(feature = "serde")]
fn deserialize_sighting_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Sighting::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Sighting {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_sighting_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            first_seen: Option<StixTimestamp>,
            #[serde(default)]
            last_seen: Option<StixTimestamp>,
            #[serde(default)]
            count: Option<u32>,
            #[serde(
                default,
                deserialize_with = "deserialize_sighting_summary",
                serialize_with = "serialize_sighting_summary"
            )]
            summary: Option<String>,
            sighting_of_ref: SightingOfRef,
            #[serde(default)]
            observed_data_refs: Vec<ObservedDataId>,
            #[serde(default)]
            where_sighted_refs: Vec<WhereSightedRef>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let sighting = Self {
            object_type: raw.object_type,
            common: raw.common,
            description: raw.description,
            first_seen: raw.first_seen,
            last_seen: raw.last_seen,
            count: raw.count,
            summary: raw.summary,
            sighting_of_ref: raw.sighting_of_ref,
            observed_data_refs: raw.observed_data_refs,
            where_sighted_refs: raw.where_sighted_refs,
        };
        sighting
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(sighting)
    }
}

impl QueryableStixObject for Sighting {
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
            ["description"] => self.description.as_deref().map(QueryValue::Str),
            ["first_seen"] => self.first_seen.as_ref().map(QueryValue::Timestamp),
            ["last_seen"] => self.last_seen.as_ref().map(QueryValue::Timestamp),
            ["count"] => self.count.map(|count| QueryValue::Int(i64::from(count))),
            ["summary"] => self.summary.as_deref().map(QueryValue::Str),
            ["sighting_of_ref"] => Some(QueryValue::Id(&self.sighting_of_ref)),
            ["created_by_ref"] => self
                .common
                .created_by_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["observed_data_refs", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.observed_data_refs.get(i))
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["where_sighted_refs", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.where_sighted_refs.get(i))
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
        let json = include_str!("../../../tests/fixtures/spec/sro/relationship.json");
        let msg = serde_json::from_str::<Sighting>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `sighting`"));
        assert!(msg.contains("got `relationship`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sro/sighting-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Sighting>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn get_field_exposes_refs() {
        let json = include_str!("../../../tests/fixtures/spec/sro/sighting-rich.json");
        let sighting: Sighting = serde_json::from_str(json).expect("parse");
        assert!(matches!(
            sighting.get_field(&["sighting_of_ref"]),
            Some(QueryValue::Id(_))
        ));
        assert!(matches!(
            sighting.get_field(&["observed_data_refs", "0"]),
            Some(QueryValue::Id(_))
        ));
        assert!(matches!(
            sighting.get_field(&["where_sighted_refs", "0"]),
            Some(QueryValue::Id(_))
        ));
    }

    #[test]
    fn validate_rejects_count_out_of_range() {
        let sighting = Sighting {
            object_type: Sighting::TYPE_NAME.to_string(),
            common: sighting_common(),
            description: None,
            first_seen: None,
            last_seen: None,
            count: Some(Sighting::COUNT_MAX + 1),
            summary: None,
            sighting_of_ref: StixId::generate("indicator"),
            observed_data_refs: Vec::new(),
            where_sighted_refs: Vec::new(),
        };
        assert_eq!(
            sighting.validate().unwrap_err(),
            ModelError::SightingCountOutOfRange
        );
    }

    #[test]
    fn validate_rejects_last_seen_before_first_seen() {
        let first = StixTimestamp::parse("2016-05-01T00:00:00.000Z").expect("timestamp");
        let last = StixTimestamp::parse("2016-04-01T00:00:00.000Z").expect("timestamp");
        let sighting = Sighting {
            object_type: Sighting::TYPE_NAME.to_string(),
            common: sighting_common(),
            description: None,
            first_seen: Some(first),
            last_seen: Some(last),
            count: None,
            summary: None,
            sighting_of_ref: StixId::generate("indicator"),
            observed_data_refs: Vec::new(),
            where_sighted_refs: Vec::new(),
        };
        assert_eq!(
            sighting.validate().unwrap_err(),
            ModelError::SightingLastSeenBeforeFirstSeen
        );
    }

    fn sighting_common() -> SdoSroCommonProps {
        let ts = StixTimestamp::parse("2016-05-12T08:17:27.000Z").expect("timestamp");
        SdoSroCommonProps::new(StixId::generate("sighting"), ts.clone(), ts)
    }
}
