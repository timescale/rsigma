//! STIX `campaign` objects (STIX §4.2).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::SdoSroCommonProps;
use crate::model::sdo::validate_first_last_seen;

/// A STIX campaign grouping adversarial behaviors over time (STIX §4.2).
///
/// Required properties: common SDO fields plus `name`. Optional fields include
/// `description`, `aliases`, `first_seen`, `last_seen`, and `objective`.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sdo::Campaign;
///
/// let json = r#"{
///   "type": "campaign",
///   "spec_version": "2.1",
///   "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
///   "created": "2016-04-06T20:03:00.000Z",
///   "modified": "2016-04-06T20:03:00.000Z",
///   "name": "Green Group Attacks Against Finance",
///   "description": "Campaign by Green Group against financial services."
/// }"#;
/// let campaign: Campaign = serde_json::from_str(json)?;
/// assert_eq!(campaign.name, "Green Group Attacks Against Finance");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Campaign {
    /// STIX object type (`campaign`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_campaign_type")
    )]
    object_type: String,
    /// SDO/SRO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Name identifying the campaign.
    pub name: String,
    /// Human-readable description.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// Alternative names for this campaign.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub aliases: Vec<String>,
    /// When this campaign was first observed.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub first_seen: Option<StixTimestamp>,
    /// When this campaign was last observed.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub last_seen: Option<StixTimestamp>,
    /// Primary goal or intended effect of the campaign.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub objective: Option<String>,
}

impl Campaign {
    /// STIX type name for campaigns.
    pub const TYPE_NAME: &'static str = "campaign";

    /// Check campaign-specific invariants (non-empty `name`, time ordering).
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)?;
        validate_first_last_seen(&self.first_seen, &self.last_seen)
    }
}

#[cfg(feature = "serde")]
fn deserialize_campaign_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Campaign::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Campaign {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_campaign_type")]
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
            objective: Option<String>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let campaign = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
            description: raw.description,
            aliases: raw.aliases,
            first_seen: raw.first_seen,
            last_seen: raw.last_seen,
            objective: raw.objective,
        };
        campaign
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(campaign)
    }
}

impl QueryableStixObject for Campaign {
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
            ["objective"] => self.objective.as_deref().map(QueryValue::Str),
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
        let json = include_str!("../../../tests/fixtures/spec/sdo/attack-pattern-minimal.json");
        let msg = serde_json::from_str::<Campaign>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `campaign`"));
        assert!(msg.contains("got `attack-pattern`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/campaign-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Campaign>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn validate_rejects_last_seen_before_first_seen() {
        let first = StixTimestamp::parse("2016-05-01T00:00:00.000Z").expect("timestamp");
        let last = StixTimestamp::parse("2016-04-01T00:00:00.000Z").expect("timestamp");
        let campaign = Campaign {
            object_type: Campaign::TYPE_NAME.to_string(),
            common: campaign_common(),
            name: "Test".into(),
            description: None,
            aliases: Vec::new(),
            first_seen: Some(first),
            last_seen: Some(last),
            objective: None,
        };
        assert_eq!(
            campaign.validate().unwrap_err(),
            ModelError::SdoLastSeenBeforeFirstSeen
        );
    }

    fn campaign_common() -> SdoSroCommonProps {
        let ts = StixTimestamp::parse("2016-05-12T08:17:27.000Z").expect("timestamp");
        SdoSroCommonProps::new(StixId::generate("campaign"), ts.clone(), ts)
    }
}
