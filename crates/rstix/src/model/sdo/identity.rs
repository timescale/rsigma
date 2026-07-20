//! STIX `identity` objects (STIX §4.5).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::SdoSroCommonProps;

/// A STIX identity representing individuals, organizations, or groups (STIX §4.5).
///
/// Required properties: common SDO fields plus `name`. Optional fields include
/// `description`, `roles`, `identity_class`, `sectors`, and `contact_information`.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sdo::Identity;
///
/// let json = r#"{
///   "type": "identity",
///   "spec_version": "2.1",
///   "id": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
///   "created": "2016-04-06T20:03:00.000Z",
///   "modified": "2016-04-06T20:03:00.000Z",
///   "name": "John Smith",
///   "identity_class": "individual"
/// }"#;
/// let identity: Identity = serde_json::from_str(json)?;
/// assert_eq!(identity.name, "John Smith");
/// assert_eq!(identity.identity_class.as_deref(), Some("individual"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Identity {
    /// STIX object type (`identity`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_identity_type")
    )]
    object_type: String,
    /// SDO/SRO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Name identifying the identity.
    pub name: String,
    /// Human-readable description.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// Roles performed by this identity.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub roles: Vec<String>,
    /// Entity class (identity-class-ov).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub identity_class: Option<String>,
    /// Industry sectors (industry-sector-ov).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub sectors: Vec<String>,
    /// Contact information for this identity.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub contact_information: Option<String>,
}

impl Identity {
    /// STIX type name for identities.
    pub const TYPE_NAME: &'static str = "identity";

    /// Check common SDO properties.
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)
    }
}

#[cfg(feature = "serde")]
fn deserialize_identity_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Identity::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Identity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_identity_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            name: String,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            roles: Vec<String>,
            #[serde(default)]
            identity_class: Option<String>,
            #[serde(default)]
            sectors: Vec<String>,
            #[serde(default)]
            contact_information: Option<String>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let identity = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
            description: raw.description,
            roles: raw.roles,
            identity_class: raw.identity_class,
            sectors: raw.sectors,
            contact_information: raw.contact_information,
        };
        identity
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(identity)
    }
}

impl QueryableStixObject for Identity {
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
            ["identity_class"] => self.identity_class.as_deref().map(QueryValue::Str),
            ["contact_information"] => self.contact_information.as_deref().map(QueryValue::Str),
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
        let json = include_str!("../../../tests/fixtures/spec/sdo/incident-minimal.json");
        let msg = serde_json::from_str::<Identity>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `identity`"));
        assert!(msg.contains("got `incident`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/identity-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Identity>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
