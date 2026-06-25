//! STIX `email-addr` objects (STIX §6.5).

use crate::core::{
    QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp, UserAccountId,
};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EmailAddr {
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_email_addr_type")
    )]
    object_type: String,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    pub value: String,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub display_name: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub belongs_to_ref: Option<UserAccountId>,
}

impl EmailAddr {
    pub const TYPE_NAME: &'static str = "email-addr";

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.value.is_empty() {
            return Err(ModelError::EmailAddrValueEmpty);
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_email_addr_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, EmailAddr::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EmailAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_email_addr_type")]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            value: String,
            #[serde(default)]
            display_name: Option<String>,
            #[serde(default)]
            belongs_to_ref: Option<UserAccountId>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            value: raw.value,
            display_name: raw.display_name,
            belongs_to_ref: raw.belongs_to_ref,
        };
        obj.validate().map_err(serde::de::Error::custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for EmailAddr {
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
            ["value"] => Some(QueryValue::Str(&self.value)),
            ["display_name"] => self.display_name.as_deref().map(QueryValue::Str),
            ["belongs_to_ref"] => self
                .belongs_to_ref
                .as_ref()
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
        let msg = serde_json::from_str::<EmailAddr>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `email-addr`"));
        assert!(msg.contains("got `url`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/email-addr-basic.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<EmailAddr>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn get_field_exposes_refs() {
        let json = include_str!("../../../tests/fixtures/spec/sco/email-addr-with-belongs-to.json");
        let obj: EmailAddr = serde_json::from_str(json).expect("parse");
        assert!(matches!(
            obj.get_field(&["belongs_to_ref"]),
            Some(QueryValue::Id(_))
        ));
    }
}
