//! STIX `windows-registry-key` objects (STIX §6.17).

use crate::core::{
    QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp, UserAccountId,
};

use crate::model::ModelError;
use crate::model::common::ScoCommonProps;

/// Windows registry value entry (STIX §6.17.2).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WindowsRegistryValue {
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub name: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub data: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub data_type: Option<String>,
}

impl WindowsRegistryValue {
    fn has_property(&self) -> bool {
        self.name.is_some() || self.data.is_some() || self.data_type.is_some()
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct WindowsRegistryKey {
    #[cfg_attr(
        feature = "serde",
        serde(
            rename = "type",
            deserialize_with = "deserialize_windows_registry_key_type"
        )
    )]
    object_type: String,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub key: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub values: Vec<WindowsRegistryValue>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub modified_time: Option<StixTimestamp>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub creator_user_ref: Option<UserAccountId>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub number_of_subkeys: Option<u64>,
}

impl WindowsRegistryKey {
    pub const TYPE_NAME: &'static str = "windows-registry-key";

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.key.is_none()
            && self.values.is_empty()
            && self.modified_time.is_none()
            && self.creator_user_ref.is_none()
            && self.number_of_subkeys.is_none()
        {
            return Err(ModelError::WindowsRegistryKeyNoProperties);
        }
        for value in &self.values {
            if !value.has_property() {
                return Err(ModelError::WindowsRegistryValueNoProperties);
            }
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_windows_registry_key_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(
        deserializer,
        WindowsRegistryKey::TYPE_NAME,
    )
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for WindowsRegistryKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(
                rename = "type",
                deserialize_with = "deserialize_windows_registry_key_type"
            )]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            #[serde(default)]
            key: Option<String>,
            #[serde(default)]
            values: Vec<WindowsRegistryValue>,
            #[serde(default)]
            modified_time: Option<StixTimestamp>,
            #[serde(default)]
            creator_user_ref: Option<UserAccountId>,
            #[serde(default)]
            number_of_subkeys: Option<u64>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            key: raw.key,
            values: raw.values,
            modified_time: raw.modified_time,
            creator_user_ref: raw.creator_user_ref,
            number_of_subkeys: raw.number_of_subkeys,
        };
        obj.validate().map_err(serde::de::Error::custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for WindowsRegistryKey {
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
            ["key"] => self.key.as_deref().map(QueryValue::Str),
            ["creator_user_ref"] => self
                .creator_user_ref
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
        let msg = serde_json::from_str::<WindowsRegistryKey>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `windows-registry-key`"));
        assert!(msg.contains("got `url`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/windows-registry-key-basic.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<WindowsRegistryKey>(serde_json::Value::Object(obj))
            .unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn get_field_exposes_refs() {
        let json =
            include_str!("../../../tests/fixtures/spec/sco/windows-registry-key-with-creator.json");
        let obj: WindowsRegistryKey = serde_json::from_str(json).expect("parse");
        assert!(matches!(
            obj.get_field(&["creator_user_ref"]),
            Some(QueryValue::Id(_))
        ));
    }
}
