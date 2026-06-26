//! STIX `user-account` objects (STIX §6.16).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;
use crate::model::sco::extensions::UnixAccountExt;

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct UserAccount {
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_user_account_type")
    )]
    object_type: String,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub user_id: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub credential: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub account_login: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub account_type: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub display_name: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub is_service_account: Option<bool>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub is_privileged: Option<bool>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub can_escalate_privs: Option<bool>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub is_disabled: Option<bool>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub account_created: Option<StixTimestamp>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub account_expires: Option<StixTimestamp>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub credential_last_changed: Option<StixTimestamp>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub account_first_login: Option<StixTimestamp>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub account_last_login: Option<StixTimestamp>,
}

impl UserAccount {
    pub const TYPE_NAME: &'static str = "user-account";

    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.has_specific_property() {
            return Err(ModelError::UserAccountNoProperties);
        }
        UnixAccountExt::validate_in_map(&self.common.extensions)?;
        Ok(())
    }

    fn has_specific_property(&self) -> bool {
        self.user_id.is_some()
            || self.credential.is_some()
            || self.account_login.is_some()
            || self.account_type.is_some()
            || self.display_name.is_some()
            || self.is_service_account.is_some()
            || self.is_privileged.is_some()
            || self.can_escalate_privs.is_some()
            || self.is_disabled.is_some()
            || self.account_created.is_some()
            || self.account_expires.is_some()
            || self.credential_last_changed.is_some()
            || self.account_first_login.is_some()
            || self.account_last_login.is_some()
            || self.common.extensions.get(UnixAccountExt::KEY).is_some()
    }
}

#[cfg(feature = "serde")]
fn deserialize_user_account_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, UserAccount::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for UserAccount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_user_account_type")]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            #[serde(default)]
            user_id: Option<String>,
            #[serde(default)]
            credential: Option<String>,
            #[serde(default)]
            account_login: Option<String>,
            #[serde(default)]
            account_type: Option<String>,
            #[serde(default)]
            display_name: Option<String>,
            #[serde(default)]
            is_service_account: Option<bool>,
            #[serde(default)]
            is_privileged: Option<bool>,
            #[serde(default)]
            can_escalate_privs: Option<bool>,
            #[serde(default)]
            is_disabled: Option<bool>,
            #[serde(default)]
            account_created: Option<StixTimestamp>,
            #[serde(default)]
            account_expires: Option<StixTimestamp>,
            #[serde(default)]
            credential_last_changed: Option<StixTimestamp>,
            #[serde(default)]
            account_first_login: Option<StixTimestamp>,
            #[serde(default)]
            account_last_login: Option<StixTimestamp>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            user_id: raw.user_id,
            credential: raw.credential,
            account_login: raw.account_login,
            account_type: raw.account_type,
            display_name: raw.display_name,
            is_service_account: raw.is_service_account,
            is_privileged: raw.is_privileged,
            can_escalate_privs: raw.can_escalate_privs,
            is_disabled: raw.is_disabled,
            account_created: raw.account_created,
            account_expires: raw.account_expires,
            credential_last_changed: raw.credential_last_changed,
            account_first_login: raw.account_first_login,
            account_last_login: raw.account_last_login,
        };
        obj.validate().map_err(serde::de::Error::custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for UserAccount {
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
            ["user_id"] => self.user_id.as_deref().map(QueryValue::Str),
            ["account_login"] => self.account_login.as_deref().map(QueryValue::Str),
            ["display_name"] => self.display_name.as_deref().map(QueryValue::Str),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/url.json");
        let msg = serde_json::from_str::<UserAccount>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `user-account`"));
        assert!(msg.contains("got `url`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/user-account-unix.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err =
            serde_json::from_value::<UserAccount>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn rejects_non_user_account_extension_without_type_specific_properties() {
        let json = r#"{
          "type": "user-account",
          "spec_version": "2.1",
          "id": "user-account--f94d689e-707d-58c3-b803-c720bb6ed096",
          "extensions": {
            "tcp-ext": {}
          }
        }"#;
        let err = serde_json::from_str::<UserAccount>(json).unwrap_err();
        assert!(
            err.to_string()
                .contains("user-account requires at least one specific property")
        );
    }

    #[test]
    fn accepts_unix_account_extension_without_type_specific_properties() {
        let json = r#"{
          "type": "user-account",
          "spec_version": "2.1",
          "id": "user-account--f94d689e-707d-58c3-b803-c720bb6ed096",
          "extensions": {
            "unix-account-ext": {
              "gid": 1001,
              "groups": ["wheel"],
              "home_dir": "/home/jdoe",
              "shell": "/bin/bash"
            }
          }
        }"#;
        let parsed: UserAccount = serde_json::from_str(json).expect("parse");
        parsed
            .validate()
            .expect("unix-account-ext satisfies STIX §6.16.2");
    }
}
