//! STIX `email-message` objects (STIX §6.6).

use std::collections::BTreeMap;

use crate::core::{
    ArtifactId, EmailAddrId, QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp,
};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;
use crate::model::sco::ref_types::EmailMimeBodyRawRef;

/// MIME part of a multipart email body (STIX §6.6.2).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EmailMimePart {
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub body: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub body_raw_ref: Option<EmailMimeBodyRawRef>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub content_type: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub content_disposition: Option<String>,
}

impl EmailMimePart {
    pub fn validate(&self) -> Result<(), ModelError> {
        let has_body = self.body.is_some();
        let has_raw = self.body_raw_ref.is_some();
        if has_body == has_raw {
            return Err(ModelError::EmailMimePartBodyXorRawRef);
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EmailMimePart {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(default)]
            body: Option<String>,
            #[serde(default)]
            body_raw_ref: Option<EmailMimeBodyRawRef>,
            #[serde(default)]
            content_type: Option<String>,
            #[serde(default)]
            content_disposition: Option<String>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let part = Self {
            body: raw.body,
            body_raw_ref: raw.body_raw_ref,
            content_type: raw.content_type,
            content_disposition: raw.content_disposition,
        };
        part.validate().map_err(serde::de::Error::custom)?;
        Ok(part)
    }
}

/// STIX `email-message` cyber-observable object.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EmailMessage {
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_email_message_type")
    )]
    object_type: String,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    pub is_multipart: bool,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub date: Option<StixTimestamp>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub content_type: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub from_ref: Option<EmailAddrId>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub sender_ref: Option<EmailAddrId>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub to_refs: Vec<EmailAddrId>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub cc_refs: Vec<EmailAddrId>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub bcc_refs: Vec<EmailAddrId>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub message_id: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub subject: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub received_lines: Vec<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub additional_header_fields: BTreeMap<String, Vec<String>>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub body: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub body_multipart: Option<Vec<EmailMimePart>>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub raw_email_ref: Option<ArtifactId>,
}

impl EmailMessage {
    pub const TYPE_NAME: &'static str = "email-message";

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.is_multipart {
            if self.body.is_some() {
                return Err(ModelError::EmailMessageBodyWithMultipart);
            }
            if self.body_multipart.is_none() {
                return Err(ModelError::EmailMessageMultipartMissing);
            }
        } else if self.body_multipart.is_some() {
            return Err(ModelError::EmailMessageMultipartWhenSinglePart);
        }
        if let Some(parts) = &self.body_multipart {
            for part in parts {
                part.validate()?;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_email_message_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, EmailMessage::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EmailMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_email_message_type")]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            is_multipart: bool,
            #[serde(default)]
            date: Option<StixTimestamp>,
            #[serde(default)]
            content_type: Option<String>,
            #[serde(default)]
            from_ref: Option<EmailAddrId>,
            #[serde(default)]
            sender_ref: Option<EmailAddrId>,
            #[serde(default)]
            to_refs: Vec<EmailAddrId>,
            #[serde(default)]
            cc_refs: Vec<EmailAddrId>,
            #[serde(default)]
            bcc_refs: Vec<EmailAddrId>,
            #[serde(default)]
            message_id: Option<String>,
            #[serde(default)]
            subject: Option<String>,
            #[serde(default)]
            received_lines: Vec<String>,
            #[serde(default)]
            additional_header_fields: BTreeMap<String, Vec<String>>,
            #[serde(default)]
            body: Option<String>,
            #[serde(default)]
            body_multipart: Option<Vec<EmailMimePart>>,
            #[serde(default)]
            raw_email_ref: Option<ArtifactId>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            is_multipart: raw.is_multipart,
            date: raw.date,
            content_type: raw.content_type,
            from_ref: raw.from_ref,
            sender_ref: raw.sender_ref,
            to_refs: raw.to_refs,
            cc_refs: raw.cc_refs,
            bcc_refs: raw.bcc_refs,
            message_id: raw.message_id,
            subject: raw.subject,
            received_lines: raw.received_lines,
            additional_header_fields: raw.additional_header_fields,
            body: raw.body,
            body_multipart: raw.body_multipart,
            raw_email_ref: raw.raw_email_ref,
        };
        obj.validate().map_err(serde::de::Error::custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for EmailMessage {
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
            ["subject"] => self.subject.as_deref().map(QueryValue::Str),
            ["from_ref"] => self
                .from_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["to_refs", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.to_refs.get(i))
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["raw_email_ref"] => self
                .raw_email_ref
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
        let msg = serde_json::from_str::<EmailMessage>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `email-message`"));
        assert!(msg.contains("got `url`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/email-message-simple.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err =
            serde_json::from_value::<EmailMessage>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn get_field_exposes_refs() {
        let json = include_str!("../../../tests/fixtures/spec/sco/email-message-simple.json");
        let obj: EmailMessage = serde_json::from_str(json).expect("parse");
        assert!(matches!(
            obj.get_field(&["from_ref"]),
            Some(QueryValue::Id(_))
        ));
        assert!(matches!(
            obj.get_field(&["to_refs", "0"]),
            Some(QueryValue::Id(_))
        ));
    }
}
