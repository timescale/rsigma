//! STIX `email-message` objects (STIX §6.6).

use std::collections::BTreeMap;

use crate::core::{
    ArtifactId, EmailAddrId, QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp,
};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;
use crate::model::sco::ref_types::EmailMimeBodyRawRef;

/// MIME part of a multipart email body (STIX §6.6.2).
///
/// Exactly one of [`body`](Self::body) or [`body_raw_ref`](Self::body_raw_ref) must
/// be present.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EmailMimePart {
    /// Body content of the MIME part (STIX §6.6.2; mutually exclusive with `body_raw_ref`).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub body: Option<String>,
    /// Reference to an artifact holding the raw body bytes (STIX §6.6.2; mutually exclusive with `body`).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub body_raw_ref: Option<EmailMimeBodyRawRef>,
    /// MIME content type of the part (STIX §6.6.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub content_type: Option<String>,
    /// Content disposition of the part (STIX §6.6.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub content_disposition: Option<String>,
}

impl EmailMimePart {
    /// Check MIME-part invariants (body/raw-ref exclusivity).
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
        part.validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(part)
    }
}

/// An email message (STIX §6.6).
///
/// When [`is_multipart`](Self::is_multipart) is true, [`body_multipart`](Self::body_multipart)
/// must be set and [`body`](Self::body) must be absent; single-part messages use `body` only.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EmailMessage {
    /// STIX object type (`email-message`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_email_message_type")
    )]
    object_type: String,
    /// SCO common properties (STIX §3.2).
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    /// Whether the message body consists of multiple MIME parts (STIX §6.6.2).
    pub is_multipart: bool,
    /// Date the email was sent (STIX §6.6.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub date: Option<StixTimestamp>,
    /// MIME content type of the message (STIX §6.6.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub content_type: Option<String>,
    /// Author of the message content (STIX §6.6.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub from_ref: Option<EmailAddrId>,
    /// Entity that sent the message (STIX §6.6.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub sender_ref: Option<EmailAddrId>,
    /// Primary recipients (STIX §6.6.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub to_refs: Vec<EmailAddrId>,
    /// Carbon-copy recipients (STIX §6.6.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub cc_refs: Vec<EmailAddrId>,
    /// Blind carbon-copy recipients (STIX §6.6.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub bcc_refs: Vec<EmailAddrId>,
    /// Message identifier from the email header (STIX §6.6.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub message_id: Option<String>,
    /// Subject line (STIX §6.6.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub subject: Option<String>,
    /// `Received` header lines in order (STIX §6.6.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub received_lines: Vec<String>,
    /// Additional email header fields not otherwise captured (STIX §6.6.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub additional_header_fields: BTreeMap<String, Vec<String>>,
    /// Body of a single-part message (STIX §6.6.2; absent when `is_multipart` is true).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub body: Option<String>,
    /// MIME parts of a multipart message (STIX §6.6.1; required when `is_multipart` is true).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub body_multipart: Option<Vec<EmailMimePart>>,
    /// Reference to an artifact holding the raw RFC 5322 message (STIX §6.6.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub raw_email_ref: Option<ArtifactId>,
}

impl EmailMessage {
    /// STIX type name for email messages.
    pub const TYPE_NAME: &'static str = "email-message";

    /// Check email-message invariants (multipart/body rules; nested MIME-part validation).
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
        crate::model::validate::validate_extra_enc_pairings(
            &self.common.extra,
            &[
                ("subject", self.subject.as_deref()),
                ("body", self.body.as_deref()),
                ("message_id", self.message_id.as_deref()),
            ],
        )?;
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
        let mut additional_header_fields = raw.additional_header_fields;
        for values in additional_header_fields.values_mut() {
            for value in values {
                *value = crate::model::rfc2047::decode_header_value(value);
            }
        }
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
            message_id: raw
                .message_id
                .map(|value| crate::model::rfc2047::decode_header_value(&value)),
            subject: raw
                .subject
                .map(|value| crate::model::rfc2047::decode_header_value(&value)),
            received_lines: raw
                .received_lines
                .into_iter()
                .map(|line| crate::model::rfc2047::decode_header_value(&line))
                .collect(),
            additional_header_fields,
            body: raw
                .body
                .map(|value| crate::model::rfc2047::decode_header_value(&value)),
            body_multipart: raw.body_multipart,
            raw_email_ref: raw.raw_email_ref,
        };
        obj.validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
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
            ["is_multipart"] => Some(QueryValue::Bool(self.is_multipart)),
            ["date"] => self.date.as_ref().map(QueryValue::Timestamp),
            ["content_type"] => self.content_type.as_deref().map(QueryValue::Str),
            ["message_id"] => self.message_id.as_deref().map(QueryValue::Str),
            ["subject"] => self.subject.as_deref().map(QueryValue::Str),
            ["subject_enc"] => self
                .common
                .extra
                .get("subject_enc")
                .and_then(serde_json::Value::as_str)
                .map(QueryValue::Str),
            ["body"] => self.body.as_deref().map(QueryValue::Str),
            ["body_enc"] => self
                .common
                .extra
                .get("body_enc")
                .and_then(serde_json::Value::as_str)
                .map(QueryValue::Str),
            ["received_lines"] if !self.received_lines.is_empty() => Some(QueryValue::Null),
            ["additional_header_fields"] if !self.additional_header_fields.is_empty() => {
                Some(QueryValue::Null)
            }
            ["body_multipart"] if self.body_multipart.as_ref().is_some_and(|p| !p.is_empty()) => {
                Some(QueryValue::Null)
            }
            ["received_lines", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.received_lines.get(i))
                .map(|line| QueryValue::Str(line.as_str())),
            ["additional_header_fields", key, index] => {
                let idx = index.parse::<usize>().ok()?;
                self.additional_header_fields
                    .get(*key)
                    .and_then(|values| values.get(idx))
                    .map(|value| QueryValue::Str(value.as_str()))
            }
            ["from_ref"] => self
                .from_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["sender_ref"] => self
                .sender_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["to_refs", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.to_refs.get(i))
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["cc_refs", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.cc_refs.get(i))
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["bcc_refs", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.bcc_refs.get(i))
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["raw_email_ref"] => self
                .raw_email_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["body_multipart", index, field] => {
                let idx = index.parse::<usize>().ok()?;
                let part = self.body_multipart.as_ref()?.get(idx)?;
                match *field {
                    "body" => part.body.as_deref().map(QueryValue::Str),
                    "content_type" => part.content_type.as_deref().map(QueryValue::Str),
                    "content_disposition" => {
                        part.content_disposition.as_deref().map(QueryValue::Str)
                    }
                    "body_raw_ref" => part
                        .body_raw_ref
                        .as_ref()
                        .map(|id| QueryValue::Id(id.as_stix_id())),
                    _ => None,
                }
            }
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
