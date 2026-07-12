//! STIX `artifact` objects (STIX §6.1).

use std::collections::BTreeMap;

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;

/// Binary or textual payload captured as a cyber-observable (STIX §6.1).
///
/// Exactly one of [`payload_bin`](Self::payload_bin) or [`url`](Self::url) must be
/// present. When [`url`](Self::url) is used, [`hashes`](Self::hashes) is required.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sco::Artifact;
///
/// let json = include_str!("../../../tests/fixtures/spec/sco/artifact-image.json");
/// let artifact: Artifact = serde_json::from_str(json)?;
/// assert_eq!(artifact.mime_type.as_deref(), Some("image/jpeg"));
/// assert!(artifact.payload_bin.is_some());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Artifact {
    /// STIX object type (`artifact`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_artifact_type")
    )]
    object_type: String,
    /// SCO common properties (STIX §3.2).
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    /// MIME type of the artifact content (STIX §6.1.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub mime_type: Option<String>,
    /// Base64-encoded payload bytes (STIX §6.1.2; mutually exclusive with `url`).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub payload_bin: Option<String>,
    /// Remote location of the payload (STIX §6.1.2; mutually exclusive with `payload_bin`).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub url: Option<String>,
    /// Cryptographic hashes of the payload (STIX §6.1.2; required when `url` is set).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub hashes: BTreeMap<String, String>,
    /// Algorithm used to encrypt the payload (STIX §6.1.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub encryption_algorithm: Option<String>,
    /// Key used to decrypt the payload (STIX §6.1.2; requires `encryption_algorithm`).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub decryption_key: Option<String>,
}

impl Artifact {
    /// STIX type name for artifacts.
    pub const TYPE_NAME: &'static str = "artifact";

    /// Check artifact invariants (payload/url exclusivity, hash and encryption rules).
    pub fn validate(&self) -> Result<(), ModelError> {
        let has_payload = self.payload_bin.is_some();
        let has_url = self.url.is_some();
        if has_payload == has_url {
            return Err(ModelError::ArtifactPayloadXorUrl);
        }
        if has_url && self.hashes.is_empty() {
            return Err(ModelError::ArtifactHashesRequiredWhenUrl);
        }
        if self.decryption_key.is_some() && self.encryption_algorithm.is_none() {
            return Err(ModelError::ArtifactDecryptionKeyWithoutEncryption);
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_artifact_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Artifact::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Artifact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_artifact_type")]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            #[serde(default)]
            mime_type: Option<String>,
            #[serde(default)]
            payload_bin: Option<String>,
            #[serde(default)]
            url: Option<String>,
            #[serde(default)]
            hashes: BTreeMap<String, String>,
            #[serde(default)]
            encryption_algorithm: Option<String>,
            #[serde(default)]
            decryption_key: Option<String>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            mime_type: raw.mime_type,
            payload_bin: raw.payload_bin,
            url: raw.url,
            hashes: raw.hashes,
            encryption_algorithm: raw.encryption_algorithm,
            decryption_key: raw.decryption_key,
        };
        obj.validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for Artifact {
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
            ["mime_type"] => self.mime_type.as_deref().map(QueryValue::Str),
            ["url"] => self.url.as_deref().map(QueryValue::Str),
            ["payload_bin"] => self.payload_bin.as_deref().map(QueryValue::Str),
            ["encryption_algorithm"] => self.encryption_algorithm.as_deref().map(QueryValue::Str),
            ["decryption_key"] => self.decryption_key.as_deref().map(QueryValue::Str),
            ["hashes", key] => self
                .hashes
                .get(*key)
                .map(String::as_str)
                .map(QueryValue::Str),
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
        let msg = serde_json::from_str::<Artifact>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `artifact`"));
        assert!(msg.contains("got `url`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/artifact-image.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Artifact>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
