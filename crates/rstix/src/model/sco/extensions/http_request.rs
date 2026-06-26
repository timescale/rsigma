//! STIX `http-request-ext` extension.

use crate::model::ModelError;
use crate::model::common::ExtensionMap;

use std::collections::BTreeMap;

use crate::core::ArtifactId;

/// HTTP request extension (STIX §6.12.2).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HttpRequestExt {
    /// HTTP method (required, non-empty).
    pub request_method: String,
    /// Request target (URI path or full request line value; required, non-empty).
    pub request_value: String,
    /// HTTP protocol version (for example `http/1.1`).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub request_version: Option<String>,
    /// Request headers, keyed by name with one or more values per header.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub request_header: BTreeMap<String, Vec<String>>,
    /// Message body length in octets.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub message_body_length: Option<u64>,
    /// Reference to an [`Artifact`](crate::model::sco::Artifact) holding the raw body.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub message_body_data_ref: Option<ArtifactId>,
}

impl HttpRequestExt {
    /// Extension dictionary key.
    pub const KEY: &'static str = "http-request-ext";

    /// Validate extension invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.request_method.is_empty() {
            return Err(ModelError::HttpRequestExtMethodEmpty);
        }
        if self.request_value.is_empty() {
            return Err(ModelError::HttpRequestExtValueEmpty);
        }

        Ok(())
    }

    /// Parse and validate this extension from an [`ExtensionMap`], if present.
    pub fn validate_in_map(map: &ExtensionMap) -> Result<(), ModelError> {
        if let Some(entry) = map.get(Self::KEY) {
            let ext: Self = super::util::deserialize_from_entry(Self::KEY, entry)?;
            ext.validate()?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn round_trips_fixture() {
        let json = include_str!(
            "../../../../tests/fixtures/spec/sco/extensions/http-request-ext-minimal.json"
        );
        let parsed: HttpRequestExt = serde_json::from_str(json).expect("parse");
        parsed.validate().expect("valid");
        let value = serde_json::to_value(&parsed).expect("serialize");
        let reparsed: HttpRequestExt = serde_json::from_value(value).expect("reparse");
        assert_eq!(parsed, reparsed);
    }
    #[test]
    fn validate_rejects_invalid_fixture() {
        let json = include_str!(
            "../../../../tests/fixtures/spec/sco/extensions/http-request-ext-invalid.json"
        );
        let parsed: HttpRequestExt = serde_json::from_str(json).expect("parse");
        assert_eq!(
            parsed.validate(),
            Err(ModelError::HttpRequestExtMethodEmpty)
        );
    }
}
