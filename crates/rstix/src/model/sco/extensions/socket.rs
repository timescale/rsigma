//! STIX `socket-ext` extension.

use crate::model::ModelError;
use crate::model::common::ExtensionMap;

use std::collections::BTreeMap;

/// Network socket extension (STIX §6.12.4).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SocketExt {
    /// Socket address family (required, non-empty; for example `AF_INET`).
    pub address_family: String,
    /// Whether the socket is in blocking mode.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub is_blocking: Option<bool>,
    /// Whether the socket is listening for connections.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub is_listening: Option<bool>,
    /// Socket options keyed by option name.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub options: BTreeMap<String, u64>,
    /// Socket type (for example `SOCK_STREAM`).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub socket_type: Option<String>,
    /// Socket file descriptor on Unix-like systems.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub socket_descriptor: Option<u64>,
    /// Socket handle on Windows.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub socket_handle: Option<u64>,
}

impl SocketExt {
    /// Extension dictionary key.
    pub const KEY: &'static str = "socket-ext";

    /// Validate extension invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.address_family.is_empty() {
            return Err(ModelError::SocketExtAddressFamilyEmpty);
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
        let json =
            include_str!("../../../../tests/fixtures/spec/sco/extensions/socket-ext-minimal.json");
        let parsed: SocketExt = serde_json::from_str(json).expect("parse");
        parsed.validate().expect("valid");
        let value = serde_json::to_value(&parsed).expect("serialize");
        let reparsed: SocketExt = serde_json::from_value(value).expect("reparse");
        assert_eq!(parsed, reparsed);
    }
    #[test]
    fn validate_rejects_invalid_fixture() {
        let json =
            include_str!("../../../../tests/fixtures/spec/sco/extensions/socket-ext-invalid.json");
        let parsed: SocketExt = serde_json::from_str(json).expect("parse");
        assert_eq!(
            parsed.validate(),
            Err(ModelError::SocketExtAddressFamilyEmpty)
        );
    }
}
