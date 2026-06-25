//! STIX `tcp-ext` extension.

use crate::model::ModelError;
use crate::model::common::ExtensionMap;

/// TCP extension (STIX §6.12.5).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TcpExt {
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub src_flags_hex: Option<String>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub dst_flags_hex: Option<String>,
}

impl TcpExt {
    /// Extension dictionary key.
    pub const KEY: &'static str = "tcp-ext";

    /// Validate extension invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.src_flags_hex.is_none() && self.dst_flags_hex.is_none() {
            return Err(ModelError::TcpExtNoProperties);
        }

        Ok(())
    }

    /// Parse and validate this extension from an [`ExtensionMap`], if present.
    pub fn validate_in_map(map: &ExtensionMap) -> Result<(), ModelError> {
        if let Some(entry) = map.get(Self::KEY) {
            let mut obj = serde_json::Map::new();
            if let Some(t) = &entry.extension_type {
                obj.insert(
                    "extension_type".into(),
                    serde_json::Value::String(t.as_str().into()),
                );
            }
            for (k, v) in &entry.properties {
                obj.insert(k.clone(), v.clone());
            }
            let ext: Self = serde_json::from_value(serde_json::Value::Object(obj))
                .map_err(|_| ModelError::ExtensionDeserializeFailed)?;
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
            include_str!("../../../../tests/fixtures/spec/sco/extensions/tcp-ext-minimal.json");
        let parsed: TcpExt = serde_json::from_str(json).expect("parse");
        parsed.validate().expect("valid");
        let value = serde_json::to_value(&parsed).expect("serialize");
        let reparsed: TcpExt = serde_json::from_value(value).expect("reparse");
        assert_eq!(parsed, reparsed);
    }
}
