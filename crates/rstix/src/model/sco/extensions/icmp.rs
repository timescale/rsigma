//! STIX `icmp-ext` extension.

use crate::model::ModelError;
use crate::model::common::ExtensionMap;

/// ICMP extension (STIX §6.12.3).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IcmpExt {
    pub icmp_type_hex: String,
    pub icmp_code_hex: String,
}

impl IcmpExt {
    /// Extension dictionary key.
    pub const KEY: &'static str = "icmp-ext";

    /// Validate extension invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.icmp_type_hex.is_empty() || self.icmp_code_hex.is_empty() {
            return Err(ModelError::IcmpExtFieldsEmpty);
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
            include_str!("../../../../tests/fixtures/spec/sco/extensions/icmp-ext-minimal.json");
        let parsed: IcmpExt = serde_json::from_str(json).expect("parse");
        parsed.validate().expect("valid");
        let value = serde_json::to_value(&parsed).expect("serialize");
        let reparsed: IcmpExt = serde_json::from_value(value).expect("reparse");
        assert_eq!(parsed, reparsed);
    }
    #[test]
    fn validate_rejects_invalid_fixture() {
        let json =
            include_str!("../../../../tests/fixtures/spec/sco/extensions/icmp-ext-invalid.json");
        let parsed: IcmpExt = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.validate(), Err(ModelError::IcmpExtFieldsEmpty));
    }
}
