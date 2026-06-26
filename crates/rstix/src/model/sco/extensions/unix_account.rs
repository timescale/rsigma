//! STIX `unix-account-ext` extension.

use crate::model::ModelError;
use crate::model::common::ExtensionMap;

/// UNIX account extension (STIX §6.16.2).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UnixAccountExt {
    /// Primary group id (GID).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub gid: Option<u64>,
    /// Supplementary group names.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub groups: Vec<String>,
    /// Home directory path.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub home_dir: Option<String>,
    /// Login shell path.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub shell: Option<String>,
}

impl UnixAccountExt {
    /// Extension dictionary key.
    pub const KEY: &'static str = "unix-account-ext";

    /// Validate extension invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.gid.is_none()
            && self.groups.is_empty()
            && self.home_dir.is_none()
            && self.shell.is_none()
        {
            return Err(ModelError::UnixAccountExtNoProperties);
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
            "../../../../tests/fixtures/spec/sco/extensions/unix-account-ext-minimal.json"
        );
        let parsed: UnixAccountExt = serde_json::from_str(json).expect("parse");
        parsed.validate().expect("valid");
        let value = serde_json::to_value(&parsed).expect("serialize");
        let reparsed: UnixAccountExt = serde_json::from_value(value).expect("reparse");
        assert_eq!(parsed, reparsed);
    }
    #[test]
    fn validate_rejects_invalid_fixture() {
        let json =
            include_str!("../../../../tests/fixtures/spec/sco/extensions/no-properties.json");
        let parsed: UnixAccountExt = serde_json::from_str(json).expect("parse");
        assert_eq!(
            parsed.validate(),
            Err(ModelError::UnixAccountExtNoProperties)
        );
    }
}
