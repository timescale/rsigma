//! STIX `windows-service-ext` extension.

use crate::model::ModelError;
use crate::model::common::ExtensionMap;

use crate::core::FileId;

/// Windows service extension (STIX §6.13.3).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WindowsServiceExt {
    /// Internal service name.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub service_name: Option<String>,
    /// Human-readable service descriptions.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub descriptions: Vec<String>,
    /// Display name shown in service management tools.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub display_name: Option<String>,
    /// Service group name.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub group_name: Option<String>,
    /// Service start type (for example `auto`, `manual`, `disabled`).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub start_type: Option<String>,
    /// References to [`File`](crate::model::sco::File) objects for service DLLs.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub service_dll_refs: Vec<FileId>,
    /// Service type (for example `share_process`, `own_process`).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub service_type: Option<String>,
    /// Current service status (for example `running`, `stopped`).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub service_status: Option<String>,
}

impl WindowsServiceExt {
    /// Extension dictionary key.
    pub const KEY: &'static str = "windows-service-ext";

    /// Validate extension invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.service_name.is_none()
            && self.descriptions.is_empty()
            && self.display_name.is_none()
            && self.group_name.is_none()
            && self.start_type.is_none()
            && self.service_dll_refs.is_empty()
            && self.service_type.is_none()
            && self.service_status.is_none()
        {
            return Err(ModelError::WindowsServiceExtNoProperties);
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
            "../../../../tests/fixtures/spec/sco/extensions/windows-service-ext-minimal.json"
        );
        let parsed: WindowsServiceExt = serde_json::from_str(json).expect("parse");
        parsed.validate().expect("valid");
        let value = serde_json::to_value(&parsed).expect("serialize");
        let reparsed: WindowsServiceExt = serde_json::from_value(value).expect("reparse");
        assert_eq!(parsed, reparsed);
    }
    #[test]
    fn validate_rejects_invalid_fixture() {
        let json =
            include_str!("../../../../tests/fixtures/spec/sco/extensions/no-properties.json");
        let parsed: WindowsServiceExt = serde_json::from_str(json).expect("parse");
        assert_eq!(
            parsed.validate(),
            Err(ModelError::WindowsServiceExtNoProperties)
        );
    }
}
