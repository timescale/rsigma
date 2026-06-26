//! STIX `pdf-ext` extension.

use crate::model::ModelError;
use crate::model::common::ExtensionMap;

use std::collections::BTreeMap;

/// PDF file extension (STIX §6.7.4).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PdfExt {
    /// PDF version string (for example `1.7`).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub version: Option<String>,
    /// Whether the PDF is linearized (optimized for web viewing).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub is_optimized: Option<bool>,
    /// Entries from the PDF Info dictionary.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub document_info_dict: BTreeMap<String, String>,
    /// First 16-byte PDF document ID.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub pdfid0: Option<String>,
    /// Second 16-byte PDF document ID.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub pdfid1: Option<String>,
}

impl PdfExt {
    /// Extension dictionary key.
    pub const KEY: &'static str = "pdf-ext";

    /// Validate extension invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.version.is_none()
            && self.is_optimized.is_none()
            && self.document_info_dict.is_empty()
            && self.pdfid0.is_none()
            && self.pdfid1.is_none()
        {
            return Err(ModelError::PdfExtNoProperties);
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
            include_str!("../../../../tests/fixtures/spec/sco/extensions/pdf-ext-minimal.json");
        let parsed: PdfExt = serde_json::from_str(json).expect("parse");
        parsed.validate().expect("valid");
        let value = serde_json::to_value(&parsed).expect("serialize");
        let reparsed: PdfExt = serde_json::from_value(value).expect("reparse");
        assert_eq!(parsed, reparsed);
    }
    #[test]
    fn validate_rejects_invalid_fixture() {
        let json =
            include_str!("../../../../tests/fixtures/spec/sco/extensions/no-properties.json");
        let parsed: PdfExt = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.validate(), Err(ModelError::PdfExtNoProperties));
    }
}
