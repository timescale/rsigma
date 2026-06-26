//! STIX `raster-image-ext` extension.

use crate::model::ModelError;
use crate::model::common::ExtensionMap;

use std::collections::BTreeMap;

/// Raster image file extension (STIX §6.7.5).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RasterImageExt {
    /// Image height in pixels.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub image_height: Option<u64>,
    /// Image width in pixels.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub image_width: Option<u64>,
    /// Color depth in bits per pixel.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub bits_per_pixel: Option<u64>,
    /// EXIF metadata tags keyed by tag name.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub exif_tags: BTreeMap<String, serde_json::Value>,
}

impl RasterImageExt {
    /// Extension dictionary key.
    pub const KEY: &'static str = "raster-image-ext";

    /// Validate extension invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.image_height.is_none()
            && self.image_width.is_none()
            && self.bits_per_pixel.is_none()
            && self.exif_tags.is_empty()
        {
            return Err(ModelError::RasterImageExtNoProperties);
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
            "../../../../tests/fixtures/spec/sco/extensions/raster-image-ext-minimal.json"
        );
        let parsed: RasterImageExt = serde_json::from_str(json).expect("parse");
        parsed.validate().expect("valid");
        let value = serde_json::to_value(&parsed).expect("serialize");
        let reparsed: RasterImageExt = serde_json::from_value(value).expect("reparse");
        assert_eq!(parsed, reparsed);
    }
    #[test]
    fn validate_rejects_invalid_fixture() {
        let json =
            include_str!("../../../../tests/fixtures/spec/sco/extensions/no-properties.json");
        let parsed: RasterImageExt = serde_json::from_str(json).expect("parse");
        assert_eq!(
            parsed.validate(),
            Err(ModelError::RasterImageExtNoProperties)
        );
    }
}
