//! The STIX `external-reference` data type (STIX §3.3).

use std::collections::BTreeMap;

use crate::model::ModelError;

/// A STIX external reference.
///
/// `source_name` is required and must be non-empty. STIX §2.5.2 requires at
/// least one of `description`, `url`, or `external_id` alongside `source_name`.
/// Both rules are enforced by [`new`] and on deserialization when the `serde`
/// feature is enabled.
///
/// # Examples
///
/// ```
/// use rstix::model::common::ExternalReference;
///
/// let reference = ExternalReference::new("capec", None, None, Some("CAPEC-163".into()))
///     .expect("valid reference");
/// assert!(reference.validate().is_ok());
/// ```
///
/// [`new`]: ExternalReference::new
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ExternalReference {
    /// Source name (required, non-empty).
    pub source_name: String,
    /// Human-readable description.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// Reference URL.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub url: Option<String>,
    /// Hashes of the referenced artifact, keyed by algorithm name.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub hashes: BTreeMap<String, String>,
    /// External identifier within the source (for example a CVE or CAPEC id).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub external_id: Option<String>,
}

impl ExternalReference {
    /// Construct a reference, enforcing STIX §2.5.2 invariants.
    ///
    /// Returns [`ModelError::ExternalReferenceMissingSourceName`] when
    /// `source_name` is empty or whitespace-only, or
    /// [`ModelError::ExternalReferenceMissingDetail`] when none of
    /// `description`, `url`, or `external_id` are set.
    pub fn new(
        source_name: impl Into<String>,
        description: Option<String>,
        url: Option<String>,
        external_id: Option<String>,
    ) -> Result<Self, ModelError> {
        let reference = Self {
            source_name: source_name.into(),
            description,
            url,
            external_id,
            ..Self::default()
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Validate STIX §2.5.2 invariants on `source_name` and detail fields.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.source_name.trim().is_empty() {
            return Err(ModelError::ExternalReferenceMissingSourceName);
        }
        if self.description.is_none() && self.url.is_none() && self.external_id.is_none() {
            return Err(ModelError::ExternalReferenceMissingDetail);
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ExternalReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            source_name: String,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            url: Option<String>,
            #[serde(default)]
            hashes: BTreeMap<String, String>,
            #[serde(default)]
            external_id: Option<String>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let reference = Self {
            source_name: raw.source_name,
            description: raw.description,
            url: raw.url,
            hashes: raw.hashes,
            external_id: raw.external_id,
        };
        reference
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ModelError;

    #[test]
    fn new_rejects_empty_source_name() {
        assert_eq!(
            ExternalReference::new("   ", None, None, None).unwrap_err(),
            ModelError::ExternalReferenceMissingSourceName
        );
    }

    #[test]
    fn new_rejects_source_name_without_detail() {
        assert_eq!(
            ExternalReference::new("capec", None, None, None).unwrap_err(),
            ModelError::ExternalReferenceMissingDetail
        );
    }
}
