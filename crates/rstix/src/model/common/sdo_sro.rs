//! Common properties shared by all STIX Domain Objects and Relationship
//! Objects (STIX §3.2).

use crate::core::{
    IdentityId, LanguageTag, MarkingDefinitionId, SpecVersion, StixId, StixTimestamp,
};
use crate::model::common::{ExtensionMap, ExternalReference, GranularMarking};

/// The full common property set for SDOs and SROs.
///
/// Flattened (via `#[serde(flatten)]`) into each concrete SDO/SRO struct. Unlike
/// [`ScoCommonProps`](crate::model::common::ScoCommonProps), `spec_version`,
/// `created`, and `modified` are required.
///
/// # Examples
///
/// ```
/// use rstix::core::{StixId, StixTimestamp};
/// use rstix::model::common::SdoSroCommonProps;
///
/// let ts = StixTimestamp::parse("2016-05-12T08:17:27.000Z").expect("valid timestamp");
/// let common = SdoSroCommonProps::new(StixId::generate("campaign"), ts.clone(), ts);
/// assert_eq!(common.id.type_name(), "campaign");
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SdoSroCommonProps {
    /// Object identifier.
    pub id: StixId,
    /// Specification version (required on SDOs and SROs).
    pub spec_version: SpecVersion,
    /// Creation timestamp.
    pub created: StixTimestamp,
    /// Last-modified timestamp.
    pub modified: StixTimestamp,
    /// Identity that created the object.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub created_by_ref: Option<IdentityId>,
    /// Whether the object has been revoked.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub revoked: Option<bool>,
    /// User-defined labels.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub labels: Vec<String>,
    /// Confidence in the correctness of the data, `0..=100`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub confidence: Option<u8>,
    /// Primary language of the object's text content.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub lang: Option<LanguageTag>,
    /// External references.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub external_references: Vec<ExternalReference>,
    /// Object-level marking references.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub object_marking_refs: Vec<MarkingDefinitionId>,
    /// Granular markings.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub granular_markings: Vec<GranularMarking>,
    /// Object extensions.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "ExtensionMap::is_empty")
    )]
    pub extensions: ExtensionMap,
}

impl SdoSroCommonProps {
    /// Construct the minimal required common properties (`spec_version` defaults
    /// to STIX 2.1; all optional fields are empty).
    pub fn new(id: StixId, created: StixTimestamp, modified: StixTimestamp) -> Self {
        Self {
            id,
            spec_version: SpecVersion::V2_1,
            created,
            modified,
            created_by_ref: None,
            revoked: None,
            labels: Vec::new(),
            confidence: None,
            lang: None,
            external_references: Vec::new(),
            object_marking_refs: Vec::new(),
            granular_markings: Vec::new(),
            extensions: ExtensionMap::default(),
        }
    }
}
