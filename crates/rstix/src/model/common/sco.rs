//! Common properties shared by all STIX Cyber-observable Objects.

use crate::core::{MarkingDefinitionId, SpecVersion, StixId};
use crate::model::common::{ExtensionMap, GranularMarking};

/// The restricted common property set for STIX Cyber-observable Objects.
///
/// Per STIX 2.1 §3.2, SCOs carry only this subset; there is intentionally no
/// `created`, `modified`, `created_by_ref`, `revoked`, `labels`, `confidence`,
/// `lang`, or `external_references` field.
///
/// # Examples
///
/// ```
/// use rstix::core::StixId;
/// use rstix::model::common::ScoCommonProps;
///
/// let common = ScoCommonProps::new(StixId::generate("ipv4-addr"));
/// assert_eq!(common.id.type_name(), "ipv4-addr");
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScoCommonProps {
    /// Object identifier.
    pub id: StixId,
    /// Specification version (optional for SCOs).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub spec_version: Option<SpecVersion>,
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
    /// Whether the observable content has been defanged.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub defanged: Option<bool>,
    /// Extensions.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "ExtensionMap::is_empty")
    )]
    pub extensions: ExtensionMap,
}

impl ScoCommonProps {
    /// Construct the minimal SCO common properties from an id.
    pub fn new(id: StixId) -> Self {
        Self {
            id,
            spec_version: None,
            object_marking_refs: Vec::new(),
            granular_markings: Vec::new(),
            defanged: None,
            extensions: ExtensionMap::default(),
        }
    }
}
