//! STIX `marking-definition` objects (STIX §7.2.1).
//!
//! ## TLP predefined ids
//!
//! The `TLP1_*` and `TLP2_*` constants are the normative STIX UUIDs for predefined
//! Traffic Light Protocol markings. They are part of the public API so callers can
//! recognize TLP markings on `object_marking_refs` without re-parsing bundle JSON.
//!
//! ## Tests
//!
//! - `constants_match_spec_ids` (unit): pins all nine ids against spec literals so
//!   a bad edit to a `pub const` fails CI.
//! - Wire round-trips in `tests/spec.rs`
//!   (`meta/marking-definition-tlp-v1-white-stix21.json`,
//!   `meta/marking-definition-tlp-v2-clear-stix21.json`,
//!   `meta/marking-definition-with-common-props-stix21.json`): TLP ids and §7.2.1
//!   optional common properties.
//!
//! See `crates/rstix/README.md` (Development Notes) for the full testing rationale.

use std::collections::BTreeMap;

use crate::core::{
    IdentityId, MarkingDefinitionId, QueryValue, QueryableStixObject, SpecVersion, StixId,
    StixTimestamp,
};
use crate::model::ModelError;
use crate::model::common::{ExtensionMap, ExternalReference, GranularMarking};
use crate::model::validate::{validate_identity_ref, validate_marking_definition_ref};

/// TLP 1.x predefined marking-definition ids (legacy **encoding** on STIX 2.1 objects).
///
/// These UUIDs identify the four predefined TLP markings that use the deprecated
/// `definition_type` / `definition` JSON shape. Real STIX 2.1 bundles still
/// reference them (for example ATT&CK). Compare `object_marking_refs` entries
/// against these constants — see the crate README section *STIX version vs TLP
/// marking encoding*.
pub const TLP1_WHITE_ID: &str = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9";
/// TLP 1.x green marking id.
pub const TLP1_GREEN_ID: &str = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da";
/// TLP 1.x amber marking id.
pub const TLP1_AMBER_ID: &str = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82";
/// TLP 1.x red marking id.
pub const TLP1_RED_ID: &str = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed";

/// TLP 2.0 predefined marking-definition ids (current **encoding** via `extensions`).
pub const TLP2_CLEAR_ID: &str = "marking-definition--94868c89-73b8-4b43-b99e-6a4f9d6ded18";
/// TLP 2.0 green marking id.
pub const TLP2_GREEN_ID: &str = "marking-definition--bab4a63c-aab9-4723-a3c3-079ae6f0b36e";
/// TLP 2.0 amber marking id.
pub const TLP2_AMBER_ID: &str = "marking-definition--55d920b0-5207-4b24-b6c0-c3b2c5f18b3e";
/// TLP 2.0 amber-strict marking id.
pub const TLP2_AMBER_STRICT_ID: &str = "marking-definition--939a9414-1955-4a77-93a3-5a4ec65c9b6e";
/// TLP 2.0 red marking id.
pub const TLP2_RED_ID: &str = "marking-definition--e828b379-4398-4577-93c8-9d3c7c13d7b5";

/// A STIX marking definition.
///
/// Marking definitions are **non-versionable**: they carry `created` but intentionally
/// no `modified` field (STIX §7.2.1).
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::core::QueryableStixObject;
/// use rstix::model::meta::{MarkingDefinition, TLP1_WHITE_ID};
///
/// let json = r#"{
///   "type": "marking-definition",
///   "spec_version": "2.1",
///   "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
///   "created": "2017-01-20T00:00:00.000Z",
///   "definition_type": "tlp",
///   "name": "TLP:WHITE",
///   "definition": { "tlp": "white" }
/// }"#;
/// let marking: MarkingDefinition = serde_json::from_str(json)?;
/// assert_eq!(marking.id.as_str(), TLP1_WHITE_ID);
/// assert!(marking.is_non_versionable());
/// assert!(marking.modified().is_none());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MarkingDefinition {
    /// STIX object type (`marking-definition`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_marking_type")
    )]
    object_type: String,
    /// Object identifier.
    pub id: StixId,
    /// Specification version (optional on marking definitions).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub spec_version: Option<SpecVersion>,
    /// Creation timestamp.
    pub created: StixTimestamp,
    /// Identity that created the object (STIX §7.2.1 common property).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub created_by_ref: Option<IdentityId>,
    /// Legacy TLP 1.x / statement **encoding** (`definition_type` + `definition`).
    ///
    /// Deprecated for **new** markings in STIX 2.1 (prefer TLP 2.0 via [`Self::extensions`]).
    /// Still present on predefined markings and in historical bundles — rstix parses it.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub definition_type: Option<String>,
    /// Legacy marking payload (`{"tlp":"white"}`, statement object, …).
    ///
    /// Stored as [`serde_json::Value`] because shape depends on [`Self::definition_type`].
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub definition: Option<serde_json::Value>,
    /// Human-readable name.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub name: Option<String>,
    /// External references (STIX §7.2.1 common property).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub external_references: Vec<ExternalReference>,
    /// Object-level marking references (STIX §7.2.1 common property).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub object_marking_refs: Vec<MarkingDefinitionId>,
    /// Granular markings (STIX §7.2.1 common property).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub granular_markings: Vec<GranularMarking>,
    /// TLP 2.0 and other extension payloads (current encoding for predefined TLP markings).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "ExtensionMap::is_empty")
    )]
    pub extensions: ExtensionMap,
    /// Unmodeled top-level properties captured during standalone deserialize.
    #[cfg_attr(
        feature = "serde",
        serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl MarkingDefinition {
    /// STIX type name for marking definitions.
    pub const TYPE_NAME: &'static str = "marking-definition";

    /// All marking definitions are non-versionable (STIX §7.2.1).
    pub const IS_NON_VERSIONABLE: bool = true;

    /// Returns [`Self::IS_NON_VERSIONABLE`] (invariant for every marking definition).
    pub const fn is_non_versionable(&self) -> bool {
        Self::IS_NON_VERSIONABLE
    }

    /// Validate marking-definition invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_id_matches_type(&self.id, Self::TYPE_NAME)?;
        if self.spec_version.is_none() {
            return Err(ModelError::MarkingDefinitionSpecVersionRequired);
        }
        if self.extensions.is_empty()
            && (self.definition_type.is_none() || self.definition.is_none())
        {
            return Err(ModelError::MarkingDefinitionLegacyPayloadRequired);
        }
        if let Some(created_by) = &self.created_by_ref {
            validate_identity_ref(created_by.as_stix_id())?;
        }
        for marking in &self.object_marking_refs {
            validate_marking_definition_ref(marking.as_stix_id())?;
        }
        for granular in &self.granular_markings {
            if let Some(marking_ref) = &granular.marking_ref {
                validate_marking_definition_ref(marking_ref.as_stix_id())?;
            }
        }
        Ok(())
    }
}

fn validate_id_matches_type(id: &StixId, type_name: &str) -> Result<(), ModelError> {
    crate::model::validate::validate_id_matches_type(id, type_name)
}

#[cfg(feature = "serde")]
fn deserialize_marking_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(
        deserializer,
        MarkingDefinition::TYPE_NAME,
    )
}

impl QueryableStixObject for MarkingDefinition {
    fn id(&self) -> &StixId {
        &self.id
    }

    fn type_name(&self) -> &'static str {
        Self::TYPE_NAME
    }

    fn spec_version(&self) -> Option<SpecVersion> {
        self.spec_version
    }

    fn created(&self) -> Option<&StixTimestamp> {
        Some(&self.created)
    }

    fn modified(&self) -> Option<&StixTimestamp> {
        None
    }

    fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
        match path {
            ["definition_type"] => self.definition_type.as_deref().map(QueryValue::Str),
            ["name"] => self.name.as_deref().map(QueryValue::Str),
            ["created_by_ref"] => self
                .created_by_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    /// Pin all nine normative TLP marking-definition ids against the STIX spec literals.
    ///
    /// This does not parse JSON; it guards `pub const` drift. Representative wire
    /// coverage for TLP 1.x white and TLP 2.0 clear lives in `tests/spec.rs`.
    #[test]
    fn constants_match_spec_ids() {
        assert_eq!(
            TLP1_WHITE_ID,
            "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
        );
        assert_eq!(
            TLP1_GREEN_ID,
            "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
        );
        assert_eq!(
            TLP1_AMBER_ID,
            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
        );
        assert_eq!(
            TLP1_RED_ID,
            "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
        );
        assert_eq!(
            TLP2_CLEAR_ID,
            "marking-definition--94868c89-73b8-4b43-b99e-6a4f9d6ded18"
        );
        assert_eq!(
            TLP2_GREEN_ID,
            "marking-definition--bab4a63c-aab9-4723-a3c3-079ae6f0b36e"
        );
        assert_eq!(
            TLP2_AMBER_ID,
            "marking-definition--55d920b0-5207-4b24-b6c0-c3b2c5f18b3e"
        );
        assert_eq!(
            TLP2_AMBER_STRICT_ID,
            "marking-definition--939a9414-1955-4a77-93a3-5a4ec65c9b6e"
        );
        assert_eq!(
            TLP2_RED_ID,
            "marking-definition--e828b379-4398-4577-93c8-9d3c7c13d7b5"
        );
    }

    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/meta/language-content.json");
        let msg = serde_json::from_str::<MarkingDefinition>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `marking-definition`"));
        assert!(msg.contains("got `language-content`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!(
            "../../../tests/fixtures/spec/meta/marking-definition-tlp-v1-white-stix21.json"
        );
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<MarkingDefinition>(serde_json::Value::Object(obj))
            .unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn get_field_exposes_created_by_ref() {
        let json = include_str!(
            "../../../tests/fixtures/spec/meta/marking-definition-with-common-props-stix21.json"
        );
        let marking: MarkingDefinition = serde_json::from_str(json).expect("parse");
        assert!(matches!(
            marking.get_field(&["created_by_ref"]),
            Some(QueryValue::Id(_))
        ));
    }
}
