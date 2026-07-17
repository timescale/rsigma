//! Effective marking resolution over a bundle.

use std::collections::HashMap;

use crate::core::{IdentityId, MarkingDefinitionId};
use crate::model::Bundle;
use crate::model::common::{GranularMarking, ScoCommonProps, SdoSroCommonProps};
use crate::model::meta::{MarkingDefinition, MetaObject};
use crate::model::stix_object::StixObject;

use super::granular::selector_matches_target;
use super::statement::StatementMarking;
#[allow(deprecated)]
use super::tlp1::TlpV1Level;
use super::tlp2::{DisclosureContext, TlpV2Level};
use super::wire::{custom_created_by_ref, custom_granular_markings, custom_object_marking_refs};

const TLP2_EXTENSION_ID: &str = "extension-definition--60477d8d-78ac-1058-8160-d776f9386f83";

/// Resolved marking state for an object or property.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EffectiveMarking {
    /// Most restrictive TLP 2.0 level among applied markings.
    pub tlp_level: Option<TlpV2Level>,
    /// Statement marking texts applied.
    pub statement_markings: Vec<String>,
    /// RFC 5646 language tags from granular language markings.
    pub language_tags: Vec<String>,
    /// All marking-definition ids contributing to this resolution.
    pub all_marking_ids: Vec<MarkingDefinitionId>,
    /// Marking-definition refs present on the object but absent from the bundle index.
    pub unresolved_marking_refs: Vec<MarkingDefinitionId>,
}

/// Resolves effective TLP and statement markings from a bundle.
pub struct MarkingResolver<'b> {
    bundle: &'b Bundle,
    markings: HashMap<String, MarkingDefinition>,
}

impl<'b> MarkingResolver<'b> {
    /// Build a resolver indexing all `marking-definition` objects in `bundle`.
    pub fn new(bundle: &'b Bundle) -> Self {
        let mut markings = HashMap::new();
        for object in bundle.objects() {
            if let StixObject::Meta(MetaObject::MarkingDefinition(marking)) = object {
                markings.insert(marking.id.as_str().to_owned(), marking.clone());
            }
        }
        Self { bundle, markings }
    }

    /// Source bundle used to index marking definitions.
    pub fn bundle(&self) -> &'b Bundle {
        self.bundle
    }

    /// Effective marking for the whole object (object-level refs; most restrictive wins).
    pub fn effective_for_object(&self, obj: &StixObject) -> EffectiveMarking {
        let refs = object_marking_refs(obj);
        self.resolve_marking_refs(obj, &refs, &[])
    }

    /// Effective marking for a specific property path or granular selector (e.g. `name`, `labels.[0]`).
    pub fn effective_for_property(&self, obj: &StixObject, property: &str) -> EffectiveMarking {
        self.effective_for_selector(obj, property)
    }

    /// Effective marking for a granular selector against `obj`.
    pub fn effective_for_selector(&self, obj: &StixObject, selector: &str) -> EffectiveMarking {
        let wire = match serde_json::to_value(obj) {
            Ok(value) => value,
            Err(_) => return self.effective_for_object(obj),
        };
        let (marking_refs, language_tags) =
            granular_contributions_for_selector(obj, selector, &wire);
        if marking_refs.is_empty() && language_tags.is_empty() {
            return self.effective_for_object(obj);
        }
        self.resolve_marking_refs(obj, &marking_refs, &language_tags)
    }

    /// True if disclosure of `obj` to `audience` is permitted under effective TLP rules.
    pub fn permits_disclosure(&self, obj: &StixObject, audience: &IdentityId) -> bool {
        let effective = self.effective_for_object(obj);
        let context = disclosure_context_for_audience(obj, audience);
        match effective.tlp_level {
            None => true,
            Some(level) => level.permits_disclosure(context),
        }
    }

    fn resolve_marking_refs(
        &self,
        obj: &StixObject,
        refs: &[MarkingDefinitionId],
        language_tags: &[String],
    ) -> EffectiveMarking {
        let mut effective = EffectiveMarking {
            language_tags: language_tags.to_vec(),
            ..EffectiveMarking::default()
        };
        let self_id = obj.id().as_str();
        for marking_id in refs {
            if marking_id.as_stix_id().as_str() == self_id {
                continue;
            }
            effective.all_marking_ids.push(marking_id.clone());
            let Some(marking) = self.markings.get(marking_id.as_stix_id().as_str()) else {
                effective.unresolved_marking_refs.push(marking_id.clone());
                continue;
            };
            if let Some(level) = tlp_level_from_marking(marking) {
                effective.tlp_level = Some(most_restrictive(effective.tlp_level, level));
            }
            if let Some(statement) = StatementMarking::from_marking_definition(marking) {
                effective.statement_markings.push(statement.statement);
            }
            for inherited in &marking.object_marking_refs {
                if inherited.as_stix_id().as_str() == self_id {
                    continue;
                }
                if let Some(level) = self
                    .markings
                    .get(inherited.as_stix_id().as_str())
                    .and_then(tlp_level_from_marking)
                {
                    effective.tlp_level = Some(most_restrictive(effective.tlp_level, level));
                }
            }
        }
        effective
    }
}

fn disclosure_context_for_audience(obj: &StixObject, audience: &IdentityId) -> DisclosureContext {
    if object_created_by_ref(obj)
        .is_some_and(|creator| creator.as_stix_id() == audience.as_stix_id())
    {
        DisclosureContext::SameOrganization
    } else {
        DisclosureContext::ThirdParty
    }
}

fn object_created_by_ref(obj: &StixObject) -> Option<IdentityId> {
    match obj {
        StixObject::Sdo(sdo) => sdo.common_props().created_by_ref.clone(),
        StixObject::Sro(sro) => sro.common_props().created_by_ref.clone(),
        StixObject::Sco(_) => None,
        StixObject::Meta(MetaObject::MarkingDefinition(marking)) => marking.created_by_ref.clone(),
        StixObject::Meta(MetaObject::LanguageContent(content)) => {
            content.common.created_by_ref.clone()
        }
        StixObject::Meta(MetaObject::ExtensionDefinition(ext)) => ext.common.created_by_ref.clone(),
        StixObject::Custom(custom) => custom_created_by_ref(custom),
    }
}

fn most_restrictive(current: Option<TlpV2Level>, next: TlpV2Level) -> TlpV2Level {
    match current {
        Some(existing) if existing >= next => existing,
        _ => next,
    }
}

#[allow(deprecated)]
fn tlp_level_from_marking(marking: &MarkingDefinition) -> Option<TlpV2Level> {
    if let Some(level) = TlpV2Level::from_marking_id_str(marking.id.as_str()) {
        return Some(level);
    }
    if let Some(entry) = marking.extensions.get(TLP2_EXTENSION_ID)
        && let Some(tlp) = entry.properties.get("tlp_2_0").and_then(|v| v.as_str())
        && let Some(level) = TlpV2Level::from_extension_value(tlp)
    {
        return Some(level);
    }
    if let Some(definition) = &marking.definition
        && let Some(tlp) = definition.get("tlp").and_then(serde_json::Value::as_str)
    {
        let v1 = match tlp.to_ascii_lowercase().as_str() {
            "white" => Some(TlpV1Level::White),
            "green" => Some(TlpV1Level::Green),
            "amber" => Some(TlpV1Level::Amber),
            "red" => Some(TlpV1Level::Red),
            _ => None,
        };
        if let Some(v1) = v1 {
            return Some(v1.to_v2());
        }
    }
    TlpV1Level::from_marking_id(marking.id.as_str()).map(TlpV1Level::to_v2)
}

fn object_marking_refs(object: &StixObject) -> Vec<MarkingDefinitionId> {
    match object {
        StixObject::Sdo(sdo) => sdo_sro_marking_refs(sdo.common_props()),
        StixObject::Sro(sro) => sdo_sro_marking_refs(sro.common_props()),
        StixObject::Sco(sco) => sco_marking_refs(sco.common_props()),
        StixObject::Meta(MetaObject::MarkingDefinition(marking)) => {
            marking.object_marking_refs.clone()
        }
        StixObject::Meta(MetaObject::LanguageContent(content)) => {
            sdo_sro_marking_refs(&content.common)
        }
        StixObject::Meta(MetaObject::ExtensionDefinition(ext)) => sdo_sro_marking_refs(&ext.common),
        StixObject::Custom(custom) => custom_object_marking_refs(custom),
    }
}

fn granular_contributions_for_selector(
    object: &StixObject,
    selector: &str,
    wire: &serde_json::Value,
) -> (Vec<MarkingDefinitionId>, Vec<String>) {
    let granular = granular_markings(object);
    let mut marking_refs = Vec::new();
    let mut language_tags = Vec::new();
    for entry in granular {
        let applies = entry
            .selectors
            .iter()
            .any(|granular_selector| selector_matches_target(wire, granular_selector, selector));
        if !applies {
            continue;
        }
        if let Some(marking_ref) = &entry.marking_ref {
            marking_refs.push(marking_ref.clone());
        }
        if let Some(lang) = &entry.lang {
            language_tags.push(lang.as_str().to_owned());
        }
    }
    (marking_refs, language_tags)
}

fn granular_markings(object: &StixObject) -> Vec<GranularMarking> {
    match object {
        StixObject::Sdo(sdo) => sdo.common_props().granular_markings.clone(),
        StixObject::Sro(sro) => sro.common_props().granular_markings.clone(),
        StixObject::Sco(sco) => sco.common_props().granular_markings.clone(),
        StixObject::Meta(MetaObject::MarkingDefinition(marking)) => {
            marking.granular_markings.clone()
        }
        StixObject::Meta(MetaObject::LanguageContent(content)) => {
            content.common.granular_markings.clone()
        }
        StixObject::Meta(MetaObject::ExtensionDefinition(ext)) => {
            ext.common.granular_markings.clone()
        }
        StixObject::Custom(custom) => custom_granular_markings(custom),
    }
}

fn sdo_sro_marking_refs(common: &SdoSroCommonProps) -> Vec<MarkingDefinitionId> {
    common.object_marking_refs.clone()
}

fn sco_marking_refs(common: &ScoCommonProps) -> Vec<MarkingDefinitionId> {
    common.object_marking_refs.clone()
}

#[cfg(test)]
mod object {
    use super::*;
    use crate::model::{SdoObject, StixObject};
    use crate::parse_bundle;

    #[test]
    fn most_restrictive_wins() {
        let bundle = parse_bundle(include_str!(
            "../../tests/fixtures/marking/object-red-green.json"
        ))
        .expect("parse");
        let resolver = MarkingResolver::new(&bundle);
        let indicator = bundle
            .objects()
            .iter()
            .find_map(|object| match object {
                StixObject::Sdo(SdoObject::Indicator(ind)) => Some(ind),
                _ => None,
            })
            .expect("indicator");
        let effective = resolver
            .effective_for_object(&StixObject::Sdo(SdoObject::Indicator(indicator.clone())));
        assert_eq!(effective.tlp_level, Some(TlpV2Level::Red));
    }
}

#[cfg(test)]
mod property {
    use super::*;
    use crate::model::{SdoObject, StixObject};
    use crate::parse_bundle;

    #[test]
    fn granular_selector_applied() {
        let bundle = parse_bundle(include_str!(
            "../../tests/fixtures/marking/object-red-green.json"
        ))
        .expect("parse");
        let resolver = MarkingResolver::new(&bundle);
        let indicator = bundle
            .objects()
            .iter()
            .find_map(|object| match object {
                StixObject::Sdo(SdoObject::Indicator(ind)) => Some(ind),
                _ => None,
            })
            .expect("indicator");
        let object = StixObject::Sdo(SdoObject::Indicator(indicator.clone()));
        assert_eq!(
            resolver.effective_for_property(&object, "name").tlp_level,
            Some(TlpV2Level::Green)
        );
        assert_eq!(
            resolver.effective_for_object(&object).tlp_level,
            Some(TlpV2Level::Red)
        );
    }
}

#[cfg(test)]
mod disclosure {
    use super::*;
    use crate::model::meta::{TLP2_AMBER_STRICT_ID, TLP2_CLEAR_ID};
    use crate::model::{SdoObject, StixObject};
    use crate::parse_bundle;

    #[test]
    fn audience_drives_disclosure_context() {
        let bundle = parse_bundle(include_str!(
            "../../tests/fixtures/marking/object-red-green.json"
        ))
        .expect("parse");
        let resolver = MarkingResolver::new(&bundle);
        let indicator = bundle
            .objects()
            .iter()
            .find_map(|object| match object {
                StixObject::Sdo(SdoObject::Indicator(ind)) => Some(ind),
                _ => None,
            })
            .expect("indicator");
        let object = StixObject::Sdo(SdoObject::Indicator(indicator.clone()));
        let outsider = IdentityId::from_stix_id(
            "identity--00000000-0000-0000-0000-000000009999"
                .parse()
                .expect("id"),
        )
        .expect("identity");
        assert!(!resolver.permits_disclosure(&object, &outsider));
    }

    #[test]
    fn amber_strict_blocks_outside_creator() {
        let json = r#"{
          "type": "bundle",
          "id": "bundle--00000000-0000-0000-0000-000000000020",
          "objects": [
            {
              "type": "marking-definition",
              "spec_version": "2.1",
              "id": "marking-definition--939a9414-1955-4a77-93a3-5a4ec65c9b6e",
              "created": "2022-03-11T19:45:00.000Z",
              "name": "TLP:AMBER+STRICT",
              "extensions": {
                "extension-definition--60477d8d-78ac-1058-8160-d776f9386f83": {
                  "extension_type": "property-extension",
                  "tlp_2_0": "amber+strict"
                }
              }
            },
            {
              "type": "identity",
              "spec_version": "2.1",
              "id": "identity--11111111-1111-1111-1111-111111111111",
              "created": "2016-05-12T08:17:27.000Z",
              "modified": "2016-05-12T08:17:27.000Z",
              "name": "Creator Org"
            },
            {
              "type": "identity",
              "spec_version": "2.1",
              "id": "identity--22222222-2222-2222-2222-222222222222",
              "created": "2016-05-12T08:17:27.000Z",
              "modified": "2016-05-12T08:17:27.000Z",
              "name": "Other Org"
            },
            {
              "type": "indicator",
              "spec_version": "2.1",
              "id": "indicator--33333333-3333-3333-3333-333333333333",
              "created": "2016-05-12T08:17:27.000Z",
              "modified": "2016-05-12T08:17:27.000Z",
              "created_by_ref": "identity--11111111-1111-1111-1111-111111111111",
              "pattern": "[file:hashes.MD5 = '644bf17e482f443f763b0b7355b14372']",
              "pattern_type": "stix",
              "valid_from": "2016-05-12T08:17:27.000Z",
              "object_marking_refs": [
                "marking-definition--939a9414-1955-4a77-93a3-5a4ec65c9b6e"
              ]
            }
          ]
        }"#;
        let bundle = parse_bundle(json).expect("parse");
        let resolver = MarkingResolver::new(&bundle);
        let indicator = bundle
            .objects()
            .iter()
            .find_map(|object| match object {
                StixObject::Sdo(SdoObject::Indicator(ind)) => Some(ind),
                _ => None,
            })
            .expect("indicator");
        let object = StixObject::Sdo(SdoObject::Indicator(indicator.clone()));
        let creator = IdentityId::from_stix_id(
            "identity--11111111-1111-1111-1111-111111111111"
                .parse()
                .expect("creator"),
        )
        .expect("identity");
        let other = IdentityId::from_stix_id(
            "identity--22222222-2222-2222-2222-222222222222"
                .parse()
                .expect("other"),
        )
        .expect("identity");
        assert!(resolver.permits_disclosure(&object, &creator));
        assert!(!resolver.permits_disclosure(&object, &other));
        let _ = (TLP2_AMBER_STRICT_ID, TLP2_CLEAR_ID);
    }
}
