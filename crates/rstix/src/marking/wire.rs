//! Wire JSON helpers for marking resolution on custom objects.

use std::str::FromStr;

use crate::core::{IdentityId, MarkingDefinitionId, StixId};
use crate::model::common::GranularMarking;
use crate::model::stix_object::CustomStixObject;

pub(crate) fn custom_object_marking_refs(custom: &CustomStixObject) -> Vec<MarkingDefinitionId> {
    string_array(custom.raw.get("object_marking_refs"))
        .into_iter()
        .filter_map(|value| {
            StixId::from_str(value.as_str())
                .ok()
                .and_then(|id| MarkingDefinitionId::from_stix_id(id).ok())
        })
        .collect()
}

pub(crate) fn custom_granular_markings(custom: &CustomStixObject) -> Vec<GranularMarking> {
    crate::model::validate::granular_markings_from_wire(&custom.raw)
}

pub(crate) fn custom_created_by_ref(custom: &CustomStixObject) -> Option<IdentityId> {
    custom
        .raw
        .get("created_by_ref")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| {
            StixId::from_str(value)
                .ok()
                .and_then(|id| IdentityId::from_stix_id(id).ok())
        })
}

fn string_array(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
