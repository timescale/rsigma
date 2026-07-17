//! Full-text search helpers for store queries.

use crate::core::QueryableStixObject;
use crate::model::meta::MetaObject;
use crate::model::sdo::SdoObject;
use crate::model::stix_object::StixObject;

use super::StixQuery;

/// Build a lowercase searchable blob for `obj`.
pub(crate) fn object_search_text(obj: &StixObject) -> String {
    let mut parts = Vec::new();
    parts.push(obj.type_name().to_ascii_lowercase());
    parts.push(obj.id().as_str().to_ascii_lowercase());

    match obj {
        StixObject::Sdo(sdo) => push_sdo_search_parts(sdo, &mut parts),
        StixObject::Sro(sro) => {
            parts.extend(
                sro.common_props()
                    .labels
                    .iter()
                    .map(|label| label.to_ascii_lowercase()),
            );
        }
        StixObject::Sco(sco) => {
            if let Ok(value) = serde_json::to_value(sco) {
                push_json_strings(&value, &mut parts);
            }
        }
        StixObject::Meta(MetaObject::MarkingDefinition(marking)) => {
            if let Some(name) = &marking.name {
                parts.push(name.to_ascii_lowercase());
            }
        }
        StixObject::Meta(MetaObject::LanguageContent(content)) => {
            parts.extend(
                content
                    .common
                    .labels
                    .iter()
                    .map(|label| label.to_ascii_lowercase()),
            );
        }
        StixObject::Meta(MetaObject::ExtensionDefinition(ext)) => {
            parts.push(ext.name.to_ascii_lowercase());
            if let Some(description) = &ext.description {
                parts.push(description.to_ascii_lowercase());
            }
        }
        StixObject::Custom(custom) => push_json_strings(&custom.raw, &mut parts),
    }

    parts.join("\n")
}

fn push_sdo_search_parts(sdo: &SdoObject, parts: &mut Vec<String>) {
    let common = sdo.common_props();
    parts.extend(common.labels.iter().map(|label| label.to_ascii_lowercase()));
    match sdo {
        SdoObject::Indicator(indicator) => {
            if let Some(name) = &indicator.name {
                parts.push(name.to_ascii_lowercase());
            }
            parts.push(indicator.pattern.raw().to_ascii_lowercase());
        }
        SdoObject::Malware(malware) => {
            if let Some(name) = &malware.name {
                parts.push(name.to_ascii_lowercase());
            }
        }
        SdoObject::ThreatActor(actor) => {
            parts.push(actor.name.to_ascii_lowercase());
        }
        SdoObject::Identity(identity) => {
            parts.push(identity.name.to_ascii_lowercase());
        }
        SdoObject::Infrastructure(infra) => {
            parts.push(infra.name.to_ascii_lowercase());
        }
        SdoObject::Campaign(campaign) => {
            parts.push(campaign.name.to_ascii_lowercase());
        }
        SdoObject::AttackPattern(pattern) => {
            parts.push(pattern.name.to_ascii_lowercase());
        }
        SdoObject::CourseOfAction(coa) => {
            parts.push(coa.name.to_ascii_lowercase());
        }
        SdoObject::Vulnerability(vuln) => {
            parts.push(vuln.name.to_ascii_lowercase());
        }
        _ => {}
    }
}

fn push_json_strings(value: &serde_json::Value, parts: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => parts.push(text.to_ascii_lowercase()),
        serde_json::Value::Array(items) => {
            for item in items {
                push_json_strings(item, parts);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                if matches!(
                    key.as_str(),
                    "name" | "description" | "pattern" | "labels" | "value"
                ) {
                    push_json_strings(item, parts);
                }
            }
        }
        _ => {}
    }
}

pub(crate) fn query_matches(q: &StixQuery, obj: &StixObject, search_text: &str) -> bool {
    if let Some(types) = &q.type_filter {
        let kind = crate::core::StixObjectKind::from_type_str(obj.type_name());
        if !kind.is_some_and(|k| types.contains(&k)) {
            return false;
        }
    }
    if let Some(since) = &q.modified_after {
        match QueryableStixObject::modified(obj) {
            Some(modified) if modified >= since => {}
            _ => return false,
        }
    }
    if let Some(labels) = &q.labels_include {
        let object_labels = object_labels(obj);
        if !labels.iter().any(|label| object_labels.contains(label)) {
            return false;
        }
    }
    if let Some(needle) = &q.text_search {
        let haystack = search_text.to_ascii_lowercase();
        if !haystack.contains(&needle.to_ascii_lowercase()) {
            return false;
        }
    }
    true
}

fn object_labels(obj: &StixObject) -> Vec<String> {
    match obj {
        StixObject::Sdo(sdo) => sdo.common_props().labels.clone(),
        StixObject::Sro(sro) => sro.common_props().labels.clone(),
        StixObject::Meta(MetaObject::MarkingDefinition(_)) => Vec::new(),
        StixObject::Meta(MetaObject::LanguageContent(content)) => content.common.labels.clone(),
        StixObject::Meta(MetaObject::ExtensionDefinition(ext)) => ext.common.labels.clone(),
        StixObject::Custom(custom) => custom
            .raw
            .get("labels")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}
