//! Full-text search helpers for store queries.

use std::borrow::Cow;

use crate::core::{QueryableStixObject, StixTimestamp};
use crate::model::ScoObject;
use crate::model::common::ExternalReference;
use crate::model::meta::MetaObject;
use crate::model::sdo::SdoObject;
use crate::model::stix_object::StixObject;

use super::{StixQuery, TextMatch};

/// Separates the searchable values inside a search blob.
const FIELD_SEPARATOR: char = '\u{1f}';

/// Build a lowercase searchable blob for `obj`.
pub(crate) fn object_search_text(obj: &StixObject) -> String {
    let mut parts = Vec::new();
    parts.push(obj.type_name().to_ascii_lowercase());
    parts.push(obj.id().as_str().to_ascii_lowercase());

    match obj {
        StixObject::Sdo(sdo) => push_sdo_search_parts(sdo, &mut parts),
        StixObject::Sro(sro) => {
            let common = sro.common_props();
            parts.extend(common.labels.iter().map(|label| label.to_ascii_lowercase()));
            push_external_reference_parts(&common.external_references, &mut parts);
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

    parts.join(&FIELD_SEPARATOR.to_string())
}

/// Search blob for an SCO from its already serialized wire JSON.
pub(crate) fn sco_search_text(sco: &ScoObject, wire: Option<&serde_json::Value>) -> String {
    let mut parts = vec![
        QueryableStixObject::type_name(sco).to_ascii_lowercase(),
        sco.id().as_str().to_ascii_lowercase(),
    ];
    if let Some(value) = wire {
        push_json_strings(value, &mut parts);
    }
    parts.join(&FIELD_SEPARATOR.to_string())
}

fn push_external_reference_parts(refs: &[ExternalReference], parts: &mut Vec<String>) {
    for reference in refs {
        parts.push(reference.source_name.to_ascii_lowercase());
        if let Some(external_id) = &reference.external_id {
            parts.push(external_id.to_ascii_lowercase());
        }
        if let Some(description) = &reference.description {
            parts.push(description.to_ascii_lowercase());
        }
        if let Some(url) = &reference.url {
            parts.push(url.to_ascii_lowercase());
        }
    }
}

fn push_sdo_search_parts(sdo: &SdoObject, parts: &mut Vec<String>) {
    let common = sdo.common_props();
    parts.extend(common.labels.iter().map(|label| label.to_ascii_lowercase()));
    push_external_reference_parts(&common.external_references, parts);
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

/// A stored object borrowed for filtering, without cloning it into a
/// [`StixObject`].
#[derive(Clone, Copy)]
pub(crate) enum StoredRef<'a> {
    Object(&'a StixObject),
    Sco(&'a ScoObject),
}

impl<'a> StoredRef<'a> {
    pub(crate) fn type_name(self) -> &'a str {
        match self {
            Self::Object(obj) => obj.type_name(),
            Self::Sco(sco) => QueryableStixObject::type_name(sco),
        }
    }

    fn modified(self) -> Option<&'a StixTimestamp> {
        match self {
            Self::Object(obj) => QueryableStixObject::modified(obj),
            Self::Sco(sco) => QueryableStixObject::modified(sco),
        }
    }

    fn has_any_label(self, wanted: &[String]) -> bool {
        let labels: &[String] = match self {
            Self::Object(StixObject::Sdo(sdo)) => &sdo.common_props().labels,
            Self::Object(StixObject::Sro(sro)) => &sro.common_props().labels,
            Self::Object(StixObject::Meta(MetaObject::LanguageContent(content))) => {
                &content.common.labels
            }
            Self::Object(StixObject::Meta(MetaObject::ExtensionDefinition(ext))) => {
                &ext.common.labels
            }
            Self::Object(StixObject::Custom(custom)) => {
                return custom
                    .raw
                    .get("labels")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|items| {
                        items
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .any(|label| wanted.iter().any(|w| w == label))
                    });
            }
            _ => &[],
        };
        wanted.iter().any(|label| labels.contains(label))
    }

    pub(crate) fn to_object(self) -> StixObject {
        match self {
            Self::Object(obj) => obj.clone(),
            Self::Sco(sco) => StixObject::Sco(sco.clone()),
        }
    }
}

/// Whether `obj` passes every filter of `q` except `id_filter`. `needle` is
/// `q.text_search` already lowercased; `search_text` yields the object's blob
/// and is only called when there is a needle.
pub(crate) fn query_matches<'t>(
    q: &StixQuery,
    needle: Option<&str>,
    obj: StoredRef<'_>,
    search_text: impl FnOnce() -> Cow<'t, str>,
) -> bool {
    if let Some(types) = &q.type_filter {
        let kind = crate::core::StixObjectKind::from_type_str(obj.type_name());
        if !kind.is_some_and(|k| types.contains(&k)) {
            return false;
        }
    }
    if let Some(since) = &q.modified_after {
        match obj.modified() {
            Some(modified) if modified >= since => {}
            _ => return false,
        }
    }
    if let Some(labels) = &q.labels_include
        && !obj.has_any_label(labels)
    {
        return false;
    }
    if let Some(needle) = needle {
        return text_matches(&search_text(), needle, q.text_match);
    }
    true
}

/// Whether a lowercase search blob matches the lowercase `needle`.
pub(crate) fn text_matches(blob: &str, needle: &str, mode: TextMatch) -> bool {
    match mode {
        TextMatch::Substring => blob.contains(needle),
        TextMatch::Exact => blob.split(FIELD_SEPARATOR).any(|field| field == needle),
        TextMatch::Token => {
            if needle.is_empty() {
                return true;
            }
            let bytes = blob.as_bytes();
            let mut from = 0;
            while let Some(found) = blob[from..].find(needle) {
                let start = from + found;
                let end = start + needle.len();
                let open = start == 0 || !is_token_byte(bytes[start - 1]);
                let close = end == bytes.len() || !is_token_byte(bytes[end]);
                if open && close {
                    return true;
                }
                from = start + blob[start..].chars().next().map_or(1, char::len_utf8);
            }
            false
        }
    }
}

/// Bytes that continue a token: ASCII letters and digits, `_`, `-`, and every
/// byte of a non-ASCII character.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || !byte.is_ascii()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(fields: &[&str]) -> String {
        fields.join(&FIELD_SEPARATOR.to_string())
    }

    #[test]
    fn token_match_needs_a_boundary_on_both_sides() {
        let text = blob(&["indicator", "[ipv4-addr:value = '10.0.0.10']"]);
        assert!(text_matches(&text, "10.0.0.1", TextMatch::Substring));
        assert!(!text_matches(&text, "10.0.0.1", TextMatch::Token));
        assert!(text_matches(&text, "10.0.0.10", TextMatch::Token));
        assert!(text_matches(&text, "ipv4-addr", TextMatch::Token));
        assert!(!text_matches(&text, "ipv4", TextMatch::Token));
        assert!(text_matches(&text, "indicator", TextMatch::Token));

        let text = blob(&["evil.example", "notevil.example x-evil.example"]);
        assert!(text_matches(&text, "evil.example", TextMatch::Token));
        let text = blob(&["notevil.example", "x-evil.example", "caf\u{e9}evil.example"]);
        assert!(!text_matches(&text, "evil.example", TextMatch::Token));
        assert!(text_matches(&text, "x-evil.example", TextMatch::Token));
    }

    #[test]
    fn token_match_finds_a_later_overlapping_occurrence() {
        assert!(text_matches("a.a.a", "a.a", TextMatch::Token));
        assert!(text_matches("aa.a", "a.a", TextMatch::Substring));
        assert!(!text_matches("aa.a", "a.a", TextMatch::Token));
        assert!(text_matches("aa.a a.a", "a.a", TextMatch::Token));
    }

    #[test]
    fn exact_match_compares_whole_fields() {
        let text = blob(&["indicator", "bad.example", "line one\nline two"]);
        assert!(text_matches(&text, "bad.example", TextMatch::Exact));
        assert!(!text_matches(&text, "bad", TextMatch::Exact));
        assert!(text_matches(&text, "line one\nline two", TextMatch::Exact));
        assert!(!text_matches(&text, "line one", TextMatch::Exact));
    }
}
