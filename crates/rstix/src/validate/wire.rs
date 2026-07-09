//! Wire-level JSON helpers for validation checks.

use std::collections::HashSet;

use serde_json::Value;

use crate::core::{StixId, StixObjectKind};
use crate::model::validate::validate_id_matches_type;

use super::diagnostic::DiagnosticCode;

const RESERVED_CUSTOM_PROPERTY_NAMES: &[&str] = &["severity", "username", "phone_number", "action"];

/// Collect STIX object ids from a bundle-shaped JSON value.
pub(crate) fn collect_object_ids(value: &Value) -> HashSet<String> {
    let mut ids = HashSet::new();
    let Some(objects) = value.get("objects").and_then(Value::as_array) else {
        return ids;
    };
    for object in objects {
        if let Some(id) = object.get("id").and_then(Value::as_str) {
            ids.insert(id.to_owned());
        }
    }
    ids
}

/// Collect STIX reference targets from JSON (`*_ref` and `*_refs` string fields).
pub(crate) fn collect_reference_targets(value: &Value) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    walk_refs(value, "$", &mut refs);
    refs
}

fn walk_refs(value: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if key.ends_with("_ref")
                    && let Some(target) = child.as_str()
                {
                    out.push((child_path.clone(), target.to_owned()));
                } else if key.ends_with("_refs")
                    && let Some(array) = child.as_array()
                {
                    for (index, entry) in array.iter().enumerate() {
                        if let Some(target) = entry.as_str() {
                            out.push((format!("{child_path}[{index}]"), target.to_owned()));
                        }
                    }
                }
                walk_refs(child, &child_path, out);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                walk_refs(item, &format!("{path}[{index}]"), out);
            }
        }
        _ => {}
    }
}

/// Count fractional digits in an RFC 3339 UTC timestamp string.
pub(crate) fn timestamp_fractional_digits(input: &str) -> u8 {
    let Some((_, tail)) = input.split_once('T') else {
        return 0;
    };
    let Some((time_part, _)) = tail.rsplit_once('Z') else {
        return 0;
    };
    let Some((_, frac)) = time_part.split_once('.') else {
        return 0;
    };
    u8::try_from(frac.len()).unwrap_or(u8::MAX)
}

/// Walk JSON for `created` / `modified` timestamp strings with fewer than three fractional digits.
pub(crate) fn collect_short_timestamp_paths(value: &Value) -> Vec<(String, String)> {
    let mut paths = Vec::new();
    walk_timestamps(value, "$", &mut paths);
    paths
}

fn walk_timestamps(value: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if matches!(key.as_str(), "created" | "modified")
                    && let Some(text) = child.as_str()
                    && text.ends_with('Z')
                    && timestamp_fractional_digits(text) < 3
                {
                    out.push((child_path.clone(), text.to_owned()));
                }
                walk_timestamps(child, &child_path, out);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                walk_timestamps(item, &format!("{path}[{index}]"), out);
            }
        }
        _ => {}
    }
}

/// Validate custom STIX type names on wire (`x-*` prefix and length/charset rules).
pub(crate) fn validate_custom_type_name(type_name: &str) -> Option<DiagnosticCode> {
    if !type_name.starts_with("x-") {
        return Some(DiagnosticCode::I0010);
    }
    let len = type_name.len();
    if !(3..=250).contains(&len) {
        return Some(DiagnosticCode::E0050);
    }
    if type_name.contains("--") {
        return Some(DiagnosticCode::E0052);
    }
    if !type_name
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Some(DiagnosticCode::E0051);
    }
    None
}

/// Walk bundle objects and validate custom type names.
pub(crate) fn collect_custom_type_issues(value: &Value) -> Vec<(String, String, DiagnosticCode)> {
    let mut issues = Vec::new();
    let Some(objects) = value.get("objects").and_then(Value::as_array) else {
        return issues;
    };
    for (index, object) in objects.iter().enumerate() {
        let Some(type_name) = object.get("type").and_then(Value::as_str) else {
            continue;
        };
        if StixObjectKind::from_type_str(type_name).is_some() {
            continue;
        }
        if let Some(code) = validate_custom_type_name(type_name) {
            issues.push((format!("objects[{index}].type"), type_name.to_owned(), code));
        }
    }
    issues
}

/// Collect objects whose `id` prefix does not match the declared `type`.
pub(crate) fn collect_id_prefix_mismatches(value: &Value) -> Vec<(String, String, String)> {
    let mut issues = Vec::new();
    let Some(objects) = value.get("objects").and_then(Value::as_array) else {
        return issues;
    };
    for (index, object) in objects.iter().enumerate() {
        let Some(type_name) = object.get("type").and_then(Value::as_str) else {
            continue;
        };
        let Some(id_str) = object.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Ok(id) = StixId::parse(id_str) else {
            continue;
        };
        if validate_id_matches_type(&id, type_name).is_err() {
            issues.push((
                format!("objects[{index}].id"),
                id_str.to_owned(),
                type_name.to_owned(),
            ));
        }
    }
    issues
}

/// Collect reserved custom property names on wire objects.
pub(crate) fn collect_reserved_custom_property_issues(value: &Value) -> Vec<(String, String)> {
    let mut issues = Vec::new();
    let Some(objects) = value.get("objects").and_then(Value::as_array) else {
        return issues;
    };
    for (index, object) in objects.iter().enumerate() {
        let Some(map) = object.as_object() else {
            continue;
        };
        for key in map.keys() {
            if RESERVED_CUSTOM_PROPERTY_NAMES.contains(&key.as_str()) && !key.starts_with("x_") {
                issues.push((format!("objects[{index}].{key}"), key.clone()));
            }
        }
    }
    issues
}

/// Walk JSON for integer values outside the IEEE-754 safe integer range (±2^53).
pub(crate) fn collect_unsafe_integer_paths(value: &Value) -> Vec<(String, i128)> {
    let mut paths = Vec::new();
    walk_unsafe_integers(value, "$", &mut paths);
    paths
}

fn walk_unsafe_integers(value: &Value, path: &str, out: &mut Vec<(String, i128)>) {
    const MAX_SAFE: i128 = 9_007_199_254_740_992;
    match value {
        Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                let wide = i128::from(int);
                if wide.abs() > MAX_SAFE {
                    out.push((path.to_owned(), wide));
                }
            } else if let Some(uint) = number.as_u64() {
                let wide = i128::from(uint);
                if wide > MAX_SAFE {
                    out.push((path.to_owned(), wide));
                }
            }
        }
        Value::Object(map) => {
            for (key, child) in map {
                walk_unsafe_integers(child, &format!("{path}.{key}"), out);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                walk_unsafe_integers(item, &format!("{path}[{index}]"), out);
            }
        }
        _ => {}
    }
}

/// Walk JSON for hash property values with invalid lengths or formats.
pub(crate) fn collect_invalid_hash_paths(value: &Value) -> Vec<(String, String)> {
    let mut paths = Vec::new();
    walk_hashes(value, "$", &mut paths);
    paths
}

fn walk_hashes(value: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::Object(hashes)) = map.get("hashes") {
                for (algorithm, hash_value) in hashes {
                    if let Some(hash) = hash_value.as_str()
                        && !hash_length_valid(algorithm, hash)
                    {
                        out.push((
                            format!("{path}.hashes.{algorithm}"),
                            format!("invalid {algorithm} hash length or format"),
                        ));
                    }
                }
            }
            for (key, child) in map {
                if key != "hashes" {
                    walk_hashes(child, &format!("{path}.{key}"), out);
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                walk_hashes(item, &format!("{path}[{index}]"), out);
            }
        }
        _ => {}
    }
}

fn hash_length_valid(algorithm: &str, hash: &str) -> bool {
    let hex_len =
        |expected: usize| hash.len() == expected && hash.chars().all(|ch| ch.is_ascii_hexdigit());
    match algorithm {
        "MD5" => hex_len(32),
        "SHA-1" => hex_len(40),
        "SHA-256" => hex_len(64),
        "SHA-512" => hex_len(128),
        "SHA3-256" => hex_len(64),
        "SHA3-512" => hex_len(128),
        "TLSH" => hash.len() == 70 && hash.chars().all(|ch| ch.is_ascii_hexdigit()),
        "SSDEEP" => {
            hash.split(':').count() == 3
                && hash.chars().all(|ch| {
                    ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | ':' | '_')
                })
        }
        "SM3" => hex_len(64),
        _ => true,
    }
}

/// Granular-marking XOR and marking_ref kind issues on wire JSON.
pub(crate) fn collect_granular_marking_issues(
    value: &Value,
) -> Vec<(String, DiagnosticCode, String)> {
    let mut issues = Vec::new();
    let Some(objects) = value.get("objects").and_then(Value::as_array) else {
        return issues;
    };
    for (obj_index, object) in objects.iter().enumerate() {
        let Some(granular_markings) = object.get("granular_markings").and_then(Value::as_array)
        else {
            continue;
        };
        for (mark_index, marking) in granular_markings.iter().enumerate() {
            let base = format!("objects[{obj_index}].granular_markings[{mark_index}]");
            let has_ref = marking.get("marking_ref").and_then(Value::as_str).is_some();
            let has_lang = marking.get("lang").and_then(Value::as_str).is_some();
            match (has_ref, has_lang) {
                (false, false) => issues.push((
                    base.clone(),
                    DiagnosticCode::E0040,
                    "granular marking must set marking_ref or lang".into(),
                )),
                (true, true) => issues.push((
                    base.clone(),
                    DiagnosticCode::E0041,
                    "granular marking must not set both marking_ref and lang".into(),
                )),
                _ => {}
            }
            if let Some(marking_ref) = marking.get("marking_ref").and_then(Value::as_str)
                && let Ok(id) = StixId::parse(marking_ref)
                && id.type_name() != "marking-definition"
            {
                issues.push((
                    format!("{base}.marking_ref"),
                    DiagnosticCode::E0023,
                    format!("granular marking_ref `{marking_ref}` is not a marking-definition"),
                ));
            }
            if let Some(selectors) = marking.get("selectors").and_then(Value::as_array) {
                for (sel_index, selector) in selectors.iter().enumerate() {
                    let Some(selector) = selector.as_str() else {
                        continue;
                    };
                    let path = format!("{base}.selectors[{sel_index}]");
                    if crate::model::validate::validate_granular_selector_syntax(selector).is_err()
                    {
                        issues.push((
                            path.clone(),
                            DiagnosticCode::E0024,
                            format!("granular-marking selector `{selector}` has invalid syntax"),
                        ));
                    } else if crate::model::validate::resolve_selector_value(object, selector)
                        .is_none()
                    {
                        issues.push((
                            path,
                            DiagnosticCode::E0024,
                            format!(
                                "granular-marking selector `{selector}` does not resolve on object"
                            ),
                        ));
                    }
                }
            }
        }
    }
    issues
}

/// SDO-only common properties on SCO objects (STIX §3.2 / W0040).
pub(crate) fn collect_sco_forbidden_property_issues(value: &Value) -> Vec<(String, String)> {
    use crate::core::ScoKind;
    use crate::model::validate::SCO_FORBIDDEN_COMMON_KEYS;

    let mut issues = Vec::new();
    let Some(objects) = value.get("objects").and_then(Value::as_array) else {
        return issues;
    };
    for (index, object) in objects.iter().enumerate() {
        let Some(type_name) = object.get("type").and_then(Value::as_str) else {
            continue;
        };
        if ScoKind::from_type_str(type_name).is_none() {
            continue;
        }
        let Some(map) = object.as_object() else {
            continue;
        };
        for key in SCO_FORBIDDEN_COMMON_KEYS {
            if map.contains_key(*key) {
                issues.push((format!("objects[{index}].{key}"), (*key).to_owned()));
            }
        }
    }
    issues
}

/// Extension schema mismatches detectable on wire (E0030).
pub(crate) fn collect_extension_schema_issues(value: &Value) -> Vec<(String, String)> {
    let mut issues = Vec::new();
    let Some(objects) = value.get("objects").and_then(Value::as_array) else {
        return issues;
    };
    for (index, object) in objects.iter().enumerate() {
        let Some(extensions) = object.get("extensions").and_then(Value::as_object) else {
            continue;
        };
        for (key, entry) in extensions {
            if key.ends_with("-ext") {
                continue;
            }
            let Some(entry_obj) = entry.as_object() else {
                issues.push((
                    format!("objects[{index}].extensions.{key}"),
                    format!("extension `{key}` must be a JSON object"),
                ));
                continue;
            };
            if key.starts_with("extension-definition--") {
                let extension_type = entry_obj.get("extension_type").and_then(Value::as_str);
                match extension_type {
                    None => issues.push((
                        format!("objects[{index}].extensions.{key}.extension_type"),
                        format!("extension `{key}` missing required extension_type"),
                    )),
                    Some(value)
                        if !matches!(
                            value,
                            "property-extension"
                                | "toplevel-property-extension"
                                | "new-sdo"
                                | "new-sco"
                                | "new-sro"
                        ) =>
                    {
                        issues.push((
                            format!("objects[{index}].extensions.{key}.extension_type"),
                            format!("extension `{key}` has unknown extension_type `{value}`"),
                        ))
                    }
                    _ => {}
                }
            }
        }
    }
    issues
}

/// Versioning snapshot extracted from wire JSON for §3.6 checks.
#[derive(Clone, Debug)]
pub(crate) struct WireVersionEntry {
    pub path: String,
    pub id: String,
    pub modified: String,
    pub created: String,
    pub revoked: bool,
    pub created_by_ref: Option<String>,
}

/// Collect versioned SDO/SRO entries from bundle-shaped JSON.
pub(crate) fn collect_versioned_objects(value: &Value) -> Vec<WireVersionEntry> {
    use crate::core::ScoKind;

    let mut entries = Vec::new();
    let Some(objects) = value.get("objects").and_then(Value::as_array) else {
        return entries;
    };
    for (index, object) in objects.iter().enumerate() {
        let Some(type_name) = object.get("type").and_then(Value::as_str) else {
            continue;
        };
        if ScoKind::from_type_str(type_name).is_some() {
            continue;
        }
        let Some(id) = object.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(created) = object.get("created").and_then(Value::as_str) else {
            continue;
        };
        let Some(modified) = object.get("modified").and_then(Value::as_str) else {
            continue;
        };
        entries.push(WireVersionEntry {
            path: format!("objects[{index}]"),
            id: id.to_owned(),
            modified: modified.to_owned(),
            created: created.to_owned(),
            revoked: object
                .get("revoked")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            created_by_ref: object
                .get("created_by_ref")
                .and_then(Value::as_str)
                .map(str::to_owned),
        });
    }
    entries
}

/// Emit STIX-W0003 when a post-revocation version exists (STIX §3.6).
pub(crate) fn collect_post_revocation_version_issues(
    entries: &[WireVersionEntry],
) -> Vec<(String, String)> {
    use std::collections::HashMap;

    let mut by_id: HashMap<&str, Vec<&WireVersionEntry>> = HashMap::new();
    for entry in entries {
        by_id.entry(entry.id.as_str()).or_default().push(entry);
    }

    let mut issues = Vec::new();
    for versions in by_id.values() {
        let mut sorted: Vec<_> = versions.to_vec();
        sorted.sort_by(|left, right| left.modified.cmp(&right.modified));
        for (index, revoked_version) in sorted.iter().enumerate() {
            if !revoked_version.revoked {
                continue;
            }
            for later in sorted.iter().skip(index + 1) {
                if later.modified > revoked_version.modified {
                    issues.push((
                        later.path.clone(),
                        format!(
                            "object `{}` has a version after revocation at `{}` (STIX §3.6)",
                            later.id, revoked_version.modified
                        ),
                    ));
                }
            }
        }
    }
    issues
}

/// Emit STIX-W0004 when a non-creator publishes a new version (STIX §3.6).
pub(crate) fn collect_third_party_version_issues(
    entries: &[WireVersionEntry],
) -> Vec<(String, String)> {
    use std::collections::HashMap;

    let mut by_id: HashMap<&str, Vec<&WireVersionEntry>> = HashMap::new();
    for entry in entries {
        by_id.entry(entry.id.as_str()).or_default().push(entry);
    }

    let mut issues = Vec::new();
    for versions in by_id.values() {
        if versions.len() < 2 {
            continue;
        }
        let mut sorted: Vec<_> = versions.to_vec();
        sorted.sort_by(|left, right| left.modified.cmp(&right.modified));
        let creator = sorted[0].created_by_ref.as_deref();
        if creator.is_none() {
            continue;
        }
        for version in sorted.iter().skip(1) {
            if version.modified <= version.created {
                continue;
            }
            if let Some(created_by) = version.created_by_ref.as_deref()
                && Some(created_by) != creator
            {
                issues.push((
                    version.path.clone(),
                    format!(
                        "version at `{}` was created by `{created_by}` but object creator is `{}`",
                        version.modified,
                        creator.unwrap_or("<unknown>")
                    ),
                ));
            }
        }
    }
    issues
}

/// object_marking_refs entries that are not marking-definition ids (E0022).
pub(crate) fn collect_object_marking_ref_kind_issues(value: &Value) -> Vec<(String, String)> {
    let mut issues = Vec::new();
    let Some(objects) = value.get("objects").and_then(Value::as_array) else {
        return issues;
    };
    for (index, object) in objects.iter().enumerate() {
        let Some(marking_refs) = object.get("object_marking_refs").and_then(Value::as_array) else {
            continue;
        };
        for (ref_index, entry) in marking_refs.iter().enumerate() {
            let Some(target) = entry.as_str() else {
                continue;
            };
            if let Ok(id) = StixId::parse(target)
                && id.type_name() != "marking-definition"
            {
                issues.push((
                    format!("objects[{index}].object_marking_refs[{ref_index}]"),
                    target.to_owned(),
                ));
            }
        }
    }
    issues
}

const TLP1_MARKING_IDS: &[&str] = &[
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
];

/// TLP 1.x and typo findings on wire JSON (W0030/W0031).
pub(crate) fn collect_tlp_marking_issues(value: &Value) -> Vec<(String, DiagnosticCode, String)> {
    let mut issues = Vec::new();
    let Some(objects) = value.get("objects").and_then(Value::as_array) else {
        return issues;
    };
    for (index, object) in objects.iter().enumerate() {
        let prefix = format!("objects[{index}]");
        if let Some(marking_refs) = object.get("object_marking_refs").and_then(Value::as_array) {
            for entry in marking_refs {
                if let Some(id) = entry.as_str()
                    && TLP1_MARKING_IDS.contains(&id)
                {
                    issues.push((
                        format!("{prefix}.object_marking_refs"),
                        DiagnosticCode::W0031,
                        "object references a TLP 1.x marking-definition id (STIX-W0031)".into(),
                    ));
                    break;
                }
            }
        }
        if object.get("type").and_then(Value::as_str) == Some("marking-definition") {
            if object.get("definition_type").is_some() {
                issues.push((
                    format!("{prefix}.definition_type"),
                    DiagnosticCode::W0031,
                    "marking-definition uses legacy TLP 1.x encoding via definition_type (STIX-W0031)".into(),
                ));
            }
            if let Some(definition) = object.get("definition")
                && let Some(tlp) = definition.get("tlp").and_then(Value::as_str)
                && tlp.eq_ignore_ascii_case("amber+stict")
            {
                issues.push((
                    format!("{prefix}.definition.tlp"),
                    DiagnosticCode::W0030,
                    "TLP 2.0 marking uses typo `amber+stict`; use `amber+strict`".into(),
                ));
            }
        }
    }
    issues
}

/// SCO deterministic UUIDv5 mismatches on wire JSON (W0002).
pub(crate) fn collect_sco_deterministic_id_issues(value: &Value) -> Vec<(String, String)> {
    use crate::core::ScoKind;
    use crate::model::validate::validate_sco_deterministic_id;

    let mut issues = Vec::new();
    let Some(objects) = value.get("objects").and_then(Value::as_array) else {
        return issues;
    };
    for (index, object) in objects.iter().enumerate() {
        let Some(type_name) = object.get("type").and_then(Value::as_str) else {
            continue;
        };
        if ScoKind::from_type_str(type_name).is_none() {
            continue;
        }
        if validate_sco_deterministic_id(type_name, object).is_err() {
            issues.push((format!("objects[{index}].id"), type_name.to_owned()));
        }
    }
    issues
}
