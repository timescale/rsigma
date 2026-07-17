//! Shared STIX model validation helpers (STIX 2.1 spec compliance).

use std::collections::{BTreeMap, HashMap};

use crate::core::{LanguageTag, StixId, StixObjectKind, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::{ExternalReference, GranularMarking, SdoSroCommonProps};
use crate::model::sdo::MalwareSampleRef;
use crate::vocab::{ENCRYPTION_ALGORITHM_ENUM, is_iana_character_set};

/// Marker for relationship matrix entries that accept any SCO target type.
const SCO_TARGET: &str = "__SCO__";

/// Common relationship types allowed between any SDO or SCO pair (STIX §5.1.2).
const COMMON_RELATIONSHIP_TYPES: &[&str] = &["related-to", "derived-from", "duplicate-of"];

/// Validate that a STIX id prefix matches the declared object `type`.
pub fn validate_id_matches_type(id: &StixId, type_name: &str) -> Result<(), ModelError> {
    if id.type_name() == type_name {
        Ok(())
    } else {
        Err(ModelError::IdTypeMismatch {
            id: id.as_str().to_owned(),
            expected_type: type_name.to_owned(),
            actual_type: id.type_name().to_owned(),
        })
    }
}

/// Validate `modified >= created` when both timestamps are present on SDO/SRO common props.
pub fn validate_modified_gte_created(
    created: &StixTimestamp,
    modified: &StixTimestamp,
) -> Result<(), ModelError> {
    if modified < created {
        return Err(ModelError::ModifiedBeforeCreated);
    }
    Ok(())
}

/// Reject object-level or granular marking references that point at this object's own id.
pub fn validate_marking_refs_not_self(
    object_id: &StixId,
    marking_refs: &[&StixId],
    granular: &[GranularMarking],
) -> Result<(), ModelError> {
    for marking in marking_refs {
        if *marking == object_id {
            return Err(ModelError::MarkingDefinitionCircularRef {
                object_id: object_id.as_str().to_owned(),
            });
        }
    }
    for granular_marking in granular {
        if let Some(marking_ref) = &granular_marking.marking_ref
            && marking_ref.as_stix_id() == object_id
        {
            return Err(ModelError::MarkingDefinitionCircularRef {
                object_id: object_id.as_str().to_owned(),
            });
        }
    }
    Ok(())
}

/// Validate that an id prefix is one of the allowed STIX type names.
pub fn validate_ref_kind(id: &StixId, allowed: &[&str]) -> Result<(), ModelError> {
    let actual = id.type_name();
    if allowed.contains(&actual) {
        Ok(())
    } else {
        Err(ModelError::InvalidReferenceKind {
            ref_id: id.as_str().to_owned(),
            expected: allowed.join(", "),
        })
    }
}

/// Validate SDO or SCO reference kind (STIX §5.1.2).
pub fn validate_stix_or_sco_ref(id: &StixId) -> Result<(), ModelError> {
    match StixObjectKind::from_type_str(id.type_name()) {
        Some(StixObjectKind::Sdo(_) | StixObjectKind::Sco(_)) => Ok(()),
        _ => Err(ModelError::InvalidReferenceKind {
            ref_id: id.as_str().to_owned(),
            expected: "SDO or SCO".to_owned(),
        }),
    }
}

/// Validate SDO reference kind.
pub fn validate_sdo_ref(id: &StixId) -> Result<(), ModelError> {
    match StixObjectKind::from_type_str(id.type_name()) {
        Some(StixObjectKind::Sdo(_)) => Ok(()),
        _ => Err(ModelError::InvalidReferenceKind {
            ref_id: id.as_str().to_owned(),
            expected: "SDO".to_owned(),
        }),
    }
}

/// Validate marking-definition reference kind.
pub fn validate_marking_definition_ref(id: &StixId) -> Result<(), ModelError> {
    validate_ref_kind(id, &["marking-definition"])
}

/// Validate identity reference kind.
pub fn validate_identity_ref(id: &StixId) -> Result<(), ModelError> {
    validate_ref_kind(id, &["identity"])
}

/// Validate SCO reference kind.
pub fn validate_sco_ref(id: &StixId) -> Result<(), ModelError> {
    match StixObjectKind::from_type_str(id.type_name()) {
        Some(StixObjectKind::Sco(_)) => Ok(()),
        _ => Err(ModelError::InvalidReferenceKind {
            ref_id: id.as_str().to_owned(),
            expected: "SCO".to_owned(),
        }),
    }
}

/// Validate SCO or SRO reference kind (observed-data `object_refs`).
pub fn validate_sco_or_sro_ref(id: &StixId) -> Result<(), ModelError> {
    match StixObjectKind::from_type_str(id.type_name()) {
        Some(StixObjectKind::Sco(_) | StixObjectKind::Sro(_)) => Ok(()),
        _ => Err(ModelError::InvalidReferenceKind {
            ref_id: id.as_str().to_owned(),
            expected: "SCO or SRO".to_owned(),
        }),
    }
}

/// Effective language tag: `en` when `lang` is absent (STIX §3.2 default).
pub fn effective_lang(lang: Option<&LanguageTag>) -> LanguageTag {
    lang.cloned()
        .unwrap_or_else(|| LanguageTag::parse("en").expect("en is a valid language tag"))
}

impl SdoSroCommonProps {
    /// Validate SDO/SRO common properties shared across typed objects.
    pub fn validate(&self, type_name: &str) -> Result<(), ModelError> {
        validate_id_matches_type(&self.id, type_name)?;
        validate_modified_gte_created(&self.created, &self.modified)?;
        let marking_refs: Vec<_> = self
            .object_marking_refs
            .iter()
            .map(|id| id.as_stix_id())
            .collect();
        validate_marking_refs_not_self(&self.id, &marking_refs, &self.granular_markings)?;
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
        self.extensions.validate()?;
        Ok(())
    }
}

/// Validate CAPEC external references on attack-pattern objects.
pub fn validate_capec_external_refs(refs: &[ExternalReference]) -> Result<(), ModelError> {
    for reference in refs {
        if reference.source_name == "capec"
            && reference
                .external_id
                .as_ref()
                .is_none_or(|id| id.is_empty() || !id.starts_with("CAPEC-"))
        {
            return Err(ModelError::InvalidCapecExternalReference);
        }
    }
    Ok(())
}

/// Validate CVE external references on vulnerability objects.
pub fn validate_cve_external_refs(refs: &[ExternalReference]) -> Result<(), ModelError> {
    for reference in refs {
        if reference.source_name == "cve"
            && reference
                .external_id
                .as_ref()
                .is_none_or(|id| id.is_empty() || !id.starts_with("CVE-"))
        {
            return Err(ModelError::InvalidCveExternalReference);
        }
    }
    Ok(())
}

/// When `is_family` is false and multiple sample refs are present, they must denote the same binary.
pub fn validate_malware_sample_refs_same_binary(
    is_family: Option<bool>,
    sample_refs: &[MalwareSampleRef],
) -> Result<(), ModelError> {
    if is_family == Some(true) || sample_refs.len() <= 1 {
        return Ok(());
    }
    let first = sample_refs[0].as_stix_id();
    for sample in &sample_refs[1..] {
        if sample.as_stix_id() != first {
            return Err(ModelError::MalwareSampleRefsNotSameBinary);
        }
    }
    Ok(())
}

fn relationship_matrix() -> &'static HashMap<(&'static str, &'static str), &'static [&'static str]>
{
    static MATRIX: std::sync::OnceLock<
        HashMap<(&'static str, &'static str), &'static [&'static str]>,
    > = std::sync::OnceLock::new();
    MATRIX.get_or_init(|| {
        HashMap::from([
            (("attack-pattern", "delivers"), &["malware"][..]),
            (
                ("attack-pattern", "targets"),
                &["identity", "location", "vulnerability"][..],
            ),
            (("attack-pattern", "uses"), &["malware", "tool"][..]),
            (
                ("campaign", "attributed-to"),
                &["intrusion-set", "threat-actor"][..],
            ),
            (("campaign", "compromises"), &["infrastructure"][..]),
            (("campaign", "originates-from"), &["location"][..]),
            (
                ("campaign", "targets"),
                &["identity", "location", "vulnerability"][..],
            ),
            (
                ("campaign", "uses"),
                &["attack-pattern", "infrastructure", "malware", "tool"][..],
            ),
            (("course-of-action", "investigates"), &["indicator"][..]),
            (
                ("course-of-action", "mitigates"),
                &[
                    "attack-pattern",
                    "indicator",
                    "malware",
                    "tool",
                    "vulnerability",
                ][..],
            ),
            (
                ("course-of-action", "remediates"),
                &["malware", "vulnerability"][..],
            ),
            (
                ("domain-name", "resolves-to"),
                &["domain-name", "ipv4-addr", "ipv6-addr"][..],
            ),
            (("identity", "located-at"), &["location"][..]),
            (("indicator", "based-on"), &["observed-data"][..]),
            (
                ("indicator", "indicates"),
                &[
                    "attack-pattern",
                    "campaign",
                    "infrastructure",
                    "intrusion-set",
                    "malware",
                    "threat-actor",
                    "tool",
                ][..],
            ),
            (
                ("infrastructure", "communicates-with"),
                &[
                    "domain-name",
                    "infrastructure",
                    "ipv4-addr",
                    "ipv6-addr",
                    "url",
                ][..],
            ),
            (
                ("infrastructure", "consists-of"),
                &[SCO_TARGET, "infrastructure", "observed-data"][..],
            ),
            (
                ("infrastructure", "controls"),
                &["infrastructure", "malware"][..],
            ),
            (("infrastructure", "delivers"), &["malware"][..]),
            (("infrastructure", "has"), &["vulnerability"][..]),
            (("infrastructure", "hosts"), &["malware", "tool"][..]),
            (("infrastructure", "located-at"), &["location"][..]),
            (("infrastructure", "uses"), &["infrastructure"][..]),
            (("intrusion-set", "attributed-to"), &["threat-actor"][..]),
            (("intrusion-set", "compromises"), &["infrastructure"][..]),
            (("intrusion-set", "originates-from"), &["location"][..]),
            (
                ("intrusion-set", "targets"),
                &["identity", "location", "vulnerability"][..],
            ),
            (
                ("intrusion-set", "uses"),
                &["attack-pattern", "infrastructure", "malware", "tool"][..],
            ),
            (("ipv4-addr", "belongs-to"), &["autonomous-system"][..]),
            (("ipv4-addr", "resolves-to"), &["mac-addr"][..]),
            (("ipv6-addr", "belongs-to"), &["autonomous-system"][..]),
            (("ipv6-addr", "resolves-to"), &["mac-addr"][..]),
            (
                ("malware", "authored-by"),
                &["intrusion-set", "threat-actor"][..],
            ),
            (
                ("malware", "communicates-with"),
                &["domain-name", "ipv4-addr", "ipv6-addr", "url"][..],
            ),
            (("malware", "controls"), &["malware"][..]),
            (("malware", "exploits"), &["vulnerability"][..]),
            (("malware", "originates-from"), &["location"][..]),
            (
                ("malware", "targets"),
                &["identity", "infrastructure", "location", "vulnerability"][..],
            ),
            (
                ("malware", "uses"),
                &["attack-pattern", "infrastructure", "malware", "tool"][..],
            ),
            (("malware", "variant-of"), &["malware"][..]),
            (("malware-analysis", "av-analysis-of"), &["malware"][..]),
            (("malware-analysis", "characterizes"), &["malware"][..]),
            (
                ("malware-analysis", "dynamic-analysis-of"),
                &["malware"][..],
            ),
            (("malware-analysis", "static-analysis-of"), &["malware"][..]),
            (("threat-actor", "attributed-to"), &["identity"][..]),
            (("threat-actor", "compromises"), &["infrastructure"][..]),
            (("threat-actor", "impersonates"), &["identity"][..]),
            (("threat-actor", "located-at"), &["location"][..]),
            (
                ("threat-actor", "targets"),
                &["identity", "location", "vulnerability"][..],
            ),
            (
                ("threat-actor", "uses"),
                &["attack-pattern", "infrastructure", "malware", "tool"][..],
            ),
            (("tool", "delivers"), &["malware"][..]),
            (("tool", "drops"), &["malware"][..]),
            (("tool", "has"), &["vulnerability"][..]),
            (
                ("tool", "targets"),
                &["identity", "infrastructure", "location", "vulnerability"][..],
            ),
            (("tool", "uses"), &["infrastructure"][..]),
        ])
    })
}

/// Distinct STIX 2.1 `relationship_type` values from the normative matrix.
pub fn stix_relationship_types() -> Vec<&'static str> {
    static TYPES: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    TYPES
        .get_or_init(|| {
            let mut types: Vec<&'static str> = relationship_matrix()
                .keys()
                .map(|(_, rel_type)| *rel_type)
                .collect();
            types.sort_unstable();
            types.dedup();
            types
        })
        .clone()
}

/// Relationship types allowed from an SDO source type per STIX 2.1 §3.5.
pub fn relationship_types_for_source(source_type: &str) -> Vec<&'static str> {
    relationship_matrix()
        .keys()
        .filter(|(source, _)| *source == source_type)
        .map(|(_, rel_type)| *rel_type)
        .collect()
}

fn target_allowed(target_type: &str, allowed: &[&str]) -> bool {
    allowed.iter().any(|entry| {
        *entry == SCO_TARGET
            && matches!(
                StixObjectKind::from_type_str(target_type),
                Some(StixObjectKind::Sco(_))
            )
            || *entry == target_type
    })
}

/// Validate relationship endpoint types against the STIX 2.1 relationship matrix.
pub fn validate_relationship_endpoints(
    source: &StixId,
    target: &StixId,
    relationship_type: &str,
) -> Result<(), ModelError> {
    validate_stix_or_sco_ref(source)?;
    validate_stix_or_sco_ref(target)?;

    if COMMON_RELATIONSHIP_TYPES.contains(&relationship_type) {
        return Ok(());
    }

    let Some(allowed_targets) = relationship_matrix().get(&(source.type_name(), relationship_type))
    else {
        // User-defined relationship names are permitted by the spec.
        return Ok(());
    };

    if target_allowed(target.type_name(), allowed_targets) {
        Ok(())
    } else {
        Err(ModelError::RelationshipEndpointMatrixInvalid {
            relationship_type: relationship_type.to_owned(),
            source_type: source.type_name().to_owned(),
            target_type: target.type_name().to_owned(),
        })
    }
}

/// Validate relationship_type charset (STIX §5.1.2).
pub fn validate_relationship_type(relationship_type: &str) -> Result<(), ModelError> {
    if relationship_type.is_empty()
        || !relationship_type
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(ModelError::RelationshipTypeInvalid);
    }
    Ok(())
}

#[cfg(feature = "serde")]
fn is_valid_domain_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    label
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// Domain-name format check (RFC 1034 / RFC 5890 per label) at the parse boundary.
///
/// Full IDNA validation requires the `serde` feature ([DD-DM-001](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#dd-dm-001--wire-must-at-parse) — wire MUST at parse).
pub fn validate_domain_name_format(value: &str) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::DomainNameValueEmpty);
    }
    if value.starts_with('.') || value.ends_with('.') || value.contains("..") {
        return Err(ModelError::DomainNameFormatInvalid);
    }
    #[cfg(feature = "serde")]
    {
        let ascii = if value.is_ascii() {
            value.to_owned()
        } else {
            idna::domain_to_ascii(value).map_err(|_| ModelError::DomainNameFormatInvalid)?
        };
        if !ascii.split('.').all(is_valid_domain_label) {
            return Err(ModelError::DomainNameFormatInvalid);
        }
    }
    Ok(())
}

/// Email address format check (RFC 5322 addr-spec) at the parse boundary.
///
/// Full addr-spec validation requires the `serde` feature ([DD-DM-001](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#dd-dm-001--wire-must-at-parse) — wire MUST at parse).
pub fn validate_email_addr_format(value: &str) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::EmailAddrValueEmpty);
    }
    #[cfg(feature = "serde")]
    if !email_address::EmailAddress::is_valid(value) {
        return Err(ModelError::EmailAddrFormatInvalid);
    }
    Ok(())
}

/// URL format check (RFC 3986) at the parse boundary.
///
/// Full RFC 3986 validation requires the `serde` feature ([DD-DM-001](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md#dd-dm-001--wire-must-at-parse) — wire MUST at parse).
pub fn validate_url_format(value: &str) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::UrlValueEmpty);
    }
    #[cfg(feature = "serde")]
    {
        let parsed = url::Url::parse(value).map_err(|_| ModelError::UrlFormatInvalid)?;
        match parsed.scheme() {
            "http" | "https" | "ftp" => Ok(()),
            _ => Err(ModelError::UrlFormatInvalid),
        }
    }
    #[cfg(not(feature = "serde"))]
    {
        Ok(())
    }
}

/// Returns true when `name` is a recognized IANA character set label (STIX §3.9.1).
pub fn validate_iana_character_set(name: &str, property: &str) -> Result<(), ModelError> {
    if is_iana_character_set(name) {
        Ok(())
    } else {
        Err(ModelError::ScoEncInvalidCharset {
            property: property.to_owned(),
        })
    }
}

/// Validate `_enc` siblings stored in `ScoCommonProps::extra` (§3.1 / §3.9.1).
///
/// Spec-defined `_enc` properties are modeled on their types; vendor or future keys
/// land in `extra` via flatten and MUST obey the same pairing and IANA charset rules.
pub fn validate_extra_enc_pairings(
    extra: &BTreeMap<String, serde_json::Value>,
    typed_bases: &[(&str, Option<&str>)],
) -> Result<(), ModelError> {
    for (enc_key, enc_value) in extra {
        let Some(enc_property) = enc_key.strip_suffix("_enc") else {
            continue;
        };
        let Some(encoding) = enc_value.as_str() else {
            continue;
        };
        let base_value = typed_bases
            .iter()
            .find_map(|(name, value)| (*name == enc_property).then_some(*value))
            .flatten()
            .map(str::to_owned)
            .or_else(|| {
                extra
                    .get(enc_property)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            });
        validate_sco_string_encoding_pair(&base_value, &Some(encoding.to_owned()), enc_key)?;
    }
    Ok(())
}

/// Validate `_enc` pairing for a typed base property and its `_enc` sibling (STIX §3.1 / §3.9.1).
pub fn validate_sco_string_encoding_pair(
    base: &Option<String>,
    enc: &Option<String>,
    enc_property: &str,
) -> Result<(), ModelError> {
    match enc {
        None => Ok(()),
        Some(encoding) => {
            if base.as_ref().is_none_or(String::is_empty) {
                return Err(ModelError::ScoEncWithoutBaseProperty {
                    property: enc_property.to_owned(),
                });
            }
            validate_iana_character_set(encoding, enc_property)
        }
    }
}

/// Parse `granular_markings` from wire JSON (typed objects and custom objects).
#[cfg(feature = "serde")]
pub fn granular_markings_from_wire(wire: &serde_json::Value) -> Vec<GranularMarking> {
    wire.get("granular_markings")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

/// Validate encryption algorithm against the STIX closed vocabulary.
pub fn validate_encryption_algorithm(value: &str) -> Result<(), ModelError> {
    if ENCRYPTION_ALGORITHM_ENUM.contains(value) {
        Ok(())
    } else {
        Err(ModelError::EncryptionAlgorithmInvalid)
    }
}

/// Validate granular-marking selector syntax (STIX §7.2.3.1).
pub fn validate_granular_selector_syntax(selector: &str) -> Result<(), ModelError> {
    if selector.is_empty() {
        return Err(ModelError::GranularSelectorSyntaxInvalid {
            selector: selector.to_owned(),
        });
    }
    for segment in selector.split('.') {
        let valid = segment.starts_with('[')
            && segment.ends_with(']')
            && segment[1..segment.len() - 1]
                .chars()
                .all(|ch| ch.is_ascii_digit())
            && !segment[1..segment.len() - 1].is_empty()
            || segment
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
                && segment
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');
        if !valid {
            return Err(ModelError::GranularSelectorSyntaxInvalid {
                selector: selector.to_owned(),
            });
        }
    }
    Ok(())
}

/// Resolve a STIX property selector against a JSON object (syntax must already be valid).
pub fn resolve_selector_value<'a>(
    value: &'a serde_json::Value,
    selector: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in selector.split('.') {
        current = if segment.starts_with('[') && segment.ends_with(']') {
            let index: usize = segment[1..segment.len() - 1].parse().ok()?;
            current.get(index)?
        } else {
            current.get(segment)?
        };
    }
    Some(current)
}

/// Returns true when a language-content translation mirrors the target property (STIX §7.1.1).
pub fn language_content_translation_matches_target(
    target: &serde_json::Value,
    translation: &serde_json::Value,
) -> bool {
    match (target, translation) {
        (serde_json::Value::Null, serde_json::Value::Null) => true,
        (serde_json::Value::Bool(_), serde_json::Value::Bool(_)) => true,
        (serde_json::Value::Number(_), serde_json::Value::Number(_)) => true,
        (serde_json::Value::String(_), serde_json::Value::String(_)) => true,
        (serde_json::Value::Array(target_items), serde_json::Value::Array(translation_items)) => {
            target_items.len() == translation_items.len()
                && target_items.iter().zip(translation_items).all(|(t, tr)| {
                    if tr.as_str().is_some_and(str::is_empty) {
                        true
                    } else {
                        language_content_translation_matches_target(t, tr)
                    }
                })
        }
        (serde_json::Value::Object(target_obj), serde_json::Value::Object(translation_obj)) => {
            translation_obj.iter().all(|(key, tr_val)| {
                target_obj
                    .get(key)
                    .is_some_and(|t_val| language_content_translation_matches_target(t_val, tr_val))
            })
        }
        _ => false,
    }
}

/// Validate language-content `contents` top-level keys as RFC 5646 tags.
pub fn validate_language_content_contents(
    contents: &std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<String, serde_json::Value>,
    >,
) -> Result<(), ModelError> {
    for lang_key in contents.keys() {
        if LanguageTag::parse(lang_key).is_err() {
            return Err(ModelError::LanguageContentInvalidLanguageCode);
        }
    }
    Ok(())
}

/// SDO-only common property keys that MUST NOT appear on SCO objects.
pub const SCO_FORBIDDEN_COMMON_KEYS: &[&str] = &[
    "created",
    "modified",
    "created_by_ref",
    "revoked",
    "labels",
    "confidence",
    "lang",
    "external_references",
];

/// Reject SDO-only common properties present on SCO JSON.
pub fn validate_sco_forbidden_common_keys(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), ModelError> {
    for key in SCO_FORBIDDEN_COMMON_KEYS {
        if obj.contains_key(*key) {
            return Err(ModelError::ScoForbiddenCommonProperty {
                property: (*key).to_owned(),
            });
        }
    }
    Ok(())
}

/// Verify SCO id against deterministic UUIDv5 when id-contributing properties exist.
///
/// STIX §2.9 marks deterministic ids as a SHOULD; callers use this for optional
/// Validation Pipeline diagnostics, not for Data Model parse rejection.
pub fn validate_sco_deterministic_id(
    type_name: &str,
    wire_value: &serde_json::Value,
) -> Result<(), ModelError> {
    use crate::core::ScoKind;
    use crate::id::verify_sco_deterministic_id;

    let Some(kind) = ScoKind::from_type_str(type_name) else {
        return Ok(());
    };
    let Some(id_str) = wire_value.get("id").and_then(serde_json::Value::as_str) else {
        return Ok(());
    };
    let Ok(actual_id) = StixId::parse(id_str) else {
        return Ok(());
    };
    verify_sco_deterministic_id(kind, wire_value, &actual_id)
        .map_err(|_| ModelError::ScoDeterministicIdMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolve_selector_value_supports_property_and_index_segments() {
        let wire = json!({"labels": ["a", "b"], "nested": {"name": "x"}});
        assert_eq!(
            resolve_selector_value(&wire, "labels"),
            Some(&json!(["a", "b"]))
        );
        assert_eq!(
            resolve_selector_value(&wire, "labels.[0]"),
            Some(&json!("a"))
        );
        assert_eq!(
            resolve_selector_value(&wire, "nested.name"),
            Some(&json!("x"))
        );
        assert!(resolve_selector_value(&wire, "missing").is_none());
    }

    #[test]
    fn language_content_translation_matches_target_type_and_list_length() {
        assert!(language_content_translation_matches_target(
            &json!("hello"),
            &json!("hallo")
        ));
        assert!(!language_content_translation_matches_target(
            &json!("hello"),
            &json!(42)
        ));
        assert!(language_content_translation_matches_target(
            &json!(["a", "b"]),
            &json!(["x", "y"])
        ));
        assert!(!language_content_translation_matches_target(
            &json!(["a", "b"]),
            &json!(["x"])
        ));
        assert!(language_content_translation_matches_target(
            &json!(["a", "b"]),
            &json!(["", "y"])
        ));
        assert!(language_content_translation_matches_target(
            &json!({"name": "x", "labels": ["a"]}),
            &json!({"name": "y"})
        ));
        assert!(!language_content_translation_matches_target(
            &json!({"name": "x"}),
            &json!({"labels": ["a"]})
        ));
    }

    #[test]
    fn sco_enc_pairing_and_charset() {
        assert!(
            validate_sco_string_encoding_pair(
                &Some("quêry.dll".into()),
                &Some("windows-1252".into()),
                "name_enc"
            )
            .is_ok()
        );
        assert!(
            validate_sco_string_encoding_pair(&None, &Some("windows-1252".into()), "name_enc")
                .is_err()
        );
        assert!(
            validate_sco_string_encoding_pair(
                &Some("name".into()),
                &Some("not-a-charset".into()),
                "name_enc"
            )
            .is_err()
        );
    }
}
