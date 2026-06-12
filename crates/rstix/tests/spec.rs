//! Integration tests backed by STIX JSON under `tests/fixtures/spec/`.
//!
//! Wire-format behavior lives here. Unit tests in `src/` cover pure parse logic
//! and error paths that do not need fixture files.

#![cfg(feature = "serde")]

mod support;

use rstix::core::SpecVersion;
use rstix::model::ModelError;
use rstix::model::common::{
    ExtensionMap, ExtensionType, ExternalReference, GranularMarking, ScoCommonProps,
    SdoSroCommonProps,
};

#[test]
fn sdo_sro_round_trips_attack_pattern() {
    let parsed = support::roundtrip::<SdoSroCommonProps>("common/sdo_attack-pattern.json");
    assert_eq!(parsed.spec_version, SpecVersion::V2_1);
    let created_by = parsed
        .created_by_ref
        .as_ref()
        .expect("fixture includes created_by_ref");
    assert_eq!(created_by.as_stix_id().type_name(), "identity");
    assert_eq!(parsed.external_references.len(), 1);
    assert_eq!(parsed.object_marking_refs.len(), 1);
}

#[test]
fn sdo_sro_minimal_omits_empty_optionals() {
    let parsed = support::roundtrip::<SdoSroCommonProps>("common/sdo_minimal.json");
    let value = serde_json::to_value(&parsed).expect("serialize");
    for absent in [
        "created_by_ref",
        "revoked",
        "labels",
        "confidence",
        "lang",
        "external_references",
        "object_marking_refs",
        "granular_markings",
        "extensions",
    ] {
        assert!(
            value.get(absent).is_none(),
            "expected {absent} to be omitted"
        );
    }
}

#[test]
fn sdo_sro_rejects_missing_spec_version() {
    support::assert_fixture_rejects::<SdoSroCommonProps>("common/sdo_missing_spec_version.json");
}

#[test]
fn sco_round_trips_ipv4_and_omits_sdo_fields() {
    let parsed = support::roundtrip::<ScoCommonProps>("common/sco_ipv4-addr.json");
    assert_eq!(parsed.spec_version, Some(SpecVersion::V2_1));

    let value = serde_json::to_value(&parsed).expect("serialize");
    for absent in [
        "created",
        "modified",
        "created_by_ref",
        "revoked",
        "labels",
        "confidence",
        "lang",
        "external_references",
    ] {
        assert!(
            value.get(absent).is_none(),
            "expected {absent} to be omitted"
        );
    }
}

#[test]
fn external_reference_round_trips_full_fixture() {
    let parsed = support::roundtrip::<ExternalReference>("common/external-reference.json");
    assert_eq!(parsed.source_name, "capec");
    assert_eq!(parsed.external_id.as_deref(), Some("CAPEC-163"));
}

#[test]
fn external_reference_minimal_omits_empty_optionals() {
    let parsed = support::roundtrip::<ExternalReference>("common/external-reference-minimal.json");
    let value = serde_json::to_value(&parsed).expect("serialize");
    assert_eq!(
        value.get("source_name").and_then(|v| v.as_str()),
        Some("capec")
    );
    for absent in ["description", "url", "hashes", "external_id"] {
        assert!(
            value.get(absent).is_none(),
            "expected {absent} to be omitted"
        );
    }
}

#[test]
fn external_reference_new_rejects_empty_source_name() {
    assert_eq!(
        ExternalReference::new("   ").unwrap_err(),
        ModelError::ExternalReferenceMissingSourceName
    );
}

#[test]
fn external_reference_rejects_invalid_fixtures() {
    support::assert_fixture_rejects::<ExternalReference>(
        "common/external-reference-missing-source.json",
    );
    support::assert_fixture_rejects::<ExternalReference>(
        "common/external-reference-empty-source.json",
    );
}

#[test]
fn extension_map_round_trips() {
    let map = support::roundtrip::<ExtensionMap>("common/extension-map.json");
    assert!(
        map.get("extension-definition--04ee437a-1b58-4f6e-8b3e-6c0d0c7b9b21")
            .is_some()
    );
}

#[test]
fn extension_type_strings_round_trip() {
    for (variant, text) in [
        (ExtensionType::NewSdo, "\"new-sdo\""),
        (ExtensionType::NewSro, "\"new-sro\""),
        (ExtensionType::NewSco, "\"new-sco\""),
        (ExtensionType::PropertyExtension, "\"property-extension\""),
        (
            ExtensionType::ToplevelPropertyExtension,
            "\"toplevel-property-extension\"",
        ),
    ] {
        assert_eq!(serde_json::to_string(&variant).unwrap(), text);
        let decoded: ExtensionType = serde_json::from_str(text).unwrap();
        assert_eq!(decoded, variant);
    }
    assert!(serde_json::from_str::<ExtensionType>("\"made-up\"").is_err());
}

#[test]
fn granular_marking_round_trips_marking_ref() {
    let parsed = support::roundtrip::<GranularMarking>("common/granular-marking-ref.json");
    assert!(parsed.marking_ref.is_some());
    assert!(parsed.lang.is_none());
}

#[test]
fn granular_marking_round_trips_lang() {
    let parsed = support::roundtrip::<GranularMarking>("common/granular-marking-lang.json");
    assert!(parsed.lang.is_some());
    assert!(parsed.marking_ref.is_none());
}

#[test]
fn granular_marking_rejects_both_and_neither() {
    support::assert_fixture_rejects::<GranularMarking>("common/granular-marking-both.json");
    support::assert_fixture_rejects::<GranularMarking>("common/granular-marking-neither.json");
}
