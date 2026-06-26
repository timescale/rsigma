//! Integration tests backed by STIX JSON under `tests/fixtures/spec/`.
//!
//! Wire-format behavior lives here. Unit tests in `src/` cover pure parse logic
//! and error paths that do not need fixture files.

#![cfg(feature = "serde")]

mod support;

use rstix::core::{Confidence, QueryableStixObject, SpecVersion};
use rstix::model::common::{
    ExtensionMap, ExternalReference, GranularMarking, ScoCommonProps, SdoSroCommonProps,
};
use rstix::model::meta::{
    ExtensionDefinition, LanguageContent, MarkingDefinition, TLP1_WHITE_ID, TLP2_CLEAR_ID,
};
use rstix::model::sco::{
    Artifact, AutonomousSystem, Directory, DomainName, EmailAddr, EmailMessage, File, Ipv4Addr,
    Ipv6Addr, MacAddr, Mutex, NetworkTraffic, Process, ScoObject, Software, Url, UserAccount,
    WindowsRegistryKey, X509Certificate,
};
use rstix::model::sro::{Relationship, Sighting};

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
    let parsed = support::roundtrip_strict::<ExternalReference>("common/external-reference.json");
    assert_eq!(parsed.source_name, "capec");
    assert_eq!(parsed.external_id.as_deref(), Some("CAPEC-163"));
}

#[test]
fn sdo_sro_confidence_round_trips_and_rejects_out_of_range() {
    let parsed = support::roundtrip::<SdoSroCommonProps>("common/sdo_confidence.json");
    assert_eq!(
        parsed.confidence,
        Some(Confidence::new(85).expect("in range"))
    );

    support::assert_fixture_rejects::<SdoSroCommonProps>("common/sdo_confidence-out-of-range.json");
}

#[test]
fn external_reference_minimal_omits_empty_optionals() {
    let parsed =
        support::roundtrip_strict::<ExternalReference>("common/external-reference-minimal.json");
    let value = serde_json::to_value(&parsed).expect("serialize");
    assert_eq!(
        value.get("source_name").and_then(|v| v.as_str()),
        Some("capec")
    );
    assert_eq!(
        value.get("external_id").and_then(|v| v.as_str()),
        Some("CAPEC-163")
    );
    for absent in ["description", "url", "hashes"] {
        assert!(
            value.get(absent).is_none(),
            "expected {absent} to be omitted"
        );
    }
}

#[test]
fn external_reference_rejects_invalid_fixtures() {
    support::assert_fixture_rejects::<ExternalReference>(
        "common/external-reference-missing-source.json",
    );
    support::assert_fixture_rejects::<ExternalReference>(
        "common/external-reference-empty-source.json",
    );
    support::assert_fixture_rejects::<ExternalReference>(
        "common/external-reference-whitespace-source.json",
    );
    support::assert_fixture_rejects::<ExternalReference>(
        "common/external-reference-source-only.json",
    );
}

#[test]
fn extension_map_round_trips() {
    let map = support::roundtrip_strict::<ExtensionMap>("common/extension-map.json");
    assert!(
        map.get("extension-definition--04ee437a-1b58-4f6e-8b3e-6c0d0c7b9b21")
            .is_some()
    );
}

#[test]
fn granular_marking_round_trips_marking_ref() {
    let parsed = support::roundtrip_strict::<GranularMarking>("common/granular-marking-ref.json");
    assert!(parsed.marking_ref.is_some());
    assert!(parsed.lang.is_none());
}

#[test]
fn granular_marking_round_trips_lang() {
    let parsed = support::roundtrip_strict::<GranularMarking>("common/granular-marking-lang.json");
    assert!(parsed.lang.is_some());
    assert!(parsed.marking_ref.is_none());
}

#[test]
fn granular_marking_rejects_both_and_neither() {
    support::assert_fixture_rejects::<GranularMarking>("common/granular-marking-both.json");
    support::assert_fixture_rejects::<GranularMarking>("common/granular-marking-neither.json");
}

#[test]
fn granular_marking_rejects_empty_selectors() {
    support::assert_fixture_rejects::<GranularMarking>(
        "common/granular-marking-empty-selectors.json",
    );
}

#[test]
fn granular_marking_rejects_missing_selectors() {
    support::assert_fixture_rejects::<GranularMarking>(
        "common/granular-marking-missing-selectors.json",
    );
}

#[test]
fn marking_definition_round_trips_legacy_and_current_tlp_encodings() {
    let legacy = support::roundtrip_strict::<MarkingDefinition>(
        "meta/marking-definition-tlp-v1-white-stix21.json",
    );
    assert_eq!(legacy.id.as_str(), TLP1_WHITE_ID);
    assert_eq!(legacy.definition_type.as_deref(), Some("tlp"));
    assert_eq!(
        legacy
            .definition
            .as_ref()
            .and_then(|v| v.get("tlp"))
            .and_then(|v| v.as_str()),
        Some("white")
    );
    assert!(legacy.is_non_versionable());

    let current = support::roundtrip_strict::<MarkingDefinition>(
        "meta/marking-definition-tlp-v2-clear-stix21.json",
    );
    assert_eq!(current.id.as_str(), TLP2_CLEAR_ID);
    assert!(!current.extensions.is_empty());
}

#[test]
fn marking_definition_round_trips_with_common_properties() {
    let parsed = support::roundtrip_strict::<MarkingDefinition>(
        "meta/marking-definition-with-common-props-stix21.json",
    );
    assert!(parsed.created_by_ref.is_some());
    assert_eq!(parsed.object_marking_refs.len(), 1);
    assert_eq!(parsed.external_references.len(), 1);
    assert_eq!(parsed.granular_markings.len(), 1);
}

#[test]
fn meta_types_reject_wrong_type_field() {
    support::assert_fixture_rejects::<MarkingDefinition>("meta/language-content.json");
    support::assert_fixture_rejects::<LanguageContent>(
        "meta/marking-definition-tlp-v1-white-stix21.json",
    );
    support::assert_fixture_rejects::<ExtensionDefinition>(
        "meta/marking-definition-tlp-v2-clear-stix21.json",
    );
}

#[test]
fn extension_definition_round_trips_and_rejects_missing_created_by_ref() {
    support::roundtrip_strict::<ExtensionDefinition>("meta/extension-definition.json");
    support::assert_fixture_rejects::<ExtensionDefinition>(
        "meta/extension-definition-missing-created-by-ref.json",
    );
}

#[test]
fn language_content_round_trips() {
    let parsed = support::roundtrip_strict::<LanguageContent>("meta/language-content.json");
    assert_eq!(parsed.object_ref.type_name(), "attack-pattern");
    assert!(parsed.contents.contains_key("de"));
}

#[test]
fn relationship_round_trips() {
    let parsed = support::roundtrip_strict::<Relationship>("sro/relationship.json");
    assert_eq!(parsed.relationship_type, "uses");
    assert_eq!(parsed.source_ref.type_name(), "malware");
    assert_eq!(parsed.target_ref.type_name(), "attack-pattern");
    assert!(parsed.description.is_none());
    assert!(parsed.start_time.is_none());
    assert!(parsed.stop_time.is_none());
}

#[test]
fn relationship_round_trips_with_times_and_description() {
    let parsed = support::roundtrip_strict::<Relationship>("sro/relationship-with-times.json");
    assert_eq!(parsed.relationship_type, "related-to");
    assert!(parsed.description.is_some());
    assert!(parsed.start_time.is_some());
    assert!(parsed.stop_time.is_some());
}

#[test]
fn relationship_round_trips_with_common_properties() {
    let parsed =
        support::roundtrip_strict::<Relationship>("sro/relationship-with-common-props-stix21.json");
    assert!(parsed.common.created_by_ref.is_some());
    assert_eq!(parsed.common.labels.len(), 1);
    assert!(parsed.common.confidence.is_some());
}

#[test]
fn relationship_rejects_invalid_fixtures() {
    support::assert_fixture_rejects::<Relationship>("sro/relationship-stop-before-start.json");
    support::assert_fixture_rejects::<Relationship>("sro/relationship-type-invalid.json");
}

#[test]
fn sighting_round_trips_minimal_spec_example() {
    let parsed = support::roundtrip_strict::<Sighting>("sro/sighting-minimal.json");
    assert_eq!(parsed.sighting_of_ref.type_name(), "indicator");
    assert!(parsed.common.created_by_ref.is_some());
}

#[test]
fn sighting_round_trips_rich_spec_example() {
    let parsed = support::roundtrip_strict::<Sighting>("sro/sighting-rich.json");
    assert_eq!(parsed.sighting_of_ref.type_name(), "indicator");
    assert_eq!(parsed.count, Some(50));
    assert_eq!(parsed.summary, Some(false));
    assert!(parsed.description.is_some());
    assert_eq!(parsed.observed_data_refs.len(), 1);
    assert_eq!(parsed.where_sighted_refs.len(), 1);
    assert!(matches!(
        &parsed.where_sighted_refs[0],
        rstix::model::sro::WhereSightedRef::Identity(_)
    ));
}

#[test]
fn sighting_round_trips_with_location_where_sighted_ref() {
    let parsed = support::roundtrip_strict::<Sighting>("sro/sighting-with-location.json");
    assert!(matches!(
        &parsed.where_sighted_refs[0],
        rstix::model::sro::WhereSightedRef::Location(_)
    ));
}

#[test]
fn sighting_minimal_omits_empty_optionals() {
    let parsed = support::roundtrip_strict::<Sighting>("sro/sighting-minimal.json");
    let value = serde_json::to_value(&parsed).expect("serialize");
    for absent in [
        "description",
        "first_seen",
        "last_seen",
        "count",
        "summary",
        "observed_data_refs",
        "where_sighted_refs",
    ] {
        assert!(
            value.get(absent).is_none(),
            "expected {absent} to be omitted"
        );
    }
}

#[test]
fn sighting_rejects_invalid_fixtures() {
    support::assert_fixture_rejects::<Sighting>("sro/sighting-count-out-of-range.json");
    support::assert_fixture_rejects::<Sighting>("sro/sighting-last-seen-before-first-seen.json");
    support::assert_fixture_rejects::<Sighting>("sro/sighting-where-sighted-wrong-type.json");
}

#[test]
fn sro_types_reject_wrong_type_field() {
    support::assert_fixture_rejects::<Relationship>("sro/sighting-minimal.json");
    support::assert_fixture_rejects::<Sighting>("sro/relationship.json");
}

#[test]
fn sco_artifact_round_trips_and_rejects_payload_xor_url() {
    support::roundtrip_strict::<Artifact>("sco/artifact-image.json");
    support::assert_fixture_rejects::<Artifact>("sco/artifact-payload-and-url.json");
}

#[test]
fn sco_autonomous_system_round_trips() {
    support::roundtrip_strict::<AutonomousSystem>("sco/autonomous-system-basic.json");
}

#[test]
fn sco_directory_round_trips_and_rejects_wrong_contains_ref() {
    support::roundtrip_strict::<Directory>("sco/directory-basic.json");
    support::assert_fixture_rejects::<Directory>("sco/directory-contains-wrong-type.json");
}

#[test]
fn sco_domain_name_round_trips_and_rejects_wrong_resolves_ref() {
    support::roundtrip_strict::<DomainName>("sco/domain-name-basic.json");
    support::assert_fixture_rejects::<DomainName>("sco/domain-name-resolves-wrong-type.json");
}

#[test]
fn sco_email_addr_round_trips_and_rejects_empty_value() {
    support::roundtrip_strict::<EmailAddr>("sco/email-addr-basic.json");
    support::assert_fixture_rejects::<EmailAddr>("sco/email-addr-empty-value.json");
}

#[test]
fn sco_email_message_round_trips_and_rejects_multipart_violation() {
    support::roundtrip_strict::<EmailMessage>("sco/email-message-simple.json");
    support::roundtrip_strict::<EmailMessage>("sco/email-message-multipart.json");
    support::assert_fixture_rejects::<EmailMessage>("sco/email-message-body-with-multipart.json");
}

#[test]
fn sco_file_round_trips_and_rejects_missing_name_and_hash() {
    support::roundtrip_strict::<File>("sco/file-basic.json");
    support::roundtrip_strict::<File>("sco/file-with-parent.json");
    support::roundtrip_strict::<File>("sco/file-with-archive-ext.json");
    support::assert_fixture_rejects::<File>("sco/file-no-name-or-hash.json");
    support::assert_fixture_rejects::<File>("sco/file-with-invalid-archive-ext.json");
}

#[test]
fn sco_ipv4_addr_round_trips_and_rejects_wrong_resolves_ref() {
    support::roundtrip_strict::<Ipv4Addr>("sco/ipv4-addr-single.json");
    support::roundtrip_strict::<Ipv4Addr>("sco/ipv4-addr-cidr.json");
    support::roundtrip_strict::<Ipv4Addr>("sco/ipv4-addr-with-belongs.json");
    support::assert_fixture_rejects::<Ipv4Addr>("sco/ipv4-addr-resolves-wrong-type.json");
}

#[test]
fn sco_ipv6_addr_round_trips() {
    support::roundtrip_strict::<Ipv6Addr>("sco/ipv6-addr-single.json");
}

#[test]
fn sco_mac_addr_round_trips() {
    support::roundtrip_strict::<MacAddr>("sco/mac-addr.json");
}

#[test]
fn sco_mutex_round_trips() {
    support::roundtrip_strict::<Mutex>("sco/mutex.json");
}

#[test]
fn sco_network_traffic_round_trips_and_rejects_invalid_fixtures() {
    support::roundtrip_strict::<NetworkTraffic>("sco/network-traffic-tcp.json");
    support::assert_fixture_rejects::<NetworkTraffic>("sco/network-traffic-no-protocols.json");
    support::assert_fixture_rejects::<NetworkTraffic>("sco/network-traffic-end-with-active.json");
    support::assert_fixture_rejects::<NetworkTraffic>(
        "sco/network-traffic-with-invalid-tcp-ext.json",
    );
}

#[test]
fn sco_process_round_trips_and_rejects_no_properties() {
    support::roundtrip_strict::<Process>("sco/process-basic.json");
    support::assert_fixture_rejects::<Process>("sco/process-no-properties.json");
    support::assert_fixture_rejects::<Process>("sco/process-with-invalid-windows-process-ext.json");
}

#[test]
fn sco_software_round_trips() {
    support::roundtrip_strict::<Software>("sco/software-basic.json");
}

#[test]
fn sco_url_round_trips() {
    support::roundtrip_strict::<Url>("sco/url.json");
}

#[test]
fn sco_user_account_round_trips_and_rejects_no_properties() {
    support::roundtrip_strict::<UserAccount>("sco/user-account-unix.json");
    support::assert_fixture_rejects::<UserAccount>("sco/user-account-no-properties.json");
    support::assert_fixture_rejects::<UserAccount>("sco/user-account-with-invalid-unix-ext.json");
}

#[test]
fn sco_windows_registry_key_round_trips() {
    support::roundtrip_strict::<WindowsRegistryKey>("sco/windows-registry-key-basic.json");
    support::roundtrip_strict::<WindowsRegistryKey>("sco/windows-registry-key-with-creator.json");
}

#[test]
fn sco_x509_certificate_round_trips() {
    support::roundtrip_strict::<X509Certificate>("sco/x509-certificate-basic.json");
}

#[test]
fn sco_types_reject_wrong_type_field() {
    support::assert_fixture_rejects::<Url>("sco/mutex.json");
    support::assert_fixture_rejects::<Mutex>("sco/url.json");
    support::assert_fixture_rejects::<File>("sco/artifact-image.json");
}

#[test]
fn sco_object_enum_delegates_queryable_stix_object() {
    let parsed = support::roundtrip_strict::<Url>("sco/url.json");
    let sco = ScoObject::Url(parsed.clone());
    assert_eq!(sco.id(), parsed.id());
    assert_eq!(sco.type_name(), Url::TYPE_NAME);
    assert!(sco.created().is_none());
    assert!(sco.modified().is_none());
}
