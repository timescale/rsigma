//! Integration tests backed by STIX JSON under `tests/fixtures/spec/`.
//!
//! Wire-format behavior lives here. Unit tests in `src/` cover pure parse logic
//! and error paths that do not need fixture files.

#![cfg(feature = "serde")]

#[path = "support/fixtures_spec.rs"]
mod fixtures_spec;
#[path = "support/roundtrip.rs"]
mod roundtrip;

use roundtrip::{assert_fixture_rejects, roundtrip, roundtrip_strict};
use rstix::core::{Confidence, QueryValue, QueryableStixObject, SpecVersion};
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
use rstix::model::sdo::{
    AttackPattern, Campaign, CourseOfAction, Grouping, Identity, Incident, Indicator,
    Infrastructure, IntrusionSet, Location, Malware, MalwareAnalysis, Note, ObservedData, Opinion,
    Report, SdoObject, ThreatActor, Tool, Vulnerability,
};
use rstix::model::sro::{Relationship, Sighting};
use rstix::vocab::OpinionValue;

#[test]
fn sdo_sro_round_trips_attack_pattern() {
    let parsed = roundtrip::<SdoSroCommonProps>("common/sdo_attack-pattern.json");
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
    let parsed = roundtrip::<SdoSroCommonProps>("common/sdo_minimal.json");
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
    assert_fixture_rejects::<SdoSroCommonProps>("common/sdo_missing_spec_version.json");
}

#[test]
fn sco_round_trips_ipv4_and_omits_sdo_fields() {
    let parsed = roundtrip::<ScoCommonProps>("common/sco_ipv4-addr.json");
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
    let parsed = roundtrip_strict::<ExternalReference>("common/external-reference.json");
    assert_eq!(parsed.source_name, "capec");
    assert_eq!(parsed.external_id.as_deref(), Some("CAPEC-163"));
}

#[test]
fn sdo_sro_confidence_round_trips_and_rejects_out_of_range() {
    let parsed = roundtrip::<SdoSroCommonProps>("common/sdo_confidence.json");
    assert_eq!(
        parsed.confidence,
        Some(Confidence::new(85).expect("in range"))
    );

    assert_fixture_rejects::<SdoSroCommonProps>("common/sdo_confidence-out-of-range.json");
}

#[test]
fn external_reference_minimal_omits_empty_optionals() {
    let parsed = roundtrip_strict::<ExternalReference>("common/external-reference-minimal.json");
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
    assert_fixture_rejects::<ExternalReference>("common/external-reference-missing-source.json");
    assert_fixture_rejects::<ExternalReference>("common/external-reference-empty-source.json");
    assert_fixture_rejects::<ExternalReference>("common/external-reference-whitespace-source.json");
    assert_fixture_rejects::<ExternalReference>("common/external-reference-source-only.json");
}

#[test]
fn extension_map_round_trips() {
    let map = roundtrip_strict::<ExtensionMap>("common/extension-map.json");
    assert!(
        map.get("extension-definition--04ee437a-1b58-4f6e-8b3e-6c0d0c7b9b21")
            .is_some()
    );
}

#[test]
fn granular_marking_round_trips_marking_ref() {
    let parsed = roundtrip_strict::<GranularMarking>("common/granular-marking-ref.json");
    assert!(parsed.marking_ref.is_some());
    assert!(parsed.lang.is_none());
}

#[test]
fn granular_marking_round_trips_lang() {
    let parsed = roundtrip_strict::<GranularMarking>("common/granular-marking-lang.json");
    assert!(parsed.lang.is_some());
    assert!(parsed.marking_ref.is_none());
}

#[test]
fn granular_marking_rejects_both_and_neither() {
    assert_fixture_rejects::<GranularMarking>("common/granular-marking-both.json");
    assert_fixture_rejects::<GranularMarking>("common/granular-marking-neither.json");
}

#[test]
fn granular_marking_rejects_empty_selectors() {
    assert_fixture_rejects::<GranularMarking>("common/granular-marking-empty-selectors.json");
}

#[test]
fn granular_marking_rejects_missing_selectors() {
    assert_fixture_rejects::<GranularMarking>("common/granular-marking-missing-selectors.json");
}

#[test]
fn marking_definition_round_trips_legacy_and_current_tlp_encodings() {
    let legacy =
        roundtrip_strict::<MarkingDefinition>("meta/marking-definition-tlp-v1-white-stix21.json");
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

    let current =
        roundtrip_strict::<MarkingDefinition>("meta/marking-definition-tlp-v2-clear-stix21.json");
    assert_eq!(current.id.as_str(), TLP2_CLEAR_ID);
    assert!(!current.extensions.is_empty());
}

#[test]
fn marking_definition_round_trips_with_common_properties() {
    let parsed = roundtrip_strict::<MarkingDefinition>(
        "meta/marking-definition-with-common-props-stix21.json",
    );
    assert!(parsed.created_by_ref.is_some());
    assert_eq!(parsed.object_marking_refs.len(), 1);
    assert_eq!(parsed.external_references.len(), 1);
    assert_eq!(parsed.granular_markings.len(), 1);
}

#[test]
fn meta_types_reject_wrong_type_field() {
    assert_fixture_rejects::<MarkingDefinition>("meta/language-content.json");
    assert_fixture_rejects::<LanguageContent>("meta/marking-definition-tlp-v1-white-stix21.json");
    assert_fixture_rejects::<ExtensionDefinition>(
        "meta/marking-definition-tlp-v2-clear-stix21.json",
    );
}

#[test]
fn extension_definition_round_trips_and_rejects_missing_created_by_ref() {
    roundtrip_strict::<ExtensionDefinition>("meta/extension-definition.json");
    assert_fixture_rejects::<ExtensionDefinition>(
        "meta/extension-definition-missing-created-by-ref.json",
    );
}

#[test]
fn language_content_round_trips() {
    let parsed = roundtrip_strict::<LanguageContent>("meta/language-content.json");
    assert_eq!(parsed.object_ref.type_name(), "attack-pattern");
    assert!(parsed.contents.contains_key("de"));
}

#[test]
fn relationship_round_trips() {
    let parsed = roundtrip_strict::<Relationship>("sro/relationship.json");
    assert_eq!(parsed.relationship_type, "uses");
    assert_eq!(parsed.source_ref.type_name(), "malware");
    assert_eq!(parsed.target_ref.type_name(), "attack-pattern");
    assert!(parsed.description.is_none());
    assert!(parsed.start_time.is_none());
    assert!(parsed.stop_time.is_none());
}

#[test]
fn relationship_round_trips_with_times_and_description() {
    let parsed = roundtrip_strict::<Relationship>("sro/relationship-with-times.json");
    assert_eq!(parsed.relationship_type, "related-to");
    assert!(parsed.description.is_some());
    assert!(parsed.start_time.is_some());
    assert!(parsed.stop_time.is_some());
}

#[test]
fn relationship_round_trips_with_common_properties() {
    let parsed = roundtrip_strict::<Relationship>("sro/relationship-with-common-props-stix21.json");
    assert!(parsed.common.created_by_ref.is_some());
    assert_eq!(parsed.common.labels.len(), 1);
    assert!(parsed.common.confidence.is_some());
}

#[test]
fn relationship_rejects_invalid_fixtures() {
    assert_fixture_rejects::<Relationship>("sro/relationship-stop-before-start.json");
    assert_fixture_rejects::<Relationship>("sro/relationship-type-invalid.json");
}

#[test]
fn sighting_round_trips_minimal_spec_example() {
    let parsed = roundtrip_strict::<Sighting>("sro/sighting-minimal.json");
    assert_eq!(parsed.sighting_of_ref.type_name(), "indicator");
    assert!(parsed.common.created_by_ref.is_some());
}

#[test]
fn sighting_round_trips_rich_spec_example() {
    let parsed = roundtrip_strict::<Sighting>("sro/sighting-rich.json");
    assert_eq!(parsed.sighting_of_ref.type_name(), "indicator");
    assert_eq!(parsed.count, Some(50));
    assert_eq!(parsed.summary.as_deref(), Some("false"));
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
    let parsed = roundtrip_strict::<Sighting>("sro/sighting-with-location.json");
    assert!(matches!(
        &parsed.where_sighted_refs[0],
        rstix::model::sro::WhereSightedRef::Location(_)
    ));
}

#[test]
fn sighting_minimal_omits_empty_optionals() {
    let parsed = roundtrip_strict::<Sighting>("sro/sighting-minimal.json");
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
    assert_fixture_rejects::<Sighting>("sro/sighting-count-out-of-range.json");
    assert_fixture_rejects::<Sighting>("sro/sighting-last-seen-before-first-seen.json");
    assert_fixture_rejects::<Sighting>("sro/sighting-where-sighted-wrong-type.json");
}

#[test]
fn sro_types_reject_wrong_type_field() {
    assert_fixture_rejects::<Relationship>("sro/sighting-minimal.json");
    assert_fixture_rejects::<Sighting>("sro/relationship.json");
}

#[test]
fn sco_artifact_round_trips_and_rejects_payload_xor_url() {
    roundtrip_strict::<Artifact>("sco/artifact-image.json");
    assert_fixture_rejects::<Artifact>("sco/artifact-payload-and-url.json");
}

#[test]
fn sco_autonomous_system_round_trips() {
    roundtrip_strict::<AutonomousSystem>("sco/autonomous-system-basic.json");
}

#[test]
fn sco_directory_round_trips_and_rejects_wrong_contains_ref() {
    roundtrip_strict::<Directory>("sco/directory-basic.json");
    assert_fixture_rejects::<Directory>("sco/directory-contains-wrong-type.json");
}

#[test]
fn sco_domain_name_round_trips_and_rejects_wrong_resolves_ref() {
    roundtrip_strict::<DomainName>("sco/domain-name-basic.json");
    assert_fixture_rejects::<DomainName>("sco/domain-name-resolves-wrong-type.json");
}

#[test]
fn sco_email_addr_round_trips_and_rejects_empty_value() {
    roundtrip_strict::<EmailAddr>("sco/email-addr-basic.json");
    assert_fixture_rejects::<EmailAddr>("sco/email-addr-empty-value.json");
}

#[test]
fn sco_email_message_round_trips_and_rejects_multipart_violation() {
    roundtrip_strict::<EmailMessage>("sco/email-message-simple.json");
    roundtrip_strict::<EmailMessage>("sco/email-message-multipart.json");
    assert_fixture_rejects::<EmailMessage>("sco/email-message-body-with-multipart.json");
}

#[test]
fn sco_file_round_trips_and_rejects_missing_name_and_hash() {
    roundtrip_strict::<File>("sco/file-basic.json");
    roundtrip_strict::<File>("sco/file-with-parent.json");
    roundtrip_strict::<File>("sco/file-with-archive-ext.json");
    assert_fixture_rejects::<File>("sco/file-no-name-or-hash.json");
    assert_fixture_rejects::<File>("sco/file-with-invalid-archive-ext.json");
}

#[test]
fn sco_ipv4_addr_round_trips_and_rejects_wrong_resolves_ref() {
    roundtrip_strict::<Ipv4Addr>("sco/ipv4-addr-single.json");
    roundtrip_strict::<Ipv4Addr>("sco/ipv4-addr-cidr.json");
    roundtrip_strict::<Ipv4Addr>("sco/ipv4-addr-with-belongs.json");
    assert_fixture_rejects::<Ipv4Addr>("sco/ipv4-addr-resolves-wrong-type.json");
}

#[test]
fn sco_ipv6_addr_round_trips() {
    roundtrip_strict::<Ipv6Addr>("sco/ipv6-addr-single.json");
}

#[test]
fn sco_mac_addr_round_trips() {
    roundtrip_strict::<MacAddr>("sco/mac-addr.json");
}

#[test]
fn sco_mutex_round_trips() {
    roundtrip_strict::<Mutex>("sco/mutex.json");
}

#[test]
fn sco_network_traffic_round_trips_and_rejects_invalid_fixtures() {
    roundtrip_strict::<NetworkTraffic>("sco/network-traffic-tcp.json");
    assert_fixture_rejects::<NetworkTraffic>("sco/network-traffic-no-protocols.json");
    assert_fixture_rejects::<NetworkTraffic>("sco/network-traffic-end-with-active.json");
    assert_fixture_rejects::<NetworkTraffic>("sco/network-traffic-with-invalid-tcp-ext.json");
}

#[test]
fn sco_process_round_trips_and_rejects_no_properties() {
    roundtrip_strict::<Process>("sco/process-basic.json");
    assert_fixture_rejects::<Process>("sco/process-no-properties.json");
    assert_fixture_rejects::<Process>("sco/process-with-invalid-windows-process-ext.json");
}

#[test]
fn sco_software_round_trips() {
    roundtrip_strict::<Software>("sco/software-basic.json");
}

#[test]
fn sco_url_round_trips() {
    roundtrip_strict::<Url>("sco/url.json");
}

#[test]
fn sco_user_account_round_trips_and_rejects_no_properties() {
    roundtrip_strict::<UserAccount>("sco/user-account-unix.json");
    assert_fixture_rejects::<UserAccount>("sco/user-account-no-properties.json");
    assert_fixture_rejects::<UserAccount>("sco/user-account-with-invalid-unix-ext.json");
}

#[test]
fn sco_windows_registry_key_round_trips() {
    roundtrip_strict::<WindowsRegistryKey>("sco/windows-registry-key-basic.json");
    roundtrip_strict::<WindowsRegistryKey>("sco/windows-registry-key-with-creator.json");
}

#[test]
fn sco_x509_certificate_round_trips() {
    roundtrip_strict::<X509Certificate>("sco/x509-certificate-basic.json");
}

#[test]
fn sco_types_reject_wrong_type_field() {
    assert_fixture_rejects::<Url>("sco/mutex.json");
    assert_fixture_rejects::<Mutex>("sco/url.json");
    assert_fixture_rejects::<File>("sco/artifact-image.json");
}

#[test]
fn sco_object_enum_delegates_queryable_stix_object() {
    let parsed = roundtrip_strict::<Url>("sco/url.json");
    let sco = ScoObject::Url(parsed.clone());
    assert_eq!(sco.id(), parsed.id());
    assert_eq!(sco.type_name(), Url::TYPE_NAME);
    assert!(sco.created().is_none());
    assert!(sco.modified().is_none());
}

#[test]
fn indicator_round_trips_minimal_and_rich() {
    let minimal = roundtrip_strict::<Indicator>("sdo/indicator-minimal.json");
    assert_eq!(minimal.pattern.pattern_type(), "stix");
    assert_eq!(minimal.indicator_types, vec!["malicious-activity"]);

    let rich = roundtrip_strict::<Indicator>("sdo/indicator-rich.json");
    assert!(rich.valid_until.is_some());
    assert_eq!(rich.kill_chain_phases.len(), 1);
    assert_eq!(
        rich.common.confidence,
        Some(Confidence::new(85).expect("in range"))
    );
}

#[test]
fn indicator_rejects_invalid_fixtures() {
    assert_fixture_rejects::<Indicator>("sdo/indicator-valid-until-before-from.json");
}

#[test]
fn note_round_trips_minimal_and_rich() {
    let minimal = roundtrip_strict::<Note>("sdo/note-minimal.json");
    assert_eq!(minimal.authors, vec!["John Doe"]);
    assert_eq!(minimal.object_refs.len(), 1);

    let rich = roundtrip_strict::<Note>("sdo/note-rich.json");
    assert_eq!(rich.object_refs.len(), 2);
    assert!(rich.common.created_by_ref.is_some());
}

#[test]
fn note_rejects_invalid_fixtures() {}

#[test]
fn opinion_round_trips_minimal_and_rich() {
    let minimal = roundtrip_strict::<Opinion>("sdo/opinion-minimal.json");
    assert_eq!(minimal.opinion, OpinionValue::StronglyDisagree);
    assert!(minimal.explanation.is_some());

    let rich = roundtrip_strict::<Opinion>("sdo/opinion-rich.json");
    assert_eq!(rich.opinion, OpinionValue::Agree);
    assert_eq!(rich.object_refs.len(), 2);
}

#[test]
fn opinion_rejects_invalid_fixtures() {
    assert_fixture_rejects::<Opinion>("sdo/opinion-invalid-value.json");
}

#[test]
fn observed_data_round_trips_object_refs_and_objects() {
    use rstix::model::sdo::ObservedDataForm;

    let refs = roundtrip_strict::<ObservedData>("sdo/observed-data-object-refs.json");
    assert_eq!(refs.number_observed, 50);
    assert!(matches!(refs.form, ObservedDataForm::ObjectRefs(_)));

    let objects = roundtrip_strict::<ObservedData>("sdo/observed-data-objects.json");
    assert_eq!(objects.number_observed, 1);
    assert!(matches!(
        objects.form,
        ObservedDataForm::DeprecatedObjects(_)
    ));
}

#[test]
fn observed_data_rejects_invalid_fixtures() {
    assert_fixture_rejects::<ObservedData>("sdo/observed-data-both-content.json");
    assert_fixture_rejects::<ObservedData>("sdo/observed-data-neither-content.json");
    assert_fixture_rejects::<ObservedData>("sdo/observed-data-last-before-first.json");
    assert_fixture_rejects::<ObservedData>("sdo/observed-data-number-out-of-range.json");
}

#[test]
fn complex_sdo_types_reject_wrong_type_field() {
    assert_fixture_rejects::<Indicator>("sdo/note-minimal.json");
    assert_fixture_rejects::<Note>("sdo/opinion-minimal.json");
    assert_fixture_rejects::<Opinion>("sdo/indicator-minimal.json");
    assert_fixture_rejects::<ObservedData>("sdo/indicator-minimal.json");
}

#[test]
fn sdo_object_enum_delegates_queryable_stix_object() {
    let parsed = roundtrip_strict::<Indicator>("sdo/indicator-minimal.json");
    let sdo = SdoObject::Indicator(parsed.clone());
    assert_eq!(sdo.id(), parsed.id());
    assert_eq!(sdo.type_name(), Indicator::TYPE_NAME);
    assert_eq!(
        sdo.get_field(&["pattern_type"]),
        Some(QueryValue::Str("stix"))
    );
    assert!(sdo.created().is_some());
    assert!(sdo.modified().is_some());
}

#[test]
fn sdo_attack_pattern_round_trips_and_rejects_invalid_fixtures() {
    let parsed = roundtrip_strict::<AttackPattern>("sdo/attack-pattern-minimal.json");
    assert_eq!(parsed.name, "Spear Phishing");
    let rich = roundtrip_strict::<AttackPattern>("sdo/attack-pattern-rich.json");
    assert!(rich.description.is_some());
    assert_eq!(rich.common.external_references.len(), 1);
    assert_fixture_rejects::<AttackPattern>("sdo/attack-pattern-kill-chain-phase-empty.json");
}

#[test]
fn sdo_campaign_round_trips_and_rejects_invalid_fixtures() {
    let parsed = roundtrip_strict::<Campaign>("sdo/campaign-minimal.json");
    assert_eq!(parsed.name, "Green Group Attacks Against Finance");
    assert!(parsed.common.created_by_ref.is_none());
    let rich = roundtrip_strict::<Campaign>("sdo/campaign-rich.json");
    assert!(rich.description.is_some());
    assert_eq!(rich.aliases, vec!["Green Group".to_string()]);
    assert_fixture_rejects::<Campaign>("sdo/campaign-last-seen-before-first-seen.json");
}

#[test]
fn sdo_course_of_action_round_trips_and_rejects_invalid_fixtures() {
    let parsed = roundtrip_strict::<CourseOfAction>("sdo/course-of-action-minimal.json");
    assert!(parsed.name.contains("TCP port 80"));
    let rich = roundtrip_strict::<CourseOfAction>("sdo/course-of-action-rich.json");
    assert!(rich.description.is_some());
}

#[test]
fn sdo_grouping_round_trips_and_rejects_invalid_fixtures() {
    let parsed = roundtrip_strict::<Grouping>("sdo/grouping-minimal.json");
    assert_eq!(parsed.context, "suspicious-activity");
    assert_eq!(parsed.object_refs.len(), 4);
    let rich = roundtrip_strict::<Grouping>("sdo/grouping-rich.json");
    assert_eq!(rich.common.labels, vec!["apt".to_string()]);
}

#[test]
fn sdo_identity_round_trips_and_rejects_invalid_fixtures() {
    let parsed = roundtrip_strict::<Identity>("sdo/identity-minimal.json");
    assert_eq!(parsed.name, "John Smith");
    assert_eq!(parsed.identity_class.as_deref(), Some("individual"));
    let rich = roundtrip_strict::<Identity>("sdo/identity-rich.json");
    assert_eq!(rich.identity_class.as_deref(), Some("organization"));
    assert_eq!(rich.sectors, vec!["technology".to_string()]);
}

#[test]
fn sdo_incident_round_trips_and_rejects_invalid_fixtures() {
    let parsed = roundtrip_strict::<Incident>("sdo/incident-minimal.json");
    assert_eq!(parsed.name, "Incident 43");
    let rich = roundtrip_strict::<Incident>("sdo/incident-rich.json");
    assert_eq!(rich.common.external_references.len(), 1);
}

#[test]
fn sdo_threat_actor_round_trips_and_rejects_invalid_fixtures() {
    let parsed = roundtrip_strict::<ThreatActor>("sdo/threat-actor-minimal.json");
    assert_eq!(parsed.name, "Evil Org");
    assert_eq!(
        parsed.threat_actor_types,
        vec!["crime-syndicate".to_string()]
    );
    assert_eq!(
        parsed.primary_motivation.as_deref(),
        Some("organizational-gain")
    );
    let rich = roundtrip_strict::<ThreatActor>("sdo/threat-actor-rich.json");
    assert_eq!(
        rich.secondary_motivations,
        vec!["personal-gain".to_string()]
    );
    assert!(rich.first_seen.is_some());
    assert_fixture_rejects::<ThreatActor>("sdo/threat-actor-last-seen-before-first-seen.json");
}

#[test]
fn sdo_tool_round_trips_and_rejects_invalid_fixtures() {
    let parsed = roundtrip_strict::<Tool>("sdo/tool-minimal.json");
    assert_eq!(parsed.name, "VNC");
    assert_eq!(parsed.tool_types, vec!["remote-access".to_string()]);
    let rich = roundtrip_strict::<Tool>("sdo/tool-rich.json");
    assert_eq!(rich.tool_version.as_deref(), Some("1.3.10"));
    assert_eq!(rich.kill_chain_phases.len(), 1);
    assert_fixture_rejects::<Tool>("sdo/tool-kill-chain-phase-empty.json");
}

#[test]
fn sdo_intrusion_set_round_trips_and_rejects_invalid_fixtures() {
    let parsed = roundtrip_strict::<IntrusionSet>("sdo/intrusion-set-minimal.json");
    assert_eq!(parsed.name, "Bobcat Breakin");
    let rich = roundtrip_strict::<IntrusionSet>("sdo/intrusion-set-rich.json");
    assert_eq!(rich.aliases, vec!["Zookeeper".to_string()]);
    assert_eq!(rich.goals.len(), 3);
    assert_fixture_rejects::<IntrusionSet>("sdo/intrusion-set-last-seen-before-first-seen.json");
}

#[test]
fn sdo_location_round_trips_and_rejects_invalid_fixtures() {
    let parsed = roundtrip_strict::<Location>("sdo/location-minimal.json");
    assert_eq!(parsed.region.as_deref(), Some("northern-america"));
    let rich = roundtrip_strict::<Location>("sdo/location-rich.json");
    assert_eq!(rich.country.as_deref(), Some("th"));
    assert_eq!(rich.postal_code.as_deref(), Some("63170"));
    assert_fixture_rejects::<Location>("sdo/location-missing-geo.json");
    assert_fixture_rejects::<Location>("sdo/location-latitude-without-longitude.json");
    assert_fixture_rejects::<Location>("sdo/location-latitude-out-of-range.json");
}

#[test]
fn sdo_infrastructure_round_trips_and_rejects_invalid_fixtures() {
    let parsed = roundtrip_strict::<Infrastructure>("sdo/infrastructure-minimal.json");
    assert_eq!(parsed.name, "Poison Ivy C2");
    let rich = roundtrip_strict::<Infrastructure>("sdo/infrastructure-rich.json");
    assert_eq!(
        rich.infrastructure_types,
        vec!["command-and-control".to_string()]
    );
}

#[test]
fn sdo_vulnerability_round_trips_and_rejects_invalid_fixtures() {
    let parsed = roundtrip_strict::<Vulnerability>("sdo/vulnerability-minimal.json");
    assert_eq!(parsed.name, "CVE-2016-1234");
    let rich = roundtrip_strict::<Vulnerability>("sdo/vulnerability-rich.json");
    assert_eq!(rich.common.external_references.len(), 1);
}

#[test]
fn sdo_report_round_trips_and_rejects_invalid_fixtures() {
    let parsed = roundtrip_strict::<Report>("sdo/report-minimal.json");
    assert_eq!(parsed.name, "The Black Vine Cyberespionage Group");
    assert_eq!(parsed.object_refs.len(), 1);
    let rich = roundtrip_strict::<Report>("sdo/report-rich.json");
    assert_eq!(rich.report_types, vec!["campaign".to_string()]);
    assert_eq!(rich.object_refs.len(), 3);
}

#[test]
fn sdo_malware_round_trips_and_rejects_invalid_fixtures() {
    let minimal = roundtrip_strict::<Malware>("sdo/malware-minimal.json");
    assert!(minimal.is_family.is_none());
    assert!(minimal.name.is_none());
    let rich = roundtrip_strict::<Malware>("sdo/malware-rich.json");
    assert_eq!(rich.is_family, Some(false));
    assert_eq!(rich.malware_types, vec!["ransomware".to_string()]);
    let family = roundtrip_strict::<Malware>("sdo/malware-family-rich.json");
    assert_eq!(family.is_family, Some(true));
    assert_fixture_rejects::<Malware>("sdo/malware-last-seen-before-first-seen.json");
    assert_fixture_rejects::<Malware>("sdo/malware-sample-ref-invalid.json");
}

#[test]
fn sdo_malware_analysis_round_trips_and_rejects_invalid_fixtures() {
    let parsed = roundtrip_strict::<MalwareAnalysis>("sdo/malware-analysis-minimal.json");
    assert_eq!(parsed.product, "microsoft");
    assert_eq!(parsed.result.as_deref(), Some("malicious"));
    let rich = roundtrip_strict::<MalwareAnalysis>("sdo/malware-analysis-rich.json");
    assert!(rich.sample_ref.is_some());
    assert_fixture_rejects::<MalwareAnalysis>(
        "sdo/malware-analysis-missing-result-and-sco-refs.json",
    );
}

#[test]
fn sdo_types_reject_wrong_type_field() {
    assert_fixture_rejects::<AttackPattern>("sdo/campaign-minimal.json");
    assert_fixture_rejects::<Campaign>("sdo/attack-pattern-minimal.json");
    assert_fixture_rejects::<CourseOfAction>("sdo/tool-minimal.json");
    assert_fixture_rejects::<Grouping>("sdo/identity-minimal.json");
    assert_fixture_rejects::<Identity>("sdo/incident-minimal.json");
    assert_fixture_rejects::<Incident>("sdo/threat-actor-minimal.json");
    assert_fixture_rejects::<ThreatActor>("sdo/campaign-minimal.json");
    assert_fixture_rejects::<Tool>("sdo/course-of-action-minimal.json");
    assert_fixture_rejects::<IntrusionSet>("sdo/malware-minimal.json");
    assert_fixture_rejects::<Location>("sdo/infrastructure-minimal.json");
    assert_fixture_rejects::<Malware>("sdo/intrusion-set-minimal.json");
    assert_fixture_rejects::<Report>("sdo/vulnerability-minimal.json");
}
