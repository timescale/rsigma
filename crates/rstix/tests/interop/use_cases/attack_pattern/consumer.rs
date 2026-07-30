//! §3.1.5 Required Consumer Persona Support (REQ-3.1-C-01..C-05).

use crate::interop_test;
use rstix::core::{QueryValue, QueryableStixObject, StixId};
use rstix::model::sdo::{AttackPattern, Identity, Vulnerability};
use rstix::model::sro::Relationship;
use serde_json::Value;

use crate::common::fixture_catalog::{
    parse_fixture_objects, summarize_fixture_wire, use_case_object_ids,
};
use crate::common::wire_preservation::{
    assert_identity_fields_preserved, assert_wire_object_preserved,
};
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::validate_interop_fixture;
use crate::use_cases::attack_pattern::{FIXTURE_TARGETS, PRODUCER_FIXTURES};

fn for_each_attack_pattern_fixture(mut f: impl FnMut(&str)) {
    for relative in PRODUCER_FIXTURES {
        f(relative);
    }
}

/// REQ-3.1-C-01 — Consumer supports §3.1.2 Producer Persona properties on normative fixtures.
pub fn assert_supports_producer_props() {
    for_each_attack_pattern_fixture(|relative| {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));

        for object_id in use_case_ids {
            let wire = objects
                .iter()
                .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
                .unwrap_or_else(|| panic!("{relative}: wire object {object_id}"));
            let stix_id = StixId::parse(&object_id).expect("object id");
            let ap = bundle
                .get_typed::<AttackPattern>(&stix_id)
                .unwrap_or_else(|| panic!("{relative}: typed attack-pattern {object_id}"));
            assert!(!ap.common.external_references.is_empty());
            assert!(!ap.kill_chain_phases.is_empty());
            assert_wire_object_preserved(relative, wire, &bundle, &object_id);
        }
    });
}

/// REQ-3.1-C-02 — Consumer receives Identity, Attack Pattern(s), and SROs (§3.1.3.2).
pub fn assert_receives_triad() {
    let relative = FIXTURE_TARGETS;
    let fixture = load_fixture(relative);
    let summary = summarize_fixture_wire(&fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: summarize fixture: {err}"));
    assert_eq!(summary.identity_ids.len(), 1);
    assert_eq!(
        summary.primary_sdo_count, 2,
        "attack-pattern + vulnerability"
    );
    assert_eq!(summary.relationship_count, 1);

    let bundle = validate_interop_fixture(relative, &fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));
    for identity_id in &summary.identity_ids {
        let id = StixId::parse(identity_id).expect("identity id");
        assert!(
            bundle.get_typed::<Identity>(&id).is_some(),
            "{relative}: Identity {identity_id} must parse"
        );
    }
    assert_eq!(bundle.objects_of_type::<AttackPattern>().count(), 1);
    assert_eq!(bundle.objects_of_type::<Vulnerability>().count(), 1);
    assert_eq!(bundle.objects_of_type::<Relationship>().count(), 1);
}

/// REQ-3.1-C-03 — Consumer resolves `created_by_ref` Identity fields (§3.1.3.2).
pub fn assert_resolves_created_by_ref() {
    let relative = FIXTURE_TARGETS;
    let fixture = load_fixture(relative);
    let bundle = validate_interop_fixture(relative, &fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");

    let mut checked = 0usize;
    for object in &objects {
        let Some(created_by_ref) = object.get("created_by_ref").and_then(Value::as_str) else {
            continue;
        };
        let identity_id = StixId::parse(created_by_ref).expect("created_by_ref");
        let wire_identity = objects
            .iter()
            .find(|obj| obj.get("id").and_then(Value::as_str) == Some(created_by_ref))
            .expect("wire Identity for created_by_ref");
        assert!(
            bundle.get_typed::<Identity>(&identity_id).is_some(),
            "{relative}: created_by_ref `{created_by_ref}` must resolve"
        );
        assert_identity_fields_preserved(relative, wire_identity, &bundle, created_by_ref);
        checked += 1;
    }
    assert!(checked > 0, "{relative}: expected created_by_ref usage");
}

/// REQ-3.1-C-04 — Consumer processes Attack Pattern fields via query + leaf validate.
///
/// Distinct from C-01 (full wire re-serialize preservation): uses
/// [`QueryableStixObject::get_field`] for `name` / `created_by_ref`, then runs
/// [`KillChainPhase::validate`] / [`ExternalReference::validate`] on each typed
/// member present on this fixture (cardinality taken from the wire object, not a
/// generic non-empty producer-prop check).
pub fn assert_processes_fields() {
    let relative = FIXTURE_TARGETS;
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let use_case_ids = use_case_object_ids(relative, &objects);
    let bundle = validate_interop_fixture(relative, &fixture.json).expect("interop gate");

    assert_eq!(
        use_case_ids.len(),
        1,
        "{relative}: one attack-pattern use-case id"
    );
    let object_id = &use_case_ids[0];
    let stix_id = StixId::parse(object_id).expect("attack-pattern id");
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .unwrap_or_else(|| panic!("{relative}: wire attack-pattern {object_id}"));
    let ap = bundle
        .get_typed::<AttackPattern>(&stix_id)
        .unwrap_or_else(|| panic!("{relative}: typed attack-pattern {object_id}"));

    match ap.get_field(&["name"]) {
        Some(QueryValue::Str(name)) => {
            assert_eq!(
                name,
                ap.name.as_str(),
                "{relative}: get_field(name) mismatch"
            );
            assert_eq!(
                Some(name),
                wire.get("name").and_then(Value::as_str),
                "{relative}: get_field(name) must match wire"
            );
        }
        other => panic!("{relative}: expected QueryValue::Str for name, got {other:?}"),
    }
    let created_by = ap
        .common
        .created_by_ref
        .as_ref()
        .unwrap_or_else(|| panic!("{relative}: created_by_ref required for field processing"));
    match ap.get_field(&["created_by_ref"]) {
        Some(QueryValue::Id(id)) => {
            assert_eq!(
                id,
                created_by.as_stix_id(),
                "{relative}: get_field(created_by_ref) mismatch"
            );
            assert_eq!(
                Some(id.as_str()),
                wire.get("created_by_ref").and_then(Value::as_str),
                "{relative}: get_field(created_by_ref) must match wire"
            );
        }
        other => panic!("{relative}: expected QueryValue::Id for created_by_ref, got {other:?}"),
    }

    let wire_phase_len = wire
        .get("kill_chain_phases")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    assert_eq!(
        ap.kill_chain_phases.len(),
        wire_phase_len,
        "{relative}: typed kill_chain_phases length must match wire"
    );
    for phase in &ap.kill_chain_phases {
        phase
            .validate()
            .unwrap_or_else(|err| panic!("{relative}: kill_chain_phase.validate: {err}"));
    }

    let wire_ref_len = wire
        .get("external_references")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    assert_eq!(
        ap.common.external_references.len(),
        wire_ref_len,
        "{relative}: typed external_references length must match wire"
    );
    for reference in &ap.common.external_references {
        reference
            .validate()
            .unwrap_or_else(|err| panic!("{relative}: external_reference.validate: {err}"));
    }
}

/// REQ-3.1-C-05 — Consumer resolves related SDOs/SROs (§3.1.3.2 `targets` relationship).
pub fn assert_processes_related() {
    let relative = FIXTURE_TARGETS;
    let bundle =
        validate_interop_fixture(relative, &load_fixture(relative).json).expect("interop gate");
    let relationships: Vec<_> = bundle.objects_of_type::<Relationship>().collect();
    assert_eq!(
        relationships.len(),
        1,
        "{relative}: expected one relationship"
    );
    let relationship = &relationships[0];
    assert_eq!(relationship.relationship_type.as_str(), "targets");
    assert!(
        bundle.get(&relationship.source_ref).is_some(),
        "source_ref must resolve"
    );
    assert!(
        bundle.get(&relationship.target_ref).is_some(),
        "target_ref must resolve"
    );
    assert!(
        bundle
            .get_typed::<AttackPattern>(&relationship.source_ref)
            .is_some()
    );
    assert!(
        bundle
            .get_typed::<Vulnerability>(&relationship.target_ref)
            .is_some()
    );
}

/// REQ-CHK-SXC-3.1 / §4.2 Table 55 — Consumer handles §3.1.3 Producer test case data.
///
/// Distinct from `REQ-CHK-SXP-3.1` (re-validation only): resolves each use-case Attack
/// Pattern as a typed SDO and closes `created_by_ref` to a typed Identity.
pub fn assert_handles_producer_testcases() {
    for relative in PRODUCER_FIXTURES {
        let fixture = load_fixture(relative);
        let objects = parse_fixture_objects(&fixture.json)
            .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
        let use_case_ids = use_case_object_ids(relative, &objects);
        let bundle = validate_interop_fixture(relative, &fixture.json).unwrap_or_else(|err| {
            panic!("{relative}: §3.1 consumer must handle producer test case: {err}")
        });

        assert!(
            !use_case_ids.is_empty(),
            "{relative}: expected attack-pattern use-case object(s)"
        );
        for object_id in use_case_ids {
            let stix_id = StixId::parse(&object_id).expect("attack-pattern id");
            let ap = bundle
                .get_typed::<AttackPattern>(&stix_id)
                .unwrap_or_else(|| panic!("{relative}: typed attack-pattern {object_id}"));
            let created_by = ap.common.created_by_ref.as_ref().unwrap_or_else(|| {
                panic!("{relative}: created_by_ref required for consumer close")
            });
            assert!(
                bundle
                    .get_typed::<Identity>(created_by.as_stix_id())
                    .is_some(),
                "{relative}: created_by_ref must resolve to typed Identity"
            );
        }
    }
}

interop_test!(
    "REQ-3.1-C-01",
    "use_cases::attack_pattern::consumer::supports_producer_props",
    supports_producer_props,
    {
        assert_supports_producer_props();
    }
);

interop_test!(
    "REQ-3.1-C-02",
    "use_cases::attack_pattern::consumer::receives_triad",
    receives_triad,
    {
        assert_receives_triad();
    }
);

interop_test!(
    "REQ-3.1-C-03",
    "use_cases::attack_pattern::consumer::resolves_created_by_ref",
    resolves_created_by_ref,
    {
        assert_resolves_created_by_ref();
    }
);

interop_test!(
    "REQ-3.1-C-04",
    "use_cases::attack_pattern::consumer::processes_fields",
    processes_fields,
    {
        assert_processes_fields();
    }
);

interop_test!(
    "REQ-3.1-C-05",
    "use_cases::attack_pattern::consumer::processes_related",
    processes_related,
    {
        assert_processes_related();
    }
);

interop_test!(
    "REQ-CHK-SXC-3.1",
    "use_cases::attack_pattern::consumer::handles_producer_testcases",
    handles_producer_testcases,
    {
        assert_handles_producer_testcases();
    }
);
