//! §3.1.2 Required Producer Persona Support (REQ-3.1-P-01..P-13).

use crate::interop_test;
use rstix::core::{SpecVersion, StixId};
use rstix::model::sdo::AttackPattern;
use rstix::model::{Bundle, ParseOptions};
use rstix::validate::{Leniency, Validator};
use serde_json::Value;

use crate::common::fixture_catalog::{parse_fixture_objects, use_case_object_ids};
use crate::common::identity::assert_identity_shape;
use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{
    InteropGateOptions, validate_interop_fixture, validate_interop_json,
};
use crate::use_cases::attack_pattern::{FIXTURE_CREATE, PRODUCER_FIXTURES};

/// Interop millisecond timestamps: exactly three fractional digits before `Z`.
fn assert_millisecond_rfc3339(label: &str, value: &str) {
    let Some((_, frac_and_z)) = value.rsplit_once('.') else {
        panic!("{label} must include fractional seconds: {value}");
    };
    assert!(
        frac_and_z.ends_with('Z'),
        "{label} must end with Z: {value}"
    );
    let digits = &frac_and_z[..frac_and_z.len() - 1];
    assert_eq!(
        digits.len(),
        3,
        "{label} must have exactly three subsecond digits: {value}"
    );
    assert!(
        digits.chars().all(|c| c.is_ascii_digit()),
        "{label} fractional part must be digits: {value}"
    );
}

fn load_attack_pattern(relative: &str) -> (AttackPattern, String) {
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: parse fixture: {err}"));
    let use_case_ids = use_case_object_ids(relative, &objects);
    assert_eq!(
        use_case_ids.len(),
        1,
        "{relative}: expected one attack-pattern use-case object"
    );
    let object_id = use_case_ids.into_iter().next().expect("attack-pattern id");
    let bundle = validate_interop_fixture(relative, &fixture.json)
        .unwrap_or_else(|err| panic!("{relative}: interop gate: {err}"));
    let stix_id = StixId::parse(&object_id).expect("attack-pattern id");
    let ap = bundle
        .get_typed::<AttackPattern>(&stix_id)
        .unwrap_or_else(|| panic!("{relative}: typed attack-pattern {object_id}"))
        .clone();
    (ap, object_id)
}

/// REQ-3.1-P-01 — Producer creates Attack Pattern content (§3.1.3.1).
pub fn assert_create_attack_pattern() {
    validate_interop_fixture(FIXTURE_CREATE, &load_fixture(FIXTURE_CREATE).json)
        .expect("§3.1.3.1 must pass interop producer gate");
}

/// REQ-3.1-P-02 — Caller-selected object set parses and re-validates (not UI-level select/specify).
pub fn assert_select_content() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let mut root: Value = serde_json::from_str(&fixture.json).expect("parse bundle JSON");
    let objects = root
        .get_mut("objects")
        .and_then(Value::as_array_mut)
        .expect("objects array");
    for object in objects.iter_mut() {
        if object.get("type").and_then(Value::as_str) == Some("attack-pattern") {
            object["name"] = Value::String("Caller-selected Attack Pattern name".into());
        }
    }
    let json = serde_json::to_string(&root).expect("serialize caller-selected bundle");
    let use_case_ids = use_case_object_ids(FIXTURE_CREATE, &parse_fixture_objects(&json).unwrap());
    validate_interop_json(
        &json,
        &InteropGateOptions {
            use_case_object_ids: use_case_ids,
        },
    )
    .expect("caller-selected bundle must pass interop gate");
}

/// REQ-3.1-P-03 — Identity in bundle complies with §2.3.4 (fixture-scoped; not a duplicate §2.3 proof).
pub fn assert_identity_compliance() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let identities: Vec<_> = objects
        .iter()
        .filter(|obj| obj.get("type").and_then(Value::as_str) == Some("identity"))
        .collect();
    assert_eq!(identities.len(), 1, "{relative}: expected one Identity");
    assert_identity_shape(relative, identities[0]);
}

/// REQ-3.1-P-04 — Attack Pattern conforms to STIX §4.1 (typed validate + strict report).
///
/// Distinct from P-01: does **not** call the interop gate/overlay. Parses the fixture,
/// runs [`AttackPattern::validate`], then requires [`Validator::interop_bundle_strict`]
/// to report valid under Zero leniency (no MUST Error / Zero-failing Warning), including
/// any diagnostic scoped to this Attack Pattern id.
pub fn assert_spec_conformance() {
    let relative = FIXTURE_CREATE;
    let fixture = load_fixture(relative);
    let bundle = Bundle::parse_with_options(&fixture.json, &ParseOptions::new().interop_bundle())
        .unwrap_or_else(|err| panic!("{relative}: parse for §4.1 check: {err}"));

    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture objects");
    let use_case_ids = use_case_object_ids(relative, &objects);
    assert_eq!(
        use_case_ids.len(),
        1,
        "{relative}: expected one attack-pattern use-case id"
    );
    let object_id = &use_case_ids[0];
    let ap_id = StixId::parse(object_id).expect("attack-pattern id");
    let ap = bundle
        .get_typed::<AttackPattern>(&ap_id)
        .unwrap_or_else(|| panic!("{relative}: typed attack-pattern {object_id}"));
    ap.validate()
        .unwrap_or_else(|err| panic!("{relative}: AttackPattern::validate (§4.1): {err}"));

    let report = Validator::interop_bundle_strict().validate_bundle(&bundle);

    // Non-vacuous MUST channel: Error diagnostics fail regardless of object_id attachment.
    let errors: Vec<_> = report.errors().collect();
    assert!(
        errors.is_empty(),
        "{relative}: MUST Error diagnostics present: {errors:?}"
    );

    // Scoped Zero failures only via structured `object_id` (no Display/message matching).
    let scoped_zero_failures: Vec<_> = report
        .diagnostics()
        .filter(|d| {
            d.object_id.as_ref() == Some(&ap_id) && Leniency::Zero.fails_validation(d.severity)
        })
        .collect();
    assert!(
        scoped_zero_failures.is_empty(),
        "{relative}: Zero-failing diagnostics on Attack Pattern {object_id}: {scoped_zero_failures:?}"
    );

    assert!(
        report.is_valid(),
        "{relative}: interop_bundle_strict (no overlay) must be valid: {:?}",
        report.diagnostics().collect::<Vec<_>>()
    );
}

/// REQ-3.1-P-05 — wire `type` is `attack-pattern` (typed lookup is supporting evidence).
pub fn assert_prop_type() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let (_ap, object_id) = load_attack_pattern(FIXTURE_CREATE);
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .expect("wire attack-pattern");
    assert_eq!(
        wire.get("type").and_then(Value::as_str),
        Some("attack-pattern"),
        "wire type must be attack-pattern"
    );
}

/// REQ-3.1-P-06 — `spec_version` is `2.1`.
pub fn assert_prop_spec_version() {
    let (ap, _) = load_attack_pattern(FIXTURE_CREATE);
    assert_eq!(ap.common.spec_version, SpecVersion::V2_1);
}

/// REQ-3.1-P-07 — `id` is a UUID with `attack-pattern--` prefix.
pub fn assert_prop_id() {
    let (_, object_id) = load_attack_pattern(FIXTURE_CREATE);
    assert!(
        object_id.starts_with("attack-pattern--"),
        "id must use attack-pattern-- prefix: {object_id}"
    );
    assert!(
        StixId::parse(&object_id).is_ok(),
        "id must be valid STIX id"
    );
}

/// REQ-3.1-P-08 — `created_by_ref` points at the Producer Identity.
pub fn assert_prop_created_by_ref() {
    let (ap, _) = load_attack_pattern(FIXTURE_CREATE);
    let created_by = ap
        .common
        .created_by_ref
        .as_ref()
        .expect("interop-mandatory created_by_ref");
    assert!(
        created_by.as_stix_id().as_str().starts_with("identity--"),
        "created_by_ref must reference Identity: {}",
        created_by.as_stix_id().as_str()
    );
}

/// REQ-3.1-P-09 — `external_references` is present and non-empty.
pub fn assert_prop_external_references() {
    let (ap, _) = load_attack_pattern(FIXTURE_CREATE);
    assert!(
        !ap.common.external_references.is_empty(),
        "interop-mandatory external_references"
    );
}

/// REQ-3.1-P-10 — `kill_chain_phases` is present and non-empty.
pub fn assert_prop_kill_chain_phases() {
    let (ap, _) = load_attack_pattern(FIXTURE_CREATE);
    assert!(
        !ap.kill_chain_phases.is_empty(),
        "interop-mandatory kill_chain_phases"
    );
}

/// REQ-3.1-P-11 — `created` timestamp is present (exactly three subsecond digits).
pub fn assert_prop_created() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let (_, object_id) = load_attack_pattern(FIXTURE_CREATE);
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .expect("wire attack-pattern");
    let created = wire
        .get("created")
        .and_then(Value::as_str)
        .expect("created timestamp");
    assert_millisecond_rfc3339("created", created);
}

/// REQ-3.1-P-12 — `modified` timestamp is present (exactly three subsecond digits).
pub fn assert_prop_modified() {
    let fixture = load_fixture(FIXTURE_CREATE);
    let objects = parse_fixture_objects(&fixture.json).expect("parse fixture");
    let (_, object_id) = load_attack_pattern(FIXTURE_CREATE);
    let wire = objects
        .iter()
        .find(|obj| obj.get("id").and_then(Value::as_str) == Some(object_id.as_str()))
        .expect("wire attack-pattern");
    let modified = wire
        .get("modified")
        .and_then(Value::as_str)
        .expect("modified timestamp");
    assert_millisecond_rfc3339("modified", modified);
}

/// REQ-3.1-P-13 — `name` identifies the Attack Pattern.
pub fn assert_prop_name() {
    let (ap, _) = load_attack_pattern(FIXTURE_CREATE);
    assert!(!ap.name.is_empty(), "interop-mandatory name");
}

/// REQ-CHK-SXP-3.1 / §4.2 Table 56 — Producer test case data (§3.1.3.1 and §3.1.3.2).
pub fn assert_producer_testcase_data() {
    for relative in PRODUCER_FIXTURES {
        validate_interop_fixture(relative, &load_fixture(relative).json).unwrap_or_else(|err| {
            panic!("{relative}: §3.1.3 producer test case must pass interop gate: {err}")
        });
    }
}

interop_test!(
    "REQ-3.1-P-01",
    "use_cases::attack_pattern::producer::create_attack_pattern",
    create_attack_pattern,
    {
        assert_create_attack_pattern();
    }
);

interop_test!(
    "REQ-3.1-P-02",
    "use_cases::attack_pattern::producer::select_content",
    select_content,
    {
        assert_select_content();
    }
);

interop_test!(
    "REQ-3.1-P-03",
    "use_cases::attack_pattern::producer::identity_compliance",
    identity_compliance,
    {
        assert_identity_compliance();
    }
);

interop_test!(
    "REQ-3.1-P-04",
    "use_cases::attack_pattern::producer::spec_conformance",
    spec_conformance,
    {
        assert_spec_conformance();
    }
);

interop_test!(
    "REQ-3.1-P-05",
    "use_cases::attack_pattern::producer::prop_type",
    prop_type,
    {
        assert_prop_type();
    }
);

interop_test!(
    "REQ-3.1-P-06",
    "use_cases::attack_pattern::producer::prop_spec_version",
    prop_spec_version,
    {
        assert_prop_spec_version();
    }
);

interop_test!(
    "REQ-3.1-P-07",
    "use_cases::attack_pattern::producer::prop_id",
    prop_id,
    {
        assert_prop_id();
    }
);

interop_test!(
    "REQ-3.1-P-08",
    "use_cases::attack_pattern::producer::prop_created_by_ref",
    prop_created_by_ref,
    {
        assert_prop_created_by_ref();
    }
);

interop_test!(
    "REQ-3.1-P-09",
    "use_cases::attack_pattern::producer::prop_external_references",
    prop_external_references,
    {
        assert_prop_external_references();
    }
);

interop_test!(
    "REQ-3.1-P-10",
    "use_cases::attack_pattern::producer::prop_kill_chain_phases",
    prop_kill_chain_phases,
    {
        assert_prop_kill_chain_phases();
    }
);

interop_test!(
    "REQ-3.1-P-11",
    "use_cases::attack_pattern::producer::prop_created",
    prop_created,
    {
        assert_prop_created();
    }
);

interop_test!(
    "REQ-3.1-P-12",
    "use_cases::attack_pattern::producer::prop_modified",
    prop_modified,
    {
        assert_prop_modified();
    }
);

interop_test!(
    "REQ-3.1-P-13",
    "use_cases::attack_pattern::producer::prop_name",
    prop_name,
    {
        assert_prop_name();
    }
);

interop_test!(
    "REQ-CHK-SXP-3.1",
    "use_cases::attack_pattern::producer::producer_testcase_data",
    producer_testcase_data,
    {
        assert_producer_testcase_data();
    }
);
