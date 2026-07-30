//! §3.1.4 Producer Example Data (non-gating).

use rstix::ParseError;
use rstix::core::{StixId, StixIdError};
use rstix::model::{Bundle, ParseOptions};
use serde_json::Value;

use crate::harness::fixture::load_fixture;
use crate::harness::interop_gate::{InteropGateOptions, validate_interop_json};
use crate::interop_test;

/// OASIS §3.1.4.1 non-normative example.
pub const EXAMPLE_CONTEXT: &str =
    "examples/attack-pattern/ex-3.1.4.1-add-context-to-indicator.json";
/// OASIS §3.1.4.2 non-normative example (published truncated UUID ids).
pub const EXAMPLE_FRAMEWORK: &str =
    "examples/attack-pattern/ex-3.1.4.2-leverage-externally-defined-frameworks.json";

/// Published truncated malware id from provenance `objects[1].id` (defect 21).
const TRUNCATED_MALWARE_ID: &str = "malware--1121ffbc-364f-857a-9987-92fbcff24ab";
/// Published truncated relationship id from provenance `objects[2].id` (defect 21).
const TRUNCATED_RELATIONSHIP_ID: &str = "relationship--11220001-3940-0405-20ff-1029b0bc922";

/// REQ-3.1-EX-4.1 — §3.1.4.1 loads and passes the interop gate (examples are non-gating).
pub fn assert_add_context_to_indicator() {
    let fixture = load_fixture(EXAMPLE_CONTEXT);
    assert_eq!(fixture.provenance.source_section, "3.1.4.1");
    // Empty use-case ids: example is not a §3.1.3 normative Producer test case.
    validate_interop_json(&fixture.json, &InteropGateOptions::default())
        .expect("§3.1.4.1 example must parse and pass interop gate");
}

/// REQ-3.1-EX-4.2 — §3.1.4.2 retains published truncated UUID ids; parse must reject them.
///
/// Structured proof only:
/// - both published truncated ids are [`StixIdError::InvalidUuid`];
/// - wire `objects[1].id` / `objects[2].id` stay the published truncated values;
/// - bundle parse fails as [`ParseError::InvalidStixId`] equal to the malware id's parse
///   error (bundle walks identity then malware, so the first id failure is objects[1]).
pub fn assert_framework_example_rejects_truncated_ids() {
    let fixture = load_fixture(EXAMPLE_FRAMEWORK);
    assert_eq!(fixture.provenance.source_section, "3.1.4.2");
    assert!(
        fixture
            .provenance
            .divergence_recorded
            .iter()
            .any(|d| d.defect == 21 && d.site == "objects[1].id"),
        "expected defect 21 on objects[1].id"
    );

    let root: Value = serde_json::from_str(&fixture.json).expect("example JSON");
    let objects = root
        .get("objects")
        .and_then(Value::as_array)
        .expect("objects array");
    let wire_malware_id = objects
        .get(1)
        .and_then(|obj| obj.get("id"))
        .and_then(Value::as_str)
        .expect("objects[1].id");
    assert_eq!(
        wire_malware_id, TRUNCATED_MALWARE_ID,
        "objects[1].id must remain the published truncated malware id"
    );
    let wire_relationship_id = objects
        .get(2)
        .and_then(|obj| obj.get("id"))
        .and_then(Value::as_str)
        .expect("objects[2].id");
    assert_eq!(
        wire_relationship_id, TRUNCATED_RELATIONSHIP_ID,
        "objects[2].id must remain the published truncated relationship id"
    );

    let malware_err = match StixId::parse(TRUNCATED_MALWARE_ID) {
        Err(err @ StixIdError::InvalidUuid(_)) => err,
        other => panic!("truncated malware id must be InvalidUuid, got {other:?}"),
    };
    let relationship_err = match StixId::parse(TRUNCATED_RELATIONSHIP_ID) {
        Err(err @ StixIdError::InvalidUuid(_)) => err,
        other => panic!("truncated relationship id must be InvalidUuid, got {other:?}"),
    };
    match (&malware_err, &relationship_err) {
        (StixIdError::InvalidUuid(_), StixIdError::InvalidUuid(_)) => {}
        _ => unreachable!(),
    }

    let err = Bundle::parse_with_options(&fixture.json, &ParseOptions::new().interop_bundle())
        .expect_err("§3.1.4.2 truncated UUID ids must fail parse");
    match err {
        ParseError::InvalidStixId(got) => {
            assert_eq!(
                got, malware_err,
                "bundle must fail on objects[1] malware id (first truncated id in walk order)"
            );
        }
        other => panic!("expected ParseError::InvalidStixId(...), got: {other:?}"),
    }
}

interop_test!(
    "REQ-3.1-EX-4.1",
    "use_cases::attack_pattern::examples::add_context_to_indicator",
    add_context_to_indicator,
    {
        assert_add_context_to_indicator();
    }
);

interop_test!(
    "REQ-3.1-EX-4.2",
    "use_cases::attack_pattern::examples::framework_example_rejects_truncated_ids",
    framework_example_rejects_truncated_ids,
    {
        assert_framework_example_rejects_truncated_ids();
    }
);
