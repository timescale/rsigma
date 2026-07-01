//! Integration tests for STIX bundle parsing.

#![cfg(feature = "serde")]

#[path = "support/fixtures_spec.rs"]
mod fixtures;

use fixtures::load_spec_fixture;
use rstix::core::{QueryableStixObject, StixId};
use rstix::model::sdo::AttackPattern;
use rstix::model::{Bundle, StixObject};
use rstix::{ParseError, parse_bundle};

#[test]
fn bundle_minimal_parses_three_objects() {
    let raw = load_spec_fixture("bundle/bundle-minimal.json");
    let bundle = parse_bundle(&raw).expect("parse bundle");
    assert_eq!(bundle.objects().len(), 3);

    let attack_id = StixId::parse("attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061").unwrap();
    let attack = bundle.get(&attack_id).expect("attack-pattern present");
    assert!(matches!(attack, StixObject::Sdo(_)));
    assert_eq!(
        QueryableStixObject::type_name(attack),
        AttackPattern::TYPE_NAME
    );

    let extra = bundle
        .extra_properties(&attack_id)
        .expect("x_* properties captured");
    assert_eq!(
        extra.get("x_custom_prop"),
        Some(&serde_json::Value::String("preserved".into()))
    );
}

#[test]
fn bundle_with_relationship_refs_validates() {
    let raw = load_spec_fixture("bundle/bundle-with-relationship-refs.json");
    let bundle = Bundle::parse(&raw).expect("parse bundle");
    assert_eq!(bundle.objects().len(), 3);
    bundle.validate_refs().expect("refs resolve");
}

#[test]
fn bundle_missing_ref_rejects() {
    let raw = load_spec_fixture("bundle/bundle-missing-ref.json");
    let err = parse_bundle(&raw).unwrap_err();
    assert!(matches!(
        err,
        ParseError::Model(rstix::model::ModelError::BundleReferenceMissing { .. })
    ));
}

#[test]
fn bundle_serializes_without_empty_objects_key() {
    let raw = load_spec_fixture("bundle/bundle-minimal.json");
    let bundle = parse_bundle(&raw).expect("parse bundle");
    let value = serde_json::to_value(&bundle).expect("serialize");
    assert!(value.get("objects").is_some());

    let empty =
        Bundle::parse(r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000000"}"#)
            .expect("empty bundle");
    let empty_value = serde_json::to_value(&empty).expect("serialize empty");
    assert!(empty_value.get("objects").is_none());
}

#[test]
fn parse_with_options_enforces_max_bundle_bytes() {
    let mut opts = rstix::ParseOptions::new();
    opts.max_bundle_bytes = 10;
    let json =
        r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000001","objects":[]}"#;
    assert!(json.len() > opts.max_bundle_bytes);
    let err = Bundle::parse_with_options(json, &opts).unwrap_err();
    assert!(matches!(
        err,
        ParseError::BundleByteLimitExceeded { max: 10 }
    ));
}

#[test]
fn sco_uuid4_with_contributing_properties_parses() {
    let raw = r#"{
      "type": "bundle",
      "id": "bundle--00000000-0000-0000-0000-000000000001",
      "objects": [{
        "type": "file",
        "spec_version": "2.1",
        "id": "file--00000000-0000-4000-8000-000000000001",
        "name": "cmd.exe"
      }]
    }"#;
    parse_bundle(raw).expect("spec-legal uuid4 sco with name should parse");
}

#[test]
fn toplevel_property_extension_round_trips_via_extra_properties() {
    let raw = r#"{
      "type": "bundle",
      "id": "bundle--00000000-0000-0000-0000-000000000001",
      "objects": [{
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "name": "John Smith",
        "extensions": {
          "extension-definition--11111111-1111-1111-1111-111111111111": {
            "extension_type": "toplevel-property-extension",
            "vendor_sector": "finance"
          }
        }
      }]
    }"#;
    let bundle = parse_bundle(raw).expect("parse");
    let id = StixId::parse("identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e").unwrap();
    let extra = bundle
        .extra_properties(&id)
        .expect("hoisted extension props captured");
    assert_eq!(
        extra.get("vendor_sector"),
        Some(&serde_json::Value::String("finance".into()))
    );

    let serialized = serde_json::to_string(&bundle).expect("serialize");
    let reparsed = parse_bundle(&serialized).expect("reparse");
    let extra_after = reparsed
        .extra_properties(&id)
        .expect("hoisted props survive round-trip");
    assert_eq!(
        extra_after.get("vendor_sector"),
        Some(&serde_json::Value::String("finance".into()))
    );
}
