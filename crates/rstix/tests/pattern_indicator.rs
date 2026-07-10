//! Indicator STIX pattern AST wiring (`pattern` + `serde` features).

use rstix::Pattern;
use rstix::model::sdo::{Indicator, IndicatorPattern};

#[test]
fn indicator_deserialize_parses_stix_pattern() {
    let json = include_str!("fixtures/spec/sdo/indicator-minimal.json");
    let indicator: Indicator = serde_json::from_str(json).expect("deserialize");
    match &indicator.pattern {
        IndicatorPattern::Stix { raw, parsed, .. } => {
            assert!(raw.contains("file:hashes"));
            assert!(
                parsed
                    .ast()
                    .semantic_eq(Pattern::parse(raw.trim()).expect("parse raw").ast())
            );
        }
        IndicatorPattern::Other { .. } => panic!("expected STIX pattern"),
    }
}

#[test]
fn indicator_deserialize_rejects_invalid_stix_pattern() {
    let json = include_str!("fixtures/spec/sdo/indicator-minimal.json");
    let mut value: serde_json::Value = serde_json::from_str(json).expect("json");
    value["pattern"] = serde_json::Value::String("[not-a-valid-pattern".into());
    let err = serde_json::from_value::<Indicator>(value).unwrap_err();
    assert!(err.to_string().contains("parse error") || err.to_string().contains("ParseError"));
}

#[test]
fn indicator_other_pattern_evaluates_as_non_stix() {
    let json = r#"{
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
      "created": "2016-04-06T20:03:48.000Z",
      "modified": "2016-04-06T20:03:48.000Z",
      "pattern": "rule test { condition: true }",
      "pattern_type": "yara",
      "valid_from": "2016-01-01T00:00:00Z"
    }"#;
    let indicator: Indicator = serde_json::from_str(json).expect("deserialize");
    let err = indicator.pattern.parsed_pattern().unwrap_err();
    assert!(matches!(
        err,
        rstix::PatternMatchError::NonStixPattern(ref kind) if kind == "yara"
    ));
}

#[test]
fn indicator_round_trip_preserves_raw_pattern_string() {
    let json = include_str!("fixtures/spec/sdo/indicator-minimal.json");
    let indicator: Indicator = serde_json::from_str(json).expect("deserialize");
    let raw_before = indicator.pattern.raw().to_owned();
    let serialized = serde_json::to_string(&indicator).expect("serialize");
    let restored: Indicator = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(restored.pattern.raw(), raw_before.as_str());
}
