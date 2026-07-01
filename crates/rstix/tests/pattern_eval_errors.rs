//! Integration tests for every [`PatternMatchError`] variant.

use rstix::Pattern;
use rstix::core::StixId;
use rstix::model::Bundle;
use rstix::model::sdo::ObservedData;
use rstix::pattern::{
    MATCHES_REGEX_SIZE_LIMIT, ObservationContext, PatternMatchError, TimestampedObservation,
    compile_matches_regex, test_pattern_match_error_non_stix_pattern,
    test_pattern_match_error_unsupported_operator_like,
};

#[path = "support/error_catalog.rs"]
mod error_catalog;
#[path = "support/sco_json.rs"]
mod sco_json;

use error_catalog::ALL as ERROR_CATALOG;
use sco_json::parse_sco_json;

#[test]
fn error_catalog_variants_are_constructible() {
    for case in ERROR_CATALOG {
        let err = (case.make_error)();
        assert!(!format!("{err}").is_empty(), "case `{}`", case.id);
    }
}

#[test]
fn missing_timestamp_empty_context_with_followed_by() {
    let pattern = Pattern::parse(
        "[ipv4-addr:value = '198.51.100.1/32'] FOLLOWEDBY [domain-name:value = 'example.com']",
    )
    .expect("pattern");
    let ctx = ObservationContext {
        observations: &[],
        bundle: None,
    };
    assert_eq!(
        pattern.evaluate(&ctx),
        Err(PatternMatchError::MissingTimestamp)
    );
}

#[test]
fn missing_timestamp_within_without_at() {
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let observations = [TimestampedObservation {
        sco: &ipv4,
        at: None,
    }];
    let ctx = ObservationContext {
        observations: &observations,
        bundle: None,
    };
    let pattern =
        Pattern::parse("[ipv4-addr:value = '198.51.100.3'] WITHIN 300 SECONDS").expect("pattern");
    assert_eq!(
        pattern.evaluate(&ctx),
        Err(PatternMatchError::MissingTimestamp)
    );
}

#[test]
fn missing_timestamp_repeats_without_at() {
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let observations = [TimestampedObservation {
        sco: &ipv4,
        at: None,
    }];
    let ctx = ObservationContext {
        observations: &observations,
        bundle: None,
    };
    let pattern =
        Pattern::parse("[ipv4-addr:value = '198.51.100.3'] REPEATS 2 TIMES").expect("pattern");
    assert_eq!(
        pattern.evaluate(&ctx),
        Err(PatternMatchError::MissingTimestamp)
    );
}

#[test]
fn missing_timestamp_start_stop_without_at() {
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let observations = [TimestampedObservation {
        sco: &ipv4,
        at: None,
    }];
    let ctx = ObservationContext {
        observations: &observations,
        bundle: None,
    };
    let pattern = Pattern::parse(
        "[ipv4-addr:value = '198.51.100.3'] START t'2020-01-01T00:00:00.000Z' STOP t'2020-01-01T01:00:00.000Z'",
    )
    .expect("pattern");
    assert_eq!(
        pattern.evaluate(&ctx),
        Err(PatternMatchError::MissingTimestamp)
    );
}

#[test]
fn missing_timestamp_and_with_nested_within_without_at() {
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let domain = parse_sco_json(include_str!("fixtures/spec/sco/domain-name-basic.json"));
    let observations = [
        TimestampedObservation {
            sco: &ipv4,
            at: None,
        },
        TimestampedObservation {
            sco: &domain,
            at: None,
        },
    ];
    let ctx = ObservationContext {
        observations: &observations,
        bundle: None,
    };
    let pattern = Pattern::parse(
        "[ipv4-addr:value = '198.51.100.3'] AND ([domain-name:value = 'example.com'] WITHIN 300 SECONDS)",
    )
    .expect("pattern");
    assert_eq!(
        pattern.evaluate(&ctx),
        Err(PatternMatchError::MissingTimestamp)
    );
}

#[test]
fn not_single_observation_and() {
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let pattern = Pattern::parse(
        "[ipv4-addr:value = '198.51.100.3'] AND [domain-name:value = 'example.com']",
    )
    .expect("pattern");
    assert_eq!(
        pattern.matches_single(&ipv4),
        Err(PatternMatchError::NotSingleObservation)
    );
}

#[test]
fn not_single_observation_followed_by() {
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let pattern = Pattern::parse(
        "[ipv4-addr:value = '198.51.100.3'] FOLLOWEDBY [domain-name:value = 'example.com']",
    )
    .expect("pattern");
    assert_eq!(
        pattern.matches_single(&ipv4),
        Err(PatternMatchError::NotSingleObservation)
    );
}

#[test]
fn not_single_observation_within() {
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let pattern =
        Pattern::parse("[ipv4-addr:value = '198.51.100.3'] WITHIN 300 SECONDS").expect("pattern");
    assert_eq!(
        pattern.matches_single(&ipv4),
        Err(PatternMatchError::NotSingleObservation)
    );
}

#[test]
fn not_single_observation_repeats() {
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let pattern =
        Pattern::parse("[ipv4-addr:value = '198.51.100.3'] REPEATS 2 TIMES").expect("pattern");
    assert_eq!(
        pattern.matches_single(&ipv4),
        Err(PatternMatchError::NotSingleObservation)
    );
}

#[test]
fn not_single_observation_start_stop() {
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let pattern = Pattern::parse(
        "[ipv4-addr:value = '198.51.100.3'] START t'2020-01-01T00:00:00.000Z' STOP t'2020-01-01T01:00:00.000Z'",
    )
    .expect("pattern");
    assert_eq!(
        pattern.matches_single(&ipv4),
        Err(PatternMatchError::NotSingleObservation)
    );
}

#[test]
fn ref_resolution_bundle_required() {
    let process = parse_sco_json(include_str!("fixtures/spec/sco/process-basic.json"));
    let pattern = Pattern::parse("[process:image_ref.name = 'proc.exe']").expect("pattern");
    assert_eq!(
        pattern.matches_single_with_bundle(&process, None),
        Err(PatternMatchError::RefResolution {
            path: "process:image_ref._ref.name".into(),
            msg: "bundle required for _ref dereference".into(),
        })
    );
}

#[test]
fn ref_resolution_object_not_found() {
    let process = parse_sco_json(include_str!("fixtures/spec/sco/process-basic.json"));
    let bundle = Bundle::parse(
        r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000001","objects":[]}"#,
    )
    .expect("bundle");
    let pattern = Pattern::parse("[process:image_ref.name = 'proc.exe']").expect("pattern");
    let err = pattern
        .matches_single_with_bundle(&process, Some(&bundle))
        .unwrap_err();
    assert!(matches!(err, PatternMatchError::RefResolution { .. }));
    assert!(err.to_string().contains("not found in bundle"));
}

#[test]
fn ref_resolution_not_sco() {
    let case = ERROR_CATALOG
        .iter()
        .find(|c| c.id == "ref-resolution-not-sco")
        .expect("catalog entry");
    let err = (case.make_error)();
    assert!(matches!(err, PatternMatchError::RefResolution { .. }));
    assert!(err.to_string().contains("is not an SCO"));
}

#[test]
fn ref_resolution_property_absent() {
    let process = parse_sco_json(
        r#"{
          "type": "process",
          "spec_version": "2.1",
          "id": "process--00000000-0000-0000-0000-000000000001",
          "pid": 1
        }"#,
    );
    let bundle = Bundle::parse(
        r#"{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000003","objects":[]}"#,
    )
    .expect("bundle");
    let pattern = Pattern::parse("[process:image_ref.name = 'proc.exe']").expect("pattern");
    let err = pattern
        .matches_single_with_bundle(&process, Some(&bundle))
        .unwrap_err();
    assert!(matches!(err, PatternMatchError::RefResolution { .. }));
    assert!(err.to_string().contains("absent or not a reference"));
}

#[test]
fn regex_compile_invalid() {
    assert!(matches!(
        compile_matches_regex("[invalid"),
        Err(PatternMatchError::RegexCompile { .. })
    ));
}

#[test]
fn regex_compile_oversized() {
    let huge = format!("(a){{{MATCHES_REGEX_SIZE_LIMIT}}}");
    assert!(matches!(
        compile_matches_regex(&huge),
        Err(PatternMatchError::RegexCompile { .. })
    ));
}

#[test]
fn unsupported_operator_test_hook() {
    let err = test_pattern_match_error_unsupported_operator_like();
    assert!(err.to_string().contains("not supported at evaluation time"));
}

#[test]
fn non_stix_pattern_test_hook() {
    let err = test_pattern_match_error_non_stix_pattern("yara");
    assert!(
        err.to_string()
            .contains("cannot be evaluated by the STIX evaluator")
    );
}

#[test]
fn ref_resolution_observed_data_missing_object_catalog() {
    let case = ERROR_CATALOG
        .iter()
        .find(|c| c.id == "observed-data-missing-object")
        .expect("catalog entry");
    let err = (case.make_error)();
    assert_eq!(
        err,
        PatternMatchError::RefResolution {
            path: "observed-data.object_refs".into(),
            msg: "missing object `ipv4-addr--00000000-0000-0000-0000-000000009999`".into(),
        }
    );
}

#[test]
fn ref_resolution_observed_data_not_sco() {
    let bundle = Bundle::parse(
        r#"{
          "type": "bundle",
          "id": "bundle--00000000-0000-0000-0000-000000000011",
          "objects": [
            {
              "type": "identity",
              "spec_version": "2.1",
              "id": "identity--00000000-0000-0000-0000-000000000001",
              "created": "2024-01-01T00:00:00.000Z",
              "modified": "2024-01-01T00:00:00.000Z",
              "name": "Alice"
            },
            {
              "type": "identity",
              "spec_version": "2.1",
              "id": "identity--00000000-0000-0000-0000-000000000002",
              "created": "2024-01-01T00:00:00.000Z",
              "modified": "2024-01-01T00:00:00.000Z",
              "name": "Bob"
            },
            {
              "type": "relationship",
              "spec_version": "2.1",
              "id": "relationship--00000000-0000-0000-0000-000000000001",
              "created": "2024-01-01T00:00:00.000Z",
              "modified": "2024-01-01T00:00:00.000Z",
              "relationship_type": "related-to",
              "source_ref": "identity--00000000-0000-0000-0000-000000000001",
              "target_ref": "identity--00000000-0000-0000-0000-000000000002"
            },
            {
              "type": "observed-data",
              "spec_version": "2.1",
              "id": "observed-data--00000000-0000-0000-0000-000000000011",
              "created": "2024-01-01T00:00:00.000Z",
              "modified": "2024-01-01T00:00:00.000Z",
              "first_observed": "2024-01-01T00:00:00.000Z",
              "last_observed": "2024-01-01T00:00:00.000Z",
              "number_observed": 1,
              "object_refs": ["relationship--00000000-0000-0000-0000-000000000001"]
            }
          ]
        }"#,
    )
    .expect("bundle");
    let id = StixId::parse("observed-data--00000000-0000-0000-0000-000000000011").expect("id");
    let observed: &ObservedData = bundle.get_typed(&id).expect("observed-data");
    let pattern = Pattern::parse("[ipv4-addr:value = '203.0.113.4']").expect("pattern");
    assert_eq!(
        pattern.evaluate_observed_data(observed, &bundle),
        Err(PatternMatchError::RefResolution {
            path: "observed-data.object_refs".into(),
            msg: "object `relationship--00000000-0000-0000-0000-000000000001` has type `relationship`, expected an SCO".into(),
        })
    );
}

#[test]
fn ref_resolution_observed_data_embedded_sro_catalog() {
    let case = ERROR_CATALOG
        .iter()
        .find(|c| c.id == "observed-data-embedded-sro")
        .expect("catalog entry");
    let err = (case.make_error)();
    assert_eq!(
        err,
        PatternMatchError::RefResolution {
            path: "observed-data.objects".into(),
            msg: "embedded SRO objects are not supported".into(),
        }
    );
}
