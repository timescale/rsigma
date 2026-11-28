//! Security and spec-semantics tests from PR #276 review (LIKE DoS, exact `=`, observation cap).

#![cfg(all(feature = "pattern", feature = "serde"))]

#[path = "support/sco_json.rs"]
mod sco_json;

use std::time::{Duration, Instant};

use rstix::Pattern;
use rstix::core::StixTimestamp;
use rstix::pattern::{
    MAX_OBSERVATIONS, ObservationContext, PatternMatchError, TimestampedObservation,
};
use sco_json::parse_sco_json;

/// PR #276: recursive `%` backtracking in LIKE was exponential; must stay linear-time.
#[test]
fn like_pathological_percent_pattern_completes_in_bounded_time() {
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let percent_run = "%".repeat(32);
    let pattern = format!("[ipv4-addr:value LIKE '{percent_run}198.51.100.3']");
    let parsed = Pattern::parse(&pattern).expect("parse LIKE pattern");

    let start = Instant::now();
    let matched = parsed.matches_single(&ipv4).expect("eval");
    let elapsed = start.elapsed();

    assert!(matched);
    assert!(
        elapsed < Duration::from_secs(1),
        "LIKE with {percent_run} took {elapsed:?}; expected O(n·m) matcher"
    );
}

/// PR #276: STIX §9.6 `=` is exact string equality; subnet containment is ISSUBSET only.
#[test]
fn equality_operator_does_not_match_cidr_containment() {
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let pattern = Pattern::parse("[ipv4-addr:value = '10.0.0.0/8']").expect("parse");
    assert!(
        !pattern.matches_single(&ipv4).expect("eval"),
        "=` must not treat CIDR strings as containment ranges"
    );

    let pattern = Pattern::parse("[ipv4-addr:value = '198.51.100.3']").expect("parse");
    assert!(pattern.matches_single(&ipv4).expect("eval"));
}

/// PR #276: CIDR host-in-network checks belong on ISSUBSET, not `=`.
#[test]
fn issubset_matches_host_in_prefix() {
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let pattern = Pattern::parse("[ipv4-addr:value ISSUBSET '198.51.100.0/24']").expect("parse");
    assert!(pattern.matches_single(&ipv4).expect("eval"));
}

/// PR #276: evaluation context must not exceed the pattern-side observation cap.
#[test]
fn too_many_observations_in_context_is_rejected() {
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let ts = StixTimestamp::parse("2024-01-01T00:00:00.000Z").expect("ts");
    let mut observations = Vec::with_capacity(MAX_OBSERVATIONS + 1);
    for _ in 0..=MAX_OBSERVATIONS {
        observations.push(TimestampedObservation {
            sco: &ipv4,
            at: Some(ts.clone()),
        });
    }
    let ctx = ObservationContext::from_scos(&observations);
    let pattern =
        Pattern::parse("[ipv4-addr:value = '198.51.100.3'] WITHIN 5 MINUTES").expect("parse");
    assert_eq!(
        pattern.evaluate(&ctx),
        Err(PatternMatchError::TooManyObservations {
            count: MAX_OBSERVATIONS + 1,
            max: MAX_OBSERVATIONS,
        })
    );
}

/// STIX §9.6.1: LIKE constant is NFC-normalized before wildcard comparison.
#[test]
fn like_nfc_normalizes_pattern_constant() {
    let composed = "\u{00F2}z";
    let decomposed = "o\u{0300}z";
    let mutex_json = format!(
        r#"{{
          "type": "mutex",
          "spec_version": "2.1",
          "id": "mutex--00000000-0000-0000-0000-000000000601",
          "name": "{composed}example"
        }}"#
    );
    let mutex = parse_sco_json(&mutex_json);
    let pattern = Pattern::parse(&format!("[mutex:name LIKE '{decomposed}%']")).expect("parse");
    assert!(pattern.matches_single(&mutex).expect("eval"));
}

/// STIX §9.6.1: MATCHES NFC-normalizes string properties before regex search.
#[test]
fn matches_nfc_normalizes_haystack() {
    let composed = "caf\u{00E9}";
    let decomposed = "cafe\u{0301}";
    let mutex_json = format!(
        r#"{{
          "type": "mutex",
          "spec_version": "2.1",
          "id": "mutex--00000000-0000-0000-0000-000000000602",
          "name": "{decomposed}"
        }}"#
    );
    let mutex = parse_sco_json(&mutex_json);
    let pattern = Pattern::parse(&format!("[mutex:name MATCHES '^{composed}$']")).expect("parse");
    assert!(pattern.matches_single(&mutex).expect("eval"));
}

/// STIX §9.6.1 MATCHES: DOTALL (`.` matches newlines) via PCRE semantics.
#[test]
fn matches_dotall_allows_dot_across_newline() {
    let mutex_json = r#"{
      "type": "mutex",
      "spec_version": "2.1",
      "id": "mutex--00000000-0000-0000-0000-000000000603",
      "name": "line1\nline2"
    }"#;
    let mutex = parse_sco_json(mutex_json);
    let pattern = Pattern::parse("[mutex:name MATCHES 'line1.line2']").expect("parse");
    assert!(pattern.matches_single(&mutex).expect("eval"));
}

/// STIX §9.5: AND inside one observation must match the same network-traffic SCO.
#[test]
fn observation_and_requires_same_sco_for_ref_paths() {
    use rstix::core::StixId;
    use rstix::model::sco::ScoObject;
    use rstix::model::{Bundle, StixObject};

    fn sco_from_bundle<'a>(bundle: &'a Bundle, id: &str) -> &'a ScoObject {
        let sid = StixId::parse(id).expect("id");
        match bundle.get(&sid).expect("object") {
            StixObject::Sco(sco) => sco,
            other => panic!("expected sco, got {other:?}"),
        }
    }

    let pattern = Pattern::parse(
        "[network-traffic:src_ref.value = '203.0.113.10' AND network-traffic:dst_ref.value = '198.51.100.58']",
    )
    .expect("parse");

    let split_bundle = Bundle::parse(include_str!(
        "fixtures/pattern/eval/spec-9-5-split-refs-bundle.json"
    ))
    .expect("bundle");
    let sco_src = sco_from_bundle(
        &split_bundle,
        "network-traffic--00000000-0000-0000-0000-000000000511",
    );
    let sco_dst = sco_from_bundle(
        &split_bundle,
        "network-traffic--00000000-0000-0000-0000-000000000512",
    );
    assert!(
        !pattern
            .matches_single_with_bundle(sco_src, Some(&split_bundle))
            .expect("eval src-only"),
        "src-only NT must not satisfy AND"
    );
    assert!(
        !pattern
            .matches_single_with_bundle(sco_dst, Some(&split_bundle))
            .expect("eval dst-only"),
        "dst-only NT must not satisfy AND"
    );
    let split_ctx = ObservationContext {
        observations: &[
            TimestampedObservation {
                sco: sco_src,
                at: None,
            },
            TimestampedObservation {
                sco: sco_dst,
                at: None,
            },
        ],
        bundle: Some(&split_bundle),
    };
    assert!(
        !pattern.evaluate(&split_ctx).expect("eval split"),
        "two NT SCOs with split src/dst must not satisfy AND on one observation"
    );

    let both_bundle = Bundle::parse(include_str!(
        "fixtures/pattern/eval/spec-9-5-both-refs-bundle.json"
    ))
    .expect("bundle");
    let sco_both = sco_from_bundle(
        &both_bundle,
        "network-traffic--00000000-0000-0000-0000-000000000513",
    );
    let both_ctx = ObservationContext {
        observations: &[TimestampedObservation {
            sco: sco_both,
            at: None,
        }],
        bundle: Some(&both_bundle),
    };
    assert!(
        pattern
            .matches_single_with_bundle(sco_both, Some(&both_bundle))
            .expect("matches_single both"),
        "Level-1 single-SCO path must match"
    );
    assert!(
        pattern.evaluate(&both_ctx).expect("eval both"),
        "single NT with both refs must match via evaluate"
    );
}

fn directory_id(n: usize) -> String {
    format!("directory--00000000-0000-4000-8000-{n:012x}")
}

/// `count` directories, each listing every directory in `contains_refs`.
fn directory_mesh(count: usize) -> rstix::model::Bundle {
    let refs: Vec<String> = (0..count)
        .map(|n| format!("\"{}\"", directory_id(n)))
        .collect();
    let objects: Vec<String> = (0..count)
        .map(|n| {
            format!(
                r#"{{"type":"directory","spec_version":"2.1","id":"{}","path":"/d{n}","contains_refs":[{}]}}"#,
                directory_id(n),
                refs.join(",")
            )
        })
        .collect();
    rstix::model::Bundle::parse(&format!(
        r#"{{"type":"bundle","id":"bundle--00000000-0000-4000-8000-000000000001","objects":[{}]}}"#,
        objects.join(",")
    ))
    .expect("mesh bundle")
}

/// Every `_refs[*]` step of a chain reaches each directory of the mesh once,
/// so the deepest chain the type-checker allows resolves over a 100-object mesh
/// (100^8 paths without deduplication).
#[test]
fn chained_refs_over_mutually_referencing_scos_resolve() {
    use rstix::model::StixObject;
    use rstix::pattern::MAX_REF_DEREFERENCES;

    let bundle = directory_mesh(100);
    let root_id = rstix::core::StixId::parse(&directory_id(0)).expect("id");
    let Some(StixObject::Sco(root)) = bundle.get(&root_id) else {
        panic!("root directory");
    };
    let chain = ["contains_refs[*]"; MAX_REF_DEREFERENCES].join(".");
    for (value, expected) in [("/d99", true), ("/missing", false)] {
        let pattern =
            Pattern::parse(&format!("[directory:{chain}.path = '{value}']")).expect("parse");
        assert_eq!(
            pattern.matches_single_with_bundle(root, Some(&bundle)),
            Ok(expected),
            "{value}"
        );
    }

    let too_deep = ["contains_refs[*]"; MAX_REF_DEREFERENCES + 1].join(".");
    assert!(matches!(
        Pattern::parse(&format!("[directory:{too_deep}.path = '/d0']")),
        Err(rstix::PatternError::TypeError { .. })
    ));
}

/// A left-deep `AND` of 256 observations whose first never matches evaluates
/// each observation expression once per observation.
#[test]
fn left_deep_and_chain_of_max_observations_evaluates() {
    let mut source = String::from("[ipv4-addr:value = '203.0.113.1']");
    for _ in 1..MAX_OBSERVATIONS {
        source.push_str(" AND [ipv4-addr:value = '198.51.100.3']");
    }
    let pattern = Pattern::parse(&source).expect("parse");
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    for count in [2, MAX_OBSERVATIONS] {
        let observations: Vec<TimestampedObservation<'_>> = (0..count)
            .map(|_| TimestampedObservation {
                sco: &ipv4,
                at: None,
            })
            .collect();
        let ctx = ObservationContext::from_scos(&observations);
        assert_eq!(pattern.evaluate(&ctx), Ok(false), "{count} observations");
    }
}

#[test]
fn dereference_reaching_too_many_objects_is_rejected() {
    use rstix::pattern::MAX_PATH_TARGETS;

    let refs: Vec<String> = (0..=MAX_PATH_TARGETS)
        .map(|n| format!("\"file--00000000-0000-4000-8000-{n:012x}\""))
        .collect();
    let wide = parse_sco_json(&format!(
        r#"{{"type":"directory","spec_version":"2.1","id":"{}","path":"/wide","contains_refs":[{}]}}"#,
        directory_id(0),
        refs.join(",")
    ));
    let bundle = directory_mesh(1);
    let pattern = Pattern::parse("[directory:contains_refs[*].name = 'x']").expect("parse");
    assert_eq!(
        pattern.matches_single_with_bundle(&wide, Some(&bundle)),
        Err(PatternMatchError::PathTooWide {
            path: "directory:contains_refs[*]._ref.name".into(),
            max: MAX_PATH_TARGETS,
        })
    );
}
