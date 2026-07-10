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
    let ipv4_json = format!(
        r#"{{
          "type": "ipv4-addr",
          "spec_version": "2.1",
          "id": "ipv4-addr--00000000-0000-0000-0000-000000000601",
          "value": "{composed}example.com"
        }}"#
    );
    let ipv4 = parse_sco_json(&ipv4_json);
    let pattern =
        Pattern::parse(&format!("[ipv4-addr:value LIKE '{decomposed}%']")).expect("parse");
    assert!(pattern.matches_single(&ipv4).expect("eval"));
}

/// STIX §9.6.1: MATCHES NFC-normalizes string properties before regex search.
#[test]
fn matches_nfc_normalizes_haystack() {
    let composed = "caf\u{00E9}";
    let decomposed = "cafe\u{0301}";
    let ipv4_json = format!(
        r#"{{
          "type": "ipv4-addr",
          "spec_version": "2.1",
          "id": "ipv4-addr--00000000-0000-0000-0000-000000000602",
          "value": "{decomposed}"
        }}"#
    );
    let ipv4 = parse_sco_json(&ipv4_json);
    let pattern =
        Pattern::parse(&format!("[ipv4-addr:value MATCHES '^{composed}$']")).expect("parse");
    assert!(pattern.matches_single(&ipv4).expect("eval"));
}

/// STIX §9.6.1 MATCHES: DOTALL (`.` matches newlines) via PCRE semantics.
#[test]
fn matches_dotall_allows_dot_across_newline() {
    let ipv4_json = r#"{
      "type": "ipv4-addr",
      "spec_version": "2.1",
      "id": "ipv4-addr--00000000-0000-0000-0000-000000000603",
      "value": "line1\nline2"
    }"#;
    let ipv4 = parse_sco_json(ipv4_json);
    let pattern = Pattern::parse("[ipv4-addr:value MATCHES 'line1.line2']").expect("parse");
    assert!(pattern.matches_single(&ipv4).expect("eval"));
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
