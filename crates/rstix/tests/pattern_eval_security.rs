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
