//! Pattern Engine parse + type-check tests (STIX Specification §9.8).

use rstix::Pattern;
use rstix::pattern::{PatternAst, PatternError};

fn fixture_lines(name: &str) -> Vec<String> {
    let path = format!("tests/fixtures/pattern/{name}");
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .map(str::trim)
        .map(str::to_owned)
        .collect()
}

#[test]
fn spec_section_9_8_level1_fixtures_parse_and_type_check() {
    for (idx, example) in fixture_lines("spec-section-9-8-level1.txt")
        .into_iter()
        .enumerate()
    {
        Pattern::parse(&example).unwrap_or_else(|e| {
            panic!("spec §9.8 level-1 fixture {idx} failed: {e:?}\n  {example}")
        });
    }
}

#[test]
fn spec_section_9_8_level23_fixtures_parse_and_type_check() {
    for (idx, example) in fixture_lines("spec-section-9-8-level23.txt")
        .into_iter()
        .enumerate()
    {
        Pattern::parse(&example).unwrap_or_else(|e| {
            panic!("spec §9.8 level-2/3 fixture {idx} failed: {e:?}\n  {example}")
        });
    }
}

#[test]
fn gap_table_examples_all_pass() {
    let examples = [
        "[file:extensions.'windows-pebinary-ext'.sections[*].entropy > 7.0]",
        "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '203.0.113.33/32']",
        "[network-traffic:dst_ref.value ISSUBSET '2001:0db8:dead:beef:0000:0000:0000:0000/64']",
        "([file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4'] FOLLOWEDBY [windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\foo\\\\bar']) WITHIN 300 SECONDS",
        "[x-usb-device:usbdrive.serial_number = '575833314133343231313937']",
        "[process:image_ref.name = 'fooproc' OR process:image_ref.name = 'procfoo']",
    ];
    for (idx, example) in examples.into_iter().enumerate() {
        Pattern::parse(example)
            .unwrap_or_else(|e| panic!("gap-table example {idx} failed: {e:?}\n  {example}"));
    }
}

#[test]
fn level2_and_two_observations() {
    let pattern =
        Pattern::parse("[ipv4-addr:value = '1.2.3.4'] AND [domain-name:value = 'example.com']")
            .expect("parse");
    assert!(matches!(pattern.ast(), PatternAst::And { .. }));
    assert_eq!(pattern.ast().observation_count(), 2);
}

#[test]
fn level2_followedby() {
    let pattern =
        Pattern::parse("[process:name = 'a'] FOLLOWEDBY [process:name = 'b']").expect("parse");
    assert!(matches!(pattern.ast(), PatternAst::FollowedBy { .. }));
}

#[test]
fn level3_within_qualifier() {
    let pattern = Pattern::parse("[ipv4-addr:value = '1.2.3.4'] WITHIN 5 MINUTES").expect("parse");
    assert!(matches!(pattern.ast(), PatternAst::Within { .. }));
}

#[test]
fn level3_repeats_qualifier() {
    let pattern = Pattern::parse("[ipv4-addr:value = '1.2.3.4'] REPEATS 3 TIMES").expect("parse");
    assert!(matches!(pattern.ast(), PatternAst::Repeats { .. }));
}

#[test]
fn level3_start_stop_postfix() {
    let pattern = Pattern::parse(
        "[ipv4-addr:value = '198.51.100.1/32'] START t'2014-06-01T00:00:00Z' STOP t'2014-07-01T00:00:00Z'",
    )
    .expect("parse");
    assert!(matches!(pattern.ast(), PatternAst::StartStop { inner, .. }
            if matches!(inner.as_ref(), PatternAst::Observation(_))));
}

#[test]
fn level3_followedby_within_binds_to_right_observation() {
    let pattern = Pattern::parse(
        "[ipv4-addr:value = '1.1.1.1'] FOLLOWEDBY [ipv4-addr:value = '2.2.2.2'] WITHIN 300 SECONDS",
    )
    .expect("parse");
    assert!(matches!(
        pattern.ast(),
        PatternAst::FollowedBy {
            right,
            ..
        } if matches!(right.as_ref(), PatternAst::Within { .. })
    ));
}

#[test]
fn level2_followedby_looser_than_and() {
    let pattern = Pattern::parse(
        "[ipv4-addr:value = '1.1.1.1'] FOLLOWEDBY [ipv4-addr:value = '2.2.2.2'] AND [ipv4-addr:value = '3.3.3.3']",
    )
    .expect("parse");
    assert!(matches!(
        pattern.ast(),
        PatternAst::FollowedBy {
            right,
            ..
        } if matches!(right.as_ref(), PatternAst::And { .. })
    ));
}

#[test]
fn custom_type_observed_type_names() {
    let pattern =
        Pattern::parse("[x-usb-device:usbdrive.serial_number = '575833314133343231313937']")
            .expect("parse");
    assert_eq!(
        pattern.observed_type_names(),
        vec!["x-usb-device".to_owned()]
    );
    assert!(pattern.observed_types().is_empty());
}

#[test]
fn type_check_rejects_invalid_property() {
    let err = Pattern::parse("[ipv4-addr:not_a_property = 'x']").unwrap_err();
    assert!(matches!(err, PatternError::TypeError { .. }));
}

#[test]
fn type_check_rejects_invalid_operator_for_type() {
    let err = Pattern::parse("[ipv4-addr:value > 'x']").unwrap_err();
    assert!(matches!(err, PatternError::TypeError { .. }));
}
