//! Dedicated evaluation tests for every STIX pattern comparison operator (STIX §9.3).

#[path = "support/eval_case.rs"]
mod eval_case;
#[path = "support/sco_json.rs"]
mod sco_json;

use eval_case::EvalCase;
use rstix::Pattern;
use rstix::core::StixTimestamp;
use rstix::pattern::{ObservationContext, TimestampedObservation};
use sco_json::parse_sco_json;

#[test]
fn operator_equality_and_inequality() {
    EvalCase {
        id: "eq",
        pattern: "[ipv4-addr:value = '198.51.100.3']",
        expect: true,
        scos: &[include_str!("fixtures/spec/sco/ipv4-addr-single.json")],
        at: &[],
        bundle: None,
    }
    .run();

    EvalCase {
        id: "not_eq",
        pattern: "[ipv4-addr:value != '10.0.0.1']",
        expect: true,
        scos: &[include_str!("fixtures/spec/sco/ipv4-addr-single.json")],
        at: &[],
        bundle: None,
    }
    .run();
}

#[test]
fn operator_in() {
    EvalCase {
        id: "in_process_name",
        pattern: "[process:name IN ('gedit-bin', 'badproc')]",
        expect: true,
        scos: &[include_str!("fixtures/spec/sco/process-basic.json")],
        at: &[],
        bundle: None,
    }
    .run();
}

#[test]
fn operator_like() {
    EvalCase {
        id: "like_directory_path",
        pattern: "[directory:path LIKE 'C:\\\\Windows\\\\%']",
        expect: true,
        scos: &[include_str!("fixtures/spec/sco/directory-basic.json")],
        at: &[],
        bundle: None,
    }
    .run();

    EvalCase {
        id: "not_like",
        pattern: "[directory:path NOT LIKE 'C:\\\\Temp\\\\%']",
        expect: true,
        scos: &[include_str!("fixtures/spec/sco/directory-basic.json")],
        at: &[],
        bundle: None,
    }
    .run();
}

#[test]
fn operator_matches() {
    EvalCase {
        id: "matches_process_command_line",
        pattern: "[process:command_line MATCHES '\\\\./gedit-bin.*']",
        expect: true,
        scos: &[include_str!("fixtures/spec/sco/process-basic.json")],
        at: &[],
        bundle: None,
    }
    .run();
}

#[test]
fn operator_exists() {
    EvalCase {
        id: "exists_registry_values",
        pattern: "[EXISTS windows-registry-key:values]",
        expect: true,
        scos: &[include_str!(
            "fixtures/spec/sco/windows-registry-key-with-creator.json"
        )],
        at: &[],
        bundle: None,
    }
    .run();

    EvalCase {
        id: "not_exists_registry_values",
        pattern: "[NOT EXISTS windows-registry-key:values]",
        expect: true,
        scos: &[include_str!(
            "fixtures/spec/sco/windows-registry-key-basic.json"
        )],
        at: &[],
        bundle: None,
    }
    .run();
}

#[test]
fn operator_order_and_hex() {
    EvalCase {
        id: "gt_float_entropy",
        pattern: "[file:extensions.'windows-pebinary-ext'.sections[*].entropy > 0.05]",
        expect: true,
        scos: &[include_str!(
            "fixtures/pattern/eval/file-with-pe-ext-embedded.json"
        )],
        at: &[],
        bundle: None,
    }
    .run();

    EvalCase {
        id: "lt_process_pid",
        pattern: "[process:pid < 2000]",
        expect: true,
        scos: &[include_str!("fixtures/spec/sco/process-basic.json")],
        at: &[],
        bundle: None,
    }
    .run();

    EvalCase {
        id: "lte_process_pid",
        pattern: "[process:pid <= 1221]",
        expect: true,
        scos: &[include_str!("fixtures/spec/sco/process-basic.json")],
        at: &[],
        bundle: None,
    }
    .run();

    EvalCase {
        id: "gte_process_pid",
        pattern: "[process:pid >= 1221]",
        expect: true,
        scos: &[include_str!("fixtures/spec/sco/process-basic.json")],
        at: &[],
        bundle: None,
    }
    .run();

    EvalCase {
        id: "hex_magic_number",
        pattern: "[file:magic_number_hex = h'ffd8']",
        expect: true,
        scos: &[include_str!("fixtures/pattern/eval/file-bmp-magic.json")],
        at: &[],
        bundle: None,
    }
    .run();
}

#[test]
fn operator_timestamp_constant() {
    EvalCase {
        id: "timestamp_file_created_alias",
        pattern: "[file:created = t'2014-01-13T07:03:17.000Z']",
        expect: true,
        scos: &[include_str!("fixtures/pattern/eval/file-with-ctime.json")],
        at: &[],
        bundle: None,
    }
    .run();
}

#[test]
fn operator_cidr_subset() {
    EvalCase {
        id: "issubset_ipv6",
        pattern: "[ipv6-addr:value ISSUBSET '2001:0db8:0000:0000:0000:0000:0000:0000/32']",
        expect: true,
        scos: &[include_str!("fixtures/spec/sco/ipv6-addr-single.json")],
        at: &[],
        bundle: None,
    }
    .run();

    EvalCase {
        id: "issuperset_ipv6",
        pattern: "[ipv6-addr:value ISSUPERSET '2001:0db8:85a3:0000:0000:8a2e:0370:7334/128']",
        expect: true,
        scos: &[include_str!("fixtures/spec/sco/ipv6-addr-single.json")],
        at: &[],
        bundle: None,
    }
    .run();
}

#[test]
fn operator_binary_payload_hex() {
    EvalCase {
        id: "binary_hex_payload",
        pattern: "[artifact:payload_bin = h'd4c3b2a102000400']",
        expect: true,
        scos: &[include_str!(
            "fixtures/pattern/eval/artifact-pcap-payload.json"
        )],
        at: &[],
        bundle: None,
    }
    .run();
}

#[test]
fn comparison_tree_not() {
    let sco = parse_sco_json(include_str!("fixtures/spec/sco/file-basic.json"));
    let pattern = Pattern::parse("[NOT (file:name = 'missing.dll')]").expect("parse");
    assert!(pattern.matches_single(&sco).expect("eval"));
}

#[test]
fn temporal_and_or_followedby() {
    let ts = |s: &str| StixTimestamp::parse(s).expect("ts");
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let domain = parse_sco_json(include_str!("fixtures/spec/sco/domain-name-basic.json"));
    let observations = [
        TimestampedObservation {
            sco: &ipv4,
            at: Some(ts("2024-01-01T00:00:00.000Z")),
        },
        TimestampedObservation {
            sco: &domain,
            at: Some(ts("2024-01-01T00:00:01.000Z")),
        },
    ];
    let ctx = ObservationContext::from_scos(&observations);

    assert!(
        Pattern::parse(
            "[ipv4-addr:value = '198.51.100.3'] AND [domain-name:value = 'example.com']"
        )
        .expect("p")
        .evaluate(&ctx)
        .expect("eval")
    );
    assert!(
        Pattern::parse("[ipv4-addr:value = '10.0.0.1'] OR [domain-name:value = 'example.com']")
            .expect("p")
            .evaluate(&ctx)
            .expect("eval")
    );
    assert!(
        Pattern::parse(
            "[ipv4-addr:value = '198.51.100.3'] FOLLOWEDBY [domain-name:value = 'example.com']"
        )
        .expect("p")
        .evaluate(&ctx)
        .expect("eval")
    );
}

#[test]
fn temporal_within_repeats_start_stop() {
    let ts = |s: &str| StixTimestamp::parse(s).expect("ts");
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let observations = [TimestampedObservation {
        sco: &ipv4,
        at: Some(ts("2024-01-01T00:00:00.000Z")),
    }];
    let ctx = ObservationContext::from_scos(&observations);
    assert!(
        Pattern::parse("[ipv4-addr:value = '198.51.100.3'] WITHIN 5 MINUTES")
            .expect("p")
            .evaluate(&ctx)
            .expect("eval")
    );

    let cidr = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-cidr.json"));
    let observations = [TimestampedObservation {
        sco: &cidr,
        at: Some(ts("2014-06-15T00:00:00.000Z")),
    }];
    let ctx = ObservationContext::from_scos(&observations);
    assert!(
        Pattern::parse(
            "[ipv4-addr:value = '198.51.100.0/24'] START t'2014-06-01T00:00:00Z' STOP t'2014-07-01T00:00:00Z'"
        )
        .expect("p")
        .evaluate(&ctx)
        .expect("eval")
    );

    let v4a = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let v4b = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let observations = [
        TimestampedObservation {
            sco: &v4a,
            at: Some(ts("2024-01-01T00:00:00.000Z")),
        },
        TimestampedObservation {
            sco: &v4b,
            at: Some(ts("2024-01-01T00:00:01.000Z")),
        },
    ];
    let ctx = ObservationContext::from_scos(&observations);
    assert!(
        Pattern::parse("[ipv4-addr:value = '198.51.100.3'] REPEATS 2 TIMES")
            .expect("p")
            .evaluate(&ctx)
            .expect("eval")
    );
}
