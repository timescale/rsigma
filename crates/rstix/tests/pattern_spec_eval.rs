//! STIX Specification §9.8 pattern evaluation regression (every fixture line + parse-all).

#[path = "support/eval_case.rs"]
mod eval_case;
#[path = "support/fixture_lines.rs"]
mod fixture_lines;
#[path = "support/sco_json.rs"]
mod sco_json;

use eval_case::EvalCase;
use fixture_lines::fixture_lines;
use rstix::Pattern;
use sco_json::parse_sco_json;

/// §9.8 Level-1 examples: each row is one spec example with a dedicated eval expectation.
const SPEC_LEVEL1_EVAL: &[EvalCase] = &[
    EvalCase {
        id: "L1-01-file-sha256",
        pattern: "[file:hashes.'SHA-256' = 'fe90a7e910cb3a4739bed9180e807e93fa70c90f25a8915476f5e4bfbac681db']",
        expect: true,
        scos: &[include_str!("fixtures/spec/sco/file-basic.json")],
        at: &[],
        bundle: None,
    },
    EvalCase {
        id: "L1-02-email-refs-multipart",
        pattern: "[email-message:from_ref.value MATCHES '.+\\\\@example\\\\.com$' AND email-message:body_multipart[*].body_raw_ref.name MATCHES '^Final Report.+\\\\.exe$']",
        expect: true,
        scos: &[include_str!(
            "fixtures/pattern/eval/spec-9-8-email-bundle-email-message.json"
        )],
        at: &[],
        bundle: Some(include_str!(
            "fixtures/pattern/eval/spec-9-8-email-bundle.json"
        )),
    },
    EvalCase {
        id: "L1-03-file-hash-and-mime",
        pattern: "[file:hashes.'SHA-256' = 'fe90a7e910cb3a4739bed9180e807e93fa70c90f25a8915476f5e4bfbac681db' AND file:mime_type = 'application/x-pdf']",
        expect: false,
        scos: &[include_str!("fixtures/spec/sco/file-basic.json")],
        at: &[],
        bundle: None,
    },
    EvalCase {
        id: "L1-04-process-name-in",
        pattern: "[process:name IN ('proccy', 'proximus', 'badproc')]",
        expect: false,
        scos: &[include_str!("fixtures/spec/sco/process-basic.json")],
        at: &[],
        bundle: None,
    },
    EvalCase {
        id: "L1-05-exists-registry-values",
        pattern: "[EXISTS windows-registry-key:values]",
        expect: true,
        scos: &[include_str!(
            "fixtures/spec/sco/windows-registry-key-with-creator.json"
        )],
        at: &[],
        bundle: None,
    },
    EvalCase {
        id: "L1-06-directory-like",
        pattern: "[directory:path LIKE 'C:\\\\Windows\\\\%\\\\foo']",
        expect: false,
        scos: &[include_str!("fixtures/spec/sco/directory-basic.json")],
        at: &[],
        bundle: None,
    },
    EvalCase {
        id: "L1-07-artifact-mime-and-payload-hex",
        pattern: "[artifact:mime_type = 'application/vnd.tcpdump.pcap' AND artifact:payload_bin = h'd4c3b2a102000400']",
        expect: true,
        scos: &[include_str!(
            "fixtures/pattern/eval/artifact-pcap-payload.json"
        )],
        at: &[],
        bundle: None,
    },
    EvalCase {
        id: "L1-08-file-parent-directory-path",
        pattern: "[file:name = 'foo.dll' AND file:parent_directory_ref.path = 'C:\\\\Windows\\\\System32']",
        expect: true,
        scos: &[include_str!(
            "fixtures/pattern/eval/spec-9-8-file-parent-bundle-file.json"
        )],
        at: &[],
        bundle: Some(include_str!(
            "fixtures/pattern/eval/spec-9-8-file-parent-bundle.json"
        )),
    },
    EvalCase {
        id: "L1-09-pe-entropy-threshold",
        pattern: "[file:extensions.'windows-pebinary-ext'.sections[*].entropy > 7.0]",
        expect: false,
        scos: &[include_str!(
            "fixtures/pattern/eval/file-with-pe-ext-embedded.json"
        )],
        at: &[],
        bundle: None,
    },
    EvalCase {
        id: "L1-10-file-mime-and-magic-hex",
        pattern: "[file:mime_type = 'image/bmp' AND file:magic_number_hex = h'ffd8']",
        expect: true,
        scos: &[include_str!("fixtures/pattern/eval/file-bmp-magic.json")],
        at: &[],
        bundle: None,
    },
    EvalCase {
        id: "L1-11-network-dst-ref",
        // PR #276: `=` is exact; dst ipv4 value is `203.0.113.33` (no /32 suffix in bundle).
        pattern: "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '203.0.113.33']",
        expect: true,
        scos: &[include_str!(
            "fixtures/pattern/eval/spec-9-8-network-traffic.json"
        )],
        at: &[],
        bundle: Some(include_str!(
            "fixtures/pattern/eval/spec-9-8-network-bundle.json"
        )),
    },
    EvalCase {
        id: "L1-12-domain-resolves-to",
        // PR #276: `=` is exact; resolved ipv4 value is `198.51.100.1` (no /32 suffix in bundle).
        pattern: "[domain-name:value = 'www.5z8.info' AND domain-name:resolves_to_refs[*].value = '198.51.100.1']",
        expect: true,
        scos: &[include_str!(
            "fixtures/pattern/eval/spec-9-8-domain-name.json"
        )],
        at: &[],
        bundle: Some(include_str!(
            "fixtures/pattern/eval/spec-9-8-domain-bundle.json"
        )),
    },
    EvalCase {
        id: "L1-13-url-or",
        pattern: "[url:value = 'http://example.com/foo' OR url:value = 'http://example.com/bar']",
        expect: true,
        scos: &[include_str!("fixtures/pattern/eval/url-example-foo.json")],
        at: &[Some("2024-01-01T00:00:00.000Z")],
        bundle: None,
    },
    EvalCase {
        id: "L1-14-x509-issuer-serial",
        pattern: "[x509-certificate:issuer = 'CN=WEBMAIL' AND x509-certificate:serial_number = '4c:0b:1d:19:74:86:a7:66:b4:1a:bf:40:27:21:76:28']",
        expect: true,
        scos: &[include_str!("fixtures/pattern/eval/x509-webmail.json")],
        at: &[],
        bundle: None,
    },
    EvalCase {
        id: "L1-15-registry-key-or",
        pattern: "[windows-registry-key:key = 'HKEY_CURRENT_USER\\\\Software\\\\CryptoLocker\\\\Files' OR windows-registry-key:key = 'HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\CurrentVersion\\\\Run\\\\CryptoLocker_0388']",
        expect: true,
        scos: &[include_str!(
            "fixtures/pattern/eval/registry-cryptolocker.json"
        )],
        at: &[Some("2024-01-01T00:00:00.000Z")],
        bundle: None,
    },
    EvalCase {
        id: "L1-16-file-or-size-and-created",
        pattern: "[(file:name = 'pdf.exe' OR file:size = 371712) AND file:created = t'2014-01-13T07:03:17Z']",
        expect: true,
        scos: &[include_str!("fixtures/pattern/eval/file-with-ctime.json")],
        at: &[],
        bundle: None,
    },
    EvalCase {
        id: "L1-17-email-sender-subject",
        pattern: "[email-message:sender_ref.value = 'sender@example.com' AND email-message:subject = 'Conference Info']",
        expect: true,
        scos: &[include_str!(
            "fixtures/pattern/eval/spec-9-8-email-bundle-email-message.json"
        )],
        at: &[],
        bundle: Some(include_str!(
            "fixtures/pattern/eval/spec-9-8-email-bundle.json"
        )),
    },
    EvalCase {
        id: "L1-18-custom-usb-device",
        pattern: "[x-usb-device:usbdrive.serial_number = '575833314133343231313937']",
        expect: true,
        scos: &[include_str!("fixtures/pattern/eval/custom-usb-device.json")],
        at: &[],
        bundle: None,
    },
    EvalCase {
        id: "L1-19-ipv6-issubset",
        pattern: "[network-traffic:dst_ref.value ISSUBSET '2001:0db8:dead:beef:0000:0000:0000:0000/64']",
        expect: true,
        scos: &[include_str!(
            "fixtures/pattern/eval/spec-9-8-ipv6-network-traffic.json"
        )],
        at: &[],
        bundle: Some(include_str!(
            "fixtures/pattern/eval/spec-9-8-ipv6-network-bundle.json"
        )),
    },
];

const SPEC_LEVEL23_EVAL: &[EvalCase] = &[
    EvalCase {
        id: "L23-01-file-or-and",
        pattern: "[file:hashes.'SHA-256' = 'bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52a9c' OR file:hashes.MD5 = 'cead3f77f6cda6ec00f57d76c9a6879f'] AND [file:hashes.'SHA-256' = 'fe90a7e910cb3a4739bed9180e807e93fa70c90f25a8915476f5e4bfbac681db']",
        expect: true,
        scos: &[
            include_str!("fixtures/pattern/eval/level23-file-a.json"),
            include_str!("fixtures/spec/sco/file-basic.json"),
        ],
        at: &[
            Some("2024-01-01T00:00:00.000Z"),
            Some("2024-01-01T00:00:01.000Z"),
        ],
        bundle: None,
    },
    EvalCase {
        id: "L23-02-followedby-within",
        pattern: "([file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4'] FOLLOWEDBY [windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\foo\\\\bar']) WITHIN 300 SECONDS",
        expect: true,
        scos: &[
            include_str!("fixtures/pattern/eval/level23-file-md5.json"),
            include_str!("fixtures/pattern/eval/registry-foo-bar.json"),
        ],
        at: &[
            Some("2024-01-01T00:00:00.000Z"),
            Some("2024-01-01T00:01:00.000Z"),
        ],
        bundle: None,
    },
    EvalCase {
        id: "L23-03-triple-user-and",
        pattern: "[user-account:account_type = 'unix' AND user-account:user_id = '1007' AND user-account:account_login = 'Peter'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1008' AND user-account:account_login = 'Paul'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1009' AND user-account:account_login = 'Mary']",
        expect: true,
        scos: &[
            include_str!("fixtures/pattern/eval/user-peter.json"),
            include_str!("fixtures/pattern/eval/user-paul.json"),
            include_str!("fixtures/pattern/eval/user-mary.json"),
        ],
        at: &[
            Some("2024-01-01T00:00:00.000Z"),
            Some("2024-01-01T00:00:01.000Z"),
            Some("2024-01-01T00:00:02.000Z"),
        ],
        bundle: Some(include_str!(
            "fixtures/pattern/eval/spec-9-8-level23-users-bundle.json"
        )),
    },
    EvalCase {
        id: "L23-04-repeats-within-network",
        pattern: "[network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'example.com'] REPEATS 3 TIMES WITHIN 1800 SECONDS",
        expect: true,
        scos: &[
            include_str!("fixtures/pattern/eval/level23-network-a.json"),
            include_str!("fixtures/pattern/eval/level23-network-b.json"),
            include_str!("fixtures/pattern/eval/level23-network-c.json"),
        ],
        at: &[
            Some("2024-01-01T00:00:00.000Z"),
            Some("2024-01-01T00:10:00.000Z"),
            Some("2024-01-01T00:20:00.000Z"),
        ],
        bundle: Some(include_str!(
            "fixtures/pattern/eval/spec-9-8-level23-network-bundle.json"
        )),
    },
    EvalCase {
        id: "L23-05-process-matches-followedby-within",
        pattern: "[process:command_line MATCHES '^.+>-add GlobalSign.cer -c -s -r localMachine Root$'] FOLLOWEDBY [process:command_line MATCHES '^.+>-add GlobalSign.cer -c -s -r localMachineTrustedPublisher$'] WITHIN 300 SECONDS",
        expect: true,
        scos: &[
            include_str!("fixtures/pattern/eval/process-globalsign-root.json"),
            include_str!("fixtures/pattern/eval/process-globalsign-publisher.json"),
        ],
        at: &[
            Some("2024-01-01T00:00:00.000Z"),
            Some("2024-01-01T00:02:00.000Z"),
        ],
        bundle: None,
    },
    EvalCase {
        id: "L23-06-file-and-registry-or-process-image",
        pattern: "([file:name = 'foo.dll'] AND [windows-registry-key:key = 'HKEY_LOCAL_MACHINE\\\\foo\\\\bar']) OR [process:image_ref.name = 'fooproc' OR process:image_ref.name = 'procfoo']",
        expect: true,
        scos: &[
            include_str!("fixtures/pattern/eval/level23-file-foo-dll.json"),
            include_str!("fixtures/pattern/eval/registry-foo-bar.json"),
        ],
        at: &[
            Some("2024-01-01T00:00:00.000Z"),
            Some("2024-01-01T00:00:01.000Z"),
        ],
        bundle: Some(include_str!(
            "fixtures/pattern/eval/spec-9-8-level23-or-bundle.json"
        )),
    },
    EvalCase {
        id: "L23-07-start-stop",
        pattern: "[ipv4-addr:value = '198.51.100.1/32'] START t'2014-06-01T00:00:00Z' STOP t'2014-07-01T00:00:00Z'",
        expect: true,
        scos: &[include_str!(
            "fixtures/pattern/eval/ipv4-addr-start-stop.json"
        )],
        at: &[Some("2014-06-15T00:00:00.000Z")],
        bundle: None,
    },
];

#[test]
fn spec_section_9_8_level1_every_line_evaluates() {
    for case in SPEC_LEVEL1_EVAL {
        case.run();
    }
}

#[test]
fn spec_section_9_8_level23_every_line_evaluates() {
    for case in SPEC_LEVEL23_EVAL {
        case.run();
    }
}

#[test]
fn spec_section_9_8_level1_fixtures_parse() {
    for (idx, line) in fixture_lines("spec-section-9-8-level1.txt")
        .into_iter()
        .enumerate()
    {
        Pattern::parse(&line)
            .unwrap_or_else(|e| panic!("level1 fixture {idx} parse failed: {e:?}\n  {line}"));
    }
}

#[test]
fn spec_section_9_8_level23_fixtures_parse() {
    for (idx, line) in fixture_lines("spec-section-9-8-level23.txt")
        .into_iter()
        .enumerate()
    {
        Pattern::parse(&line)
            .unwrap_or_else(|e| panic!("level23 fixture {idx} parse failed: {e:?}\n  {line}"));
    }
}

#[test]
fn missing_timestamp_on_temporal_pattern() {
    let ipv4 = parse_sco_json(include_str!("fixtures/spec/sco/ipv4-addr-single.json"));
    let observations = [rstix::pattern::TimestampedObservation {
        sco: &ipv4,
        at: None,
    }];
    let ctx = rstix::pattern::ObservationContext::from_scos(&observations);
    let pattern = Pattern::parse(
        "[ipv4-addr:value = '198.51.100.3'] FOLLOWEDBY [ipv4-addr:value = '10.0.0.1']",
    )
    .expect("parse");
    assert_eq!(
        pattern.evaluate(&ctx),
        Err(rstix::pattern::PatternMatchError::MissingTimestamp)
    );
}
