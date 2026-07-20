//! Modifier contradiction, `|all`, encoding-chain, and numeric fixtures.
//!
//! Ground truth is the legacy compile/evaluate path. Lowering must reproduce
//! the same accept/reject and match/no-match decisions.

mod common;

use common::{engine_from, matches, titles_for, try_compile};
use serde_json::json;

// =============================================================================
// Contradictions — must fail at compile time
// =============================================================================

#[test]
fn cidr_rejects_contains() {
    let err = try_compile(
        r#"
title: Cidr Contains
logsource: { category: test }
detection:
    selection:
        Address|cidr|contains: "192.168.0.0/16"
    condition: selection
"#,
    );
    assert!(err.is_err(), "cidr+contains should fail: {err:?}");
}

#[test]
fn re_rejects_contains() {
    let err = try_compile(
        r#"
title: Re Contains
logsource: { category: test }
detection:
    selection:
        CommandLine|re|contains: ".*whoami.*"
    condition: selection
"#,
    );
    assert!(err.is_err(), "re+contains should fail: {err:?}");
}

#[test]
fn numeric_gt_rejects_contains() {
    let err = try_compile(
        r#"
title: Gt Contains
logsource: { category: test }
detection:
    selection:
        Port|gt|contains: "80"
    condition: selection
"#,
    );
    assert!(err.is_err(), "gt+contains should fail: {err:?}");
}

#[test]
fn base64_rejects_base64offset() {
    let err = try_compile(
        r#"
title: Base64 Both
logsource: { category: test }
detection:
    selection:
        Data|base64|base64offset: "test"
    condition: selection
"#,
    );
    assert!(err.is_err(), "base64+base64offset should fail: {err:?}");
}

#[test]
fn wide_rejects_utf16() {
    let err = try_compile(
        r#"
title: Wide Utf16
logsource: { category: test }
detection:
    selection:
        CommandLine|wide|utf16: 'evil'
    condition: selection
"#,
    );
    assert!(err.is_err(), "wide+utf16 should fail: {err:?}");
}

#[test]
fn multiline_without_re_rejected() {
    let err = try_compile(
        r#"
title: Multiline No Re
logsource: { category: test }
detection:
    selection:
        Image|multiline: 'test'
    condition: selection
"#,
    );
    assert!(err.is_err(), "multiline without re should fail: {err:?}");
}

#[test]
fn windash_rejects_gt() {
    let err = try_compile(
        r#"
title: Windash Gt
logsource: { category: test }
detection:
    selection:
        Port|windash|gt: 80
    condition: selection
"#,
    );
    assert!(err.is_err(), "windash+gt should fail: {err:?}");
}

#[test]
fn all_on_single_value_rejected() {
    let err = try_compile(
        r#"
title: All Single
logsource: { category: test }
detection:
    selection:
        Image|all: 'notepad.exe'
    condition: selection
"#,
    );
    assert!(err.is_err(), "|all on a single value should fail: {err:?}");
}

// =============================================================================
// Accepted modifier combinations with match oracles
// =============================================================================

#[test]
fn all_with_multiple_values_requires_every_value() {
    let engine = engine_from(
        r#"
title: All Multi
logsource: { category: test }
detection:
    selection:
        CommandLine|contains|all:
            - 'powershell'
            - '-enc'
            - 'http'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"CommandLine": "powershell.exe -enc http://evil.com/x"})
    ));
    assert!(!matches(
        &engine,
        &json!({"CommandLine": "powershell.exe -enc dummy"})
    ));
}

#[test]
fn wide_base64_chain_matches_encoded_payload() {
    // "Test" as UTF-16LE then base64 → VABlAHMAdAA=
    let engine = engine_from(
        r#"
title: Wide Base64
logsource: { category: test }
detection:
    selection:
        Payload|wide|base64: 'Test'
    condition: selection
"#,
    );
    assert!(matches(&engine, &json!({"Payload": "VABlAHMAdAA="})));
    assert!(!matches(&engine, &json!({"Payload": "VGVzdA=="})));
}

#[test]
fn base64offset_matches_plain_base64_contains() {
    // |base64offset expands to contains-matchers over offset variants; the
    // ordinary base64 of the plaintext is always among them.
    let engine = engine_from(
        r#"
title: Base64Offset
logsource: { category: test }
detection:
    selection:
        Data|base64offset: 'Test'
    condition: selection
"#,
    );
    assert!(matches(&engine, &json!({"Data": "prefix VGVzdA== suffix"})));
    assert!(!matches(&engine, &json!({"Data": "nope"})));
}

#[test]
fn windash_matches_slash_variant() {
    let engine = engine_from(
        r#"
title: Windash
logsource: { category: test }
detection:
    selection:
        CommandLine|windash|contains: '-Force'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"CommandLine": "powershell /Force"})
    ));
    assert!(matches(
        &engine,
        &json!({"CommandLine": "powershell -Force"})
    ));
    assert!(!matches(
        &engine,
        &json!({"CommandLine": "powershell -Help"})
    ));
}

#[test]
fn cased_is_case_sensitive() {
    let engine = engine_from(
        r#"
title: Cased
logsource: { category: test }
detection:
    selection:
        CommandLine|cased: 'PowerShell'
    condition: selection
"#,
    );
    assert!(matches(&engine, &json!({"CommandLine": "PowerShell"})));
    assert!(!matches(&engine, &json!({"CommandLine": "powershell"})));
}

#[test]
fn startswith_and_endswith() {
    let engine = engine_from(
        r#"
title: Affixes
logsource: { category: test }
detection:
    selection:
        Image|startswith: 'C:\\Windows'
        Image|endswith: 'cmd.exe'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"Image": "C:\\Windows\\System32\\cmd.exe"})
    ));
    assert!(!matches(
        &engine,
        &json!({"Image": "C:\\Windows\\System32\\powershell.exe"})
    ));
}

#[test]
fn exists_true_and_false() {
    let engine = engine_from(
        r#"
title: Exists True
logsource: { category: test }
detection:
    selection:
        Image|exists: true
    condition: selection
"#,
    );
    assert!(matches(&engine, &json!({"Image": "foo.exe"})));
    assert!(!matches(&engine, &json!({"CommandLine": "foo"})));

    let engine = engine_from(
        r#"
title: Exists False
logsource: { category: test }
detection:
    selection:
        Image|exists: false
    condition: selection
"#,
    );
    assert!(!matches(&engine, &json!({"Image": "foo.exe"})));
    assert_eq!(
        titles_for(&engine, &json!({"CommandLine": "foo"})),
        vec!["Exists False".to_string()]
    );
}

#[test]
fn numeric_comparisons() {
    let engine = engine_from(
        r#"
title: Numeric Gt
logsource: { category: test }
detection:
    selection:
        Port|gt: 80
    condition: selection
"#,
    );
    assert!(matches(&engine, &json!({"Port": 443})));
    assert!(!matches(&engine, &json!({"Port": 80})));

    let engine = engine_from(
        r#"
title: Numeric Eq
logsource: { category: test }
detection:
    selection:
        Port: 80
    condition: selection
"#,
    );
    assert!(matches(&engine, &json!({"Port": 80})));
    assert!(!matches(&engine, &json!({"Port": 443})));
}

#[test]
fn fieldref_compiles_and_matches() {
    let engine = engine_from(
        r#"
title: FieldRef
logsource: { category: test }
detection:
    selection:
        TargetImage|fieldref: 'SourceImage'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"TargetImage": "a.exe", "SourceImage": "a.exe"})
    ));
    assert!(!matches(
        &engine,
        &json!({"TargetImage": "a.exe", "SourceImage": "b.exe"})
    ));
}

#[test]
fn cidr_matches_network() {
    let engine = engine_from(
        r#"
title: Cidr
logsource: { category: test }
detection:
    selection:
        DestinationIp|cidr: '192.168.0.0/16'
    condition: selection
"#,
    );
    assert!(matches(&engine, &json!({"DestinationIp": "192.168.1.10"})));
    assert!(!matches(&engine, &json!({"DestinationIp": "10.0.0.1"})));
}
