//! Modifier contradiction, `|all`, encoding-chain, and numeric fixtures.
//!
//! Ground truth is the legacy compile/evaluate path. Lowering must reproduce
//! the same accept/reject and match/no-match decisions.

mod common;

use common::{engine_from, matches, rule_with_item, titles_for, try_compile};
use rsigma_parser::{Detection, SigmaValue};
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
fn cidr_requires_a_network_address() {
    let lower = |cidr: &str| {
        rsigma_ir::lower_rule(
            &rule_with_item(&["cidr"], cidr),
            &rsigma_ir::LowerOptions::default(),
        )
    };
    for ok in [
        "10.0.0.0/8",
        "0.0.0.0/0",
        "10.0.0.1/32",
        "2001:db8::/32",
        "::/0",
        "2001:db8::1/128",
    ] {
        assert!(lower(ok).is_ok(), "{ok} should lower");
    }
    for (bad, reason) in [
        ("10.1.2.3/8", "host bits set"),
        ("2001:db8::1/32", "host bits set"),
        ("10.0.0.0/33", "invalid prefix length"),
        ("10.0.0.0", "expected address/prefix"),
        ("not-an-ip/8", "invalid IP address"),
    ] {
        let err = lower(bad).expect_err(bad).to_string();
        assert!(err.contains(reason), "{bad}: {err}");
    }
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
fn all_on_single_value_is_accepted_as_redundant() {
    let result = try_compile(
        r#"
title: All Single
logsource: { category: test }
detection:
    selection:
        Image|all: 'notepad.exe'
    condition: selection
"#,
    );
    assert!(
        result.is_ok(),
        "|all on a single value should compile: {result:?}"
    );
}

#[test]
fn lowering_rejects_contradictions_on_rewritten_items() {
    for modifiers in [
        &["cidr", "contains"][..],
        &["re", "contains"],
        &["base64", "base64offset"],
        &["wide", "utf16"],
        &["multiline"],
        &["i", "re"],
        &["contains", "fieldref"],
    ] {
        let rule = rule_with_item(modifiers, "x");
        let err = rsigma_ir::lower_rule(&rule, &rsigma_ir::LowerOptions::default());
        assert!(
            matches!(err, Err(rsigma_ir::IrError::InvalidModifiers(_))),
            "{modifiers:?}: {err:?}"
        );
    }
}

#[test]
fn lowering_rejects_non_boolean_exists_on_a_rewritten_item() {
    let rule = rule_with_item(&["exists"], "yes");
    let err = rsigma_ir::lower_rule(&rule, &rsigma_ir::LowerOptions::default());
    assert!(
        matches!(err, Err(rsigma_ir::IrError::IncompatibleValue(_))),
        "{err:?}"
    );
}

#[test]
fn lowering_negates_exists_under_neq() {
    for (value, expect) in [("true", false), ("false", true)] {
        let yaml = format!(
            "title: T\nlogsource: {{ category: test }}\ndetection:\n    selection:\n        \
             Field|exists|neq: {value}\n    condition: selection\n"
        );
        let collection = rsigma_parser::parse_sigma_yaml(&yaml).unwrap();
        let ir = rsigma_ir::lower_rule(&collection.rules[0], &rsigma_ir::LowerOptions::default())
            .unwrap();
        let Some(rsigma_ir::IrDetection::AllOf(items)) = ir.detections.get("selection") else {
            panic!("expected AllOf");
        };
        assert!(
            matches!(items[0].matcher, rsigma_ir::IrMatcher::Exists(e) if e == expect),
            "exists|neq: {value}: {:?}",
            items[0].matcher
        );
        assert_eq!(items[0].exists, Some(expect));
    }
}

#[test]
fn lowering_rejects_invalid_values_on_rewritten_items() {
    let rule = rule_with_item(&["fieldref"], "Other*");
    let err = rsigma_ir::lower_rule(&rule, &rsigma_ir::LowerOptions::default());
    assert!(
        matches!(err, Err(rsigma_ir::IrError::IncompatibleValue(_))),
        "{err:?}"
    );

    let mut rule = rule_with_item(&["contains"], "5");
    let Some(Detection::AllOf(items)) = rule.detection.named.get_mut("selection") else {
        unreachable!("the selection is a single mapping");
    };
    items[0].values = vec![SigmaValue::Integer(5)];
    let err = rsigma_ir::lower_rule(&rule, &rsigma_ir::LowerOptions::default());
    assert!(
        matches!(err, Err(rsigma_ir::IrError::IncompatibleValue(_))),
        "{err:?}"
    );
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
fn fieldref_contains_matches_substring() {
    let engine = engine_from(
        r#"
title: FieldRef Contains
logsource: { category: test }
detection:
    selection:
        userIdentity.arn|fieldref|contains: responseElements.accessKey.userName
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({
            "userIdentity.arn": "arn:aws:iam::123:user/alice",
            "responseElements.accessKey.userName": "alice"
        })
    ));
    assert!(matches(
        &engine,
        &json!({
            "userIdentity.arn": "arn:aws:iam::123:user/Alice",
            "responseElements.accessKey.userName": "alice"
        })
    ));
    assert!(!matches(
        &engine,
        &json!({
            "userIdentity.arn": "arn:aws:iam::123:user/bob",
            "responseElements.accessKey.userName": "alice"
        })
    ));
}

#[test]
fn fieldref_startswith_and_endswith() {
    let start = engine_from(
        r#"
title: FieldRef Starts
logsource: { category: test }
detection:
    selection:
        Image|fieldref|startswith: Folder
    condition: selection
"#,
    );
    assert!(matches(
        &start,
        &json!({"Image": "C:\\Windows\\cmd.exe", "Folder": "C:\\Windows"})
    ));
    assert!(!matches(
        &start,
        &json!({"Image": "C:\\Windows\\cmd.exe", "Folder": "cmd.exe"})
    ));

    let end = engine_from(
        r#"
title: FieldRef Ends
logsource: { category: test }
detection:
    selection:
        Image|fieldref|endswith: OriginalFileName
    condition: selection
"#,
    );
    assert!(matches(
        &end,
        &json!({"Image": "C:\\Temp\\net.exe", "OriginalFileName": "net.exe"})
    ));
    assert!(!matches(
        &end,
        &json!({"Image": "C:\\Temp\\net.exe", "OriginalFileName": "cmd.exe"})
    ));
}

#[test]
fn fieldref_contains_cased_and_numeric_needle() {
    let engine = engine_from(
        r#"
title: FieldRef Cased
logsource: { category: test }
detection:
    selection:
        Message|fieldref|contains|cased: Token
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"Message": "id=Admin", "Token": "Admin"})
    ));
    assert!(!matches(
        &engine,
        &json!({"Message": "id=Admin", "Token": "admin"})
    ));

    let numeric = engine_from(
        r#"
title: FieldRef Numeric
logsource: { category: test }
detection:
    selection:
        Message|fieldref|contains: Code
    condition: selection
"#,
    );
    assert!(matches(
        &numeric,
        &json!({"Message": "exit 42", "Code": 42})
    ));
}

#[test]
fn fieldref_contains_all_requires_every_name() {
    let engine = engine_from(
        r#"
title: FieldRef All
logsource: { category: test }
detection:
    selection:
        CommandLine|fieldref|contains|all:
            - User
            - Host
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"CommandLine": "alice@host", "User": "alice", "Host": "host"})
    ));
    assert!(!matches(
        &engine,
        &json!({"CommandLine": "alice@other", "User": "alice", "Host": "host"})
    ));
}

#[test]
fn fieldref_neq_negates_equality() {
    let engine = engine_from(
        r#"
title: FieldRef Neq
logsource: { category: test }
detection:
    selection:
        Image|fieldref|neq: ParentImage
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"Image": "a.exe", "ParentImage": "b.exe"})
    ));
    assert!(!matches(
        &engine,
        &json!({"Image": "a.exe", "ParentImage": "a.exe"})
    ));
    assert!(matches(&engine, &json!({"Image": "a.exe"})));
    assert!(matches(&engine, &json!({"ParentImage": "a.exe"})));
}

#[test]
fn neq_negates_the_whole_value_list() {
    let any = engine_from(
        r#"
title: Neq List
logsource: { category: test }
detection:
    selection:
        User|neq:
            - root
            - admin
    condition: selection
"#,
    );
    assert!(matches(&any, &json!({"User": "alice"})));
    assert!(!matches(&any, &json!({"User": "root"})));
    assert!(!matches(&any, &json!({"User": "admin"})));
    assert!(matches(&any, &json!({"Other": "x"})));

    let all = engine_from(
        r#"
title: Neq All
logsource: { category: test }
detection:
    selection:
        CommandLine|contains|all|neq:
            - whoami
            - /all
    condition: selection
"#,
    );
    assert!(matches(&all, &json!({"CommandLine": "whoami"})));
    assert!(!matches(&all, &json!({"CommandLine": "whoami /all"})));
}

#[test]
fn neq_negates_regex_and_cidr() {
    let engine = engine_from(
        r#"
title: Neq Pattern
logsource: { category: test }
detection:
    selection:
        CommandLine|re|neq: 'whoami'
        SourceIp|cidr|neq: 10.0.0.0/8
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"CommandLine": "ipconfig", "SourceIp": "192.168.1.1"})
    ));
    assert!(!matches(
        &engine,
        &json!({"CommandLine": "whoami /all", "SourceIp": "192.168.1.1"})
    ));
    assert!(!matches(
        &engine,
        &json!({"CommandLine": "ipconfig", "SourceIp": "10.1.2.3"})
    ));
}

#[test]
fn fieldref_rejects_wildcard_and_leading_string_modifier() {
    let wildcard = try_compile(
        r#"
title: FieldRef Wildcard
logsource: { category: test }
detection:
    selection:
        Image|fieldref: 'Other*'
    condition: selection
"#,
    );
    assert!(
        wildcard.is_err(),
        "wildcard fieldref should fail: {wildcard:?}"
    );

    let order = try_compile(
        r#"
title: Contains Then FieldRef
logsource: { category: test }
detection:
    selection:
        Image|contains|fieldref: ParentImage
    condition: selection
"#,
    );
    let err = order.expect_err("contains before fieldref should fail");
    let msg = err.to_string();
    assert!(
        msg.contains("must follow |fieldref"),
        "unexpected error: {msg}"
    );

    let both = try_compile(
        r#"
title: FieldRef Two Strings
logsource: { category: test }
detection:
    selection:
        Image|fieldref|contains|startswith: ParentImage
    condition: selection
"#,
    );
    assert!(both.is_err(), "two string ops should fail: {both:?}");

    let with_re = try_compile(
        r#"
title: FieldRef Re
logsource: { category: test }
detection:
    selection:
        Image|fieldref|re: ParentImage
    condition: selection
"#,
    );
    assert!(with_re.is_err(), "fieldref|re should fail: {with_re:?}");
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
