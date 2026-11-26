//! IR-compiled evaluation semantics.
//!
//! These lock in the match/no-match behavior of rules compiled through the IR
//! path (`compile_rule` = `lower_rule` → `compile_to_compiled`) against
//! representative events. They cover the Sigma corners the IR layer had to get
//! right: selectors over zero names, `them` skipping `_`-prefixed names,
//! modifier resolution, CIDR, keywords, `rsigma.include_event`, and modifier
//! contradictions. (These previously ran as a differential against the removed
//! `compile_rule_legacy`; they now assert the expected result directly.)

mod common;

use common::{collection_from, rule_from, rule_with_condition, rule_with_item};
use rsigma_eval::{JsonEvent, compile_rule, evaluate_rule};
use serde_json::{Value, json};

/// Assert each `(event, expected_match)` against the IR-compiled rule.
fn assert_matches(yaml: &str, cases: &[(Value, bool)]) {
    let rule = rule_from(yaml);
    let compiled = compile_rule(&rule).expect("IR compile");
    for (event, expected) in cases {
        let hit = evaluate_rule(&compiled, &JsonEvent::borrow(event)).is_some();
        assert_eq!(hit, *expected, "match mismatch for event {event}");
    }
}

#[test]
fn baselines_and_of_two_fields() {
    assert_matches(
        r#"
title: Simple And
logsource: { category: test }
detection:
    selection:
        Image: 'notepad.exe'
        User: 'alice'
    condition: selection
"#,
        &[
            (json!({"Image": "notepad.exe", "User": "alice"}), true),
            (json!({"Image": "notepad.exe", "User": "bob"}), false),
            (json!({"Image": "calc.exe", "User": "alice"}), false),
        ],
    );
}

#[test]
fn all_of_zero_matches_does_not_compile() {
    // `all of selection_*` matches zero detection names here, which has no
    // defined result. The parser rejects it; compile repeats the check for
    // conditions rewritten after parsing.
    let rule = rule_with_condition("all of selection_*");
    assert!(compile_rule(&rule).is_err());
}

#[test]
fn them_skips_underscore_names() {
    // `1 of them` ignores the `_internal` detection, so an event that only
    // matches `_internal` does not fire.
    assert_matches(
        r#"
title: Them Skip
logsource: { category: test }
detection:
    selection:
        Image: 'notepad.exe'
    _internal:
        Image: 'evil.exe'
    condition: 1 of them
"#,
        &[
            (json!({"Image": "notepad.exe"}), true),
            (json!({"Image": "evil.exe"}), false),
        ],
    );
}

#[test]
fn contains_modifier() {
    assert_matches(
        r#"
title: Contains
logsource: { category: test }
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#,
        &[
            (json!({"CommandLine": "cmd /c whoami"}), true),
            (json!({"CommandLine": "cmd /c dir"}), false),
        ],
    );
}

#[test]
fn cidr_modifier() {
    assert_matches(
        r#"
title: Cidr
logsource: { category: test }
detection:
    selection:
        DestinationIp|cidr: '192.168.0.0/16'
    condition: selection
"#,
        &[
            (json!({"DestinationIp": "192.168.1.10"}), true),
            (json!({"DestinationIp": "10.0.0.1"}), false),
        ],
    );
}

#[test]
fn keywords() {
    assert_matches(
        r#"
title: Keywords
logsource: { category: test }
detection:
    keywords:
        - whoami
        - mimikatz
    condition: keywords
"#,
        &[
            (json!({"msg": "user ran whoami"}), true),
            (json!({"msg": "nothing here"}), false),
        ],
    );
}

const BOOL_KEYWORD: &str = r#"
title: Bool Keyword
logsource: { category: test }
detection:
    keywords:
        - true
    condition: keywords
"#;

#[test]
fn bool_keywords_search_for_the_word() {
    let cases = [
        (json!({"a": "true"}), true),
        (json!({"msg": "flag is TRUE now"}), true),
        (json!({"a": "false"}), false),
        // Keyword search covers string and number values, not JSON booleans.
        (json!({"a": true}), false),
    ];
    assert_matches(BOOL_KEYWORD, &cases);

    let mut engine = rsigma_eval::Engine::new();
    engine
        .add_collection(&collection_from(BOOL_KEYWORD))
        .expect("compile");
    for (event, expected) in &cases {
        let hit = !engine.evaluate(&JsonEvent::borrow(event)).is_empty();
        assert_eq!(hit, *expected, "engine match mismatch for event {event}");
    }
    let plain = rsigma_eval::PlainEvent::new("debug=true".to_string());
    assert!(!engine.evaluate(&plain).is_empty(), "plain-text event");
}

#[test]
fn field_less_bools_search_for_the_word() {
    let yaml = |key: &str| {
        format!(
            "title: Field-less Bool\nlogsource: {{ category: test }}\ndetection:\n    sel:\n        '{key}': true\n    condition: sel\n"
        )
    };
    assert_matches(
        &yaml(""),
        &[
            (json!({"msg": "flag is TRUE now"}), true),
            (json!({"a": "false"}), false),
            (json!({"a": true}), false),
        ],
    );
    assert_matches(
        &yaml("|neq"),
        &[
            (json!({"msg": "flag is TRUE now"}), false),
            (json!({"a": "false"}), true),
        ],
    );
}

#[test]
fn include_event_attr_captures_event() {
    let yaml = r#"
title: Include Event
logsource: { category: test }
detection:
    selection:
        Image: 'notepad.exe'
    condition: selection
rsigma.include_event: "true"
"#;
    let rule = rule_from(yaml);
    let compiled = compile_rule(&rule).expect("IR compile");
    assert!(compiled.include_event);
    let event = json!({"Image": "notepad.exe"});
    let res = evaluate_rule(&compiled, &JsonEvent::borrow(&event)).expect("match");
    assert!(res.as_detection().unwrap().event.is_some());
}

#[test]
fn modifier_contradiction_is_rejected() {
    let rule = rule_with_item(&["cidr", "contains"], "192.168.0.0/16");
    assert!(compile_rule(&rule).is_err());
}

#[test]
fn collection_with_correlation_parses() {
    // Smoke: a multi-document collection (detection + correlation) parses.
    let _ = collection_from(
        r#"
title: Login
id: login-rule
logsource: { category: auth }
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many Logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
"#,
    );
}
