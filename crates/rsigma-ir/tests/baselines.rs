//! Simple match / no-match / boolean-condition baselines.

mod common;

use common::{engine_from, matches, titles_for};
use serde_json::json;

#[test]
fn simple_match_and_no_match() {
    let engine = engine_from(
        r#"
title: Simple Match
id: simple-match
logsource: { category: test }
detection:
    selection:
        Image: 'cmd.exe'
    condition: selection
level: low
"#,
    );
    assert_eq!(
        titles_for(&engine, &json!({"Image": "cmd.exe"})),
        vec!["Simple Match".to_string()]
    );
    assert!(!matches(&engine, &json!({"Image": "notepad.exe"})));
    assert!(!matches(&engine, &json!({})));
}

#[test]
fn contains_and_not_conditions() {
    let engine = engine_from(
        r#"
title: Contains Not
logsource: { category: test }
detection:
    selection:
        Image: 'good.exe'
    exclusion:
        CommandLine|contains: 'hidden'
    condition: selection and not exclusion
"#,
    );
    assert!(matches(
        &engine,
        &json!({"Image": "good.exe", "CommandLine": "hello"})
    ));
    assert!(!matches(
        &engine,
        &json!({"Image": "good.exe", "CommandLine": "hidden command"})
    ));
}

#[test]
fn and_or_conditions() {
    let engine = engine_from(
        r#"
title: And Or
logsource: { category: test }
detection:
    sel_a:
        Image: 'powershell.exe'
    sel_b:
        CommandLine|contains: '-enc'
    sel_c:
        CommandLine|contains: 'evil'
    condition: sel_a and (sel_b or sel_c)
"#,
    );
    assert!(matches(
        &engine,
        &json!({"Image": "powershell.exe", "CommandLine": "ps -enc aa"})
    ));
    assert!(matches(
        &engine,
        &json!({"Image": "powershell.exe", "CommandLine": "evil tool"})
    ));
    assert!(!matches(
        &engine,
        &json!({"Image": "powershell.exe", "CommandLine": "hello"})
    ));
}

#[test]
fn null_value_match() {
    let engine = engine_from(
        r#"
title: Null Match
logsource: { category: test }
detection:
    selection:
        Process: null
    condition: selection
"#,
    );
    assert!(matches(&engine, &json!({"Process": null})));
    assert!(!matches(&engine, &json!({"Process": "cmd"})));
}

#[test]
fn keywords_match_any_field() {
    let engine = engine_from(
        r#"
title: Keyword Rule
logsource: { category: test }
detection:
    keywords:
        - 'suspicious'
        - 'malware'
    condition: keywords
level: high
"#,
    );
    assert!(matches(
        &engine,
        &json!({"CommandLine": "running suspicious tool"})
    ));
    assert!(matches(&engine, &json!({"Message": "malware dropper"})));
    assert!(!matches(&engine, &json!({"CommandLine": "notepad"})));
}
