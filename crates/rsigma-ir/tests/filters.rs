//! Filter-rule fixtures.
//!
//! Lock parse + legacy `Engine::apply_filter` / `add_collection` behavior so
//! `lower_filter` has a concrete oracle.

mod common;

use common::{collection_from, filter_from, matches};
use rsigma_eval::Engine;
use rsigma_parser::FilterRuleTarget;
use serde_json::json;

#[test]
fn filter_rule_parses_specific_target() {
    let filter = filter_from(
        r#"
title: Suspicious Process
id: rule-001
logsource: { category: test }
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Filter SYSTEM
filter:
    rules:
        - rule-001
    selection:
        User: 'SYSTEM'
    condition: not selection
"#,
    );
    assert_eq!(filter.title, "Filter SYSTEM");
    assert_eq!(
        filter.rules,
        FilterRuleTarget::Specific(vec!["rule-001".to_string()])
    );
    assert!(filter.detection.named.contains_key("selection"));
}

#[test]
fn filter_excludes_matching_events() {
    let collection = collection_from(
        r#"
title: Suspicious Process
id: rule-001
logsource: { category: test }
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: high
---
title: Filter SYSTEM
filter:
    rules:
        - rule-001
    selection:
        User: 'SYSTEM'
    condition: not selection
"#,
    );
    let mut engine = Engine::new();
    engine
        .add_collection(&collection)
        .expect("detection + filter must compile");

    assert!(matches(
        &engine,
        &json!({"CommandLine": "whoami", "User": "admin"})
    ));
    assert!(!matches(
        &engine,
        &json!({"CommandLine": "whoami", "User": "SYSTEM"})
    ));
}

#[test]
fn filter_rules_any_applies_to_all_detections() {
    let collection = collection_from(
        r#"
title: Detection A
id: det-a
logsource: { category: test }
detection:
    sel:
        EventType: alert
    condition: sel
---
title: Filter Out Test Env
filter:
    rules: any
    selection:
        Environment: 'test'
    condition: not selection
"#,
    );
    let mut engine = Engine::new();
    engine
        .add_collection(&collection)
        .expect("filter rules: any must compile");

    assert!(matches(
        &engine,
        &json!({"EventType": "alert", "Environment": "prod"})
    ));
    assert!(!matches(
        &engine,
        &json!({"EventType": "alert", "Environment": "test"})
    ));
}
