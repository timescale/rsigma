//! Correlation-rule fixtures.
//!
//! Lock parse + legacy correlation-engine behavior so `lower_correlation`
//! has a concrete oracle.

mod common;

use common::{collection_from, correlation_from};
use rsigma_eval::{CorrelationConfig, CorrelationEngine, JsonEvent};
use rsigma_parser::{ConditionOperator, CorrelationCondition, CorrelationType};
use serde_json::json;

#[test]
fn correlation_event_count_parses() {
    let corr = correlation_from(
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
id: many-logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
level: high
"#,
    );
    assert_eq!(corr.title, "Many Logins");
    assert_eq!(corr.id.as_deref(), Some("many-logins"));
    assert_eq!(corr.correlation_type, CorrelationType::EventCount);
    assert_eq!(corr.rules, vec!["login-rule".to_string()]);
    assert_eq!(corr.group_by, vec!["User".to_string()]);
    assert!(!corr.generate);
    match &corr.condition {
        CorrelationCondition::Threshold {
            predicates, field, ..
        } => {
            assert_eq!(predicates, &[(ConditionOperator::Gte, 3)]);
            assert!(field.is_none());
        }
        other => panic!("expected threshold condition, got {other:?}"),
    }
}

#[test]
fn correlation_event_count_fires_on_threshold() {
    let collection = collection_from(
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
level: high
"#,
    );
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine
        .add_collection(&collection)
        .expect("correlation collection must compile");

    for i in 0..3 {
        let v = json!({"EventType": "login", "User": "admin"});
        let event = JsonEvent::borrow(&v);
        let result = engine.process_event_at(&event, 1000 + i);
        if i < 2 {
            assert!(
                result.iter().all(|r| !r.is_correlation()),
                "should not fire before threshold"
            );
        } else {
            let correlations = result.iter().filter(|r| r.is_correlation()).count();
            assert_eq!(correlations, 1, "third event must fire the correlation");
        }
    }
}
