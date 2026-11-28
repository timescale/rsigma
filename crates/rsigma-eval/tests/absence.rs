//! End-to-end absence correlation behavior: firing from event time, evidence,
//! chaining, and the batch path.

mod helpers;

use helpers::{corr_engine, corr_engine_with_config, process};
use rsigma_eval::CorrelationConfig;
use serde_json::json;

const LOGIN_WITHOUT_MFA: &str = r#"
title: Login
id: login_success
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: MFA
id: mfa_success
logsource:
    category: auth
detection:
    selection:
        EventType: mfa
    condition: selection
---
title: Login without MFA
name: login_without_mfa
correlation:
    type: temporal_ordered
    rules:
        - login_success
        - mfa_success
    group-by:
        - User
    timespan: 5m
    condition: login_success and not mfa_success
rsigma.absence_grace: 30s
"#;

fn login(user: &str) -> serde_json::Value {
    json!({"EventType": "login", "User": user})
}

fn mfa(user: &str) -> serde_json::Value {
    json!({"EventType": "mfa", "User": user})
}

#[test]
fn login_without_mfa_fires_after_the_deadline_and_grace() {
    let mut engine = corr_engine(LOGIN_WITHOUT_MFA);
    let results = process(&mut engine, login("alice"), 1_735_689_600);
    assert!(results.is_empty(), "{results:?}");

    let fired = engine.advance_clock(None, 1_735_689_600 + 300 + 30);
    assert!(fired.is_empty(), "fires only strictly after fire_at");
    let fired = engine.advance_clock(None, 1_735_689_600 + 300 + 31);
    assert_eq!(fired.len(), 1);

    let body = fired[0].as_correlation().unwrap();
    let absence = body.absence.as_ref().expect("absence detail");
    assert_eq!(absence.missing, ["mfa_success"]);
    assert_eq!(absence.window_start, 1_735_689_600);
    assert_eq!(absence.deadline, 1_735_689_900);
    assert_eq!(body.aggregated_value, 1.0);
}

#[test]
fn mfa_in_the_window_prevents_the_alert() {
    let mut engine = corr_engine(LOGIN_WITHOUT_MFA);
    process(&mut engine, login("alice"), 1000);
    process(&mut engine, mfa("alice"), 1010);
    assert!(engine.advance_clock(None, 2000).is_empty());
}

#[test]
fn temporal_accepts_a_negated_hit_before_the_positive() {
    let yaml = LOGIN_WITHOUT_MFA.replace("type: temporal_ordered", "type: temporal");
    let mut engine = corr_engine(&yaml);
    process(&mut engine, mfa("alice"), 1000);
    process(&mut engine, login("alice"), 1100);
    assert!(engine.advance_clock(None, 2000).is_empty());

    let mut engine = corr_engine(&yaml);
    process(&mut engine, login("alice"), 1000);
    process(&mut engine, mfa("alice"), 1010);
    assert!(engine.advance_clock(None, 2000).is_empty());
}

#[test]
fn an_absence_child_chains_into_an_event_count_parent() {
    let yaml = format!(
        "{LOGIN_WITHOUT_MFA}---
title: Many missing MFA
name: many_missing
correlation:
    type: event_count
    rules: [login_without_mfa]
    group-by: [User]
    timespan: 5m
    condition:
        gte: 1
"
    );
    let mut engine = corr_engine(&yaml);
    process(&mut engine, login("alice"), 1000);
    let fired = engine.advance_clock(None, 1400);
    let titles: Vec<&str> = fired.iter().map(|r| r.header.rule_title.as_str()).collect();
    assert_eq!(titles, ["Many missing MFA"]);
}

#[test]
fn a_fired_child_correlation_cancels_a_parent_negated_reference() {
    let yaml = r#"
title: A
id: a_rule
logsource:
    category: test
detection:
    selection:
        Action: a
    condition: selection
---
title: B
id: b_rule
logsource:
    category: test
detection:
    selection:
        Action: b
    condition: selection
---
title: Child
name: child
correlation:
    type: event_count
    rules: [b_rule]
    group-by: [User]
    timespan: 5m
    condition:
        gte: 1
---
title: A without child
correlation:
    type: temporal
    rules: [a_rule, child]
    group-by: [User]
    timespan: 5m
    condition: a_rule and not child
"#;
    let mut engine = corr_engine_with_config(
        yaml,
        CorrelationConfig {
            emit_detections: true,
            ..CorrelationConfig::default()
        },
    );
    process(&mut engine, json!({"Action": "b", "User": "alice"}), 1000);
    process(&mut engine, json!({"Action": "a", "User": "alice"}), 1100);
    assert!(engine.advance_clock(None, 2000).is_empty());
}

#[test]
fn absence_evidence_is_filtered_to_the_satisfying_range() {
    let yaml = r#"
title: A
id: a_rule
logsource:
    category: test
detection:
    selection:
        Action: a
    condition: selection
---
title: C
id: c_rule
logsource:
    category: test
detection:
    selection:
        Action: c
    condition: selection
---
title: B
id: b_rule
logsource:
    category: test
detection:
    selection:
        Action: b
    condition: selection
---
title: A or C without B
correlation:
    type: temporal
    rules: [a_rule, b_rule, c_rule]
    group-by: [User]
    timespan: 5m
    condition: (a_rule or c_rule) and not b_rule
rsigma.correlation_event_mode: refs
"#;
    let mut engine = corr_engine(yaml);
    process(&mut engine, json!({"Action": "c", "User": "alice"}), 900);
    process(&mut engine, json!({"Action": "a", "User": "alice"}), 1000);
    let fired = engine.advance_clock(None, 2000);
    assert_eq!(fired.len(), 2);
    let body = fired[1].as_correlation().unwrap();
    let refs = body.event_refs.as_ref().expect("refs");
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].timestamp, 1000);
    let sources = body.event_sources.as_ref().expect("sources");
    assert_eq!(sources[0].rule.as_deref(), Some("a_rule"));
}

#[test]
fn full_event_mode_reports_the_contributing_event() {
    let yaml = format!("{LOGIN_WITHOUT_MFA}rsigma.correlation_event_mode: full\n");
    let mut engine = corr_engine(&yaml);
    process(&mut engine, login("alice"), 1000);
    let fired = engine.advance_clock(None, 1400);
    let body = fired[0].as_correlation().unwrap();
    let events = body.events.as_ref().expect("events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["EventType"], "login");
}

#[test]
fn correlation_only_output_is_suppressed_without_generate() {
    let yaml = format!(
        "{LOGIN_WITHOUT_MFA}---
title: Parent
name: parent
correlation:
    type: event_count
    rules: [login_without_mfa]
    group-by: [User]
    timespan: 5m
    condition:
        gte: 1
"
    );
    let mut engine = corr_engine(&yaml);
    process(&mut engine, login("alice"), 1000);
    let fired = engine.advance_clock(None, 1400);
    let titles: Vec<&str> = fired.iter().map(|r| r.header.rule_title.as_str()).collect();
    assert_eq!(titles, ["Parent"]);
}

#[test]
fn batch_processing_matches_per_event_processing() {
    let events = [login("alice"), mfa("bob"), login("bob"), mfa("alice")];
    let timestamps = [1000, 1010, 1020, 1030];

    let mut per_event = corr_engine(LOGIN_WITHOUT_MFA);
    let mut expected: Vec<Vec<rsigma_eval::EvaluationResult>> = Vec::new();
    for (event, ts) in events.iter().zip(timestamps) {
        expected.push(process(&mut per_event, event.clone(), ts));
    }

    let borrowed: Vec<rsigma_eval::JsonEvent> =
        events.iter().map(rsigma_eval::JsonEvent::borrow).collect();
    let refs: Vec<&rsigma_eval::JsonEvent> = borrowed.iter().collect();
    let mut batch = corr_engine(LOGIN_WITHOUT_MFA);
    let actual = batch.process_batch(&refs);
    let render = |batches: Vec<Vec<rsigma_eval::EvaluationResult>>| -> Vec<Vec<String>> {
        batches
            .into_iter()
            .map(|batch| {
                batch
                    .iter()
                    .map(|result| serde_json::to_string(result).unwrap())
                    .collect()
            })
            .collect()
    };
    assert_eq!(render(actual), render(expected));
}
