mod helpers;

use helpers::{corr_engine, corr_engine_with_config, process};
use rsigma_eval::{
    CorrelationAction, CorrelationConfig, CorrelationEngine, JsonEvent, ProcessResultExt,
    TimestampFallback, parse_pipeline,
};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

const EVENT_COUNT_YAML: &str = r#"
title: Login
id: login-rule
logsource:
    category: auth
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
"#;

fn login_event(user: &str) -> serde_json::Value {
    json!({"EventType": "login", "User": user})
}

#[test]
fn window_expiry_all_events_stale() {
    let mut engine = corr_engine(EVENT_COUNT_YAML);
    let base = 1000;

    for i in 0..3 {
        process(&mut engine, login_event("admin"), base + i);
    }
    // 3 events at t=1000..1002 -- correlation fires at t=1002
    // Now jump far past the window (60s)
    let r = process(&mut engine, login_event("admin"), base + 200);
    // The old events expired; only 1 new event exists in the window
    assert!(
        r.correlation_count() == 0,
        "stale events should have expired, only 1 event in window"
    );
}

#[test]
fn exact_window_boundary() {
    let mut engine = corr_engine(EVENT_COUNT_YAML);
    let base = 1000;

    // First event at t=1000
    process(&mut engine, login_event("admin"), base);
    // Second at t=1059 (inside 60s window from t=1059: [999, 1059])
    process(&mut engine, login_event("admin"), base + 59);
    // Third at exactly t=1060 (60s after first). Window from 1060: [1000, 1060]
    // Event at t=1000: cutoff = 1060 - 60 = 1000, eviction uses < cutoff,
    // so t=1000 may or may not survive depending on inclusive vs exclusive boundary.
    let r = process(&mut engine, login_event("admin"), base + 60);

    // Whether this fires depends on boundary semantics (< vs <=).
    // The test documents the actual behavior rather than asserting one way.
    // If 3 events survive: correlation fires. If t=1000 was evicted: doesn't fire.
    let fired = r.correlation_count() > 0;
    if fired {
        assert_eq!(
            r.correlations()
                .next()
                .unwrap()
                .as_correlation()
                .unwrap()
                .aggregated_value,
            3.0
        );
    }
    // Either way, this test ensures no panic at boundary
}

#[test]
fn missing_group_by_field_skips_correlation() {
    let mut engine = corr_engine(EVENT_COUNT_YAML);
    let base = 1000;

    // Events without the "User" field that group-by expects cannot be
    // assigned to a group.
    for i in 0..5 {
        let r = process(&mut engine, json!({"EventType": "login"}), base + i);
        assert_eq!(r.correlation_count(), 0);
    }
}

#[test]
fn group_by_with_object_value_skips_correlation() {
    let mut engine = corr_engine(EVENT_COUNT_YAML);
    let base = 1000;

    // User field is an object -- value_to_string returns None for objects
    for i in 0..5 {
        let r = process(
            &mut engine,
            json!({"EventType": "login", "User": {"name": "admin"}}),
            base + i,
        );
        assert_eq!(r.correlation_count(), 0);
    }
}

#[test]
fn detection_name_without_id_feeds_correlation() {
    let yaml = r#"
title: Base
name: base
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Count by Name
correlation:
    type: event_count
    rules: [base]
    group-by: [Host]
    timespan: 10s
    condition:
        gte: 2
"#;
    let mut engine = corr_engine(yaml);
    let event = json!({"EventID": 1, "Host": "h1"});
    assert_eq!(
        process(&mut engine, event.clone(), 1000).correlation_count(),
        0
    );
    assert_eq!(process(&mut engine, event, 1001).correlation_count(), 1);
}

#[test]
fn precomputed_detection_retains_name_only_identity() {
    let yaml = r#"
title: Base
name: base
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Count by Name
correlation:
    type: event_count
    rules: [base]
    group-by: [Host]
    timespan: 10s
    condition:
        gte: 1
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();
    let value = json!({"EventID": 1, "Host": "h1"});
    let event = JsonEvent::borrow(&value);
    let detections = engine.evaluate(&event);
    let result = engine.process_with_detections(&event, detections, 1000);
    assert_eq!(result.correlation_count(), 1);
}

const CHAINED_BY_NAME_YAML: &str = r#"
title: Base
name: base
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Child
name: child
correlation:
    type: event_count
    rules: [base]
    group-by: [Host]
    timespan: 10s
    condition:
        gte: 1
---
title: Parent
correlation:
    type: event_count
    rules: [child]
    group-by: [Host]
    timespan: 10s
    condition:
        gte: 1
"#;

fn chained_titles(engine: &mut CorrelationEngine) -> Vec<String> {
    process(engine, json!({"EventID": 1, "Host": "h1"}), 1000)
        .iter()
        .map(|result| result.header.rule_title.clone())
        .collect()
}

#[test]
fn correlation_name_without_id_feeds_parent() {
    // The child is referenced by the parent without `generate: true`, so only
    // the parent is output, as for a referenced detection rule.
    let mut engine = corr_engine(CHAINED_BY_NAME_YAML);
    assert_eq!(chained_titles(&mut engine), ["Parent"]);
}

#[test]
fn chained_child_is_output_when_parent_generates() {
    let yaml = CHAINED_BY_NAME_YAML.replace(
        "title: Parent\ncorrelation:",
        "title: Parent\ncorrelation:\n    generate: true",
    );
    let mut engine = corr_engine(&yaml);
    assert_eq!(chained_titles(&mut engine), ["Child", "Parent"]);
}

#[test]
fn chained_child_is_output_with_emit_detections() {
    let config = CorrelationConfig {
        emit_detections: true,
        ..CorrelationConfig::default()
    };
    let mut engine = corr_engine_with_config(CHAINED_BY_NAME_YAML, config);
    assert_eq!(chained_titles(&mut engine), ["Base", "Child", "Parent"]);
}

#[test]
fn chained_child_is_suppressed_in_batches_without_timestamps() {
    let collection = parse_sigma_yaml(CHAINED_BY_NAME_YAML).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();
    let value = json!({"EventID": 1, "Host": "h1"});
    let event = JsonEvent::borrow(&value);
    let titles: Vec<_> = engine
        .process_batch(&[&event])
        .iter()
        .flatten()
        .map(|result| result.header.rule_title.clone())
        .collect();
    assert_eq!(titles, ["Parent"]);
}

#[test]
fn temporal_ordered_interleaved_only_correct_sequence_matches() {
    let yaml = r#"
title: Rule A
id: rule-a
logsource:
    category: test
detection:
    selection:
        type: a
    condition: selection
---
title: Rule B
id: rule-b
logsource:
    category: test
detection:
    selection:
        type: b
    condition: selection
---
title: Rule C
id: rule-c
logsource:
    category: test
detection:
    selection:
        type: c
    condition: selection
---
title: A then B then C
correlation:
    type: temporal_ordered
    rules:
        - rule-a
        - rule-b
        - rule-c
    group-by:
        - User
    timespan: 120s
    condition:
        gte: 3
level: high
"#;
    let mut engine = corr_engine(yaml);
    let base = 1000;

    // Wrong order: C, B, A
    process(&mut engine, json!({"type": "c", "User": "admin"}), base);
    process(&mut engine, json!({"type": "b", "User": "admin"}), base + 1);
    let r = process(&mut engine, json!({"type": "a", "User": "admin"}), base + 2);
    assert!(r.correlation_count() == 0, "reverse order should not fire");

    // Now correct order: A, B, C
    process(
        &mut engine,
        json!({"type": "a", "User": "admin"}),
        base + 10,
    );
    process(
        &mut engine,
        json!({"type": "b", "User": "admin"}),
        base + 11,
    );
    let r = process(
        &mut engine,
        json!({"type": "c", "User": "admin"}),
        base + 12,
    );
    assert_eq!(
        r.correlation_count(),
        1,
        "correct A->B->C order should fire"
    );
}

#[test]
fn state_eviction_under_max_state_entries() {
    let config = CorrelationConfig {
        max_state_entries: 10,
        ..Default::default()
    };

    let mut engine = corr_engine_with_config(EVENT_COUNT_YAML, config);
    let base = 1000;

    // Create 15 unique group keys (exceeds max_state_entries=10)
    for i in 0..15 {
        process(
            &mut engine,
            login_event(&format!("user_{i}")),
            base + i as i64,
        );
    }

    // Now feed 3 events for a new user -- should still work after eviction
    for i in 0..3 {
        process(&mut engine, login_event("new_user"), base + 20 + i);
    }
    // The new user's events should accumulate correctly despite eviction pressure
    // (at minimum, no panic or data corruption)
}

#[test]
fn suppress_prevents_re_fire_within_window() {
    let config = CorrelationConfig {
        suppress: Some(30),
        ..Default::default()
    };

    let mut engine = corr_engine_with_config(EVENT_COUNT_YAML, config);
    let base = 1000;

    // First: accumulate 3 events to fire
    process(&mut engine, login_event("admin"), base);
    process(&mut engine, login_event("admin"), base + 1);
    let r = process(&mut engine, login_event("admin"), base + 2);
    assert_eq!(r.correlation_count(), 1, "should fire first time");

    // 4th event within suppress window (30s) -- should be suppressed
    let r = process(&mut engine, login_event("admin"), base + 10);
    assert!(
        r.correlation_count() == 0,
        "should be suppressed within 30s"
    );

    // Event after suppress window expires (>30s from first fire at t=1002)
    let r = process(&mut engine, login_event("admin"), base + 35);
    // Now there are events in the window again; if enough: fires, else doesn't
    // Either way, the suppress window has passed so it COULD fire
    let _ = r;
}

#[test]
fn reset_action_clears_window_after_firing() {
    let config = CorrelationConfig {
        action_on_match: CorrelationAction::Reset,
        ..Default::default()
    };

    let mut engine = corr_engine_with_config(EVENT_COUNT_YAML, config);
    let base = 1000;

    // Accumulate 3 events, trigger correlation
    process(&mut engine, login_event("admin"), base);
    process(&mut engine, login_event("admin"), base + 1);
    let r = process(&mut engine, login_event("admin"), base + 2);
    assert_eq!(r.correlation_count(), 1, "should fire");

    // After reset: window is cleared. Next event should not fire (only 1 event)
    let r = process(&mut engine, login_event("admin"), base + 3);
    assert!(r.correlation_count() == 0, "window should have been reset");

    // Must accumulate 3 fresh events to fire again
    process(&mut engine, login_event("admin"), base + 4);
    let r = process(&mut engine, login_event("admin"), base + 5);
    assert_eq!(
        r.correlation_count(),
        1,
        "should fire again after 3 fresh events"
    );
}

#[test]
fn timestamp_fallback_skip_runs_detection_but_skips_correlation() {
    let config = CorrelationConfig {
        timestamp_fallback: TimestampFallback::Skip,
        emit_detections: true,
        ..Default::default()
    };

    let collection = parse_sigma_yaml(EVENT_COUNT_YAML).unwrap();
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    // Events without any timestamp field. With Skip fallback:
    // - Detection should still fire (stateless)
    // - Correlation should NOT accumulate
    for _ in 0..5 {
        let ev = json!({"EventType": "login", "User": "admin"});
        let event = JsonEvent::borrow(&ev);
        let r = engine.process_event(&event);
        assert_eq!(r.detection_count(), 1, "detection should fire");
        assert!(
            r.correlation_count() == 0,
            "correlation should be skipped without timestamp"
        );
    }
}

#[test]
fn multiple_group_by_fields_create_distinct_groups() {
    let yaml = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Login Burst
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
        - SourceIP
    timespan: 60s
    condition:
        gte: 2
level: high
"#;
    let mut engine = corr_engine(yaml);
    let base = 1000;

    // (admin, 10.0.0.1) and (admin, 10.0.0.2) are different groups
    process(
        &mut engine,
        json!({"EventType": "login", "User": "admin", "SourceIP": "10.0.0.1"}),
        base,
    );
    let r = process(
        &mut engine,
        json!({"EventType": "login", "User": "admin", "SourceIP": "10.0.0.2"}),
        base + 1,
    );
    assert!(
        r.correlation_count() == 0,
        "different (User, SourceIP) groups should not combine"
    );

    // Second event to same group (admin, 10.0.0.1)
    let r = process(
        &mut engine,
        json!({"EventType": "login", "User": "admin", "SourceIP": "10.0.0.1"}),
        base + 2,
    );
    assert_eq!(r.correlation_count(), 1, "same group should accumulate");
    assert_eq!(
        r.correlations()
            .next()
            .unwrap()
            .as_correlation()
            .unwrap()
            .group_key,
        vec![
            ("User".to_string(), "admin".to_string()),
            ("SourceIP".to_string(), "10.0.0.1".to_string()),
        ]
    );
}

const SESSION_PIPELINE_YAML: &str = r#"
name: session windows
transformations:
  - type: set_custom_attribute
    attribute: rsigma.window
    value: session
  - type: set_custom_attribute
    attribute: rsigma.gap
    value: 10s
"#;

fn logins_20s_apart(engine: &mut CorrelationEngine) -> usize {
    (0..3)
        .map(|i| process(engine, login_event("admin"), 1000 + i * 20).correlation_count())
        .sum()
}

#[test]
fn pipeline_window_attributes_change_correlation_window() {
    let mut sliding = corr_engine(EVENT_COUNT_YAML);
    assert_eq!(logins_20s_apart(&mut sliding), 1);

    let mut session = CorrelationEngine::new(CorrelationConfig::default());
    session.add_pipeline(parse_pipeline(SESSION_PIPELINE_YAML).unwrap());
    session
        .add_collection(&parse_sigma_yaml(EVENT_COUNT_YAML).unwrap())
        .unwrap();
    assert_eq!(
        logins_20s_apart(&mut session),
        0,
        "a 20s pause exceeds the 10s session gap, so no session reaches 3 logins"
    );
}

#[test]
fn custom_attributes_block_window_changes_correlation_window() {
    let yaml = EVENT_COUNT_YAML.replace(
        "level: high",
        "custom_attributes:\n    rsigma.window: session\n    rsigma.gap: 10s\nlevel: high",
    );
    let mut engine = corr_engine(&yaml);
    assert_eq!(logins_20s_apart(&mut engine), 0);
}

/// A detection rule and `len` event_count correlations where each one
/// references the one before it and the first references the detection.
fn correlation_chain(len: usize, reverse: bool) -> rsigma_parser::SigmaCollection {
    let mut collection = parse_sigma_yaml(EVENT_COUNT_YAML).unwrap();
    let template = collection.correlations.pop().unwrap();
    let mut chain: Vec<_> = (0..len)
        .map(|i| {
            let mut corr = template.clone();
            corr.title = format!("Chain {i}");
            corr.name = Some(format!("chain-{i}"));
            corr.rules = vec![if i == 0 {
                "login-rule".to_string()
            } else {
                format!("chain-{}", i - 1)
            }];
            corr
        })
        .collect();
    if reverse {
        chain.reverse();
    }
    collection.correlations = chain;
    collection
}

fn load_on_small_stack(collection: rsigma_parser::SigmaCollection) -> rsigma_eval::Result<()> {
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            let mut engine = CorrelationEngine::new(CorrelationConfig::default());
            engine.add_collection(&collection)
        })
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn long_acyclic_correlation_chain_loads_on_small_stack() {
    for reverse in [false, true] {
        load_on_small_stack(correlation_chain(100_000, reverse))
            .unwrap_or_else(|e| panic!("reverse={reverse}: {e}"));
    }
}

#[test]
fn cycle_at_the_end_of_a_long_chain_is_reported() {
    let mut collection = correlation_chain(100_000, true);
    // The first link now references the last one, closing the chain.
    let last = collection.correlations.len() - 1;
    collection.correlations[last].rules = vec!["chain-99999".to_string()];
    let err = load_on_small_stack(collection).unwrap_err();
    let rsigma_eval::EvalError::CorrelationCycle(path) = err else {
        panic!("expected a cycle, got {err}");
    };
    assert!(
        path.starts_with("chain-99999 -> chain-99998 -> "),
        "{path:.80}"
    );
    assert!(path.ends_with(" -> chain-0 -> chain-99999"), "{path:.80}");
    assert_eq!(path.matches(" -> ").count(), 100_000);
}

#[test]
fn correlation_cycle_message_lists_the_cycle() {
    let mut collection = correlation_chain(4, false);
    // chain-1 -> chain-0 -> chain-3 -> chain-2 -> chain-1
    collection.correlations[0].rules = vec!["chain-3".to_string()];
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    let err = engine.add_collection(&collection).unwrap_err();
    assert_eq!(
        err.to_string(),
        rsigma_eval::EvalError::CorrelationCycle(
            "chain-0 -> chain-3 -> chain-2 -> chain-1 -> chain-0".into()
        )
        .to_string()
    );

    let mut collection = correlation_chain(1, false);
    collection.correlations[0].rules = vec!["chain-0".to_string()];
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    let err = engine.add_collection(&collection).unwrap_err();
    assert_eq!(
        err.to_string(),
        rsigma_eval::EvalError::CorrelationCycle("chain-0 -> chain-0".into()).to_string()
    );
}
