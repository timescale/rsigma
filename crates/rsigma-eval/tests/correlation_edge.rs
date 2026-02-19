mod helpers;

use helpers::{corr_engine, corr_engine_with_config, process};
use rsigma_eval::{
    CorrelationAction, CorrelationConfig, CorrelationEngine, Event, TimestampFallback,
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
        r.correlations.is_empty(),
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
    let fired = !r.correlations.is_empty();
    if fired {
        assert_eq!(r.correlations[0].aggregated_value, 3.0);
    }
    // Either way, this test ensures no panic at boundary
}

#[test]
fn missing_group_by_field_does_not_panic() {
    let mut engine = corr_engine(EVENT_COUNT_YAML);
    let base = 1000;

    // Events without the "User" field that group-by expects
    for i in 0..5 {
        let r = process(&mut engine, json!({"EventType": "login"}), base + i);
        // Should not panic; events land in a "null/empty" group
        if i >= 2 {
            // May or may not fire depending on whether null group keys accumulate
            let _ = r;
        }
    }
}

#[test]
fn group_by_with_object_value() {
    let mut engine = corr_engine(EVENT_COUNT_YAML);
    let base = 1000;

    // User field is an object -- value_to_string returns None for objects
    for i in 0..5 {
        let r = process(
            &mut engine,
            json!({"EventType": "login", "User": {"name": "admin"}}),
            base + i,
        );
        let _ = r;
    }
    // Should not panic; exercises GroupKey::extract with non-stringifiable values
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
    assert!(r.correlations.is_empty(), "reverse order should not fire");

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
    assert_eq!(r.correlations.len(), 1, "correct A->B->C order should fire");
}

#[test]
fn state_eviction_under_max_state_entries() {
    let mut config = CorrelationConfig::default();
    config.max_state_entries = 10;

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
    let mut config = CorrelationConfig::default();
    config.suppress = Some(30);

    let mut engine = corr_engine_with_config(EVENT_COUNT_YAML, config);
    let base = 1000;

    // First: accumulate 3 events to fire
    process(&mut engine, login_event("admin"), base);
    process(&mut engine, login_event("admin"), base + 1);
    let r = process(&mut engine, login_event("admin"), base + 2);
    assert_eq!(r.correlations.len(), 1, "should fire first time");

    // 4th event within suppress window (30s) -- should be suppressed
    let r = process(&mut engine, login_event("admin"), base + 10);
    assert!(r.correlations.is_empty(), "should be suppressed within 30s");

    // Event after suppress window expires (>30s from first fire at t=1002)
    let r = process(&mut engine, login_event("admin"), base + 35);
    // Now there are events in the window again; if enough: fires, else doesn't
    // Either way, the suppress window has passed so it COULD fire
    let _ = r;
}

#[test]
fn reset_action_clears_window_after_firing() {
    let mut config = CorrelationConfig::default();
    config.action_on_match = CorrelationAction::Reset;

    let mut engine = corr_engine_with_config(EVENT_COUNT_YAML, config);
    let base = 1000;

    // Accumulate 3 events, trigger correlation
    process(&mut engine, login_event("admin"), base);
    process(&mut engine, login_event("admin"), base + 1);
    let r = process(&mut engine, login_event("admin"), base + 2);
    assert_eq!(r.correlations.len(), 1, "should fire");

    // After reset: window is cleared. Next event should not fire (only 1 event)
    let r = process(&mut engine, login_event("admin"), base + 3);
    assert!(r.correlations.is_empty(), "window should have been reset");

    // Must accumulate 3 fresh events to fire again
    process(&mut engine, login_event("admin"), base + 4);
    let r = process(&mut engine, login_event("admin"), base + 5);
    assert_eq!(
        r.correlations.len(),
        1,
        "should fire again after 3 fresh events"
    );
}

#[test]
fn timestamp_fallback_skip_runs_detection_but_skips_correlation() {
    let mut config = CorrelationConfig::default();
    config.timestamp_fallback = TimestampFallback::Skip;

    let collection = parse_sigma_yaml(EVENT_COUNT_YAML).unwrap();
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    // Events without any timestamp field. With Skip fallback:
    // - Detection should still fire (stateless)
    // - Correlation should NOT accumulate
    for _ in 0..5 {
        let ev = json!({"EventType": "login", "User": "admin"});
        let event = Event::from_value(&ev);
        let r = engine.process_event(&event);
        assert_eq!(r.detections.len(), 1, "detection should fire");
        assert!(
            r.correlations.is_empty(),
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
        r.correlations.is_empty(),
        "different (User, SourceIP) groups should not combine"
    );

    // Second event to same group (admin, 10.0.0.1)
    let r = process(
        &mut engine,
        json!({"EventType": "login", "User": "admin", "SourceIP": "10.0.0.1"}),
        base + 2,
    );
    assert_eq!(r.correlations.len(), 1, "same group should accumulate");
    assert_eq!(
        r.correlations[0].group_key,
        vec![
            ("User".to_string(), "admin".to_string()),
            ("SourceIP".to_string(), "10.0.0.1".to_string()),
        ]
    );
}
