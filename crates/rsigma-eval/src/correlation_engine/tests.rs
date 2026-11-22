use super::*;
use crate::event::JsonEvent;
use crate::result::ProcessResultExt;
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

// =========================================================================
// Timestamp parsing
// =========================================================================

#[test]
fn test_parse_timestamp_epoch_secs() {
    let val = EventValue::Int(1720612200);
    assert_eq!(parse_timestamp_value(&val), Some(1720612200));
}

#[test]
fn test_parse_timestamp_epoch_millis() {
    let val = EventValue::Int(1720612200000);
    assert_eq!(parse_timestamp_value(&val), Some(1720612200));
}

#[test]
fn test_parse_timestamp_rfc3339() {
    let val = EventValue::Str(std::borrow::Cow::Borrowed("2024-07-10T12:30:00Z"));
    let ts = parse_timestamp_value(&val).unwrap();
    assert_eq!(ts, 1720614600);
}

#[test]
fn test_parse_timestamp_naive() {
    let val = EventValue::Str(std::borrow::Cow::Borrowed("2024-07-10T12:30:00"));
    let ts = parse_timestamp_value(&val).unwrap();
    assert_eq!(ts, 1720614600);
}

#[test]
fn test_parse_timestamp_with_space() {
    let val = EventValue::Str(std::borrow::Cow::Borrowed("2024-07-10 12:30:00"));
    let ts = parse_timestamp_value(&val).unwrap();
    assert_eq!(ts, 1720614600);
}

#[test]
fn test_parse_timestamp_fractional() {
    let val = EventValue::Str(std::borrow::Cow::Borrowed("2024-07-10T12:30:00.123Z"));
    let ts = parse_timestamp_value(&val).unwrap();
    assert_eq!(ts, 1720614600);
}

#[test]
fn test_parse_timestamp_every_form() {
    for (val, expected) in [
        (json!("2024-07-10T12:30:00Z"), Some(1720614600)),
        (json!("2024-07-10T12:30:00.500Z"), Some(1720614600)),
        (json!("2024-07-10T14:30:00+02:00"), Some(1720614600)),
        (json!("2024-07-10T12:30:00"), Some(1720614600)),
        (json!("2024-07-10T12:30:00.500"), Some(1720614600)),
        (json!("2024-07-10 12:30:00"), Some(1720614600)),
        (json!("2024-07-10 12:30:00.500"), Some(1720614600)),
        (json!(1720614600), Some(1720614600)),
        (json!(1720614600500_i64), Some(1720614600)),
        (json!(1720614600.5), Some(1720614600)),
        (json!("garbage"), None),
        (json!(-1), None),
        (json!(-1720614600500_i64), None),
        (json!(-0.5), None),
        (json!(1e300), None),
        (json!(u64::MAX), None),
        (json!(i64::MAX), None),
        (json!("1969-12-31T23:59:59Z"), None),
    ] {
        let event = json!({ "ts": val });
        let event = JsonEvent::borrow(&event);
        let field = event.get_field("ts").unwrap();
        assert_eq!(parse_timestamp_value(&field), expected, "{val}");
    }
}

#[test]
fn test_extract_timestamp_from_event() {
    let config = CorrelationConfig {
        timestamp_fields: vec!["@timestamp".to_string()],
        max_state_entries: 100_000,
        ..Default::default()
    };
    let engine = CorrelationEngine::new(config);

    let v = json!({"@timestamp": "2024-07-10T12:30:00Z", "data": "test"});
    let event = JsonEvent::borrow(&v);
    let ts = engine.extract_event_timestamp(&event);
    assert_eq!(ts, Some(1720614600));
}

#[test]
fn test_extract_timestamp_fallback_fields() {
    let config = CorrelationConfig {
        timestamp_fields: vec![
            "@timestamp".to_string(),
            "timestamp".to_string(),
            "EventTime".to_string(),
        ],
        max_state_entries: 100_000,
        ..Default::default()
    };
    let engine = CorrelationEngine::new(config);

    // First field missing, second field present
    let v = json!({"timestamp": 1720613400, "data": "test"});
    let event = JsonEvent::borrow(&v);
    let ts = engine.extract_event_timestamp(&event);
    assert_eq!(ts, Some(1720613400));
}

#[test]
fn test_extract_timestamp_skips_out_of_range_fields() {
    let config = CorrelationConfig {
        timestamp_fields: vec!["@timestamp".to_string(), "timestamp".to_string()],
        ..Default::default()
    };
    let engine = CorrelationEngine::new(config);

    for bad in [
        json!(-5),
        json!(1e300),
        json!(i64::MAX),
        json!("1900-01-01T00:00:00Z"),
    ] {
        let v = json!({"@timestamp": bad, "timestamp": 1720613400});
        let event = JsonEvent::borrow(&v);
        assert_eq!(
            engine.extract_event_timestamp(&event),
            Some(1720613400),
            "{bad} should fall through to the next field",
        );

        let v = json!({"@timestamp": bad});
        let event = JsonEvent::borrow(&v);
        assert_eq!(engine.extract_event_timestamp(&event), None, "{bad}");
    }
}

#[test]
fn test_out_of_range_timestamp_uses_the_skip_fallback() {
    let yaml = r#"
title: test rule
id: ts-range-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
level: low
---
title: test correlation
correlation:
    type: event_count
    rules:
        - ts-range-rule
    group-by:
        - User
    timespan: 10s
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig {
        timestamp_fallback: TimestampFallback::Skip,
        emit_detections: true,
        ..Default::default()
    });
    engine.add_collection(&collection).unwrap();

    for ts in [json!(-100), json!(-200), json!(1e300), json!(1e301)] {
        let v = json!({"action": "click", "User": "alice", "@timestamp": ts});
        let event = JsonEvent::borrow(&v);
        let r = engine.process_event(&event);
        assert!(r.detection_count() > 0, "detection should still fire");
        assert_eq!(
            r.correlation_count(),
            0,
            "{ts} must not feed correlation state"
        );
    }
    assert_eq!(engine.state_count(), 0);
}

#[test]
fn test_extract_timestamp_returns_none_when_missing() {
    let config = CorrelationConfig {
        timestamp_fields: vec!["@timestamp".to_string()],
        ..Default::default()
    };
    let engine = CorrelationEngine::new(config);

    let v = json!({"data": "no timestamp here"});
    let event = JsonEvent::borrow(&v);
    assert_eq!(engine.extract_event_timestamp(&event), None);
}

#[test]
fn test_timestamp_fallback_skip() {
    let yaml = r#"
title: test rule
id: ts-skip-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
level: low
---
title: test correlation
correlation:
    type: event_count
    rules:
        - ts-skip-rule
    group-by:
        - User
    timespan: 10s
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig {
        timestamp_fallback: TimestampFallback::Skip,
        emit_detections: true,
        ..Default::default()
    });
    engine.add_collection(&collection).unwrap();
    assert_eq!(engine.correlation_rule_count(), 1);

    // Events with no timestamp field — should NOT update correlation state
    let v = json!({"action": "click", "User": "alice"});
    let event = JsonEvent::borrow(&v);

    let r1 = engine.process_event(&event);
    assert!(r1.detection_count() > 0, "detection should still fire");

    let r2 = engine.process_event(&event);
    assert!(r2.detection_count() > 0, "detection should still fire");

    let r3 = engine.process_event(&event);
    assert!(r3.detection_count() > 0, "detection should still fire");

    // No correlations should fire because events were skipped
    assert!(r1.correlation_count() == 0);
    assert!(r2.correlation_count() == 0);
    assert!(r3.correlation_count() == 0);
}

#[test]
fn test_timestamp_fallback_wallclock_default() {
    let yaml = r#"
title: test rule
id: ts-wc-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
level: low
---
title: test correlation
correlation:
    type: event_count
    rules:
        - ts-wc-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();
    assert_eq!(engine.correlation_rule_count(), 1);

    // Events with no timestamp — WallClock fallback means they get Utc::now()
    // and should be close enough to correlate (generous 60s window)
    let v = json!({"action": "click", "User": "alice"});
    let event = JsonEvent::borrow(&v);

    let _r1 = engine.process_event(&event);
    let _r2 = engine.process_event(&event);
    let r3 = engine.process_event(&event);

    // With WallClock, all events get near-identical timestamps and should correlate
    assert!(
        r3.correlation_count() > 0,
        "WallClock fallback should allow correlation"
    );
}

// =========================================================================
// Event count correlation
// =========================================================================

#[test]
fn test_event_count_basic() {
    let yaml = r#"
title: Base Rule
id: base-rule-001
name: base_rule
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: low
---
title: Multiple Whoami
id: corr-001
correlation:
    type: event_count
    rules:
        - base-rule-001
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    assert_eq!(engine.detection_rule_count(), 1);
    assert_eq!(engine.correlation_rule_count(), 1);

    // Send 3 events from same user within the window
    let base_ts = 1000i64;
    for i in 0..3 {
        let v = json!({"CommandLine": "whoami", "User": "admin"});
        let event = JsonEvent::borrow(&v);
        let result = engine.process_event_at(&event, base_ts + i * 10);

        // The referenced detection feeds correlation state but is not emitted.
        assert_eq!(result.detection_count(), 0);

        if i < 2 {
            // Not enough events yet
            assert!(result.correlation_count() == 0);
        } else {
            // 3rd event triggers the correlation
            assert_eq!(result.correlation_count(), 1);
            assert_eq!(
                result.correlations().next().unwrap().header.rule_title,
                "Multiple Whoami"
            );
            assert_eq!(
                result
                    .correlations()
                    .next()
                    .unwrap()
                    .as_correlation()
                    .unwrap()
                    .aggregated_value,
                3.0
            );
        }
    }
}

#[test]
fn test_event_count_different_groups() {
    let yaml = r#"
title: Login
id: login-001
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
level: low
---
title: Many Logins
id: corr-login
correlation:
    type: event_count
    rules:
        - login-001
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    // User "alice" sends 2 events, "bob" sends 3
    let ts = 1000i64;
    for i in 0..2 {
        let v = json!({"EventType": "login", "User": "alice"});
        let event = JsonEvent::borrow(&v);
        let r = engine.process_event_at(&event, ts + i);
        assert!(r.correlation_count() == 0);
    }
    for i in 0..3 {
        let v = json!({"EventType": "login", "User": "bob"});
        let event = JsonEvent::borrow(&v);
        let r = engine.process_event_at(&event, ts + i);
        if i == 2 {
            assert_eq!(r.correlation_count(), 1);
            assert_eq!(
                r.correlations()
                    .next()
                    .unwrap()
                    .as_correlation()
                    .unwrap()
                    .group_key,
                vec![("User".to_string(), "bob".to_string())]
            );
        }
    }
}

#[test]
fn test_event_count_window_expiry() {
    let yaml = r#"
title: Base
id: base-002
logsource:
    category: test
detection:
    selection:
        action: click
    condition: selection
---
title: Rapid Clicks
id: corr-002
correlation:
    type: event_count
    rules:
        - base-002
    group-by:
        - User
    timespan: 10s
    condition:
        gte: 3
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    // Send 2 events at t=0,1 then 1 event at t=15 (outside window)
    let v = json!({"action": "click", "User": "admin"});
    let event = JsonEvent::borrow(&v);
    engine.process_event_at(&event, 0);
    engine.process_event_at(&event, 1);
    let r = engine.process_event_at(&event, 15);
    // Only 1 event in window [5, 15], not enough
    assert!(r.correlation_count() == 0);
}

// =========================================================================
// Window modes: tumbling and session
// =========================================================================

/// Build an `event_count` correlation with the given window/gap settings.
fn window_mode_yaml(window_lines: &str) -> String {
    format!(
        r#"
title: Base
id: base-win
logsource:
    category: test
detection:
    selection:
        action: click
    condition: selection
---
title: Windowed Clicks
id: corr-win
correlation:
    type: event_count
    rules:
        - base-win
    group-by:
        - User
{window_lines}
    condition:
        gte: 3
level: medium
"#
    )
}

fn windowed_engine(window_lines: &str) -> CorrelationEngine {
    let collection = parse_sigma_yaml(&window_mode_yaml(window_lines)).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();
    engine
}

#[test]
fn test_tumbling_window_fires_within_bucket() {
    let mut engine = windowed_engine("    timespan: 10s\n    window: tumbling");
    let v = json!({"action": "click", "User": "admin"});
    let event = JsonEvent::borrow(&v);
    // t=1,2,3 are all in bucket [0,10): three events -> fires.
    engine.process_event_at(&event, 1);
    engine.process_event_at(&event, 2);
    let r = engine.process_event_at(&event, 3);
    assert_eq!(r.correlation_count(), 1);
}

#[test]
fn test_tumbling_window_misses_across_boundary() {
    let mut engine = windowed_engine("    timespan: 10s\n    window: tumbling");
    let v = json!({"action": "click", "User": "admin"});
    let event = JsonEvent::borrow(&v);
    // t=8,9 are in bucket [0,10); t=12 starts bucket [10,20) and resets state.
    engine.process_event_at(&event, 8);
    engine.process_event_at(&event, 9);
    let r = engine.process_event_at(&event, 12);
    // Three events within 4s, but split across the tumbling boundary -> no fire.
    assert_eq!(r.correlation_count(), 0);
}

#[test]
fn test_sliding_window_catches_across_boundary() {
    // The same timestamps the tumbling test misses fire under a sliding window,
    // which is the boundary-miss the feature lets authors avoid.
    let mut engine = windowed_engine("    timespan: 10s\n    window: sliding");
    let v = json!({"action": "click", "User": "admin"});
    let event = JsonEvent::borrow(&v);
    engine.process_event_at(&event, 8);
    engine.process_event_at(&event, 9);
    let r = engine.process_event_at(&event, 12);
    // Window (2,12] contains all three events -> fires.
    assert_eq!(r.correlation_count(), 1);
}

#[test]
fn test_session_window_extends_within_gap() {
    let mut engine = windowed_engine("    window: session\n    gap: 5s\n    timespan: 100s");
    let v = json!({"action": "click", "User": "admin"});
    let event = JsonEvent::borrow(&v);
    // Steps 4s apart stay in one session; total span 8s is under the 100s cap.
    engine.process_event_at(&event, 0);
    engine.process_event_at(&event, 4);
    let r = engine.process_event_at(&event, 8);
    assert_eq!(r.correlation_count(), 1);
}

#[test]
fn test_session_window_resets_after_gap() {
    let mut engine = windowed_engine("    window: session\n    gap: 5s\n    timespan: 100s");
    let v = json!({"action": "click", "User": "admin"});
    let event = JsonEvent::borrow(&v);
    // The 16s gap before t=20 exceeds the 5s gap, so the session restarts.
    engine.process_event_at(&event, 0);
    engine.process_event_at(&event, 4);
    let r = engine.process_event_at(&event, 20);
    assert_eq!(r.correlation_count(), 0);
}

#[test]
fn test_session_window_caps_at_timespan() {
    let mut engine = windowed_engine("    window: session\n    gap: 100s\n    timespan: 10s");
    let v = json!({"action": "click", "User": "admin"});
    let event = JsonEvent::borrow(&v);
    // Gaps are small, but t=12 would push the span past the 10s cap -> restart.
    engine.process_event_at(&event, 0);
    engine.process_event_at(&event, 5);
    let r = engine.process_event_at(&event, 12);
    assert_eq!(r.correlation_count(), 0);
}

#[test]
fn test_tumbling_late_event_does_not_wipe_bucket() {
    let mut engine = windowed_engine("    timespan: 10s\n    window: tumbling");
    let v = json!({"action": "click", "User": "admin"});
    let event = JsonEvent::borrow(&v);
    // t=12,15 accumulate in bucket [10,20).
    engine.process_event_at(&event, 12);
    engine.process_event_at(&event, 15);
    // A late arrival from the previous bucket [0,10) is discarded instead of
    // resetting the active bucket.
    let late = engine.process_event_at(&event, 9);
    assert_eq!(late.correlation_count(), 0);
    // The bucket still holds t=12,15, so the third in-bucket event fires.
    let r = engine.process_event_at(&event, 16);
    assert_eq!(r.correlation_count(), 1);
}

#[test]
fn test_evict_expired_preserves_session_cap() {
    // Regression: time-based eviction must not trim the front of a live
    // session. Doing so forgets the true session start and lets the window
    // exceed the `timespan` cap (drifting toward sliding semantics).
    let mut engine = windowed_engine("    window: session\n    gap: 10s\n    timespan: 20s");
    let v = json!({"action": "click", "User": "admin"});
    let event = JsonEvent::borrow(&v);
    // Session: t=0,9,16 (gaps 9s and 7s, span 16s <= 20s cap) -> fires.
    engine.process_event_at(&event, 0);
    engine.process_event_at(&event, 9);
    let r = engine.process_event_at(&event, 16);
    assert_eq!(r.correlation_count(), 1);
    // At now=21 the session is live (21-16=5s <= 10s gap). A trailing-cutoff
    // eviction would trim t=0 (21-20=1) and forget the session start.
    engine.evict_expired(21);
    // t=24 extends within the gap (24-16=8s) but exceeds the cap from the true
    // start (24-0=24s > 20s), so the session must restart with count 1, not
    // accumulate t=9,16,24 and fire again.
    let r = engine.process_event_at(&event, 24);
    assert_eq!(r.correlation_count(), 0);
}

#[test]
fn test_evict_expired_drops_stale_session_group() {
    let mut engine = windowed_engine("    window: session\n    gap: 10s\n    timespan: 20s");
    let v = json!({"action": "click", "User": "admin"});
    let event = JsonEvent::borrow(&v);
    engine.process_event_at(&event, 0);
    engine.process_event_at(&event, 9);
    // At now=40 the session is dead (40-9=31s > 10s gap): the whole group is
    // dropped rather than partially trimmed.
    engine.evict_expired(40);
    // A fresh event starts a new session from scratch.
    engine.process_event_at(&event, 41);
    let r = engine.process_event_at(&event, 45);
    // Only two events in the new session -> no fire (gte 3).
    assert_eq!(r.correlation_count(), 0);
}

// =========================================================================
// Per-group entry cap (max_group_entries)
// =========================================================================

fn windowed_engine_with_group_cap(window_lines: &str, cap: usize) -> CorrelationEngine {
    let collection = parse_sigma_yaml(&window_mode_yaml(window_lines)).unwrap();
    let config = CorrelationConfig {
        max_group_entries: Some(cap),
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();
    engine
}

#[test]
fn test_hard_cap_evicts_the_stalest_groups() {
    let collection = parse_sigma_yaml(&window_mode_yaml("    timespan: 1h")).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig {
        max_state_entries: 20,
        ..Default::default()
    });
    engine.add_collection(&collection).unwrap();

    // Twenty groups whose latest timestamps arrive out of order.
    let latest = |i: i64| 100 + (i * 7) % 20;
    for i in 0..20 {
        let v = json!({"action": "click", "User": format!("user_{i}")});
        engine.process_event_at(&JsonEvent::borrow(&v), latest(i));
    }
    assert_eq!(engine.state_count(), 20);

    // The cap is reached, so the next new group trims the state to 90% first:
    // the two groups with the oldest latest timestamps go.
    let v = json!({"action": "click", "User": "newcomer"});
    engine.process_event_at(&JsonEvent::borrow(&v), 200);

    let users: std::collections::HashSet<String> = engine
        .state
        .keys()
        .filter_map(|key| key.group_key.0[0].clone())
        .collect();
    assert_eq!(users.len(), 19);
    assert!(users.contains("newcomer"));
    let evicted: Vec<String> = (0..20)
        .filter(|&i| latest(i) < 102)
        .map(|i| format!("user_{i}"))
        .collect();
    assert_eq!(evicted.len(), 2);
    for user in &evicted {
        assert!(!users.contains(user), "{user} is among the stalest");
    }

    // A cap of one evicts every entry before each new group.
    let mut engine = CorrelationEngine::new(CorrelationConfig {
        max_state_entries: 1,
        ..Default::default()
    });
    engine.add_collection(&collection).unwrap();
    for i in 0..3 {
        let v = json!({"action": "click", "User": format!("user_{i}")});
        engine.process_event_at(&JsonEvent::borrow(&v), 100 + i);
        assert_eq!(engine.state_count(), 1);
    }
}

#[test]
fn test_long_window_without_group_cap_is_flagged() {
    let flagged = |window_lines: &str, config: CorrelationConfig| {
        let collection = parse_sigma_yaml(&window_mode_yaml(window_lines)).unwrap();
        let mut engine = CorrelationEngine::new(config);
        engine.add_collection(&collection).unwrap();
        engine.has_unbounded_long_window(&engine.correlations[0])
    };
    assert!(flagged("    timespan: 2h", CorrelationConfig::default()));
    assert!(!flagged("    timespan: 1h", CorrelationConfig::default()));
    assert!(!flagged(
        "    timespan: 2h",
        CorrelationConfig {
            max_group_entries: Some(10_000),
            ..Default::default()
        }
    ));

    let yaml = window_mode_yaml("    timespan: 24h").replace(
        "id: corr-win\n",
        "id: corr-win\nrsigma.max_group_entries: '10000'\n",
    );
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine
        .add_collection(&parse_sigma_yaml(&yaml).unwrap())
        .unwrap();
    assert!(!engine.has_unbounded_long_window(&engine.correlations[0]));
}

#[test]
fn test_max_group_entries_caps_event_count() {
    // Cap of 2 retained entries: the gte-3 threshold can never be met,
    // no matter how many events land in the window.
    let mut engine = windowed_engine_with_group_cap("    timespan: 100s", 2);
    let v = json!({"action": "click", "User": "admin"});
    let event = JsonEvent::borrow(&v);
    let mut fired = 0;
    for ts in 0..10 {
        fired += engine.process_event_at(&event, ts).correlation_count();
    }
    assert_eq!(fired, 0);

    // Control: the same stream without a cap fires.
    let mut engine = windowed_engine("    timespan: 100s");
    let mut fired = 0;
    for ts in 0..10 {
        fired += engine.process_event_at(&event, ts).correlation_count();
    }
    assert!(fired > 0);
}

#[test]
fn test_max_group_entries_session_keeps_span_anchor() {
    // Cap of 2 on a session window (gap 10s, span cap 20s). Truncation must
    // keep the session's oldest entry: if the anchor were dropped, the span
    // would be measured from a later event and the t=24 arrival would extend
    // the session (24-9=15s <= 20s) instead of resetting it (24-0=24s > 20s),
    // letting the count reach the gte-3 threshold.
    let mut engine =
        windowed_engine_with_group_cap("    window: session\n    gap: 10s\n    timespan: 20s", 2);
    let v = json!({"action": "click", "User": "admin"});
    let event = JsonEvent::borrow(&v);
    let mut fired = 0;
    for ts in [0, 5, 9, 16, 24] {
        fired += engine.process_event_at(&event, ts).correlation_count();
    }
    assert_eq!(fired, 0);
}

#[test]
fn test_rsigma_max_group_entries_attribute_overrides_engine_default() {
    // The per-correlation `rsigma.max_group_entries` custom attribute wins
    // over the engine-level default (here: unbounded engine, capped rule).
    let yaml = r#"
title: Base
id: base-cap
logsource:
    category: test
detection:
    selection:
        action: click
    condition: selection
---
title: Capped Clicks
id: corr-cap
rsigma.max_group_entries: '2'
correlation:
    type: event_count
    rules:
        - base-cap
    group-by:
        - User
    timespan: 100s
    condition:
        gte: 3
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let v = json!({"action": "click", "User": "admin"});
    let event = JsonEvent::borrow(&v);
    let mut fired = 0;
    for ts in 0..10 {
        fired += engine.process_event_at(&event, ts).correlation_count();
    }
    assert_eq!(fired, 0);
}

#[test]
fn test_max_group_entries_value_count_saturates_distinct() {
    // value_count with a cap of 2: at most 2 distinct values retained, so a
    // gte-3 distinct threshold cannot fire.
    let yaml = r#"
title: Login
id: base-vc-cap
logsource:
    category: test
detection:
    selection:
        action: login
    condition: selection
---
title: Many Users
id: corr-vc-cap
correlation:
    type: value_count
    rules:
        - base-vc-cap
    group-by:
        - Host
    timespan: 100s
    condition:
        field: User
        gte: 3
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let config = CorrelationConfig {
        max_group_entries: Some(2),
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    let mut fired = 0;
    for (ts, user) in [(1, "a"), (2, "b"), (3, "c"), (4, "d"), (5, "e")] {
        let v = json!({"action": "login", "Host": "srv01", "User": user});
        let event = JsonEvent::borrow(&v);
        fired += engine.process_event_at(&event, ts).correlation_count();
    }
    assert_eq!(fired, 0);
}

// =========================================================================
// Value count correlation
// =========================================================================

#[test]
fn test_value_count() {
    let yaml = r#"
title: Failed Login
id: failed-login-001
logsource:
    category: auth
detection:
    selection:
        EventType: failed_login
    condition: selection
level: low
---
title: Failed Logins From Many Users
id: corr-vc-001
correlation:
    type: value_count
    rules:
        - failed-login-001
    group-by:
        - Host
    timespan: 60s
    condition:
        field: User
        gte: 3
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts = 1000i64;
    // 3 different users failing login on same host
    for (i, user) in ["alice", "bob", "charlie"].iter().enumerate() {
        let v = json!({"EventType": "failed_login", "Host": "srv01", "User": user});
        let event = JsonEvent::borrow(&v);
        let r = engine.process_event_at(&event, ts + i as i64);
        if i == 2 {
            assert_eq!(r.correlation_count(), 1);
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
    }
}

#[test]
fn test_value_count_multi_field_uses_composite_key() {
    // value_count with `field: [User, SrcIp]` must count distinct (User,
    // SrcIp) tuples, not silently fall back to the first field. The previous
    // behavior used `fields.first()` and counted only distinct users, so
    // three events for the same user from different source IPs would never
    // fire a `gte: 3` threshold.
    let yaml = r#"
title: Failed Login
id: failed-login-002
logsource:
    category: auth
detection:
    selection:
        EventType: failed_login
    condition: selection
level: low
---
title: Failed Logins From Many User-Sources
id: corr-vc-002
correlation:
    type: value_count
    rules:
        - failed-login-002
    group-by:
        - Host
    timespan: 60s
    condition:
        field: [User, SrcIp]
        gte: 3
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts = 1000i64;
    // Same user, three distinct source IPs: should fire under the tuple key
    // but never under the old first-field behavior.
    let events = [
        ("alice", "10.0.0.1"),
        ("alice", "10.0.0.2"),
        ("alice", "10.0.0.3"),
    ];
    let mut fired = false;
    for (i, (user, ip)) in events.iter().enumerate() {
        let v = json!({
            "EventType": "failed_login",
            "Host": "srv01",
            "User": user,
            "SrcIp": ip,
        });
        let event = JsonEvent::borrow(&v);
        let r = engine.process_event_at(&event, ts + i as i64);
        if r.correlation_count() == 1 {
            fired = true;
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
    }
    assert!(
        fired,
        "value_count with multi-field key should fire when 3 distinct (User, SrcIp) tuples are seen"
    );
}

#[test]
fn test_value_count_multi_field_duplicate_tuple_does_not_double_count() {
    // Same (User, SrcIp) tuple repeated should be counted as one distinct
    // value, regardless of how many times it appears.
    let yaml = r#"
title: Failed Login
id: failed-login-003
logsource:
    category: auth
detection:
    selection:
        EventType: failed_login
    condition: selection
level: low
---
title: Distinct (User, SrcIp) Threshold
id: corr-vc-003
correlation:
    type: value_count
    rules:
        - failed-login-003
    group-by:
        - Host
    timespan: 60s
    condition:
        field: [User, SrcIp]
        gte: 3
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts = 1000i64;
    // Two distinct tuples repeated; the threshold of 3 should never trigger.
    let events = [
        ("alice", "10.0.0.1"),
        ("alice", "10.0.0.2"),
        ("alice", "10.0.0.1"),
        ("alice", "10.0.0.2"),
    ];
    for (i, (user, ip)) in events.iter().enumerate() {
        let v = json!({
            "EventType": "failed_login",
            "Host": "srv01",
            "User": user,
            "SrcIp": ip,
        });
        let event = JsonEvent::borrow(&v);
        let r = engine.process_event_at(&event, ts + i as i64);
        assert_eq!(
            r.correlation_count(),
            0,
            "only 2 distinct tuples seen so far; should not fire"
        );
    }
}

// =========================================================================
// Temporal correlation
// =========================================================================

#[test]
fn test_temporal() {
    let yaml = r#"
title: Recon A
id: recon-a
name: recon_a
logsource:
    category: process
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Recon B
id: recon-b
name: recon_b
logsource:
    category: process
detection:
    selection:
        CommandLine|contains: 'ipconfig'
    condition: selection
---
title: Recon Combo
id: corr-temporal
correlation:
    type: temporal
    rules:
        - recon-a
        - recon-b
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts = 1000i64;
    // Only recon A fires
    let v1 = json!({"CommandLine": "whoami", "User": "admin"});
    let ev1 = JsonEvent::borrow(&v1);
    let r1 = engine.process_event_at(&ev1, ts);
    assert!(r1.correlation_count() == 0);

    // Now recon B fires — both rules have fired within window
    let v2 = json!({"CommandLine": "ipconfig /all", "User": "admin"});
    let ev2 = JsonEvent::borrow(&v2);
    let r2 = engine.process_event_at(&ev2, ts + 10);
    assert_eq!(r2.correlation_count(), 1);
    assert_eq!(
        r2.correlations().next().unwrap().header.rule_title,
        "Recon Combo"
    );
}

#[test]
fn test_temporal_without_condition_requires_every_rule() {
    // An omitted condition on a temporal correlation means every referenced
    // rule must match within the timespan, not just any one of them.
    let yaml = r#"
title: Rule A
id: rule-a
logsource:
    category: test
detection:
    selection:
        EventType: a
    condition: selection
---
title: Rule B
id: rule-b
logsource:
    category: test
detection:
    selection:
        EventType: b
    condition: selection
---
title: A and B
correlation:
    type: temporal
    rules:
        - rule-a
        - rule-b
    group-by:
        - Host
    timespan: 5m
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let a = json!({"EventType": "a", "Host": "h1"});
    let b = json!({"EventType": "b", "Host": "h1"});
    assert_eq!(
        engine
            .process_event_at(&JsonEvent::borrow(&a), 1000)
            .correlation_count(),
        0,
        "a single referenced rule must not satisfy the default condition"
    );
    assert_eq!(
        engine
            .process_event_at(&JsonEvent::borrow(&a), 1010)
            .correlation_count(),
        0,
        "repeated hits of the same rule must not satisfy the default condition"
    );
    assert_eq!(
        engine
            .process_event_at(&JsonEvent::borrow(&b), 1020)
            .correlation_count(),
        1
    );
}

#[test]
fn test_temporal_referenced_by_name_when_rule_also_has_id() {
    // Regression: when a rule carries both `id` and `name` and the temporal
    // correlation references it by `name`, the tracked identity must be the
    // referenced name; tracking the id means the window never satisfies the
    // condition and the correlation silently never fires.
    let yaml = r#"
title: Recon A
id: recon-a
name: recon_a
logsource:
    category: process
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Recon B
id: recon-b
name: recon_b
logsource:
    category: process
detection:
    selection:
        CommandLine|contains: 'ipconfig'
    condition: selection
---
title: Recon Combo By Name
id: corr-temporal-by-name
correlation:
    type: temporal
    rules:
        - recon_a
        - recon_b
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts = 1000i64;
    let v1 = json!({"CommandLine": "whoami", "User": "admin"});
    let ev1 = JsonEvent::borrow(&v1);
    assert_eq!(engine.process_event_at(&ev1, ts).correlation_count(), 0);

    let v2 = json!({"CommandLine": "ipconfig /all", "User": "admin"});
    let ev2 = JsonEvent::borrow(&v2);
    let r2 = engine.process_event_at(&ev2, ts + 10);
    assert_eq!(
        r2.correlation_count(),
        1,
        "temporal correlation referencing rules by name must fire when the rules also carry ids"
    );
}

// =========================================================================
// Temporal ordered correlation
// =========================================================================

#[test]
fn test_temporal_ordered() {
    let yaml = r#"
title: Failed Login
id: failed-001
name: failed_login
logsource:
    category: auth
detection:
    selection:
        EventType: failed_login
    condition: selection
---
title: Success Login
id: success-001
name: successful_login
logsource:
    category: auth
detection:
    selection:
        EventType: success_login
    condition: selection
---
title: Brute Force Then Login
id: corr-bf
correlation:
    type: temporal_ordered
    rules:
        - failed-001
        - success-001
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: critical
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts = 1000i64;
    // Failed login first
    let v1 = json!({"EventType": "failed_login", "User": "admin"});
    let ev1 = JsonEvent::borrow(&v1);
    let r1 = engine.process_event_at(&ev1, ts);
    assert!(r1.correlation_count() == 0);

    // Then successful login — correct order!
    let v2 = json!({"EventType": "success_login", "User": "admin"});
    let ev2 = JsonEvent::borrow(&v2);
    let r2 = engine.process_event_at(&ev2, ts + 10);
    assert_eq!(r2.correlation_count(), 1);
}

#[test]
fn test_temporal_ordered_wrong_order() {
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
title: A then B
id: corr-ab
correlation:
    type: temporal_ordered
    rules:
        - rule-a
        - rule-b
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts = 1000i64;
    // B fires first, then A — wrong order
    let v1 = json!({"type": "b", "User": "admin"});
    let ev1 = JsonEvent::borrow(&v1);
    engine.process_event_at(&ev1, ts);

    let v2 = json!({"type": "a", "User": "admin"});
    let ev2 = JsonEvent::borrow(&v2);
    let r2 = engine.process_event_at(&ev2, ts + 10);
    assert!(r2.correlation_count() == 0);
}

// =========================================================================
// Numeric aggregation (value_sum, value_avg)
// =========================================================================

#[test]
fn test_value_sum() {
    let yaml = r#"
title: Web Access
id: web-001
logsource:
    category: web
detection:
    selection:
        action: upload
    condition: selection
---
title: Large Upload
id: corr-sum
correlation:
    type: value_sum
    rules:
        - web-001
    group-by:
        - User
    timespan: 60s
    condition:
        field: bytes_sent
        gt: 1000
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts = 1000i64;
    let v1 = json!({"action": "upload", "User": "alice", "bytes_sent": 600});
    let ev1 = JsonEvent::borrow(&v1);
    let r1 = engine.process_event_at(&ev1, ts);
    assert!(r1.correlation_count() == 0);

    let v2 = json!({"action": "upload", "User": "alice", "bytes_sent": 500});
    let ev2 = JsonEvent::borrow(&v2);
    let r2 = engine.process_event_at(&ev2, ts + 5);
    assert_eq!(r2.correlation_count(), 1);
    assert!(
        (r2.correlations()
            .next()
            .unwrap()
            .as_correlation()
            .unwrap()
            .aggregated_value
            - 1100.0)
            .abs()
            < f64::EPSILON
    );
}

#[test]
fn test_value_avg() {
    let yaml = r#"
title: Request
id: req-001
logsource:
    category: web
detection:
    selection:
        type: request
    condition: selection
---
title: High Avg Latency
id: corr-avg
correlation:
    type: value_avg
    rules:
        - req-001
    group-by:
        - Service
    timespan: 60s
    condition:
        field: latency_ms
        gt: 500
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts = 1000i64;
    // Avg of 400, 600, 800 = 600 > 500
    for (i, latency) in [400, 600, 800].iter().enumerate() {
        let v = json!({"type": "request", "Service": "api", "latency_ms": latency});
        let event = JsonEvent::borrow(&v);
        let r = engine.process_event_at(&event, ts + i as i64);
        if i == 2 {
            assert_eq!(r.correlation_count(), 1);
            assert!(
                (r.correlations()
                    .next()
                    .unwrap()
                    .as_correlation()
                    .unwrap()
                    .aggregated_value
                    - 600.0)
                    .abs()
                    < f64::EPSILON
            );
        }
    }
}

// =========================================================================
// State management
// =========================================================================

#[test]
fn test_state_count() {
    let yaml = r#"
title: Base
id: base-sc
logsource:
    category: test
detection:
    selection:
        action: test
    condition: selection
---
title: Count
id: corr-sc
correlation:
    type: event_count
    rules:
        - base-sc
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 100
level: low
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let v = json!({"action": "test", "User": "alice"});
    let event = JsonEvent::borrow(&v);
    engine.process_event_at(&event, 1000);
    assert_eq!(engine.state_count(), 1);

    let v2 = json!({"action": "test", "User": "bob"});
    let event2 = JsonEvent::borrow(&v2);
    engine.process_event_at(&event2, 1001);
    assert_eq!(engine.state_count(), 2);

    // Evict everything
    engine.evict_expired(2000);
    assert_eq!(engine.state_count(), 0);
}

// =========================================================================
// Generate flag
// =========================================================================

#[test]
fn test_generate_flag_default_false() {
    let yaml = r#"
title: Base
id: gen-base
logsource:
    category: test
detection:
    selection:
        action: test
    condition: selection
---
title: Correlation
id: gen-corr
correlation:
    type: event_count
    rules:
        - gen-base
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 1
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    // generate defaults to false, so only the correlation is emitted.
    let v = json!({"action": "test", "User": "alice"});
    let event = JsonEvent::borrow(&v);
    let r = engine.process_event_at(&event, 1000);
    assert_eq!(r.detection_count(), 0);
    assert_eq!(r.correlation_count(), 1);
}

// =========================================================================
// Real-world example: AWS bucket enumeration
// =========================================================================

#[test]
fn test_aws_bucket_enumeration() {
    let yaml = r#"
title: Potential Bucket Enumeration on AWS
id: f305fd62-beca-47da-ad95-7690a0620084
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: "s3.amazonaws.com"
        eventName: "ListBuckets"
    condition: selection
level: low
---
title: Multiple AWS bucket enumerations
id: be246094-01d3-4bba-88de-69e582eba0cc
status: experimental
correlation:
    type: event_count
    rules:
        - f305fd62-beca-47da-ad95-7690a0620084
    group-by:
        - userIdentity.arn
    timespan: 1h
    condition:
        gte: 5
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let base_ts = 1_700_000_000i64;
    for i in 0..5 {
        let v = json!({
            "eventSource": "s3.amazonaws.com",
            "eventName": "ListBuckets",
            "userIdentity.arn": "arn:aws:iam::123456789:user/attacker"
        });
        let event = JsonEvent::borrow(&v);
        let r = engine.process_event_at(&event, base_ts + i * 60);
        if i == 4 {
            assert_eq!(r.correlation_count(), 1);
            assert_eq!(
                r.correlations().next().unwrap().header.rule_title,
                "Multiple AWS bucket enumerations"
            );
            assert_eq!(
                r.correlations()
                    .next()
                    .unwrap()
                    .as_correlation()
                    .unwrap()
                    .aggregated_value,
                5.0
            );
        }
    }
}

// =========================================================================
// Chaining: event_count -> temporal_ordered
// =========================================================================

/// Chaining tests assert on intermediate correlations, which are referenced
/// by their parents and therefore only output with `emit_detections`.
fn emit_every_hop() -> CorrelationConfig {
    CorrelationConfig {
        emit_detections: true,
        ..CorrelationConfig::default()
    }
}

#[test]
fn test_chaining_event_count_to_temporal() {
    // Reproduces the spec's "failed logins followed by successful login" example.
    // Chain: failed_login (detection) -> many_failed (event_count) -> brute_then_login (temporal_ordered)
    let yaml = r#"
title: Single failed login
id: failed-login-chain
name: failed_login
logsource:
    category: auth
detection:
    selection:
        EventType: failed_login
    condition: selection
---
title: Successful login
id: success-login-chain
name: successful_login
logsource:
    category: auth
detection:
    selection:
        EventType: success_login
    condition: selection
---
title: Multiple failed logins
id: many-failed-chain
name: multiple_failed_login
correlation:
    type: event_count
    rules:
        - failed-login-chain
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
level: medium
---
title: Brute Force Followed by Login
id: brute-force-chain
correlation:
    type: temporal_ordered
    rules:
        - many-failed-chain
        - success-login-chain
    group-by:
        - User
    timespan: 120s
    condition:
        gte: 2
level: critical
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    assert_eq!(engine.detection_rule_count(), 2);
    assert_eq!(engine.correlation_rule_count(), 2);

    let ts = 1000i64;

    // Send 3 failed logins → triggers "many_failed_chain"
    for i in 0..3 {
        let v = json!({"EventType": "failed_login", "User": "victim"});
        let event = JsonEvent::borrow(&v);
        let r = engine.process_event_at(&event, ts + i);
        if i == 2 {
            // The event_count correlation fires, but its parent references it
            // without `generate: true`, so it is not output, and
            // temporal_ordered still needs the successful-login detection.
            assert_eq!(r.correlation_count(), 0);
        }
    }

    // Now send a successful login → should trigger the chained temporal_ordered
    // Note: chaining happens in chain_correlations when many-failed-chain fires
    // and then success-login-chain matches the detection.
    // The temporal_ordered correlation needs BOTH many-failed-chain AND success-login-chain
    // to have fired. success-login-chain is a detection rule, not a correlation,
    // so it gets matched via the regular detection path.
    let v = json!({"EventType": "success_login", "User": "victim"});
    let event = JsonEvent::borrow(&v);
    let r = engine.process_event_at(&event, ts + 30);

    // The referenced detection is suppressed but still feeds the parent.
    assert_eq!(r.detection_count(), 0);
    assert!(
        r.correlations()
            .any(|c| c.header.rule_title == "Brute Force Followed by Login"),
        "chained temporal_ordered must be emitted, not only stored"
    );
}

// =========================================================================
// Field aliases
// =========================================================================

#[test]
fn test_field_aliases() {
    let yaml = r#"
title: Internal Error
id: internal-error-001
name: internal_error
logsource:
    category: web
detection:
    selection:
        http.response.status_code: 500
    condition: selection
---
title: New Connection
id: new-conn-001
name: new_network_connection
logsource:
    category: network
detection:
    selection:
        event.type: connection
    condition: selection
---
title: Error Then Connection
id: corr-alias
correlation:
    type: temporal
    rules:
        - internal-error-001
        - new-conn-001
    group-by:
        - internal_ip
    timespan: 60s
    condition:
        gte: 2
    aliases:
        internal_ip:
            internal_error: destination.ip
            new_network_connection: source.ip
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts = 1000i64;

    // Internal error with destination.ip = 10.0.0.5
    let v1 = json!({
        "http.response.status_code": 500,
        "destination.ip": "10.0.0.5"
    });
    let ev1 = JsonEvent::borrow(&v1);
    let r1 = engine.process_event_at(&ev1, ts);
    assert_eq!(r1.detection_count(), 0);
    assert!(r1.correlation_count() == 0);

    // New connection with source.ip = 10.0.0.5 (same IP, aliased)
    let v2 = json!({
        "event.type": "connection",
        "source.ip": "10.0.0.5"
    });
    let ev2 = JsonEvent::borrow(&v2);
    let r2 = engine.process_event_at(&ev2, ts + 5);
    assert_eq!(r2.detection_count(), 0);
    // Both rules fired for the same internal_ip group → temporal should fire
    assert_eq!(r2.correlation_count(), 1);
    assert_eq!(
        r2.correlations().next().unwrap().header.rule_title,
        "Error Then Connection"
    );
    // Check group key contains the aliased field
    assert!(
        r2.correlations()
            .next()
            .unwrap()
            .as_correlation()
            .unwrap()
            .group_key
            .iter()
            .any(|(k, v)| k == "internal_ip" && v == "10.0.0.5")
    );
}

// =========================================================================
// Value percentile (basic smoke test)
// =========================================================================

#[test]
fn test_value_percentile() {
    let yaml = r#"
title: Process Creation
id: proc-001
logsource:
    category: process
detection:
    selection:
        type: process_creation
    condition: selection
---
title: Rare Process
id: corr-percentile
correlation:
    type: value_percentile
    rules:
        - proc-001
    group-by:
        - ComputerName
    timespan: 60s
    condition:
        field: image
        lte: 50
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts = 1000i64;
    // Push some numeric-ish values for the image field
    for (i, val) in [10.0, 20.0, 30.0, 40.0, 50.0].iter().enumerate() {
        let v = json!({"type": "process_creation", "ComputerName": "srv01", "image": val});
        let event = JsonEvent::borrow(&v);
        let _ = engine.process_event_at(&event, ts + i as i64);
    }
    // The median (30.0) should be <= 50, so condition fires
    // Note: percentile implementation is simplified for in-memory eval
}

// =========================================================================
// Extended temporal conditions (end-to-end)
// =========================================================================

#[test]
fn test_extended_temporal_and_condition() {
    // Temporal correlation with "rule_a and rule_b" extended condition
    let yaml = r#"
title: Login Attempt
id: login-attempt
logsource:
    category: auth
detection:
    selection:
        EventType: login_failure
    condition: selection
---
title: Password Change
id: password-change
logsource:
    category: auth
detection:
    selection:
        EventType: password_change
    condition: selection
---
title: Credential Attack
correlation:
    type: temporal
    rules:
        - login-attempt
        - password-change
    group-by:
        - User
    timespan: 300s
    condition: login-attempt and password-change
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts = 1000i64;

    // Login failure by alice
    let ev1 = json!({"EventType": "login_failure", "User": "alice"});
    let r1 = engine.process_event_at(&JsonEvent::borrow(&ev1), ts);
    assert!(r1.correlation_count() == 0, "only one rule fired so far");

    // Password change by alice — both rules have now fired
    let ev2 = json!({"EventType": "password_change", "User": "alice"});
    let r2 = engine.process_event_at(&JsonEvent::borrow(&ev2), ts + 10);
    assert_eq!(
        r2.correlation_count(),
        1,
        "temporal correlation should fire: both rules matched"
    );
    assert_eq!(
        r2.correlations().next().unwrap().header.rule_title,
        "Credential Attack"
    );
}

#[test]
fn test_extended_temporal_or_condition() {
    // Temporal with "rule_a or rule_b" — should fire when either fires
    let yaml = r#"
title: SSH Login
id: ssh-login
logsource:
    category: auth
detection:
    selection:
        EventType: ssh_login
    condition: selection
---
title: VPN Login
id: vpn-login
logsource:
    category: auth
detection:
    selection:
        EventType: vpn_login
    condition: selection
---
title: Any Remote Access
correlation:
    type: temporal
    rules:
        - ssh-login
        - vpn-login
    group-by:
        - User
    timespan: 60s
    condition: ssh-login or vpn-login
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    // Only SSH login by bob — "or" means this suffices
    let ev = json!({"EventType": "ssh_login", "User": "bob"});
    let r = engine.process_event_at(&JsonEvent::borrow(&ev), 1000);
    assert_eq!(r.correlation_count(), 1);
    assert_eq!(
        r.correlations().next().unwrap().header.rule_title,
        "Any Remote Access"
    );
}

#[test]
fn test_extended_temporal_partial_and_no_fire() {
    // Temporal "and" with only one rule firing should not trigger
    let yaml = r#"
title: Recon Step 1
id: recon-1
logsource:
    category: process
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Recon Step 2
id: recon-2
logsource:
    category: process
detection:
    selection:
        CommandLine|contains: 'ipconfig'
    condition: selection
---
title: Full Recon
correlation:
    type: temporal
    rules:
        - recon-1
        - recon-2
    group-by:
        - Host
    timespan: 120s
    condition: recon-1 and recon-2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    // Only whoami (recon-1) — should not fire
    let ev = json!({"CommandLine": "whoami", "Host": "srv01"});
    let r = engine.process_event_at(&JsonEvent::borrow(&ev), 1000);
    assert!(
        r.correlation_count() == 0,
        "only one of two AND rules fired"
    );

    // Now ipconfig (recon-2) — should fire
    let ev2 = json!({"CommandLine": "ipconfig /all", "Host": "srv01"});
    let r2 = engine.process_event_at(&JsonEvent::borrow(&ev2), 1010);
    assert_eq!(r2.correlation_count(), 1);
    assert_eq!(
        r2.correlations().next().unwrap().header.rule_title,
        "Full Recon"
    );
}

// =========================================================================
// Filter rules with correlation engine
// =========================================================================

#[test]
fn test_filter_with_correlation() {
    // Detection rule + filter + event_count correlation
    let yaml = r#"
title: Failed Auth
id: failed-auth
logsource:
    category: auth
detection:
    selection:
        EventType: auth_failure
    condition: selection
---
title: Exclude Service Accounts
logsource:
    category: auth
filter:
    rules:
        - failed-auth
    selection:
        User|startswith: 'svc_'
    condition: not selection
---
title: Brute Force
correlation:
    type: event_count
    rules:
        - failed-auth
    group-by:
        - User
    timespan: 300s
    condition:
        gte: 3
level: critical
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts = 1000i64;

    // Service account failures should be filtered — don't count
    for i in 0..5 {
        let ev = json!({"EventType": "auth_failure", "User": "svc_backup"});
        let r = engine.process_event_at(&JsonEvent::borrow(&ev), ts + i);
        assert!(
            r.correlation_count() == 0,
            "service account should be filtered, no correlation"
        );
    }

    // Normal user failures should count
    for i in 0..2 {
        let ev = json!({"EventType": "auth_failure", "User": "alice"});
        let r = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 10 + i);
        assert!(r.correlation_count() == 0, "not yet 3 events");
    }

    // Third failure triggers correlation
    let ev = json!({"EventType": "auth_failure", "User": "alice"});
    let r = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 12);
    assert_eq!(r.correlation_count(), 1);
    assert_eq!(
        r.correlations().next().unwrap().header.rule_title,
        "Brute Force"
    );
}

// =========================================================================
// action: repeat with correlation engine
// =========================================================================

#[test]
fn test_repeat_rules_in_correlation() {
    // Two detection rules via repeat, both feed into event_count
    let yaml = r#"
title: File Access A
id: file-a
logsource:
    category: file_access
detection:
    selection:
        FileName|endswith: '.docx'
    condition: selection
---
action: repeat
title: File Access B
id: file-b
detection:
    selection:
        FileName|endswith: '.xlsx'
    condition: selection
---
title: Mass File Access
correlation:
    type: event_count
    rules:
        - file-a
        - file-b
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 2);
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();
    assert_eq!(engine.detection_rule_count(), 2);

    let ts = 1000i64;
    // Mix of docx and xlsx accesses by same user
    let ev1 = json!({"FileName": "report.docx", "User": "bob"});
    engine.process_event_at(&JsonEvent::borrow(&ev1), ts);
    let ev2 = json!({"FileName": "data.xlsx", "User": "bob"});
    engine.process_event_at(&JsonEvent::borrow(&ev2), ts + 1);
    let ev3 = json!({"FileName": "notes.docx", "User": "bob"});
    let r = engine.process_event_at(&JsonEvent::borrow(&ev3), ts + 2);

    assert_eq!(r.correlation_count(), 1);
    assert_eq!(
        r.correlations().next().unwrap().header.rule_title,
        "Mass File Access"
    );
}

// =========================================================================
// Expand modifier with correlation engine
// =========================================================================

#[test]
fn test_expand_modifier_with_correlation() {
    let yaml = r#"
title: User Temp File
id: user-temp
logsource:
    category: file_access
detection:
    selection:
        FilePath|expand: 'C:\Users\\%User%\Temp'
    condition: selection
---
title: Excessive Temp Access
correlation:
    type: event_count
    rules:
        - user-temp
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts = 1000i64;
    // Event where User field matches the placeholder
    let ev1 = json!({"FilePath": "C:\\Users\\alice\\Temp", "User": "alice"});
    let r1 = engine.process_event_at(&JsonEvent::borrow(&ev1), ts);
    assert!(r1.correlation_count() == 0);

    let ev2 = json!({"FilePath": "C:\\Users\\alice\\Temp", "User": "alice"});
    let r2 = engine.process_event_at(&JsonEvent::borrow(&ev2), ts + 1);
    assert_eq!(r2.correlation_count(), 1);
    assert_eq!(
        r2.correlations().next().unwrap().header.rule_title,
        "Excessive Temp Access"
    );

    // Different user — should NOT match (path says alice, user is bob)
    let ev3 = json!({"FilePath": "C:\\Users\\alice\\Temp", "User": "bob"});
    let r3 = engine.process_event_at(&JsonEvent::borrow(&ev3), ts + 2);
    // Detection doesn't fire for this event since expand resolves to C:\Users\bob\Temp
    assert_eq!(r3.detection_count(), 0);
}

// =========================================================================
// Timestamp modifier with correlation engine
// =========================================================================

#[test]
fn test_timestamp_modifier_with_correlation() {
    let yaml = r#"
title: Night Login
id: night-login
logsource:
    category: auth
detection:
    login:
        EventType: login
    night:
        Timestamp|hour: 3
    condition: login and night
---
title: Frequent Night Logins
correlation:
    type: event_count
    rules:
        - night-login
    group-by:
        - User
    timespan: 3600s
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts = 1000i64;
    // Login at 3AM
    let ev1 = json!({"EventType": "login", "User": "alice", "Timestamp": "2024-01-15T03:10:00Z"});
    let r1 = engine.process_event_at(&JsonEvent::borrow(&ev1), ts);
    assert_eq!(r1.detection_count(), 0);
    assert!(r1.correlation_count() == 0);

    let ev2 = json!({"EventType": "login", "User": "alice", "Timestamp": "2024-01-15T03:45:00Z"});
    let r2 = engine.process_event_at(&JsonEvent::borrow(&ev2), ts + 1);
    assert_eq!(r2.correlation_count(), 1);
    assert_eq!(
        r2.correlations().next().unwrap().header.rule_title,
        "Frequent Night Logins"
    );

    // Login at noon — should NOT count
    let ev3 = json!({"EventType": "login", "User": "bob", "Timestamp": "2024-01-15T12:00:00Z"});
    let r3 = engine.process_event_at(&JsonEvent::borrow(&ev3), ts + 2);
    assert!(
        r3.detection_count() == 0,
        "noon login should not match night rule"
    );
}

// =========================================================================
// Correlation condition range (multiple predicates)
// =========================================================================

#[test]
fn test_event_count_range_condition() {
    let yaml = r#"
title: Login Attempt
id: login-attempt-001
name: login_attempt
logsource:
    product: windows
detection:
    selection:
        EventType: login
    condition: selection
level: low
---
title: Login Count Range
id: corr-range-001
correlation:
    type: event_count
    rules:
        - login-attempt-001
    group-by:
        - User
    timespan: 3600s
    condition:
        gt: 2
        lte: 5
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ts: i64 = 1_000_000;

    // Send 2 events — gt:2 is false
    for i in 0..2 {
        let ev = json!({"EventType": "login", "User": "alice"});
        let r = engine.process_event_at(&JsonEvent::borrow(&ev), ts + i);
        assert!(
            r.correlation_count() == 0,
            "2 events should not fire (gt:2)"
        );
    }

    // 3rd event — gt:2 is true, lte:5 is true → fires
    let ev3 = json!({"EventType": "login", "User": "alice"});
    let r3 = engine.process_event_at(&JsonEvent::borrow(&ev3), ts + 3);
    assert_eq!(r3.correlation_count(), 1, "3 events: gt:2 AND lte:5");

    // Send events 4, 5 — still in range
    for i in 4..=5 {
        let ev = json!({"EventType": "login", "User": "alice"});
        let r = engine.process_event_at(&JsonEvent::borrow(&ev), ts + i);
        assert_eq!(r.correlation_count(), 1, "{i} events still in range");
    }

    // 6th event — lte:5 is false → no fire
    let ev6 = json!({"EventType": "login", "User": "alice"});
    let r6 = engine.process_event_at(&JsonEvent::borrow(&ev6), ts + 6);
    assert!(
        r6.correlation_count() == 0,
        "6 events exceeds lte:5, should not fire"
    );
}

// =========================================================================
// Suppression
// =========================================================================

fn suppression_yaml() -> &'static str {
    r#"
title: Login
id: login-base
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
        - login-base
    group-by:
        - User
    timeframe: 60s
    condition:
        gte: 3
level: high
"#
}

#[test]
fn test_suppression_window() {
    let collection = parse_sigma_yaml(suppression_yaml()).unwrap();
    let config = CorrelationConfig {
        suppress: Some(10), // suppress for 10 seconds
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    let ev = json!({"EventType": "login", "User": "alice"});
    let ts = 1000;

    // Fire 3 events to hit threshold
    engine.process_event_at(&JsonEvent::borrow(&ev), ts);
    engine.process_event_at(&JsonEvent::borrow(&ev), ts + 1);
    let r3 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 2);
    assert_eq!(r3.correlation_count(), 1, "should fire on 3rd event");

    // 4th event within suppress window → suppressed
    let r4 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 3);
    assert!(
        r4.correlation_count() == 0,
        "should be suppressed within 10s window"
    );

    // 5th event still within suppress window → suppressed
    let r5 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 9);
    assert!(
        r5.correlation_count() == 0,
        "should be suppressed at ts+9 (< ts+2+10)"
    );

    // Event after suppress window expires → fires again
    let r6 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 13);
    assert_eq!(
        r6.correlation_count(),
        1,
        "should fire again after suppress window expires"
    );
}

#[test]
fn test_suppression_per_group_key() {
    let collection = parse_sigma_yaml(suppression_yaml()).unwrap();
    let config = CorrelationConfig {
        suppress: Some(60),
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    let ts = 1000;

    // Alice hits threshold
    let ev_a = json!({"EventType": "login", "User": "alice"});
    engine.process_event_at(&JsonEvent::borrow(&ev_a), ts);
    engine.process_event_at(&JsonEvent::borrow(&ev_a), ts + 1);
    let r = engine.process_event_at(&JsonEvent::borrow(&ev_a), ts + 2);
    assert_eq!(r.correlation_count(), 1, "alice should fire");

    // Bob hits threshold — different group key, not suppressed
    let ev_b = json!({"EventType": "login", "User": "bob"});
    engine.process_event_at(&JsonEvent::borrow(&ev_b), ts + 3);
    engine.process_event_at(&JsonEvent::borrow(&ev_b), ts + 4);
    let r = engine.process_event_at(&JsonEvent::borrow(&ev_b), ts + 5);
    assert_eq!(r.correlation_count(), 1, "bob should fire independently");

    // Alice is still suppressed
    let r = engine.process_event_at(&JsonEvent::borrow(&ev_a), ts + 6);
    assert!(r.correlation_count() == 0, "alice still suppressed");
}

// =========================================================================
// Action on match: Reset
// =========================================================================

#[test]
fn test_action_reset() {
    let collection = parse_sigma_yaml(suppression_yaml()).unwrap();
    let config = CorrelationConfig {
        action_on_match: CorrelationAction::Reset,
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    let ev = json!({"EventType": "login", "User": "alice"});
    let ts = 1000;

    // Hit threshold: 3 events
    engine.process_event_at(&JsonEvent::borrow(&ev), ts);
    engine.process_event_at(&JsonEvent::borrow(&ev), ts + 1);
    let r3 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 2);
    assert_eq!(r3.correlation_count(), 1, "should fire on 3rd event");

    // State was reset, so 4th and 5th events should NOT fire
    let r4 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 3);
    assert!(r4.correlation_count() == 0, "reset: need 3 more events");

    let r5 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 4);
    assert!(r5.correlation_count() == 0, "reset: still only 2");

    // 6th event (3rd after reset) should fire again
    let r6 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 5);
    assert_eq!(
        r6.correlation_count(),
        1,
        "should fire again after 3 events post-reset"
    );
}

// =========================================================================
// Generate flag / emit_detections
// =========================================================================

#[test]
fn test_emit_detections_false_by_default() {
    let collection = parse_sigma_yaml(suppression_yaml()).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ev = json!({"EventType": "login", "User": "alice"});
    let r = engine.process_event_at(&JsonEvent::borrow(&ev), 1000);
    assert_eq!(
        r.detection_count(),
        0,
        "detections are suppressed by default"
    );
}

#[test]
fn test_emit_detections_true_emits_all_detections() {
    let collection = parse_sigma_yaml(suppression_yaml()).unwrap();
    let config = CorrelationConfig {
        emit_detections: true,
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    let ev = json!({"EventType": "login", "User": "alice"});
    let r = engine.process_event_at(&JsonEvent::borrow(&ev), 1000);
    assert_eq!(r.detection_count(), 1);
}

#[test]
fn test_generate_true_keeps_detections() {
    // When generate: true, detections should be emitted even with emit_detections=false
    let yaml = r#"
title: Login
name: login_gen
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many Logins
generate: true
correlation:
    type: event_count
    rules:
        - login_gen
    group-by:
        - User
    timeframe: 60s
    condition:
        gte: 3
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let config = CorrelationConfig {
        emit_detections: false,
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    let ev = json!({"EventType": "login", "User": "alice"});
    let r = engine.process_event_at(&JsonEvent::borrow(&ev), 1000);
    // generate: true means this rule is NOT correlation-only
    assert_eq!(
        r.detection_count(),
        1,
        "generate:true keeps detection output"
    );
}

#[test]
fn test_generate_true_wins_across_id_and_name_references() {
    let yaml = r#"
title: Login
id: 00000000-0000-4000-8000-000000000001
name: login
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Count by ID
correlation:
    type: event_count
    rules: [00000000-0000-4000-8000-000000000001]
    group-by: [User]
    timespan: 60s
    condition:
        gte: 3
---
title: Count by Name
generate: true
correlation:
    type: event_count
    rules: [login]
    group-by: [User]
    timespan: 60s
    condition:
        gte: 3
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ev = json!({"EventType": "login", "User": "alice"});
    let result = engine.process_event_at(&JsonEvent::borrow(&ev), 1000);
    assert_eq!(result.detection_count(), 1);
}

// =========================================================================
// Suppression + Reset combined
// =========================================================================

#[test]
fn test_suppress_and_reset_combined() {
    let collection = parse_sigma_yaml(suppression_yaml()).unwrap();
    let config = CorrelationConfig {
        suppress: Some(5),
        action_on_match: CorrelationAction::Reset,
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    let ev = json!({"EventType": "login", "User": "alice"});
    let ts = 1000;

    // Hit threshold: fires and resets
    engine.process_event_at(&JsonEvent::borrow(&ev), ts);
    engine.process_event_at(&JsonEvent::borrow(&ev), ts + 1);
    let r3 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 2);
    assert_eq!(r3.correlation_count(), 1, "fires on 3rd event");

    // Push 3 more events quickly (state was reset, so new count → 3)
    // but suppress window hasn't expired (ts+2 + 5 = ts+7)
    engine.process_event_at(&JsonEvent::borrow(&ev), ts + 3);
    engine.process_event_at(&JsonEvent::borrow(&ev), ts + 4);
    let r = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 5);
    assert!(
        r.correlation_count() == 0,
        "threshold met again but still suppressed"
    );

    // After suppress expires (at ts+8, which is ts+2+6 > suppress=5),
    // the accumulated events from step 2 (ts+3,4,5) still satisfy gte:3,
    // so the first event after expiry fires immediately and resets.
    let r = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 8);
    assert_eq!(
        r.correlation_count(),
        1,
        "fires after suppress expires (accumulated events + new one)"
    );

    // State was reset again at ts+8, suppress window now ts+8..ts+13.
    // Need 3 new events to fire, and suppress must expire.
    engine.process_event_at(&JsonEvent::borrow(&ev), ts + 9);
    engine.process_event_at(&JsonEvent::borrow(&ev), ts + 10);
    let r = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 11);
    assert!(
        r.correlation_count() == 0,
        "threshold met but suppress window hasn't expired (ts+11 - ts+8 = 3 < 5)"
    );
}

// =========================================================================
// No suppression (default behavior preserved)
// =========================================================================

#[test]
fn test_no_suppression_fires_every_event() {
    let collection = parse_sigma_yaml(suppression_yaml()).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ev = json!({"EventType": "login", "User": "alice"});
    let ts = 1000;

    engine.process_event_at(&JsonEvent::borrow(&ev), ts);
    engine.process_event_at(&JsonEvent::borrow(&ev), ts + 1);
    let r3 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 2);
    assert_eq!(r3.correlation_count(), 1);

    // Without suppression, 4th event should also fire
    let r4 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 3);
    assert_eq!(
        r4.correlation_count(),
        1,
        "no suppression: fires on every event after threshold"
    );

    let r5 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 4);
    assert_eq!(r5.correlation_count(), 1, "still fires");
}

// =========================================================================
// Custom attribute → engine config tests
// =========================================================================

fn yaml_str_attrs<const N: usize>(
    pairs: [(&str, &str); N],
) -> std::collections::HashMap<String, yaml_serde::Value> {
    pairs
        .into_iter()
        .map(|(k, v)| (k.to_string(), yaml_serde::Value::String(v.to_string())))
        .collect()
}

#[test]
fn test_custom_attr_timestamp_field() {
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    let attrs = yaml_str_attrs([("rsigma.timestamp_field", "time")]);
    engine.apply_custom_attributes(&attrs);

    assert_eq!(
        engine.config.timestamp_fields[0], "time",
        "rsigma.timestamp_field should be prepended"
    );
    // Defaults should still be there after the custom one
    assert!(
        engine
            .config
            .timestamp_fields
            .contains(&"@timestamp".to_string())
    );
}

#[test]
fn test_custom_attr_timestamp_field_no_duplicates() {
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    let attrs = yaml_str_attrs([("rsigma.timestamp_field", "time")]);
    // Apply twice — should not duplicate
    engine.apply_custom_attributes(&attrs);
    engine.apply_custom_attributes(&attrs);

    let count = engine
        .config
        .timestamp_fields
        .iter()
        .filter(|f| *f == "time")
        .count();
    assert_eq!(count, 1, "should not duplicate timestamp_field entries");
}

#[test]
fn test_custom_attr_suppress() {
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    assert!(engine.config.suppress.is_none());

    let attrs = yaml_str_attrs([("rsigma.suppress", "5m")]);
    engine.apply_custom_attributes(&attrs);

    assert_eq!(engine.config.suppress, Some(300));
}

#[test]
fn test_custom_attr_suppress_does_not_override_cli() {
    let config = CorrelationConfig {
        suppress: Some(60), // CLI set to 60s
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);

    let attrs = yaml_str_attrs([("rsigma.suppress", "5m")]);
    engine.apply_custom_attributes(&attrs);

    assert_eq!(
        engine.config.suppress,
        Some(60),
        "CLI suppress should not be overridden by custom attribute"
    );
}

#[test]
fn test_custom_attr_action() {
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    assert_eq!(engine.config.action_on_match, CorrelationAction::Alert);

    let attrs = yaml_str_attrs([("rsigma.action", "reset")]);
    engine.apply_custom_attributes(&attrs);

    assert_eq!(engine.config.action_on_match, CorrelationAction::Reset);
}

#[test]
fn test_custom_attr_action_does_not_override_cli() {
    let config = CorrelationConfig {
        action_on_match: CorrelationAction::Reset, // CLI set to reset
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);

    let attrs = yaml_str_attrs([("rsigma.action", "alert")]);
    engine.apply_custom_attributes(&attrs);

    assert_eq!(
        engine.config.action_on_match,
        CorrelationAction::Reset,
        "CLI action should not be overridden by custom attribute"
    );
}

#[test]
fn test_custom_attr_timestamp_field_used_for_extraction() {
    // The event has "time" but not "@timestamp" or "timestamp"
    let collection = parse_sigma_yaml(suppression_yaml()).unwrap();
    let mut config = CorrelationConfig::default();
    // Prepend "event_time" to simulate --timestamp-field
    config.timestamp_fields.insert(0, "event_time".to_string());
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    // Event with "event_time" field
    let ev = json!({
        "EventType": "login",
        "User": "alice",
        "event_time": "2026-02-11T12:00:00Z"
    });
    let result = engine.process_event(&JsonEvent::borrow(&ev));

    // The detection should match, and timestamp should be ~1739275200 (2026-02-11)
    assert!(result.detection_count() > 0 || result.correlation_count() == 0);
    // The key test: ensure the engine extracted the event timestamp, not Utc::now.
    // If it used Utc::now, the test would still pass but the timestamp would be
    // wildly different. We verify by checking the extracted value directly.
    let ts = engine
        .extract_event_timestamp(&JsonEvent::borrow(&ev))
        .expect("should extract timestamp");
    assert!(
        ts > 1_700_000_000 && ts < 1_800_000_000,
        "timestamp should be ~2026 epoch, got {ts}"
    );
}

// =========================================================================
// Cycle detection
// =========================================================================

#[test]
fn test_correlation_cycle_direct() {
    // Two correlations that reference each other: A -> B -> A
    let yaml = r#"
title: detection rule
id: det-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
level: low
---
title: correlation A
id: corr-a
correlation:
    type: event_count
    rules:
        - corr-b
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: high
---
title: correlation B
id: corr-b
correlation:
    type: event_count
    rules:
        - corr-a
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    let result = engine.add_collection(&collection);
    assert!(result.is_err(), "should detect direct cycle");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("cycle"), "error should mention cycle: {err}");
    assert!(
        err.contains("corr-a") && err.contains("corr-b"),
        "error should name both correlations: {err}"
    );
}

#[test]
fn test_correlation_cycle_self() {
    // A correlation that references itself
    let yaml = r#"
title: detection rule
id: det-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
level: low
---
title: self-ref correlation
id: self-corr
correlation:
    type: event_count
    rules:
        - self-corr
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    let result = engine.add_collection(&collection);
    assert!(result.is_err(), "should detect self-referencing cycle");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("cycle"), "error should mention cycle: {err}");
    assert!(
        err.contains("self-corr"),
        "error should name the correlation: {err}"
    );
}

#[test]
fn test_correlation_no_cycle_valid_chain() {
    // Valid chain: detection -> corr-A -> corr-B (no cycle)
    let yaml = r#"
title: detection rule
id: det-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
level: low
---
title: correlation A
id: corr-a
correlation:
    type: event_count
    rules:
        - det-rule
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: high
---
title: correlation B
id: corr-b
correlation:
    type: event_count
    rules:
        - corr-a
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    let result = engine.add_collection(&collection);
    assert!(
        result.is_ok(),
        "valid chain should not be rejected: {result:?}"
    );
}

#[test]
fn test_chaining_temporal_of_two_correlations() {
    // Reproduces issue #458: a temporal whose rules are other correlations
    // must emit when both children fire. The port-scan child groups by an
    // extra field; the parent projects down to src_ip.
    let yaml = r#"
title: Firewall Drop Event
id: drop-det
logsource:
    category: firewall
detection:
    selection:
        action: block
    condition: selection
---
title: Multiple Firewall Drops
id: drop-corr
correlation:
    type: event_count
    rules:
        - drop-det
    group-by:
        - src_ip
    timespan: 10m
    condition:
        gte: 3
level: medium
---
title: Firewall Port Event
id: port-det
logsource:
    category: firewall
detection:
    selection:
        dst_port|exists: true
    condition: selection
---
title: Port Scan
id: port-corr
correlation:
    type: value_count
    rules:
        - port-det
    group-by:
        - src_ip
        - dst_ip
    timespan: 1m
    condition:
        gte: 3
        field: dst_port
level: medium
---
title: Firewall Temporal Correlation
id: nest-temporal
correlation:
    type: temporal
    rules:
        - port-corr
        - drop-corr
    group-by:
        - src_ip
    timespan: 1h
    condition:
        gte: 2
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(emit_every_hop());
    engine.add_collection(&collection).unwrap();

    let ts = 1_000i64;
    let ports = [21, 22, 23];
    let mut last = None;
    for (i, port) in ports.iter().enumerate() {
        let v = json!({
            "action": "block",
            "src_ip": "10.1.1.1",
            "dst_ip": "10.1.1.2",
            "dst_port": port,
        });
        let event = JsonEvent::borrow(&v);
        last = Some(engine.process_event_at(&event, ts + i as i64));
    }
    let r = last.expect("processed events");
    let titles: Vec<_> = r
        .correlations()
        .map(|c| c.header.rule_title.as_str())
        .collect();
    assert!(
        titles.contains(&"Multiple Firewall Drops"),
        "inner event_count should fire: {titles:?}"
    );
    assert!(
        titles.contains(&"Port Scan"),
        "inner value_count should fire: {titles:?}"
    );
    assert!(
        titles.contains(&"Firewall Temporal Correlation"),
        "temporal of two correlations must be emitted: {titles:?}"
    );
}

#[test]
fn test_chaining_event_count_of_event_count() {
    // detection -> corr-A (gte 2) -> corr-B (gte 2). Both parents must emit.
    let yaml = r#"
title: click
id: det-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
---
title: correlation A
id: corr-a
correlation:
    type: event_count
    rules:
        - det-rule
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: high
---
title: correlation B
id: corr-b
correlation:
    type: event_count
    rules:
        - corr-a
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(emit_every_hop());
    engine.add_collection(&collection).unwrap();

    let ts = 1_000i64;
    for i in 0..3 {
        let v = json!({"action": "click", "User": "alice"});
        let event = JsonEvent::borrow(&v);
        let r = engine.process_event_at(&event, ts + i);
        if i == 1 {
            let titles: Vec<_> = r
                .correlations()
                .map(|c| c.header.rule_title.as_str())
                .collect();
            assert_eq!(titles, ["correlation A"], "A fires once, B still at 1");
        }
        if i == 2 {
            let titles: Vec<_> = r
                .correlations()
                .map(|c| c.header.rule_title.as_str())
                .collect();
            assert!(
                titles.contains(&"correlation A") && titles.contains(&"correlation B"),
                "second A fire must emit chained B: {titles:?}"
            );
        }
    }
}

#[test]
fn test_chaining_in_full_event_mode() {
    // The chained parent carries the events its child retained at each firing,
    // each once, oldest first, and keeps the child's group.
    let yaml = r#"
title: click
id: det-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
---
title: correlation A
id: corr-a
correlation:
    type: event_count
    rules:
        - det-rule
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: high
---
title: correlation B
id: corr-b
correlation:
    type: event_count
    rules:
        - corr-a
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig {
        correlation_event_mode: CorrelationEventMode::Full,
        max_correlation_events: 10,
        ..emit_every_hop()
    });
    engine.add_collection(&collection).unwrap();

    let mut last = None;
    for i in 0..3 {
        let v = json!({"action": "click", "User": "alice", "n": i + 1});
        last = Some(engine.process_event_at(&JsonEvent::borrow(&v), 1_000 + i));
    }
    let result = last.unwrap();
    let bodies: Vec<_> = result
        .correlations()
        .map(|c| (c.header.rule_title.as_str(), c.as_correlation().unwrap()))
        .collect();
    let [("correlation A", a), ("correlation B", b)] = bodies.as_slice() else {
        panic!("expected A then chained B, got {bodies:?}");
    };
    assert_eq!(a.events.as_ref().map(Vec::len), Some(3));
    assert_eq!(event_ns(b), [1, 2, 3]);
    assert_eq!(b.group_key, [("User".to_string(), "alice".to_string())]);
    assert_eq!(b.aggregated_value, 2.0);
}

#[test]
fn test_chaining_parent_referenced_by_child_name() {
    let yaml = r#"
title: click
id: det-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
---
title: correlation A
id: corr-a
name: corr_a_name
correlation:
    type: event_count
    rules:
        - det-rule
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: high
---
title: correlation B
id: corr-b
correlation:
    type: event_count
    rules:
        - corr_a_name
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 1
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(emit_every_hop());
    engine.add_collection(&collection).unwrap();

    let ts = 1_000i64;
    let mut last = None;
    for i in 0..2 {
        let v = json!({"action": "click", "User": "alice"});
        let event = JsonEvent::borrow(&v);
        last = Some(engine.process_event_at(&event, ts + i));
    }
    let r = last.expect("processed events");
    let titles: Vec<_> = r
        .correlations()
        .map(|c| c.header.rule_title.as_str())
        .collect();
    assert!(
        titles.contains(&"correlation A") && titles.contains(&"correlation B"),
        "parent referenced by child name must emit: {titles:?}"
    );
}

/// Linear `event_count` chain of `levels` correlations, each `gte: 1`.
/// `corr-0` references the detection; `corr-i` references `corr-(i-1)`.
fn nested_event_count_chain_yaml(levels: usize) -> String {
    let mut yaml = String::from(
        r#"title: click
id: det-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
"#,
    );
    for i in 0..levels {
        let parent = if i == 0 {
            "det-rule".to_string()
        } else {
            format!("corr-{}", i - 1)
        };
        yaml.push_str(&format!(
            r#"---
title: level {i}
id: corr-{i}
correlation:
    type: event_count
    rules:
        - {parent}
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 1
level: high
"#
        ));
    }
    yaml
}

fn process_one_click(engine: &mut CorrelationEngine) -> Vec<String> {
    let v = json!({"action": "click", "User": "alice"});
    let event = JsonEvent::borrow(&v);
    engine
        .process_event_at(&event, 1_000)
        .correlations()
        .map(|c| c.header.rule_title.clone())
        .collect()
}

#[test]
fn test_chaining_ten_levels_all_emit() {
    let levels = MAX_CHAIN_DEPTH;
    let collection = parse_sigma_yaml(&nested_event_count_chain_yaml(levels)).unwrap();
    let mut engine = CorrelationEngine::new(emit_every_hop());
    engine.add_collection(&collection).unwrap();
    assert_eq!(engine.correlation_rule_count(), levels);

    let titles = process_one_click(&mut engine);
    let expected: Vec<String> = (0..levels).map(|i| format!("level {i}")).collect();
    for title in &expected {
        assert!(
            titles.contains(title),
            "10-deep chain must emit {title}: {titles:?}"
        );
    }
    assert_eq!(titles.len(), levels, "exactly {levels} firings: {titles:?}");
}

#[test]
fn test_chaining_eleventh_hop_is_dropped() {
    // First-level fire + 10 parent hops emit corr-0 .. corr-10.
    // corr-11 is the leftover hop past MAX_CHAIN_DEPTH: no emit, no window.
    let levels = MAX_CHAIN_DEPTH + 2;
    let collection = parse_sigma_yaml(&nested_event_count_chain_yaml(levels)).unwrap();
    let mut engine = CorrelationEngine::new(emit_every_hop());
    engine.add_collection(&collection).unwrap();
    assert_eq!(engine.correlation_rule_count(), levels);

    let titles = process_one_click(&mut engine);
    for i in 0..=MAX_CHAIN_DEPTH {
        let title = format!("level {i}");
        assert!(
            titles.contains(&title),
            "hop {i} must still emit: {titles:?}"
        );
    }
    assert!(
        !titles.iter().any(|t| t == "level 11"),
        "11th hop must not be emitted: {titles:?}"
    );

    let snap = engine.introspect();
    let info = |id: &str| {
        snap.correlations
            .iter()
            .find(|c| c.id.as_deref() == Some(id))
            .unwrap_or_else(|| panic!("missing {id}"))
    };
    assert_eq!(
        info("corr-10").active_groups,
        1,
        "last in-cap hop has state"
    );
    assert_eq!(
        info("corr-11").active_groups,
        0,
        "hop past the cap must not update window state"
    );
}

#[test]
fn test_correlation_cycle_transitive() {
    // Transitive cycle: A -> B -> C -> A
    let yaml = r#"
title: detection rule
id: det-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
level: low
---
title: correlation A
id: corr-a
correlation:
    type: event_count
    rules:
        - corr-c
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: high
---
title: correlation B
id: corr-b
correlation:
    type: event_count
    rules:
        - corr-a
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: high
---
title: correlation C
id: corr-c
correlation:
    type: event_count
    rules:
        - corr-b
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    let result = engine.add_collection(&collection);
    assert!(result.is_err(), "should detect transitive cycle");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("cycle"), "error should mention cycle: {err}");
}

// =========================================================================
// Correlation event inclusion tests
// =========================================================================

#[test]
fn test_correlation_events_disabled_by_default() {
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
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    for i in 0..3 {
        let v = json!({"EventType": "login", "User": "admin", "@timestamp": 1000 + i});
        let event = JsonEvent::borrow(&v);
        let result = engine.process_event_at(&event, 1000 + i);
        if i == 2 {
            assert_eq!(result.correlation_count(), 1);
            // Events should NOT be included by default
            assert!(
                result
                    .correlations()
                    .next()
                    .unwrap()
                    .as_correlation()
                    .unwrap()
                    .events
                    .is_none()
            );
        }
    }
}

#[test]
fn test_correlation_events_included_when_enabled() {
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
    let collection = parse_sigma_yaml(yaml).unwrap();
    let config = CorrelationConfig {
        correlation_event_mode: CorrelationEventMode::Full,
        max_correlation_events: 10,
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    let events_sent: Vec<serde_json::Value> = (0..3)
        .map(|i| json!({"EventType": "login", "User": "admin", "@timestamp": 1000 + i}))
        .collect();

    let mut corr_result = None;
    for (i, ev) in events_sent.iter().enumerate() {
        let event = JsonEvent::borrow(ev);
        let result = engine.process_event_at(&event, 1000 + i as i64);
        if result.correlation_count() > 0 {
            corr_result = Some(result);
        }
    }

    let result = corr_result.expect("correlation should have fired");
    let corr_result_ref = result.correlations().next().unwrap();
    let corr = corr_result_ref.as_correlation().unwrap();

    // Events should be included
    let events = corr.events.as_ref().expect("events should be present");
    assert_eq!(
        events.len(),
        3,
        "all 3 contributing events should be stored"
    );

    // Verify all sent events are present
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event["EventType"], "login");
        assert_eq!(event["User"], "admin");
        assert_eq!(event["@timestamp"], 1000 + i as i64);
    }
}

#[test]
fn test_correlation_events_max_cap() {
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
title: Many Logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 5
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let config = CorrelationConfig {
        correlation_event_mode: CorrelationEventMode::Full,
        max_correlation_events: 3, // only keep last 3
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    let mut corr_result = None;
    for i in 0..5 {
        let v = json!({"EventType": "login", "User": "admin", "idx": i});
        let event = JsonEvent::borrow(&v);
        let result = engine.process_event_at(&event, 1000 + i);
        if result.correlation_count() > 0 {
            corr_result = Some(result);
        }
    }

    let result = corr_result.expect("correlation should have fired");
    let events = result
        .correlations()
        .next()
        .unwrap()
        .as_correlation()
        .unwrap()
        .events
        .as_ref()
        .expect("events should be present");

    // Only the last 3 events should be retained (cap = 3)
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["idx"], 2);
    assert_eq!(events[1]["idx"], 3);
    assert_eq!(events[2]["idx"], 4);
}

#[test]
fn test_correlation_events_with_reset_action() {
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
title: Many Logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let config = CorrelationConfig {
        correlation_event_mode: CorrelationEventMode::Full,
        action_on_match: CorrelationAction::Reset,
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    // First round: 2 events -> fires
    for i in 0..2 {
        let v = json!({"EventType": "login", "User": "admin", "round": 1, "idx": i});
        let event = JsonEvent::borrow(&v);
        let result = engine.process_event_at(&event, 1000 + i);
        if i == 1 {
            assert_eq!(result.correlation_count(), 1);
            let events = result
                .correlations()
                .next()
                .unwrap()
                .as_correlation()
                .unwrap()
                .events
                .as_ref()
                .unwrap();
            assert_eq!(events.len(), 2);
        }
    }

    // After reset, event buffer should be cleared.
    // Second round: need 2 more events to fire again
    let v = json!({"EventType": "login", "User": "admin", "round": 2, "idx": 0});
    let event = JsonEvent::borrow(&v);
    let result = engine.process_event_at(&event, 1010);
    assert!(
        result.correlation_count() == 0,
        "should not fire with only 1 event after reset"
    );

    let v = json!({"EventType": "login", "User": "admin", "round": 2, "idx": 1});
    let event = JsonEvent::borrow(&v);
    let result = engine.process_event_at(&event, 1011);
    assert_eq!(result.correlation_count(), 1);
    let events = result
        .correlations()
        .next()
        .unwrap()
        .as_correlation()
        .unwrap()
        .events
        .as_ref()
        .unwrap();
    assert_eq!(events.len(), 2);
    // Should only have round 2 events
    assert_eq!(events[0]["round"], 2);
    assert_eq!(events[1]["round"], 2);
}

#[test]
fn test_correlation_events_with_set_include() {
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
title: Many Logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    // Enable via setter
    engine.set_correlation_event_mode(CorrelationEventMode::Full);

    for i in 0..2 {
        let v = json!({"EventType": "login", "User": "admin"});
        let event = JsonEvent::borrow(&v);
        let result = engine.process_event_at(&event, 1000 + i);
        if i == 1 {
            assert_eq!(result.correlation_count(), 1);
            assert!(
                result
                    .correlations()
                    .next()
                    .unwrap()
                    .as_correlation()
                    .unwrap()
                    .events
                    .is_some()
            );
            assert_eq!(
                result
                    .correlations()
                    .next()
                    .unwrap()
                    .as_correlation()
                    .unwrap()
                    .events
                    .as_ref()
                    .unwrap()
                    .len(),
                2
            );
        }
    }
}

#[test]
fn test_correlation_events_eviction_syncs_with_window() {
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
title: Many Logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 10s
    condition:
        gte: 3
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let config = CorrelationConfig {
        correlation_event_mode: CorrelationEventMode::Full,
        max_correlation_events: 100,
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    // Push 2 events at ts=1000,1001 — within the 10s window
    for i in 0..2 {
        let v = json!({"EventType": "login", "User": "admin", "idx": i});
        let event = JsonEvent::borrow(&v);
        engine.process_event_at(&event, 1000 + i);
    }

    // Push 1 more event at ts=1015 — the first 2 events are now outside the
    // 10s window (cutoff = 1015 - 10 = 1005)
    let v = json!({"EventType": "login", "User": "admin", "idx": 2});
    let event = JsonEvent::borrow(&v);
    let result = engine.process_event_at(&event, 1015);
    // Should NOT fire: only 1 event in window (the one at ts=1015)
    assert!(
        result.correlation_count() == 0,
        "should not fire — old events evicted"
    );

    // Push 2 more to reach threshold
    for i in 3..5 {
        let v = json!({"EventType": "login", "User": "admin", "idx": i});
        let event = JsonEvent::borrow(&v);
        let result = engine.process_event_at(&event, 1016 + i - 3);
        if i == 4 {
            assert_eq!(result.correlation_count(), 1);
            let events = result
                .correlations()
                .next()
                .unwrap()
                .as_correlation()
                .unwrap()
                .events
                .as_ref()
                .unwrap();
            // Should have events from ts=1015,1016,1017 — not the old ones
            assert_eq!(events.len(), 3);
            for ev in events {
                assert!(ev["idx"].as_i64().unwrap() >= 2);
            }
        }
    }
}

#[test]
fn test_event_buffer_monitoring() {
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
title: Many Logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 100
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let config = CorrelationConfig {
        correlation_event_mode: CorrelationEventMode::Full,
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    assert_eq!(engine.event_buffer_count(), 0);
    assert_eq!(engine.event_buffer_bytes(), 0);

    // Push some events
    for i in 0..5 {
        let v = json!({"EventType": "login", "User": "admin"});
        let event = JsonEvent::borrow(&v);
        engine.process_event_at(&event, 1000 + i);
    }

    assert_eq!(engine.event_buffer_count(), 1); // one group key
    assert!(engine.event_buffer_bytes() > 0);
}

#[test]
fn test_correlation_refs_mode_basic() {
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
    let collection = parse_sigma_yaml(yaml).unwrap();
    let config = CorrelationConfig {
        correlation_event_mode: CorrelationEventMode::Refs,
        max_correlation_events: 10,
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    let mut corr_result = None;
    for i in 0..3 {
        let v = json!({"EventType": "login", "User": "admin", "id": format!("evt-{i}"), "@timestamp": 1000 + i});
        let event = JsonEvent::borrow(&v);
        let result = engine.process_event_at(&event, 1000 + i);
        if result.correlation_count() > 0 {
            corr_result = Some(result.correlations().next().unwrap().clone());
        }
    }

    let result = corr_result.expect("correlation should have fired");
    let result_body = result.as_correlation().unwrap();
    // In refs mode: events should be None, event_refs should be Some
    assert!(
        result_body.events.is_none(),
        "Full events should not be included in refs mode"
    );
    let refs = result_body
        .event_refs
        .as_ref()
        .expect("event_refs should be present in refs mode");
    assert_eq!(refs.len(), 3);
    assert_eq!(refs[0].timestamp, 1000);
    assert_eq!(refs[0].id, Some("evt-0".to_string()));
    assert_eq!(refs[1].id, Some("evt-1".to_string()));
    assert_eq!(refs[2].id, Some("evt-2".to_string()));
}

#[test]
fn test_correlation_refs_mode_no_id_field() {
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
title: Many Logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let config = CorrelationConfig {
        correlation_event_mode: CorrelationEventMode::Refs,
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    let mut corr_result = None;
    for i in 0..2 {
        let v = json!({"EventType": "login", "User": "admin"});
        let event = JsonEvent::borrow(&v);
        let result = engine.process_event_at(&event, 1000 + i);
        if result.correlation_count() > 0 {
            corr_result = Some(result.correlations().next().unwrap().clone());
        }
    }

    let result = corr_result.expect("correlation should have fired");
    let refs = result
        .as_correlation()
        .unwrap()
        .event_refs
        .as_ref()
        .expect("event_refs should be present");
    // No ID field in events → id should be None
    for r in refs {
        assert_eq!(r.id, None);
    }
}

#[test]
fn test_per_correlation_custom_attributes_from_yaml() {
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
title: Many Logins
custom_attributes:
    rsigma.correlation_event_mode: refs
    rsigma.max_correlation_events: "5"
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
    let collection = parse_sigma_yaml(yaml).unwrap();
    // Engine mode is None (default), but per-correlation should override to Refs
    let config = CorrelationConfig::default();
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    let mut corr_result = None;
    for i in 0..3 {
        let v = json!({"EventType": "login", "User": "admin", "id": format!("e{i}")});
        let event = JsonEvent::borrow(&v);
        let result = engine.process_event_at(&event, 1000 + i);
        if result.correlation_count() > 0 {
            corr_result = Some(result.correlations().next().unwrap().clone());
        }
    }

    let result = corr_result.expect("correlation should fire with per-correlation refs mode");
    let result_body = result.as_correlation().unwrap();
    // Per-correlation override should enable refs mode even though engine default is None
    assert!(result_body.events.is_none());
    let refs = result_body
        .event_refs
        .as_ref()
        .expect("event_refs via per-correlation override");
    assert_eq!(refs.len(), 3);
    assert_eq!(refs[0].id, Some("e0".to_string()));
}

#[test]
fn test_per_correlation_custom_attr_suppress_and_action() {
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
title: Many Logins
custom_attributes:
    rsigma.suppress: 10s
    rsigma.action: reset
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    // Verify the compiled correlation has per-rule overrides
    assert_eq!(engine.correlations[0].suppress_secs, Some(10));
    assert_eq!(
        engine.correlations[0].action,
        Some(CorrelationAction::Reset)
    );
}

#[test]
fn test_process_with_detections_matches_process_event_at() {
    let yaml = r#"
title: Login Failure
id: login-fail
logsource:
    category: auth
detection:
    selection:
        EventType: login_failure
    condition: selection
---
title: Brute Force
correlation:
    type: event_count
    rules:
        - login-fail
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();

    // Run with process_event_at
    let mut engine1 = CorrelationEngine::new(CorrelationConfig::default());
    engine1.add_collection(&collection).unwrap();

    let events: Vec<serde_json::Value> = (0..5)
        .map(|i| json!({"EventType": "login_failure", "User": "admin", "@timestamp": format!("2025-01-01T00:00:0{}Z", i + 1)}))
        .collect();

    let results1: Vec<ProcessResult> = events
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let e = JsonEvent::borrow(v);
            engine1.process_event_at(&e, 1000 + i as i64)
        })
        .collect();

    // Run with evaluate + process_with_detections
    let mut engine2 = CorrelationEngine::new(CorrelationConfig::default());
    engine2.add_collection(&collection).unwrap();

    let results2: Vec<ProcessResult> = events
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let e = JsonEvent::borrow(v);
            let detections = engine2.evaluate(&e);
            engine2.process_with_detections(&e, detections, 1000 + i as i64)
        })
        .collect();

    // Same number of results
    assert_eq!(results1.len(), results2.len());
    for (r1, r2) in results1.iter().zip(results2.iter()) {
        assert_eq!(r1.detection_count(), r2.detection_count());
        assert_eq!(r1.correlation_count(), r2.correlation_count());
    }
}

#[test]
fn test_process_batch_matches_sequential() {
    let yaml = r#"
title: Login Failure
id: login-fail-batch
logsource:
    category: auth
detection:
    selection:
        EventType: login_failure
    condition: selection
---
title: Brute Force Batch
correlation:
    type: event_count
    rules:
        - login-fail-batch
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();

    let event_values: Vec<serde_json::Value> = (0..5)
        .map(|i| json!({"EventType": "login_failure", "User": "admin", "@timestamp": format!("2025-01-01T00:00:0{}Z", i + 1)}))
        .collect();

    // Sequential
    let mut engine1 = CorrelationEngine::new(CorrelationConfig::default());
    engine1.add_collection(&collection).unwrap();
    let sequential: Vec<ProcessResult> = event_values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let e = JsonEvent::borrow(v);
            engine1.process_event_at(&e, 1000 + i as i64)
        })
        .collect();

    // Batch
    let mut engine2 = CorrelationEngine::new(CorrelationConfig::default());
    engine2.add_collection(&collection).unwrap();
    let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();
    let refs: Vec<&JsonEvent> = events.iter().collect();
    let batch = engine2.process_batch(&refs);

    assert_eq!(sequential.len(), batch.len());
    for (seq, bat) in sequential.iter().zip(batch.iter()) {
        assert_eq!(seq.detection_count(), bat.detection_count());
        assert_eq!(seq.correlation_count(), bat.correlation_count());
    }
}

#[test]
fn test_process_batch_keeps_rule_identity_without_timestamps() {
    let yaml = r#"
title: Login
name: login_a
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Login
name: login_b
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Count A
correlation:
    type: event_count
    rules:
        - login_a
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let event_values: Vec<serde_json::Value> = (0..2)
        .map(|_| json!({"EventType": "login", "User": "admin"}))
        .collect();
    let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();
    let refs: Vec<&JsonEvent> = events.iter().collect();
    let batch = engine.process_batch(&refs);

    let fired: Vec<&str> = batch
        .iter()
        .flatten()
        .filter(|result| result.is_correlation())
        .map(|result| result.header.rule_title.as_str())
        .collect();
    assert_eq!(fired, vec!["Count A"]);
}

#[test]
fn test_correlation_result_custom_attributes() {
    let yaml = r#"
title: Login
id: login-cra
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
level: low
---
title: Many Logins
my_custom_field: hello
priority: 9
nested:
    key: value
correlation:
    type: event_count
    rules:
        - login-cra
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let base_ts = 1000i64;
    for i in 0..2 {
        let v = json!({"EventType": "login", "User": "alice"});
        let event = JsonEvent::borrow(&v);
        let result = engine.process_event_at(&event, base_ts + i * 10);

        if i == 1 {
            assert_eq!(result.correlation_count(), 1);
            let corr = &result.correlations().next().unwrap();
            assert_eq!(corr.header.rule_title, "Many Logins");
            assert_eq!(
                corr.header.custom_attributes.get("my_custom_field"),
                Some(&serde_json::Value::String("hello".to_string()))
            );
            assert_eq!(
                corr.header.custom_attributes.get("priority"),
                Some(&serde_json::json!(9))
            );
            let nested = corr.header.custom_attributes.get("nested").unwrap();
            assert_eq!(nested.get("key"), Some(&serde_json::json!("value")));

            assert!(!corr.header.custom_attributes.contains_key("title"));
            assert!(!corr.header.custom_attributes.contains_key("correlation"));
            assert!(!corr.header.custom_attributes.contains_key("level"));
        }
    }
}

#[test]
fn test_detection_result_custom_attributes() {
    let yaml = r#"
title: Login Detection
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
level: low
my_detection_tag: important
score: 42
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let v = json!({"EventType": "login"});
    let event = JsonEvent::borrow(&v);
    let result = engine.process_event(&event);

    assert_eq!(result.detection_count(), 1);
    let det = &result.detections().next().unwrap();
    assert_eq!(
        det.header.custom_attributes.get("my_detection_tag"),
        Some(&serde_json::Value::String("important".to_string()))
    );
    assert_eq!(
        det.header.custom_attributes.get("score"),
        Some(&serde_json::json!(42))
    );
    assert!(!det.header.custom_attributes.contains_key("title"));
}
// =========================================================================
// Tenant isolation
// =========================================================================

const TENANT_RULES: &str = r#"
title: Login
id: login-tenant
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many logins
id: many-logins-tenant
correlation:
    type: event_count
    rules:
        - login-tenant
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
"#;

fn tenant_engine(require_tenant: bool) -> CorrelationEngine {
    let collection = parse_sigma_yaml(TENANT_RULES).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig {
        require_tenant,
        ..Default::default()
    });
    engine.add_collection(&collection).unwrap();
    engine
}

#[test]
fn tenant_keyed_windows_fire_separately() {
    let a = crate::tenant::TenantId::new("a").unwrap();
    let b = crate::tenant::TenantId::new("b").unwrap();
    let mut engine = tenant_engine(false);
    let value = json!({"EventType": "login", "User": "admin"});
    let event = JsonEvent::borrow(&value);

    assert_eq!(
        engine
            .process_event_at_for_tenant(&event, 1000, Some(&a))
            .correlation_count(),
        0
    );
    assert_eq!(
        engine
            .process_event_at_for_tenant(&event, 1001, Some(&b))
            .correlation_count(),
        0
    );
    let fired = engine.process_event_at_for_tenant(&event, 1002, Some(&a));
    assert_eq!(fired.correlation_count(), 1);
    assert_eq!(
        fired
            .correlations()
            .next()
            .unwrap()
            .header
            .tenant_id
            .as_ref(),
        Some(&a)
    );
    assert_eq!(engine.state_count(), 2, "one window per tenant");
}

#[test]
fn chained_correlation_keeps_the_tenant() {
    let yaml = r#"
title: Failed login
id: failed-login-chain-tenant
logsource:
    category: auth
detection:
    selection:
        EventType: failed_login
    condition: selection
---
title: Successful login
id: success-login-chain-tenant
logsource:
    category: auth
detection:
    selection:
        EventType: success_login
    condition: selection
---
title: Multiple failed logins
id: many-failed-chain-tenant
correlation:
    type: event_count
    rules:
        - failed-login-chain-tenant
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
---
title: Brute Force Followed by Login
id: brute-force-chain-tenant
correlation:
    type: temporal_ordered
    rules:
        - many-failed-chain-tenant
        - success-login-chain-tenant
    group-by:
        - User
    timespan: 120s
    condition:
        gte: 2
level: critical
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let a = crate::tenant::TenantId::new("a").unwrap();
    let failed = json!({"EventType": "failed_login", "User": "victim"});
    let failed = JsonEvent::borrow(&failed);
    for i in 0..3 {
        engine.process_event_at_for_tenant(&failed, 1000 + i, Some(&a));
    }
    let success = json!({"EventType": "success_login", "User": "victim"});
    let success = JsonEvent::borrow(&success);
    let b = crate::tenant::TenantId::new("b").unwrap();
    let other = engine.process_event_at_for_tenant(&success, 1020, Some(&b));
    assert!(
        other
            .correlations()
            .all(|c| c.header.rule_title != "Brute Force Followed by Login"),
        "tenant b's login does not complete tenant a's chain"
    );
    let fired = engine.process_event_at_for_tenant(&success, 1030, Some(&a));
    let chained = fired
        .correlations()
        .find(|c| c.header.rule_title == "Brute Force Followed by Login")
        .expect("chained correlation fires");
    assert_eq!(chained.header.tenant_id.as_ref(), Some(&a));
}

#[test]
fn evict_all_keeps_tenant_state_separate() {
    let a = crate::tenant::TenantId::new("a").unwrap();
    let b = crate::tenant::TenantId::new("b").unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig {
        max_state_entries: 2,
        ..Default::default()
    });
    engine
        .add_collection(&parse_sigma_yaml(TENANT_RULES).unwrap())
        .unwrap();

    let first = json!({"EventType": "login", "User": "user_1"});
    let first = JsonEvent::borrow(&first);
    engine.process_event_at_for_tenant(&first, 100, Some(&a));
    engine.process_event_at_for_tenant(&first, 250, Some(&b));

    let second = json!({"EventType": "login", "User": "user_2"});
    let second = JsonEvent::borrow(&second);
    engine.process_event_at_for_tenant(&second, 300, Some(&a));

    assert_eq!(engine.state_count(), 2);
    let snapshot = engine.introspect_for_tenant(None, None, Some(&a));
    assert_eq!(snapshot.groups.len(), 1);
    assert_eq!(snapshot.groups[0].tenant.as_ref(), Some(&a));
    assert_eq!(snapshot.groups[0].group_key_display, "User=user_2");

    let snapshot = engine.introspect_for_tenant(None, None, Some(&b));
    assert_eq!(snapshot.groups.len(), 1);
    assert_eq!(snapshot.groups[0].tenant.as_ref(), Some(&b));
    assert_eq!(snapshot.groups[0].group_key_display, "User=user_1");
}

#[test]
fn require_tenant_skips_untenanted_events_and_counts_them() {
    let mut engine = tenant_engine(true);
    let value = json!({"EventType": "login", "User": "admin"});
    let event = JsonEvent::borrow(&value);

    let result = engine.process_event_at(&event, 1000);
    assert_eq!(result.correlation_count(), 0);
    assert_eq!(engine.untenanted_skipped(), 1);
    assert_eq!(engine.state_count(), 0);

    let a = crate::tenant::TenantId::new("a").unwrap();
    engine.process_event_at_for_tenant(&event, 1001, Some(&a));
    engine.process_event_at_for_tenant(&event, 1002, Some(&a));
    assert_eq!(engine.untenanted_skipped(), 1);
    assert_eq!(engine.state_count(), 1);
}

#[test]
fn a_tenant_quota_evicts_only_its_own_entries() {
    let a = crate::tenant::TenantId::new("a").unwrap();
    let b = crate::tenant::TenantId::new("b").unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig {
        max_state_entries_per_tenant: Some(2),
        ..Default::default()
    });
    engine
        .add_collection(&parse_sigma_yaml(TENANT_RULES).unwrap())
        .unwrap();

    let quiet = json!({"EventType": "login", "User": "quiet"});
    let quiet = JsonEvent::borrow(&quiet);
    engine.process_event_at_for_tenant(&quiet, 100, Some(&b));

    for i in 0..3 {
        let value = json!({"EventType": "login", "User": format!("noisy_{i}")});
        let event = JsonEvent::borrow(&value);
        engine.process_event_at_for_tenant(&event, 200 + i, Some(&a));
    }

    assert_eq!(engine.state_count(), 3, "quiet tenant plus two noisy");
    let noisy = engine.introspect_for_tenant(None, None, Some(&a));
    assert_eq!(noisy.groups.len(), 2);
    let quiet = engine.introspect_for_tenant(None, None, Some(&b));
    assert_eq!(quiet.groups.len(), 1);
    assert_eq!(quiet.groups[0].group_key_display, "User=quiet");
    assert_eq!(engine.take_tenant_quota_evictions(), 1);
}

#[test]
fn quota_eviction_of_an_expired_window_keeps_its_suppression() {
    let a = crate::tenant::TenantId::new("a").unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig {
        max_state_entries_per_tenant: Some(1),
        suppress: Some(3600),
        ..Default::default()
    });
    engine
        .add_collection(&parse_sigma_yaml(TENANT_RULES).unwrap())
        .unwrap();
    let login = |user: &str| json!({"EventType": "login", "User": user});
    let x = login("x");
    let y = login("y");
    let x = JsonEvent::borrow(&x);
    let y = JsonEvent::borrow(&y);

    engine.process_event_at_for_tenant(&x, 100, Some(&a));
    let fired = engine.process_event_at_for_tenant(&x, 101, Some(&a));
    assert_eq!(fired.correlation_count(), 1);

    // x's window has expired; y at the cap evicts it.
    engine.process_event_at_for_tenant(&y, 200, Some(&a));
    engine.process_event_at_for_tenant(&x, 210, Some(&a));
    let again = engine.process_event_at_for_tenant(&x, 211, Some(&a));
    assert_eq!(
        again.correlation_count(),
        0,
        "x is still inside its suppress window"
    );
}

#[test]
fn restored_and_late_quota_state_counts_toward_the_cap() {
    let a = crate::tenant::TenantId::new("a").unwrap();
    let mut source = tenant_engine(false);
    for user in ["u1", "u2"] {
        let value = json!({"EventType": "login", "User": user});
        source.process_event_at_for_tenant(&JsonEvent::borrow(&value), 100, Some(&a));
    }
    let snapshot = source.export_state();

    let mut restored = CorrelationEngine::new(CorrelationConfig {
        max_state_entries_per_tenant: Some(2),
        require_tenant: true,
        ..Default::default()
    });
    restored
        .add_collection(&parse_sigma_yaml(TENANT_RULES).unwrap())
        .unwrap();
    assert!(restored.import_state(snapshot));
    let third = json!({"EventType": "login", "User": "u3"});
    restored.process_event_at_for_tenant(&JsonEvent::borrow(&third), 110, Some(&a));
    assert_eq!(restored.take_tenant_quota_evictions(), 1);
    assert_eq!(restored.state_count(), 2);

    // A cap set after state exists indexes that state.
    source.set_max_state_entries_per_tenant(Some(2));
    source.process_event_at_for_tenant(&JsonEvent::borrow(&third), 110, Some(&a));
    assert_eq!(source.take_tenant_quota_evictions(), 1);
    assert_eq!(source.state_count(), 2);
}

#[test]
fn the_global_cap_still_applies_without_a_per_tenant_cap() {
    let mut engine = CorrelationEngine::new(CorrelationConfig {
        max_state_entries: 2,
        ..Default::default()
    });
    engine
        .add_collection(&parse_sigma_yaml(TENANT_RULES).unwrap())
        .unwrap();
    for i in 0..5 {
        let value = json!({"EventType": "login", "User": format!("u{i}")});
        let event = JsonEvent::borrow(&value);
        engine.process_event_at(&event, i);
    }
    assert!(engine.state_count() <= 2);
    assert_eq!(engine.take_tenant_quota_evictions(), 0);
}

#[test]
fn imported_buffers_without_seqs_get_distinct_sequences() {
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
title: Many Logins
id: many-logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 300s
    condition:
        gte: 5
level: high
"#;
    let config = CorrelationConfig {
        correlation_event_mode: CorrelationEventMode::Full,
        max_correlation_events: 10,
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config.clone());
    engine
        .add_collection(&parse_sigma_yaml(yaml).unwrap())
        .unwrap();
    for i in 0..3 {
        let v = json!({"EventType": "login", "User": "alice"});
        engine.process_event_at(&JsonEvent::borrow(&v), 1000 + i);
    }

    let snapshot = engine.export_state();
    let mut value = serde_json::to_value(&snapshot).unwrap();
    strip_legacy_entry_keys(&mut value);
    let snapshot: CorrelationSnapshot = serde_json::from_value(value).unwrap();

    let mut restored = CorrelationEngine::new(config);
    restored
        .add_collection(&parse_sigma_yaml(yaml).unwrap())
        .unwrap();
    assert!(restored.import_state(snapshot));

    let mut seqs = Vec::new();
    for buf in restored.event_buffers.values() {
        if let crate::correlation::Retained::Full(entries) = buf.retained() {
            seqs.extend(entries.iter().map(|e| e.seq));
        }
    }
    assert_eq!(seqs.len(), 3, "every restored entry is still buffered");
    assert!(seqs.iter().all(|&s| s != 0), "seqs are assigned: {seqs:?}");
    let unique: std::collections::HashSet<_> = seqs.iter().copied().collect();
    assert_eq!(unique.len(), 3, "seqs are distinct: {seqs:?}");
    let highest = *seqs.iter().max().unwrap();
    assert!(
        restored.next_event_seq > highest,
        "next_event_seq {} must exceed {highest}",
        restored.next_event_seq
    );

    let v = json!({"EventType": "login", "User": "alice"});
    restored.process_event_at(&JsonEvent::borrow(&v), 1003);
    let after = restored
        .event_buffers
        .values()
        .map(|b| b.max_seq())
        .max()
        .unwrap();
    assert!(
        after > highest,
        "the next processed event gets a seq above the restored ones: {after} vs {highest}"
    );
}

/// Remove `seq`, `rule`, and `via` from every serialized buffer entry, as an
/// older binary wrote it.
fn strip_legacy_entry_keys(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            if map.contains_key("ts") && map.contains_key("data") {
                map.remove("seq");
                map.remove("rule");
                map.remove("via");
            }
            for child in map.values_mut() {
                strip_legacy_entry_keys(child);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                strip_legacy_entry_keys(child);
            }
        }
        _ => {}
    }
}

// =========================================================================
// Chain retention
// =========================================================================

const RETENTION_CHAIN: &str = r#"
title: click
id: det-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
---
title: correlation A
id: corr-a
correlation:
    type: event_count
    rules:
        - det-rule
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 1
level: high
---
title: correlation B
id: corr-b
correlation:
    type: event_count
    rules:
        - corr-a
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 1
level: high
custom_attributes:
    rsigma.correlation_event_mode: full
"#;

#[test]
fn test_child_without_own_mode_buffers_for_full_parent_but_emits_no_events() {
    let collection = parse_sigma_yaml(RETENTION_CHAIN).unwrap();
    let mut engine = CorrelationEngine::new(emit_every_hop());
    engine.add_collection(&collection).unwrap();

    let v = json!({"action": "click", "User": "alice"});
    let r = engine.process_event_at(&JsonEvent::borrow(&v), 1000);
    let a = r
        .correlations()
        .find(|c| c.header.rule_title == "correlation A")
        .expect("the child fires");
    assert!(
        a.as_correlation().unwrap().events.is_none(),
        "own mode none emits no events"
    );
    assert!(
        engine.event_buffers.keys().any(|k| k.corr_idx == 0),
        "the child buffers events for its parent"
    );
}

#[test]
fn test_refs_child_under_full_parent_emits_ids_from_events() {
    let yaml = r#"
title: click
id: det-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
---
title: correlation A
id: corr-a
correlation:
    type: event_count
    rules:
        - det-rule
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 2
level: high
custom_attributes:
    rsigma.correlation_event_mode: refs
---
title: correlation B
id: corr-b
correlation:
    type: event_count
    rules:
        - corr-a
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 1
level: high
custom_attributes:
    rsigma.correlation_event_mode: full
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(emit_every_hop());
    engine.add_collection(&collection).unwrap();

    let mut last = None;
    for i in 0..2 {
        let v = json!({"action": "click", "User": "alice", "id": format!("e-{i}")});
        last = Some(engine.process_event_at(&JsonEvent::borrow(&v), 1000 + i));
    }
    let r = last.unwrap();
    let a = r
        .correlations()
        .find(|c| c.header.rule_title == "correlation A")
        .expect("the child fires");
    let refs = a
        .as_correlation()
        .unwrap()
        .event_refs
        .as_ref()
        .expect("refs mode emits refs");
    let ids: Vec<_> = refs.iter().filter_map(|r| r.id.as_deref()).collect();
    assert_eq!(ids, ["e-0", "e-1"]);
}

#[test]
fn test_child_own_cap_bounds_its_output_under_a_larger_parent_cap() {
    let yaml = r#"
title: click
id: det-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
---
title: correlation A
id: corr-a
correlation:
    type: event_count
    rules:
        - det-rule
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 5
level: high
custom_attributes:
    rsigma.correlation_event_mode: full
    rsigma.max_correlation_events: "3"
---
title: correlation B
id: corr-b
correlation:
    type: event_count
    rules:
        - corr-a
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 1
level: high
custom_attributes:
    rsigma.correlation_event_mode: full
    rsigma.max_correlation_events: "10"
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(emit_every_hop());
    engine.add_collection(&collection).unwrap();

    let mut last = None;
    for i in 0..5 {
        let v = json!({"action": "click", "User": "alice", "idx": i});
        last = Some(engine.process_event_at(&JsonEvent::borrow(&v), 1000 + i));
    }
    let r = last.unwrap();
    let a = r
        .correlations()
        .find(|c| c.header.rule_title == "correlation A")
        .expect("the child fires");
    let events = a
        .as_correlation()
        .unwrap()
        .events
        .as_ref()
        .expect("full mode emits events");
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["idx"], 2);
    assert_eq!(events[2]["idx"], 4);
}

#[test]
fn test_no_event_buffers_without_an_event_mode() {
    let collection = parse_sigma_yaml(RETENTION_CHAIN).unwrap();
    // The chain YAML sets full on the parent, so strip it for this case.
    let mut collection = collection;
    for corr in &mut collection.correlations {
        corr.custom_attributes
            .remove("rsigma.correlation_event_mode");
    }
    let mut engine = CorrelationEngine::new(emit_every_hop());
    engine.add_collection(&collection).unwrap();

    let v = json!({"action": "click", "User": "alice"});
    engine.process_event_at(&JsonEvent::borrow(&v), 1000);
    assert_eq!(engine.event_buffer_count(), 0);
    assert_eq!(engine.event_ref_buffer_count(), 0);
}

#[test]
fn test_event_mode_set_after_collection_takes_effect_on_next_event() {
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
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();
    engine.set_correlation_event_mode(CorrelationEventMode::Full);

    let mut last = None;
    for i in 0..2 {
        let v = json!({"EventType": "login", "User": "admin"});
        last = Some(engine.process_event_at(&JsonEvent::borrow(&v), 1000 + i));
    }
    let r = last.unwrap();
    let corr = r.correlations().next().expect("correlation fires");
    assert!(
        corr.as_correlation().unwrap().events.is_some(),
        "the mode set after loading applies to the next event"
    );
}

#[test]
fn test_correlation_cycle_loaded_without_validation_terminates_retention_walk() {
    let yaml = r#"
title: click
id: det-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
---
title: correlation A
id: corr-a
correlation:
    type: event_count
    rules:
        - det-rule
        - corr-b
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 1
level: high
---
title: correlation B
id: corr-b
correlation:
    type: event_count
    rules:
        - corr-a
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 1
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(emit_every_hop());
    for rule in &collection.rules {
        engine.add_rule(rule).unwrap();
    }
    for corr in &collection.correlations {
        engine.add_correlation(corr).unwrap();
    }

    let v = json!({"action": "click", "User": "alice"});
    let r = engine.process_event_at(&JsonEvent::borrow(&v), 1000);
    assert!(!r.correlations().next().is_none());
    assert!(engine.state_count() > 0);
}

// =========================================================================
// Chained correlation events
// =========================================================================

/// One correlation in a [`chain_events_yaml`] chain: its threshold, the window
/// lines under `correlation:`, and the document's trailing YAML lines.
struct Hop {
    gte: u32,
    window: &'static str,
    extra: &'static str,
}

impl Hop {
    fn new(gte: u32) -> Self {
        Hop {
            gte,
            window: "    timespan: 1h",
            extra: "",
        }
    }

    fn window(mut self, window: &'static str) -> Self {
        self.window = window;
        self
    }

    fn extra(mut self, extra: &'static str) -> Self {
        self.extra = extra;
        self
    }
}

/// Detection `det-rule` on clicks, child `corr-a` counting clicks per `User`,
/// and parent `corr-b` counting the child's firings per `User`.
fn chain_events_yaml(child: Hop, parent: Hop) -> String {
    format!(
        r#"
title: click
id: det-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
---
title: correlation A
id: corr-a
correlation:
    type: event_count
    rules:
        - det-rule
    group-by:
        - User
{}
    condition:
        gte: {}
level: high
{}
---
title: correlation B
id: corr-b
correlation:
    type: event_count
    rules:
        - corr-a
    group-by:
        - User
{}
    condition:
        gte: {}
level: high
{}
"#,
        child.window, child.gte, child.extra, parent.window, parent.gte, parent.extra
    )
}

fn chain_events_engine(yaml: &str, config: CorrelationConfig) -> CorrelationEngine {
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();
    engine
}

const FULL: &str = "custom_attributes:\n    rsigma.correlation_event_mode: full";
const REFS: &str = "custom_attributes:\n    rsigma.correlation_event_mode: refs";

/// Feed click number `n` for `alice` at `ts`.
fn click(engine: &mut CorrelationEngine, ts: i64, n: i64) -> ProcessResult {
    let v = json!({"action": "click", "User": "alice", "n": n, "id": format!("e{n}")});
    engine.process_event_at(&JsonEvent::borrow(&v), ts)
}

/// The body of the result titled `title`, if it fired.
fn fired<'a>(result: &'a ProcessResult, title: &str) -> Option<&'a CorrelationBody> {
    result
        .correlations()
        .find(|c| c.header.rule_title == title)
        .and_then(|c| c.as_correlation())
}

/// The `n` markers of a result's events, in order.
fn event_ns(body: &CorrelationBody) -> Vec<i64> {
    body.events
        .as_ref()
        .expect("events present")
        .iter()
        .map(|e| e["n"].as_i64().unwrap())
        .collect()
}

/// The ids of a result's event refs, in order.
fn ref_ids(body: &CorrelationBody) -> Vec<String> {
    body.event_refs
        .as_ref()
        .expect("event refs present")
        .iter()
        .map(|r| r.id.clone().unwrap())
        .collect()
}

#[test]
fn test_chained_parent_reports_refs() {
    let yaml = chain_events_yaml(Hop::new(1), Hop::new(2).extra(REFS));
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    click(&mut engine, 1000, 1);
    let r = click(&mut engine, 1001, 2);
    let b = fired(&r, "correlation B").expect("parent fires");
    assert!(b.events.is_none());
    assert_eq!(ref_ids(b), ["e1", "e2"]);
}

#[test]
fn test_chained_events_reach_the_top_of_a_three_level_chain() {
    let yaml = format!(
        "{}---\ntitle: correlation C\nid: corr-c\ncorrelation:\n    type: event_count\n    rules:\n        - corr-b\n    group-by:\n        - User\n    timespan: 1h\n    condition:\n        gte: 2\nlevel: high\n{FULL}\n",
        chain_events_yaml(Hop::new(1), Hop::new(1))
    );
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    assert!(fired(&click(&mut engine, 1000, 1), "correlation C").is_none());
    let r = click(&mut engine, 1001, 2);
    let c = fired(&r, "correlation C").expect("top correlation fires");
    assert_eq!(event_ns(c), [1, 2]);
}

#[test]
fn test_refiring_child_does_not_duplicate_parent_events() {
    // The child re-fires on every click once it has two, each time handing
    // over every click it holds.
    let yaml = chain_events_yaml(Hop::new(2), Hop::new(3).extra(FULL));
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    for n in 1..=3 {
        assert!(fired(&click(&mut engine, 1000 + n, n), "correlation B").is_none());
    }
    let r = click(&mut engine, 1004, 4);
    let b = fired(&r, "correlation B").expect("parent fires on the third child firing");
    assert_eq!(event_ns(b), [1, 2, 3, 4]);
}

#[test]
fn test_temporal_parent_carries_events_from_both_children() {
    let yaml = format!(
        r#"
title: click
id: det-click
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
---
title: view
id: det-view
logsource:
    product: test
detection:
    selection:
        action: view
    condition: selection
---
title: clicks
id: corr-clicks
correlation:
    type: event_count
    rules:
        - det-click
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 1
---
title: views
id: corr-views
correlation:
    type: event_count
    rules:
        - det-view
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 1
---
title: clicks and views
id: corr-both
correlation:
    type: temporal
    rules:
        - corr-clicks
        - corr-views
    group-by:
        - User
    timespan: 5m
level: high
{FULL}
"#
    );
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    let v = json!({"action": "click", "User": "alice", "n": 1});
    engine.process_event_at(&JsonEvent::borrow(&v), 1000);
    let v = json!({"action": "view", "User": "alice", "n": 2});
    let r = engine.process_event_at(&JsonEvent::borrow(&v), 1001);
    let both = fired(&r, "clicks and views").expect("temporal parent fires");
    assert_eq!(event_ns(both), [1, 2]);
}

#[test]
fn test_resetting_child_still_hands_events_to_its_parent() {
    // A correlation's `rsigma.action` also becomes the engine default, so the
    // parent pins its own.
    let yaml = chain_events_yaml(
        Hop::new(2).extra("custom_attributes:\n    rsigma.action: reset"),
        Hop::new(1).extra(
            "custom_attributes:\n    rsigma.correlation_event_mode: full\n    rsigma.action: alert",
        ),
    );
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    click(&mut engine, 1000, 1);
    let r = click(&mut engine, 1001, 2);
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [1, 2]);

    // The child starts over, but the parent keeps what it already merged.
    click(&mut engine, 1002, 3);
    let r = click(&mut engine, 1003, 4);
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [1, 2, 3, 4]);
}

#[test]
fn test_resetting_parent_reports_only_events_after_its_last_firing() {
    let yaml = chain_events_yaml(
        Hop::new(1).window("    timespan: 1s"),
        Hop::new(2).extra(
            "custom_attributes:\n    rsigma.correlation_event_mode: full\n    rsigma.action: reset",
        ),
    );
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    click(&mut engine, 1000, 1);
    let r = click(&mut engine, 1010, 2);
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [1, 2]);
    click(&mut engine, 1020, 3);
    let r = click(&mut engine, 1030, 4);
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [3, 4]);
}

#[test]
fn test_sliding_parent_drops_child_events_older_than_its_timespan() {
    let yaml = chain_events_yaml(
        Hop::new(1).window("    timespan: 5m"),
        Hop::new(2)
            .window("    timespan: 10s\n    window: sliding")
            .extra(FULL),
    );
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    click(&mut engine, 1000, 1);
    let r = click(&mut engine, 1005, 2);
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [1, 2]);

    // The child still holds clicks 1 and 2 and hands them over again, but
    // they are older than the parent's 10s window.
    assert!(fired(&click(&mut engine, 1030, 3), "correlation B").is_none());
    let r = click(&mut engine, 1031, 4);
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [3, 4]);
}

#[test]
fn test_tumbling_parent_clears_events_when_its_bucket_resets() {
    let yaml = chain_events_yaml(
        Hop::new(1).window("    timespan: 5s"),
        Hop::new(2)
            .window("    timespan: 60s\n    window: tumbling")
            .extra(FULL),
    );
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    click(&mut engine, 1001, 1);
    let r = click(&mut engine, 1010, 2);
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [1, 2]);
    click(&mut engine, 1030, 3);
    let r = click(&mut engine, 1040, 4);
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [3, 4]);
}

#[test]
fn test_session_parent_clears_events_when_its_session_resets() {
    let yaml = chain_events_yaml(
        Hop::new(1).window("    timespan: 5s"),
        Hop::new(2)
            .window("    window: session\n    gap: 30s\n    timespan: 1h")
            .extra(FULL),
    );
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    click(&mut engine, 1000, 1);
    let r = click(&mut engine, 1010, 2);
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [1, 2]);
    click(&mut engine, 1100, 3);
    let r = click(&mut engine, 1110, 4);
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [3, 4]);
}

#[test]
fn test_suppressed_parent_keeps_events_for_its_next_firing() {
    // A correlation's `rsigma.suppress` also becomes the engine default, so the
    // child pins a window short enough to fire on every click.
    let yaml = chain_events_yaml(
        Hop::new(1)
            .window("    timespan: 5s")
            .extra("custom_attributes:\n    rsigma.suppress: 1s"),
        Hop::new(1).extra(
            "custom_attributes:\n    rsigma.correlation_event_mode: full\n    rsigma.suppress: 10s",
        ),
    );
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    let r = click(&mut engine, 1000, 1);
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [1]);
    assert!(fired(&click(&mut engine, 1002, 2), "correlation B").is_none());
    let r = click(&mut engine, 1020, 3);
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [1, 2, 3]);
}

#[test]
fn test_parent_event_mode_alone_gives_the_parent_events() {
    let yaml = chain_events_yaml(Hop::new(1), Hop::new(1).extra(FULL));
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    let r = click(&mut engine, 1000, 1);
    assert_eq!(
        engine.config.correlation_event_mode,
        CorrelationEventMode::None
    );
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [1]);
}

#[test]
fn test_refs_parent_over_full_child_converts_events_to_refs() {
    let yaml = chain_events_yaml(Hop::new(1).extra(FULL), Hop::new(2).extra(REFS));
    let mut engine = chain_events_engine(&yaml, emit_every_hop());
    click(&mut engine, 1000, 1);
    let r = click(&mut engine, 1001, 2);
    assert_eq!(event_ns(fired(&r, "correlation A").unwrap()), [1, 2]);
    let b = fired(&r, "correlation B").unwrap();
    assert!(b.events.is_none());
    assert_eq!(ref_ids(b), ["e1", "e2"]);
}

#[test]
fn test_parent_cap_smaller_than_child_retention_keeps_the_newest() {
    let yaml = chain_events_yaml(
        Hop::new(1).extra(FULL),
        Hop::new(3).extra(
            "custom_attributes:\n    rsigma.correlation_event_mode: full\n    rsigma.max_correlation_events: \"2\"",
        ),
    );
    let mut engine = chain_events_engine(&yaml, emit_every_hop());
    click(&mut engine, 1000, 1);
    click(&mut engine, 1001, 2);
    let r = click(&mut engine, 1002, 3);
    assert_eq!(event_ns(fired(&r, "correlation A").unwrap()), [1, 2, 3]);
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [2, 3]);
}

#[test]
fn test_chained_events_stay_within_their_tenant() {
    let yaml = chain_events_yaml(Hop::new(1), Hop::new(2).extra(FULL));
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    let a = crate::tenant::TenantId::new("a").unwrap();
    let b = crate::tenant::TenantId::new("b").unwrap();
    let event = |n: i64| json!({"action": "click", "User": "alice", "n": n});
    engine.process_event_at_for_tenant(&JsonEvent::borrow(&event(1)), 1000, Some(&a));
    engine.process_event_at_for_tenant(&JsonEvent::borrow(&event(2)), 1001, Some(&b));
    let r = engine.process_event_at_for_tenant(&JsonEvent::borrow(&event(3)), 1002, Some(&a));
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [1, 3]);
    let r = engine.process_event_at_for_tenant(&JsonEvent::borrow(&event(4)), 1003, Some(&b));
    assert_eq!(event_ns(fired(&r, "correlation B").unwrap()), [2, 4]);
}

#[test]
fn test_parent_with_unbuildable_group_key_merges_nothing() {
    let yaml = chain_events_yaml(Hop::new(1), Hop::new(1).extra(FULL)).replace(
        "        - corr-a\n    group-by:\n        - User",
        "        - corr-a\n    group-by:\n        - Host",
    );
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    let r = click(&mut engine, 1000, 1);
    assert!(fired(&r, "correlation B").is_none());
    assert!(engine.event_buffers.keys().all(|k| k.corr_idx == 0));
}

// =========================================================================
// Event sources
// =========================================================================

fn source(rule: &str, via: Option<&str>) -> EventSource {
    EventSource {
        rule: Some(rule.to_string()),
        via: via.map(str::to_string),
    }
}

fn sources(body: &CorrelationBody) -> &[EventSource] {
    body.event_sources
        .as_deref()
        .expect("event sources present")
}

#[test]
fn test_direct_correlation_sources_name_the_matched_rule() {
    let yaml = chain_events_yaml(Hop::new(2).extra(FULL), Hop::new(1));
    let mut engine = chain_events_engine(&yaml, emit_every_hop());
    click(&mut engine, 1000, 1);
    let r = click(&mut engine, 1001, 2);
    let a = fired(&r, "correlation A").unwrap();
    assert_eq!(
        sources(a),
        [source("det-rule", None), source("det-rule", None)]
    );
}

#[test]
fn test_temporal_sources_tell_its_rules_apart() {
    let yaml = format!(
        r#"
title: click
id: det-click
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
---
title: view
id: det-view
logsource:
    product: test
detection:
    selection:
        action: view
    condition: selection
---
title: click then view
id: corr-both
correlation:
    type: temporal
    rules:
        - det-click
        - det-view
    group-by:
        - User
    timespan: 5m
level: high
{REFS}
"#
    );
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    let v = json!({"action": "view", "User": "alice", "id": "v1"});
    engine.process_event_at(&JsonEvent::borrow(&v), 1000);
    let v = json!({"action": "click", "User": "alice", "id": "c1"});
    let r = engine.process_event_at(&JsonEvent::borrow(&v), 1001);
    let both = fired(&r, "click then view").unwrap();
    assert_eq!(ref_ids(both), ["v1", "c1"]);
    assert_eq!(
        sources(both),
        [source("det-view", None), source("det-click", None)]
    );
}

#[test]
fn test_chained_sources_name_the_child_correlation() {
    let yaml = chain_events_yaml(Hop::new(1), Hop::new(2).extra(FULL));
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    click(&mut engine, 1000, 1);
    let r = click(&mut engine, 1001, 2);
    let b = fired(&r, "correlation B").unwrap();
    assert_eq!(
        sources(b),
        [
            source("det-rule", Some("corr-a")),
            source("det-rule", Some("corr-a"))
        ]
    );
}

#[test]
fn test_chained_source_uses_the_name_of_a_child_without_id() {
    let yaml = chain_events_yaml(Hop::new(1), Hop::new(1).extra(FULL))
        .replace("id: corr-a\n", "name: burst\n")
        .replace("        - corr-a\n", "        - burst\n");
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    let r = click(&mut engine, 1000, 1);
    let b = fired(&r, "correlation B").unwrap();
    assert_eq!(sources(b), [source("det-rule", Some("burst"))]);
}

#[test]
fn test_event_delivered_by_two_children_keeps_the_first_source() {
    let yaml = format!(
        r#"
title: click
id: det-rule
logsource:
    product: test
detection:
    selection:
        action: click
    condition: selection
---
title: first
id: corr-first
correlation:
    type: event_count
    rules:
        - det-rule
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 1
---
title: second
id: corr-second
correlation:
    type: event_count
    rules:
        - det-rule
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 1
---
title: both children
id: corr-both
correlation:
    type: temporal
    rules:
        - corr-first
        - corr-second
    group-by:
        - User
    timespan: 5m
level: high
{FULL}
"#
    );
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    let r = click(&mut engine, 1000, 1);
    let both = fired(&r, "both children").unwrap();
    assert_eq!(event_ns(both), [1]);
    assert_eq!(sources(both), [source("det-rule", Some("corr-first"))]);
}

#[test]
fn test_top_of_three_level_chain_names_its_immediate_child() {
    let yaml = format!(
        "{}---\ntitle: correlation C\nid: corr-c\ncorrelation:\n    type: event_count\n    rules:\n        - corr-b\n    group-by:\n        - User\n    timespan: 1h\n    condition:\n        gte: 1\nlevel: high\n{FULL}\n",
        chain_events_yaml(Hop::new(1), Hop::new(1))
    );
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    let r = click(&mut engine, 1000, 1);
    let c = fired(&r, "correlation C").unwrap();
    assert_eq!(sources(c), [source("det-rule", Some("corr-b"))]);
}

#[test]
fn test_capped_sources_stay_aligned_with_events() {
    let yaml = chain_events_yaml(
        Hop::new(1),
        Hop::new(3).extra(
            "custom_attributes:\n    rsigma.correlation_event_mode: refs\n    rsigma.max_correlation_events: \"2\"",
        ),
    );
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    click(&mut engine, 1000, 1);
    click(&mut engine, 1001, 2);
    let r = click(&mut engine, 1002, 3);
    let b = fired(&r, "correlation B").unwrap();
    assert_eq!(ref_ids(b), ["e2", "e3"]);
    assert_eq!(sources(b).len(), 2);
}

#[test]
fn test_entries_restored_without_sources_report_empty_sources() {
    let yaml = chain_events_yaml(Hop::new(3).extra(FULL), Hop::new(1));
    let mut engine = chain_events_engine(&yaml, CorrelationConfig::default());
    click(&mut engine, 1000, 1);
    click(&mut engine, 1001, 2);

    let mut value = serde_json::to_value(engine.export_state()).unwrap();
    strip_legacy_entry_keys(&mut value);
    let snapshot: CorrelationSnapshot = serde_json::from_value(value).unwrap();
    let mut restored = chain_events_engine(&yaml, emit_every_hop());
    assert!(restored.import_state(snapshot));

    let r = click(&mut restored, 1002, 3);
    let a = fired(&r, "correlation A").unwrap();
    assert_eq!(event_ns(a), [1, 2, 3]);
    assert_eq!(
        sources(a),
        [
            EventSource::default(),
            EventSource::default(),
            source("det-rule", None)
        ]
    );
}

#[test]
fn test_no_event_mode_emits_no_sources() {
    let collection = parse_sigma_yaml(RETENTION_CHAIN).unwrap();
    let mut engine = CorrelationEngine::new(emit_every_hop());
    engine.add_collection(&collection).unwrap();
    let v = json!({"action": "click", "User": "alice"});
    let r = engine.process_event_at(&JsonEvent::borrow(&v), 1000);
    let a = fired(&r, "correlation A").unwrap();
    assert!(a.event_sources.is_none());
    assert!(fired(&r, "correlation B").unwrap().event_sources.is_some());
}
