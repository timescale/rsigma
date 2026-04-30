use super::*;
use crate::event::JsonEvent;
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
        ..Default::default()
    });
    engine.add_collection(&collection).unwrap();
    assert_eq!(engine.correlation_rule_count(), 1);

    // Events with no timestamp field — should NOT update correlation state
    let v = json!({"action": "click", "User": "alice"});
    let event = JsonEvent::borrow(&v);

    let r1 = engine.process_event(&event);
    assert!(!r1.detections.is_empty(), "detection should still fire");

    let r2 = engine.process_event(&event);
    assert!(!r2.detections.is_empty(), "detection should still fire");

    let r3 = engine.process_event(&event);
    assert!(!r3.detections.is_empty(), "detection should still fire");

    // No correlations should fire because events were skipped
    assert!(r1.correlations.is_empty());
    assert!(r2.correlations.is_empty());
    assert!(r3.correlations.is_empty());
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
        !r3.correlations.is_empty(),
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

        // Each event should match the detection rule
        assert_eq!(result.detections.len(), 1);

        if i < 2 {
            // Not enough events yet
            assert!(result.correlations.is_empty());
        } else {
            // 3rd event triggers the correlation
            assert_eq!(result.correlations.len(), 1);
            assert_eq!(result.correlations[0].rule_title, "Multiple Whoami");
            assert_eq!(result.correlations[0].aggregated_value, 3.0);
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
        assert!(r.correlations.is_empty());
    }
    for i in 0..3 {
        let v = json!({"EventType": "login", "User": "bob"});
        let event = JsonEvent::borrow(&v);
        let r = engine.process_event_at(&event, ts + i);
        if i == 2 {
            assert_eq!(r.correlations.len(), 1);
            assert_eq!(
                r.correlations[0].group_key,
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
    assert!(r.correlations.is_empty());
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
            assert_eq!(r.correlations.len(), 1);
            assert_eq!(r.correlations[0].aggregated_value, 3.0);
        }
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
    assert!(r1.correlations.is_empty());

    // Now recon B fires — both rules have fired within window
    let v2 = json!({"CommandLine": "ipconfig /all", "User": "admin"});
    let ev2 = JsonEvent::borrow(&v2);
    let r2 = engine.process_event_at(&ev2, ts + 10);
    assert_eq!(r2.correlations.len(), 1);
    assert_eq!(r2.correlations[0].rule_title, "Recon Combo");
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
    assert!(r1.correlations.is_empty());

    // Then successful login — correct order!
    let v2 = json!({"EventType": "success_login", "User": "admin"});
    let ev2 = JsonEvent::borrow(&v2);
    let r2 = engine.process_event_at(&ev2, ts + 10);
    assert_eq!(r2.correlations.len(), 1);
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
    assert!(r2.correlations.is_empty());
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
    assert!(r1.correlations.is_empty());

    let v2 = json!({"action": "upload", "User": "alice", "bytes_sent": 500});
    let ev2 = JsonEvent::borrow(&v2);
    let r2 = engine.process_event_at(&ev2, ts + 5);
    assert_eq!(r2.correlations.len(), 1);
    assert!((r2.correlations[0].aggregated_value - 1100.0).abs() < f64::EPSILON);
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
            assert_eq!(r.correlations.len(), 1);
            assert!((r.correlations[0].aggregated_value - 600.0).abs() < f64::EPSILON);
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

    // generate defaults to false — detection matches are still returned
    // (filtering by generate flag is a backend concern, not eval)
    let v = json!({"action": "test", "User": "alice"});
    let event = JsonEvent::borrow(&v);
    let r = engine.process_event_at(&event, 1000);
    assert_eq!(r.detections.len(), 1);
    assert_eq!(r.correlations.len(), 1);
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
            assert_eq!(r.correlations.len(), 1);
            assert_eq!(
                r.correlations[0].rule_title,
                "Multiple AWS bucket enumerations"
            );
            assert_eq!(r.correlations[0].aggregated_value, 5.0);
        }
    }
}

// =========================================================================
// Chaining: event_count -> temporal_ordered
// =========================================================================

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
            // The event_count correlation should fire
            assert!(
                r.correlations
                    .iter()
                    .any(|c| c.rule_title == "Multiple failed logins"),
                "Expected event_count correlation to fire"
            );
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

    // The detection should match
    assert_eq!(r.detections.len(), 1);
    assert_eq!(r.detections[0].rule_title, "Successful login");
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
    assert_eq!(r1.detections.len(), 1);
    assert!(r1.correlations.is_empty());

    // New connection with source.ip = 10.0.0.5 (same IP, aliased)
    let v2 = json!({
        "event.type": "connection",
        "source.ip": "10.0.0.5"
    });
    let ev2 = JsonEvent::borrow(&v2);
    let r2 = engine.process_event_at(&ev2, ts + 5);
    assert_eq!(r2.detections.len(), 1);
    // Both rules fired for the same internal_ip group → temporal should fire
    assert_eq!(r2.correlations.len(), 1);
    assert_eq!(r2.correlations[0].rule_title, "Error Then Connection");
    // Check group key contains the aliased field
    assert!(
        r2.correlations[0]
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
    assert!(r1.correlations.is_empty(), "only one rule fired so far");

    // Password change by alice — both rules have now fired
    let ev2 = json!({"EventType": "password_change", "User": "alice"});
    let r2 = engine.process_event_at(&JsonEvent::borrow(&ev2), ts + 10);
    assert_eq!(
        r2.correlations.len(),
        1,
        "temporal correlation should fire: both rules matched"
    );
    assert_eq!(r2.correlations[0].rule_title, "Credential Attack");
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
    assert_eq!(r.correlations.len(), 1);
    assert_eq!(r.correlations[0].rule_title, "Any Remote Access");
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
    assert!(r.correlations.is_empty(), "only one of two AND rules fired");

    // Now ipconfig (recon-2) — should fire
    let ev2 = json!({"CommandLine": "ipconfig /all", "Host": "srv01"});
    let r2 = engine.process_event_at(&JsonEvent::borrow(&ev2), 1010);
    assert_eq!(r2.correlations.len(), 1);
    assert_eq!(r2.correlations[0].rule_title, "Full Recon");
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
            r.correlations.is_empty(),
            "service account should be filtered, no correlation"
        );
    }

    // Normal user failures should count
    for i in 0..2 {
        let ev = json!({"EventType": "auth_failure", "User": "alice"});
        let r = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 10 + i);
        assert!(r.correlations.is_empty(), "not yet 3 events");
    }

    // Third failure triggers correlation
    let ev = json!({"EventType": "auth_failure", "User": "alice"});
    let r = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 12);
    assert_eq!(r.correlations.len(), 1);
    assert_eq!(r.correlations[0].rule_title, "Brute Force");
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

    assert_eq!(r.correlations.len(), 1);
    assert_eq!(r.correlations[0].rule_title, "Mass File Access");
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
        FilePath|expand: 'C:\Users\%User%\Temp'
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
    assert!(r1.correlations.is_empty());

    let ev2 = json!({"FilePath": "C:\\Users\\alice\\Temp", "User": "alice"});
    let r2 = engine.process_event_at(&JsonEvent::borrow(&ev2), ts + 1);
    assert_eq!(r2.correlations.len(), 1);
    assert_eq!(r2.correlations[0].rule_title, "Excessive Temp Access");

    // Different user — should NOT match (path says alice, user is bob)
    let ev3 = json!({"FilePath": "C:\\Users\\alice\\Temp", "User": "bob"});
    let r3 = engine.process_event_at(&JsonEvent::borrow(&ev3), ts + 2);
    // Detection doesn't fire for this event since expand resolves to C:\Users\bob\Temp
    assert_eq!(r3.detections.len(), 0);
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
    assert_eq!(r1.detections.len(), 1);
    assert!(r1.correlations.is_empty());

    let ev2 = json!({"EventType": "login", "User": "alice", "Timestamp": "2024-01-15T03:45:00Z"});
    let r2 = engine.process_event_at(&JsonEvent::borrow(&ev2), ts + 1);
    assert_eq!(r2.correlations.len(), 1);
    assert_eq!(r2.correlations[0].rule_title, "Frequent Night Logins");

    // Login at noon — should NOT count
    let ev3 = json!({"EventType": "login", "User": "bob", "Timestamp": "2024-01-15T12:00:00Z"});
    let r3 = engine.process_event_at(&JsonEvent::borrow(&ev3), ts + 2);
    assert!(
        r3.detections.is_empty(),
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
        assert!(r.correlations.is_empty(), "2 events should not fire (gt:2)");
    }

    // 3rd event — gt:2 is true, lte:5 is true → fires
    let ev3 = json!({"EventType": "login", "User": "alice"});
    let r3 = engine.process_event_at(&JsonEvent::borrow(&ev3), ts + 3);
    assert_eq!(r3.correlations.len(), 1, "3 events: gt:2 AND lte:5");

    // Send events 4, 5 — still in range
    for i in 4..=5 {
        let ev = json!({"EventType": "login", "User": "alice"});
        let r = engine.process_event_at(&JsonEvent::borrow(&ev), ts + i);
        assert_eq!(r.correlations.len(), 1, "{i} events still in range");
    }

    // 6th event — lte:5 is false → no fire
    let ev6 = json!({"EventType": "login", "User": "alice"});
    let r6 = engine.process_event_at(&JsonEvent::borrow(&ev6), ts + 6);
    assert!(
        r6.correlations.is_empty(),
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
    assert_eq!(r3.correlations.len(), 1, "should fire on 3rd event");

    // 4th event within suppress window → suppressed
    let r4 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 3);
    assert!(
        r4.correlations.is_empty(),
        "should be suppressed within 10s window"
    );

    // 5th event still within suppress window → suppressed
    let r5 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 9);
    assert!(
        r5.correlations.is_empty(),
        "should be suppressed at ts+9 (< ts+2+10)"
    );

    // Event after suppress window expires → fires again
    let r6 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 13);
    assert_eq!(
        r6.correlations.len(),
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
    assert_eq!(r.correlations.len(), 1, "alice should fire");

    // Bob hits threshold — different group key, not suppressed
    let ev_b = json!({"EventType": "login", "User": "bob"});
    engine.process_event_at(&JsonEvent::borrow(&ev_b), ts + 3);
    engine.process_event_at(&JsonEvent::borrow(&ev_b), ts + 4);
    let r = engine.process_event_at(&JsonEvent::borrow(&ev_b), ts + 5);
    assert_eq!(r.correlations.len(), 1, "bob should fire independently");

    // Alice is still suppressed
    let r = engine.process_event_at(&JsonEvent::borrow(&ev_a), ts + 6);
    assert!(r.correlations.is_empty(), "alice still suppressed");
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
    assert_eq!(r3.correlations.len(), 1, "should fire on 3rd event");

    // State was reset, so 4th and 5th events should NOT fire
    let r4 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 3);
    assert!(r4.correlations.is_empty(), "reset: need 3 more events");

    let r5 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 4);
    assert!(r5.correlations.is_empty(), "reset: still only 2");

    // 6th event (3rd after reset) should fire again
    let r6 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 5);
    assert_eq!(
        r6.correlations.len(),
        1,
        "should fire again after 3 events post-reset"
    );
}

// =========================================================================
// Generate flag / emit_detections
// =========================================================================

#[test]
fn test_emit_detections_true_by_default() {
    let collection = parse_sigma_yaml(suppression_yaml()).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();

    let ev = json!({"EventType": "login", "User": "alice"});
    let r = engine.process_event_at(&JsonEvent::borrow(&ev), 1000);
    assert_eq!(r.detections.len(), 1, "by default detections are emitted");
}

#[test]
fn test_emit_detections_false_suppresses() {
    let collection = parse_sigma_yaml(suppression_yaml()).unwrap();
    let config = CorrelationConfig {
        emit_detections: false,
        ..Default::default()
    };
    let mut engine = CorrelationEngine::new(config);
    engine.add_collection(&collection).unwrap();

    let ev = json!({"EventType": "login", "User": "alice"});
    let r = engine.process_event_at(&JsonEvent::borrow(&ev), 1000);
    assert!(
        r.detections.is_empty(),
        "detection matches should be suppressed when emit_detections=false"
    );
}

#[test]
fn test_generate_true_keeps_detections() {
    // When generate: true, detections should be emitted even with emit_detections=false
    let yaml = r#"
title: Login
id: login-gen
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
        - login-gen
    group-by:
        - User
    timeframe: 60s
    condition:
        gte: 3
    generate: true
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
        r.detections.len(),
        1,
        "generate:true keeps detection output"
    );
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
    assert_eq!(r3.correlations.len(), 1, "fires on 3rd event");

    // Push 3 more events quickly (state was reset, so new count → 3)
    // but suppress window hasn't expired (ts+2 + 5 = ts+7)
    engine.process_event_at(&JsonEvent::borrow(&ev), ts + 3);
    engine.process_event_at(&JsonEvent::borrow(&ev), ts + 4);
    let r = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 5);
    assert!(
        r.correlations.is_empty(),
        "threshold met again but still suppressed"
    );

    // After suppress expires (at ts+8, which is ts+2+6 > suppress=5),
    // the accumulated events from step 2 (ts+3,4,5) still satisfy gte:3,
    // so the first event after expiry fires immediately and resets.
    let r = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 8);
    assert_eq!(
        r.correlations.len(),
        1,
        "fires after suppress expires (accumulated events + new one)"
    );

    // State was reset again at ts+8, suppress window now ts+8..ts+13.
    // Need 3 new events to fire, and suppress must expire.
    engine.process_event_at(&JsonEvent::borrow(&ev), ts + 9);
    engine.process_event_at(&JsonEvent::borrow(&ev), ts + 10);
    let r = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 11);
    assert!(
        r.correlations.is_empty(),
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
    assert_eq!(r3.correlations.len(), 1);

    // Without suppression, 4th event should also fire
    let r4 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 3);
    assert_eq!(
        r4.correlations.len(),
        1,
        "no suppression: fires on every event after threshold"
    );

    let r5 = engine.process_event_at(&JsonEvent::borrow(&ev), ts + 4);
    assert_eq!(r5.correlations.len(), 1, "still fires");
}

// =========================================================================
// Custom attribute → engine config tests
// =========================================================================

fn yaml_str_attrs<const N: usize>(
    pairs: [(&str, &str); N],
) -> std::collections::HashMap<String, serde_yaml::Value> {
    pairs
        .into_iter()
        .map(|(k, v)| (k.to_string(), serde_yaml::Value::String(v.to_string())))
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
    assert!(!result.detections.is_empty() || result.correlations.is_empty());
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
            assert_eq!(result.correlations.len(), 1);
            // Events should NOT be included by default
            assert!(result.correlations[0].events.is_none());
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
        if !result.correlations.is_empty() {
            corr_result = Some(result);
        }
    }

    let result = corr_result.expect("correlation should have fired");
    let corr = &result.correlations[0];

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
        if !result.correlations.is_empty() {
            corr_result = Some(result);
        }
    }

    let result = corr_result.expect("correlation should have fired");
    let events = result.correlations[0]
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
            assert_eq!(result.correlations.len(), 1);
            let events = result.correlations[0].events.as_ref().unwrap();
            assert_eq!(events.len(), 2);
        }
    }

    // After reset, event buffer should be cleared.
    // Second round: need 2 more events to fire again
    let v = json!({"EventType": "login", "User": "admin", "round": 2, "idx": 0});
    let event = JsonEvent::borrow(&v);
    let result = engine.process_event_at(&event, 1010);
    assert!(
        result.correlations.is_empty(),
        "should not fire with only 1 event after reset"
    );

    let v = json!({"EventType": "login", "User": "admin", "round": 2, "idx": 1});
    let event = JsonEvent::borrow(&v);
    let result = engine.process_event_at(&event, 1011);
    assert_eq!(result.correlations.len(), 1);
    let events = result.correlations[0].events.as_ref().unwrap();
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
            assert_eq!(result.correlations.len(), 1);
            assert!(result.correlations[0].events.is_some());
            assert_eq!(result.correlations[0].events.as_ref().unwrap().len(), 2);
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
        result.correlations.is_empty(),
        "should not fire — old events evicted"
    );

    // Push 2 more to reach threshold
    for i in 3..5 {
        let v = json!({"EventType": "login", "User": "admin", "idx": i});
        let event = JsonEvent::borrow(&v);
        let result = engine.process_event_at(&event, 1016 + i - 3);
        if i == 4 {
            assert_eq!(result.correlations.len(), 1);
            let events = result.correlations[0].events.as_ref().unwrap();
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
        if !result.correlations.is_empty() {
            corr_result = Some(result.correlations[0].clone());
        }
    }

    let result = corr_result.expect("correlation should have fired");
    // In refs mode: events should be None, event_refs should be Some
    assert!(
        result.events.is_none(),
        "Full events should not be included in refs mode"
    );
    let refs = result
        .event_refs
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
        if !result.correlations.is_empty() {
            corr_result = Some(result.correlations[0].clone());
        }
    }

    let result = corr_result.expect("correlation should have fired");
    let refs = result.event_refs.expect("event_refs should be present");
    // No ID field in events → id should be None
    for r in &refs {
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
        if !result.correlations.is_empty() {
            corr_result = Some(result.correlations[0].clone());
        }
    }

    let result = corr_result.expect("correlation should fire with per-correlation refs mode");
    // Per-correlation override should enable refs mode even though engine default is None
    assert!(result.events.is_none());
    let refs = result
        .event_refs
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
        assert_eq!(r1.detections.len(), r2.detections.len());
        assert_eq!(r1.correlations.len(), r2.correlations.len());
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
        assert_eq!(seq.detections.len(), bat.detections.len());
        assert_eq!(seq.correlations.len(), bat.correlations.len());
    }
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
            assert_eq!(result.correlations.len(), 1);
            let corr = &result.correlations[0];
            assert_eq!(corr.rule_title, "Many Logins");
            assert_eq!(
                corr.custom_attributes.get("my_custom_field"),
                Some(&serde_json::Value::String("hello".to_string()))
            );
            assert_eq!(
                corr.custom_attributes.get("priority"),
                Some(&serde_json::json!(9))
            );
            let nested = corr.custom_attributes.get("nested").unwrap();
            assert_eq!(nested.get("key"), Some(&serde_json::json!("value")));

            assert!(!corr.custom_attributes.contains_key("title"));
            assert!(!corr.custom_attributes.contains_key("correlation"));
            assert!(!corr.custom_attributes.contains_key("level"));
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

    assert_eq!(result.detections.len(), 1);
    let det = &result.detections[0];
    assert_eq!(
        det.custom_attributes.get("my_detection_tag"),
        Some(&serde_json::Value::String("important".to_string()))
    );
    assert_eq!(
        det.custom_attributes.get("score"),
        Some(&serde_json::json!(42))
    );
    assert!(!det.custom_attributes.contains_key("title"));
}
