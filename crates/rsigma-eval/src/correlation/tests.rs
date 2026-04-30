use super::*;
use crate::event::JsonEvent;
use serde_json::json;

#[test]
fn test_group_key_extract() {
    let v = json!({"User": "admin", "Host": "srv01"});
    let event = JsonEvent::borrow(&v);
    let group_by = vec![
        GroupByField::Direct("User".to_string()),
        GroupByField::Direct("Host".to_string()),
    ];
    let key = GroupKey::extract(&event, &group_by, &["rule1"]);
    assert_eq!(
        key.0,
        vec![Some("admin".to_string()), Some("srv01".to_string())]
    );
}

#[test]
fn test_group_key_missing_field() {
    let v = json!({"User": "admin"});
    let event = JsonEvent::borrow(&v);
    let group_by = vec![
        GroupByField::Direct("User".to_string()),
        GroupByField::Direct("Host".to_string()),
    ];
    let key = GroupKey::extract(&event, &group_by, &["rule1"]);
    assert_eq!(key.0, vec![Some("admin".to_string()), None]);
}

#[test]
fn test_group_key_aliased() {
    let v = json!({"source.ip": "10.0.0.1"});
    let event = JsonEvent::borrow(&v);
    let group_by = vec![GroupByField::Aliased {
        alias: "internal_ip".to_string(),
        mapping: HashMap::from([
            ("rule_a".to_string(), "source.ip".to_string()),
            ("rule_b".to_string(), "destination.ip".to_string()),
        ]),
    }];
    let key = GroupKey::extract(&event, &group_by, &["rule_a"]);
    assert_eq!(key.0, vec![Some("10.0.0.1".to_string())]);
}

#[test]
fn test_condition_check() {
    let cond = CompiledCondition {
        field: None,
        predicates: vec![(ConditionOperator::Gte, 100.0)],
        percentile: None,
    };
    assert!(!cond.check(99.0));
    assert!(cond.check(100.0));
    assert!(cond.check(101.0));
}

#[test]
fn test_condition_check_range() {
    let cond = CompiledCondition {
        field: None,
        predicates: vec![
            (ConditionOperator::Gt, 100.0),
            (ConditionOperator::Lte, 200.0),
        ],
        percentile: None,
    };
    assert!(!cond.check(100.0));
    assert!(cond.check(101.0));
    assert!(cond.check(200.0));
    assert!(!cond.check(201.0));
}

#[test]
fn test_window_event_count() {
    let mut state = WindowState::new_for(CorrelationType::EventCount);
    for i in 0..5 {
        state.push_event_count(1000 + i);
    }
    let cond = CompiledCondition {
        field: None,
        predicates: vec![(ConditionOperator::Gte, 5.0)],
        percentile: None,
    };
    assert_eq!(
        state.check_condition(&cond, CorrelationType::EventCount, &[], None),
        Some(5.0)
    );
}

#[test]
fn test_window_event_count_eviction() {
    let mut state = WindowState::new_for(CorrelationType::EventCount);
    for i in 0..10 {
        state.push_event_count(1000 + i);
    }
    // Evict events before ts=1005
    state.evict(1005);
    let cond = CompiledCondition {
        field: None,
        predicates: vec![(ConditionOperator::Gte, 5.0)],
        percentile: None,
    };
    assert_eq!(
        state.check_condition(&cond, CorrelationType::EventCount, &[], None),
        Some(5.0)
    );
}

#[test]
fn test_window_value_count() {
    let mut state = WindowState::new_for(CorrelationType::ValueCount);
    state.push_value_count(1000, "user1".to_string());
    state.push_value_count(1001, "user2".to_string());
    state.push_value_count(1002, "user1".to_string()); // duplicate
    state.push_value_count(1003, "user3".to_string());

    let cond = CompiledCondition {
        field: Some(vec!["User".to_string()]),
        predicates: vec![(ConditionOperator::Gte, 3.0)],
        percentile: None,
    };
    assert_eq!(
        state.check_condition(&cond, CorrelationType::ValueCount, &[], None),
        Some(3.0)
    );
}

#[test]
fn test_window_temporal() {
    let refs = vec!["rule_a".to_string(), "rule_b".to_string()];
    let mut state = WindowState::new_for(CorrelationType::Temporal);
    state.push_temporal(1000, "rule_a");
    // Only rule_a fired — condition: all refs must fire
    let cond = CompiledCondition {
        field: None,
        predicates: vec![(ConditionOperator::Gte, 2.0)],
        percentile: None,
    };
    assert!(
        state
            .check_condition(&cond, CorrelationType::Temporal, &refs, None)
            .is_none()
    );

    // Now rule_b fires too
    state.push_temporal(1001, "rule_b");
    assert_eq!(
        state.check_condition(&cond, CorrelationType::Temporal, &refs, None),
        Some(2.0)
    );
}

#[test]
fn test_window_temporal_ordered() {
    let refs = vec![
        "rule_a".to_string(),
        "rule_b".to_string(),
        "rule_c".to_string(),
    ];
    let mut state = WindowState::new_for(CorrelationType::TemporalOrdered);
    // Fire in order: a, b, c
    state.push_temporal(1000, "rule_a");
    state.push_temporal(1001, "rule_b");
    state.push_temporal(1002, "rule_c");

    let cond = CompiledCondition {
        field: None,
        predicates: vec![(ConditionOperator::Gte, 3.0)],
        percentile: None,
    };
    assert!(
        state
            .check_condition(&cond, CorrelationType::TemporalOrdered, &refs, None)
            .is_some()
    );
}

#[test]
fn test_window_temporal_ordered_wrong_order() {
    let refs = vec!["rule_a".to_string(), "rule_b".to_string()];
    let mut state = WindowState::new_for(CorrelationType::TemporalOrdered);
    // Fire in wrong order: b before a
    state.push_temporal(1000, "rule_b");
    state.push_temporal(1001, "rule_a");

    let cond = CompiledCondition {
        field: None,
        predicates: vec![(ConditionOperator::Gte, 2.0)],
        percentile: None,
    };
    assert!(
        state
            .check_condition(&cond, CorrelationType::TemporalOrdered, &refs, None)
            .is_none()
    );
}

#[test]
fn test_window_value_sum() {
    let mut state = WindowState::new_for(CorrelationType::ValueSum);
    state.push_numeric(1000, 500.0);
    state.push_numeric(1001, 600.0);

    let cond = CompiledCondition {
        field: Some(vec!["bytes_sent".to_string()]),
        predicates: vec![(ConditionOperator::Gt, 1000.0)],
        percentile: None,
    };
    assert_eq!(
        state.check_condition(&cond, CorrelationType::ValueSum, &[], None),
        Some(1100.0)
    );
}

#[test]
fn test_window_value_avg() {
    let mut state = WindowState::new_for(CorrelationType::ValueAvg);
    state.push_numeric(1000, 100.0);
    state.push_numeric(1001, 200.0);
    state.push_numeric(1002, 300.0);

    let cond = CompiledCondition {
        field: Some(vec!["bytes".to_string()]),
        predicates: vec![(ConditionOperator::Gte, 200.0)],
        percentile: None,
    };
    assert_eq!(
        state.check_condition(&cond, CorrelationType::ValueAvg, &[], None),
        Some(200.0)
    );
}

#[test]
fn test_window_value_median() {
    let mut state = WindowState::new_for(CorrelationType::ValueMedian);
    state.push_numeric(1000, 10.0);
    state.push_numeric(1001, 20.0);
    state.push_numeric(1002, 30.0);

    let cond = CompiledCondition {
        field: Some(vec!["latency".to_string()]),
        predicates: vec![(ConditionOperator::Gte, 20.0)],
        percentile: None,
    };
    assert_eq!(
        state.check_condition(&cond, CorrelationType::ValueMedian, &[], None),
        Some(20.0)
    );
}

#[test]
fn test_compile_correlation_basic() {
    use rsigma_parser::parse_sigma_yaml;

    let yaml = r#"
title: Base Rule
id: f305fd62-beca-47da-ad95-7690a0620084
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: "s3.amazonaws.com"
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
        gte: 100
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.correlations.len(), 1);

    let compiled = compile_correlation(&collection.correlations[0]).unwrap();
    assert_eq!(compiled.correlation_type, CorrelationType::EventCount);
    assert_eq!(compiled.timespan_secs, 3600);
    assert_eq!(compiled.rule_refs.len(), 1);
    assert_eq!(compiled.group_by.len(), 1);
    assert!(compiled.condition.check(100.0));
    assert!(!compiled.condition.check(99.0));
}

// =========================================================================
// Extended temporal condition tests
// =========================================================================

#[test]
fn test_eval_temporal_expr_and() {
    let mut rule_hits = HashMap::new();
    rule_hits.insert("rule_a".to_string(), VecDeque::from([1000]));
    rule_hits.insert("rule_b".to_string(), VecDeque::from([1001]));

    let expr = ConditionExpr::And(vec![
        ConditionExpr::Identifier("rule_a".to_string()),
        ConditionExpr::Identifier("rule_b".to_string()),
    ]);
    assert!(eval_temporal_expr(&expr, &rule_hits));
}

#[test]
fn test_eval_temporal_expr_and_incomplete() {
    let mut rule_hits = HashMap::new();
    rule_hits.insert("rule_a".to_string(), VecDeque::from([1000]));
    // rule_b not fired

    let expr = ConditionExpr::And(vec![
        ConditionExpr::Identifier("rule_a".to_string()),
        ConditionExpr::Identifier("rule_b".to_string()),
    ]);
    assert!(!eval_temporal_expr(&expr, &rule_hits));
}

#[test]
fn test_eval_temporal_expr_or() {
    let mut rule_hits = HashMap::new();
    rule_hits.insert("rule_a".to_string(), VecDeque::from([1000]));

    let expr = ConditionExpr::Or(vec![
        ConditionExpr::Identifier("rule_a".to_string()),
        ConditionExpr::Identifier("rule_b".to_string()),
    ]);
    assert!(eval_temporal_expr(&expr, &rule_hits));
}

#[test]
fn test_eval_temporal_expr_not() {
    let rule_hits = HashMap::new();

    let expr = ConditionExpr::Not(Box::new(ConditionExpr::Identifier("rule_a".to_string())));
    assert!(eval_temporal_expr(&expr, &rule_hits));
}

#[test]
fn test_eval_temporal_expr_complex() {
    let mut rule_hits = HashMap::new();
    rule_hits.insert("rule_a".to_string(), VecDeque::from([1000]));
    rule_hits.insert("rule_b".to_string(), VecDeque::from([1001]));
    // rule_c NOT fired

    // (rule_a and rule_b) and not rule_c
    let expr = ConditionExpr::And(vec![
        ConditionExpr::And(vec![
            ConditionExpr::Identifier("rule_a".to_string()),
            ConditionExpr::Identifier("rule_b".to_string()),
        ]),
        ConditionExpr::Not(Box::new(ConditionExpr::Identifier("rule_c".to_string()))),
    ]);
    assert!(eval_temporal_expr(&expr, &rule_hits));
}

#[test]
fn test_check_condition_with_extended_expr() {
    let refs = vec!["rule_a".to_string(), "rule_b".to_string()];
    let mut state = WindowState::new_for(CorrelationType::Temporal);
    state.push_temporal(1000, "rule_a");
    state.push_temporal(1001, "rule_b");

    let cond = CompiledCondition {
        field: None,
        predicates: vec![(ConditionOperator::Gte, 1.0)],
        percentile: None,
    };
    let expr = ConditionExpr::And(vec![
        ConditionExpr::Identifier("rule_a".to_string()),
        ConditionExpr::Identifier("rule_b".to_string()),
    ]);

    // With expression: should match (both rules fired)
    assert!(
        state
            .check_condition(&cond, CorrelationType::Temporal, &refs, Some(&expr))
            .is_some()
    );

    // Now test with only rule_a: expression should fail
    let mut state2 = WindowState::new_for(CorrelationType::Temporal);
    state2.push_temporal(1000, "rule_a");
    assert!(
        state2
            .check_condition(&cond, CorrelationType::Temporal, &refs, Some(&expr))
            .is_none()
    );
}

// =========================================================================
// Percentile linear interpolation tests
// =========================================================================

#[test]
fn test_percentile_linear_interp_single() {
    assert!((percentile_linear_interp(&[42.0], 50.0) - 42.0).abs() < f64::EPSILON);
}

#[test]
fn test_percentile_linear_interp_basic() {
    // Values: [1, 2, 3, 4, 5]
    let values = &[1.0, 2.0, 3.0, 4.0, 5.0];
    // 0th percentile = 1.0
    assert!((percentile_linear_interp(values, 0.0) - 1.0).abs() < f64::EPSILON);
    // 25th percentile = 2.0
    assert!((percentile_linear_interp(values, 25.0) - 2.0).abs() < f64::EPSILON);
    // 50th percentile = 3.0
    assert!((percentile_linear_interp(values, 50.0) - 3.0).abs() < f64::EPSILON);
    // 75th percentile = 4.0
    assert!((percentile_linear_interp(values, 75.0) - 4.0).abs() < f64::EPSILON);
    // 100th percentile = 5.0
    assert!((percentile_linear_interp(values, 100.0) - 5.0).abs() < f64::EPSILON);
}

#[test]
fn test_percentile_linear_interp_interpolation() {
    // Values: [10, 20, 30, 40]
    let values = &[10.0, 20.0, 30.0, 40.0];
    // 50th percentile: rank = 0.5 * 3 = 1.5, interp between 20 and 30 = 25
    assert!((percentile_linear_interp(values, 50.0) - 25.0).abs() < f64::EPSILON);
}

#[test]
fn test_percentile_linear_interp_1st_percentile() {
    // Values: [1, 2, 3, ..., 100]
    let values: Vec<f64> = (1..=100).map(|x| x as f64).collect();
    // 1st percentile = 1.0 + 0.01 * 99 * (2.0 - 1.0) ~ 1.99
    let p1 = percentile_linear_interp(&values, 1.0);
    assert!((p1 - 1.99).abs() < 0.01);
}

#[test]
fn test_value_percentile_check_condition() {
    let mut state = WindowState::new_for(CorrelationType::ValuePercentile);
    // Push 100 values: 1.0, 2.0, ..., 100.0
    for i in 1..=100 {
        state.push_numeric(1000 + i, i as f64);
    }

    let cond = CompiledCondition {
        field: Some(vec!["latency".to_string()]),
        predicates: vec![(ConditionOperator::Lte, 50.0)],
        percentile: None,
    };
    // 50th percentile of 1..100 should be ~50.5
    let result = state.check_condition(&cond, CorrelationType::ValuePercentile, &[], None);
    assert!(result.is_some());
    let val = result.unwrap();
    assert!((val - 50.5).abs() < 1.0, "expected ~50.5, got {val}");
}

#[test]
fn test_percentile_0th_and_100th() {
    let values = &[5.0, 10.0, 15.0, 20.0];
    assert!((percentile_linear_interp(values, 0.0) - 5.0).abs() < f64::EPSILON);
    assert!((percentile_linear_interp(values, 100.0) - 20.0).abs() < f64::EPSILON);
}

#[test]
fn test_percentile_two_values() {
    let values = &[10.0, 20.0];
    // 50th percentile between 10 and 20 = 15
    assert!((percentile_linear_interp(values, 50.0) - 15.0).abs() < f64::EPSILON);
    // 25th percentile = 12.5
    assert!((percentile_linear_interp(values, 25.0) - 12.5).abs() < f64::EPSILON);
}

#[test]
fn test_percentile_clamps_out_of_range() {
    let values = &[1.0, 2.0, 3.0];
    // Negative percentile clamps to 0
    assert!((percentile_linear_interp(values, -10.0) - 1.0).abs() < f64::EPSILON);
    // > 100 clamps to 100
    assert!((percentile_linear_interp(values, 150.0) - 3.0).abs() < f64::EPSILON);
}

#[test]
fn test_value_percentile_empty_window() {
    let state = WindowState::new_for(CorrelationType::ValuePercentile);
    let cond = CompiledCondition {
        field: Some(vec!["latency".to_string()]),
        predicates: vec![(ConditionOperator::Lte, 50.0)],
        percentile: None,
    };
    // Empty window should return None
    assert!(
        state
            .check_condition(&cond, CorrelationType::ValuePercentile, &[], None)
            .is_none()
    );
}

#[test]
fn test_extended_temporal_or_single_rule() {
    // "rule_a or rule_b" — only rule_a fired
    let mut rule_hits = HashMap::new();
    rule_hits.insert("rule_a".to_string(), VecDeque::from([1000]));

    let expr = ConditionExpr::Or(vec![
        ConditionExpr::Identifier("rule_a".to_string()),
        ConditionExpr::Identifier("rule_b".to_string()),
    ]);
    assert!(eval_temporal_expr(&expr, &rule_hits));
}

#[test]
fn test_extended_temporal_empty_hits() {
    let rule_hits = HashMap::new();

    // "rule_a and rule_b" — nothing fired
    let expr = ConditionExpr::And(vec![
        ConditionExpr::Identifier("rule_a".to_string()),
        ConditionExpr::Identifier("rule_b".to_string()),
    ]);
    assert!(!eval_temporal_expr(&expr, &rule_hits));

    // "rule_a or rule_b" — nothing fired
    let expr_or = ConditionExpr::Or(vec![
        ConditionExpr::Identifier("rule_a".to_string()),
        ConditionExpr::Identifier("rule_b".to_string()),
    ]);
    assert!(!eval_temporal_expr(&expr_or, &rule_hits));
}

#[test]
fn test_extended_temporal_with_empty_deque() {
    // Rule exists in map but with empty deque (all evicted)
    let mut rule_hits = HashMap::new();
    rule_hits.insert("rule_a".to_string(), VecDeque::new());
    rule_hits.insert("rule_b".to_string(), VecDeque::from([1000]));

    let expr = ConditionExpr::And(vec![
        ConditionExpr::Identifier("rule_a".to_string()),
        ConditionExpr::Identifier("rule_b".to_string()),
    ]);
    // rule_a has empty deque — should be treated as not fired
    assert!(!eval_temporal_expr(&expr, &rule_hits));
}

#[test]
fn test_check_condition_temporal_no_extended_expr() {
    // Standard temporal without extended expr: uses threshold count
    let refs = vec![
        "rule_a".to_string(),
        "rule_b".to_string(),
        "rule_c".to_string(),
    ];
    let mut state = WindowState::new_for(CorrelationType::Temporal);
    state.push_temporal(1000, "rule_a");
    state.push_temporal(1001, "rule_b");

    // Threshold: at least 2 rules must fire
    let cond = CompiledCondition {
        field: None,
        predicates: vec![(ConditionOperator::Gte, 2.0)],
        percentile: None,
    };
    // Without extended expr: 2 of 3 rules fired, meets gte 2
    assert_eq!(
        state.check_condition(&cond, CorrelationType::Temporal, &refs, None),
        Some(2.0)
    );

    // With threshold 3: not enough
    let cond3 = CompiledCondition {
        field: None,
        predicates: vec![(ConditionOperator::Gte, 3.0)],
        percentile: None,
    };
    assert!(
        state
            .check_condition(&cond3, CorrelationType::Temporal, &refs, None)
            .is_none()
    );
}

// =========================================================================
// EventBuffer tests
// =========================================================================

#[test]
fn test_event_buffer_push_and_decompress() {
    let mut buf = EventBuffer::new(10);
    let event = json!({"User": "admin", "action": "login", "src_ip": "10.0.0.1"});
    buf.push(1000, &event);

    assert_eq!(buf.len(), 1);
    assert!(!buf.is_empty());

    let events = buf.decompress_all();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], event);
}

#[test]
fn test_event_buffer_compression_saves_memory() {
    let mut buf = EventBuffer::new(100);
    // Push a realistic-sized event (~500 bytes JSON)
    let event = json!({
        "User": "admin",
        "action": "login",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "EventTime": "2024-07-10T12:30:00Z",
        "process": "sshd",
        "host": "production-server-01.example.com",
        "message": "Accepted password for admin from 192.168.1.100 port 22 ssh2",
        "severity": "info",
        "tags": ["authentication", "network", "linux"]
    });

    let raw_size = serde_json::to_vec(&event).unwrap().len();
    buf.push(1000, &event);
    let compressed_size = buf.compressed_bytes();

    // Compressed should be notably smaller than raw
    assert!(
        compressed_size < raw_size,
        "Compressed {compressed_size}B should be less than raw {raw_size}B"
    );

    // Verify roundtrip
    let events = buf.decompress_all();
    assert_eq!(events[0], event);
}

#[test]
fn test_event_buffer_max_events_cap() {
    let mut buf = EventBuffer::new(3);

    for i in 0..5 {
        buf.push(1000 + i, &json!({"idx": i}));
    }

    // Only the last 3 should remain
    assert_eq!(buf.len(), 3);
    let events = buf.decompress_all();
    assert_eq!(events[0], json!({"idx": 2}));
    assert_eq!(events[1], json!({"idx": 3}));
    assert_eq!(events[2], json!({"idx": 4}));
}

#[test]
fn test_event_buffer_eviction() {
    let mut buf = EventBuffer::new(10);
    for i in 0..5 {
        buf.push(1000 + i, &json!({"idx": i}));
    }
    assert_eq!(buf.len(), 5);

    // Evict everything before ts 1003
    buf.evict(1003);
    assert_eq!(buf.len(), 2);

    let events = buf.decompress_all();
    assert_eq!(events[0], json!({"idx": 3}));
    assert_eq!(events[1], json!({"idx": 4}));
}

#[test]
fn test_event_buffer_clear() {
    let mut buf = EventBuffer::new(10);
    buf.push(1000, &json!({"a": 1}));
    buf.push(1001, &json!({"b": 2}));
    assert_eq!(buf.len(), 2);

    buf.clear();
    assert!(buf.is_empty());
    assert_eq!(buf.len(), 0);
    assert_eq!(buf.compressed_bytes(), 0);
}

#[test]
fn test_compress_decompress_roundtrip() {
    // Test various JSON shapes
    let values = vec![
        json!(null),
        json!(42),
        json!("hello world"),
        json!({"nested": {"deep": [1, 2, 3]}}),
        json!([1, "two", null, true, {"five": 5}]),
    ];
    for val in values {
        let compressed = compress_event(&val).unwrap();
        let decompressed = decompress_event(&compressed).unwrap();
        assert_eq!(decompressed, val, "Roundtrip failed for {val}");
    }
}

// =========================================================================
// EventRefBuffer tests
// =========================================================================

#[test]
fn test_event_ref_buffer_push_and_refs() {
    let mut buf = EventRefBuffer::new(10);
    buf.push(1000, &json!({"id": "evt-1", "data": "hello"}));
    buf.push(1001, &json!({"_id": 42, "data": "world"}));
    buf.push(1002, &json!({"data": "no-id"}));

    assert_eq!(buf.len(), 3);
    let refs = buf.refs();
    assert_eq!(refs[0].timestamp, 1000);
    assert_eq!(refs[0].id, Some("evt-1".to_string()));
    assert_eq!(refs[1].timestamp, 1001);
    assert_eq!(refs[1].id, Some("42".to_string()));
    assert_eq!(refs[2].timestamp, 1002);
    assert_eq!(refs[2].id, None);
}

#[test]
fn test_event_ref_buffer_max_cap() {
    let mut buf = EventRefBuffer::new(3);
    for i in 0..5 {
        buf.push(1000 + i, &json!({"id": format!("e-{i}")}));
    }
    assert_eq!(buf.len(), 3);
    let refs = buf.refs();
    assert_eq!(refs[0].id, Some("e-2".to_string()));
    assert_eq!(refs[1].id, Some("e-3".to_string()));
    assert_eq!(refs[2].id, Some("e-4".to_string()));
}

#[test]
fn test_event_ref_buffer_eviction() {
    let mut buf = EventRefBuffer::new(10);
    for i in 0..5 {
        buf.push(1000 + i, &json!({"id": format!("e-{i}")}));
    }
    buf.evict(1003);
    assert_eq!(buf.len(), 2);
    let refs = buf.refs();
    assert_eq!(refs[0].timestamp, 1003);
    assert_eq!(refs[1].timestamp, 1004);
}

#[test]
fn test_event_ref_buffer_clear() {
    let mut buf = EventRefBuffer::new(10);
    buf.push(1000, &json!({"id": "a"}));
    buf.push(1001, &json!({"id": "b"}));
    assert_eq!(buf.len(), 2);

    buf.clear();
    assert!(buf.is_empty());
    assert_eq!(buf.len(), 0);
}

#[test]
fn test_extract_event_id_common_fields() {
    assert_eq!(
        extract_event_id(&json!({"id": "abc"})),
        Some("abc".to_string())
    );
    assert_eq!(
        extract_event_id(&json!({"_id": 123})),
        Some("123".to_string())
    );
    assert_eq!(
        extract_event_id(&json!({"event_id": "x-1"})),
        Some("x-1".to_string())
    );
    assert_eq!(
        extract_event_id(&json!({"EventRecordID": 999})),
        Some("999".to_string())
    );
    assert_eq!(extract_event_id(&json!({"no_id_field": true})), None);
}

#[test]
fn test_compile_correlation_with_custom_attributes() {
    use rsigma_parser::*;

    let mut custom_attributes: HashMap<String, serde_yaml::Value> =
        std::collections::HashMap::new();
    custom_attributes.insert(
        "rsigma.correlation_event_mode".to_string(),
        serde_yaml::Value::String("refs".to_string()),
    );
    custom_attributes.insert(
        "rsigma.max_correlation_events".to_string(),
        serde_yaml::Value::String("25".to_string()),
    );
    custom_attributes.insert(
        "rsigma.suppress".to_string(),
        serde_yaml::Value::String("5m".to_string()),
    );
    custom_attributes.insert(
        "rsigma.action".to_string(),
        serde_yaml::Value::String("reset".to_string()),
    );

    let rule = CorrelationRule {
        title: "Test Corr".to_string(),
        id: Some("corr-1".to_string()),
        name: None,
        status: None,
        description: None,
        author: None,
        date: None,
        modified: None,
        related: vec![],
        references: vec![],
        taxonomy: None,
        license: None,
        tags: vec![],
        fields: vec![],
        falsepositives: vec![],
        level: Some(Level::High),
        scope: vec![],
        correlation_type: CorrelationType::EventCount,
        rules: vec!["rule-1".to_string()],
        group_by: vec!["User".to_string()],
        timespan: Timespan::parse("60s").unwrap(),
        condition: CorrelationCondition::Threshold {
            predicates: vec![(ConditionOperator::Gte, 5)],
            field: None,
            percentile: None,
        },
        aliases: vec![],
        generate: false,
        custom_attributes,
    };

    let compiled = compile_correlation(&rule).unwrap();

    // Per-correlation overrides should be resolved from custom_attributes
    assert_eq!(
        compiled.event_mode,
        Some(crate::correlation_engine::CorrelationEventMode::Refs)
    );
    assert_eq!(compiled.max_events, Some(25));
    assert_eq!(compiled.suppress_secs, Some(300)); // 5m = 300s
    assert_eq!(
        compiled.action,
        Some(crate::correlation_engine::CorrelationAction::Reset)
    );
}
