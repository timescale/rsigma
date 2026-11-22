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
    let key = GroupKey::extract(&event, &group_by, &["rule1"]).unwrap();
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
    assert!(GroupKey::extract(&event, &group_by, &["rule1"]).is_none());
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
    let key = GroupKey::extract(&event, &group_by, &["rule_a"]).unwrap();
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
fn test_window_temporal_duplicate_rule_refs_count_once() {
    let refs = vec![
        "rule_a".to_string(),
        "rule_a".to_string(),
        "rule_b".to_string(),
    ];
    let cond = CompiledCondition {
        field: None,
        predicates: vec![(ConditionOperator::Gte, 2.0)],
        percentile: None,
    };
    let mut state = WindowState::new_for(CorrelationType::Temporal);
    state.push_temporal(1000, "rule_a");
    assert!(
        state
            .check_condition(&cond, CorrelationType::Temporal, &refs, None)
            .is_none()
    );
    assert_eq!(
        state.current_value(CorrelationType::Temporal, &refs, None),
        Some(1.0)
    );

    state.push_temporal(1001, "rule_b");
    assert_eq!(
        state.check_condition(&cond, CorrelationType::Temporal, &refs, None),
        Some(2.0)
    );
}

#[test]
fn test_window_temporal_ordered_duplicate_rule_refs_count_once() {
    let refs = vec![
        "rule_a".to_string(),
        "rule_a".to_string(),
        "rule_b".to_string(),
    ];
    let mut state = WindowState::new_for(CorrelationType::TemporalOrdered);
    state.push_temporal(1000, "rule_a");
    state.push_temporal(1001, "rule_b");
    let cond = CompiledCondition {
        field: None,
        predicates: vec![(ConditionOperator::Gte, 2.0)],
        percentile: None,
    };
    assert_eq!(
        state.check_condition(&cond, CorrelationType::TemporalOrdered, &refs, None),
        Some(2.0)
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
    assert!((percentile_linear_interp(&mut [42.0], 50.0) - 42.0).abs() < f64::EPSILON);
}

#[test]
fn test_percentile_linear_interp_basic() {
    // Values: [1, 2, 3, 4, 5]
    let values = &mut [1.0, 2.0, 3.0, 4.0, 5.0];
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
    let values = &mut [10.0, 20.0, 30.0, 40.0];
    // 50th percentile: rank = 0.5 * 3 = 1.5, interp between 20 and 30 = 25
    assert!((percentile_linear_interp(values, 50.0) - 25.0).abs() < f64::EPSILON);
}

#[test]
fn test_percentile_linear_interp_1st_percentile() {
    // Values: [1, 2, 3, ..., 100]
    let mut values: Vec<f64> = (1..=100).map(|x| x as f64).collect();
    // 1st percentile = 1.0 + 0.01 * 99 * (2.0 - 1.0) ~ 1.99
    let p1 = percentile_linear_interp(&mut values, 1.0);
    assert!((p1 - 1.99).abs() < 0.01);
}

/// Percentile by full sort, the definition the selection-based version must
/// reproduce exactly.
fn sorted_percentile(values: &[f64], percentile: f64) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    if n == 1 {
        return sorted[0];
    }
    let rank = percentile.clamp(0.0, 100.0) / 100.0 * (n - 1) as f64;
    let (lower, upper) = (rank.floor() as usize, rank.ceil() as usize);
    if lower == upper || upper >= n {
        sorted[lower.min(n - 1)]
    } else {
        sorted[lower] + (rank - lower as f64) * (sorted[upper] - sorted[lower])
    }
}

/// Deterministic unsorted samples with repeats and signed zeros.
fn scrambled_samples(n: usize) -> Vec<f64> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15 ^ n as u64;
    (0..n)
        .map(|i| {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            match i % 7 {
                0 => 0.0,
                1 => -0.0,
                2 => ((x >> 40) % 16) as f64,
                _ => ((x >> 11) as f64 / (1u64 << 53) as f64 - 0.5) * 1e6,
            }
        })
        .collect()
}

#[test]
fn test_percentile_selection_matches_sorted_reference() {
    for n in (1..=64).chain([99, 100, 1_000, 5_001]) {
        let samples = scrambled_samples(n);
        for p in (0..=100).map(f64::from).chain([0.5, 33.3, 99.9]) {
            let got = percentile_linear_interp(&mut samples.clone(), p);
            let want = sorted_percentile(&samples, p);
            assert_eq!(
                got.to_bits(),
                want.to_bits(),
                "n={n} p={p}: {got} != {want}"
            );
        }
    }
}

#[test]
fn test_window_median_matches_sorted_reference() {
    let cond = CompiledCondition {
        field: Some(vec!["latency".to_string()]),
        predicates: vec![(ConditionOperator::Gte, f64::MIN)],
        percentile: None,
    };
    for n in (1..=64).chain([99, 100, 1_000, 5_000]) {
        let samples = scrambled_samples(n);
        let mut state = WindowState::new_for(CorrelationType::ValueMedian);
        for (i, v) in samples.iter().enumerate() {
            state.push_numeric(i as i64, *v);
        }
        let mut sorted = samples.clone();
        sorted.sort_by(f64::total_cmp);
        let mid = n / 2;
        let want = if n % 2 == 0 {
            (sorted[mid - 1] + sorted[mid]) / 2.0
        } else {
            sorted[mid]
        };
        let checked = state.check_condition(&cond, CorrelationType::ValueMedian, &[], None);
        let current = state.current_value(CorrelationType::ValueMedian, &[], None);
        assert_eq!(checked.map(f64::to_bits), Some(want.to_bits()), "n={n}");
        assert_eq!(current.map(f64::to_bits), Some(want.to_bits()), "n={n}");
    }
}

#[test]
fn test_value_percentile_check_condition() {
    let mut state = WindowState::new_for(CorrelationType::ValuePercentile);
    // Push 100 values: 1.0, 2.0, ..., 100.0
    for i in 1..=100 {
        state.push_numeric(1000 + i, i as f64);
    }

    let cond = |op, threshold| CompiledCondition {
        field: Some(vec!["latency".to_string()]),
        predicates: vec![(op, threshold)],
        percentile: None,
    };
    let check = |c: &CompiledCondition| {
        state.check_condition(c, CorrelationType::ValuePercentile, &[], None)
    };

    // The 50th percentile of 1..=100 is 50.5.
    let val = check(&cond(ConditionOperator::Lte, 51.0)).expect("50.5 <= 51");
    assert!(
        (val - 50.5).abs() < f64::EPSILON,
        "expected 50.5, got {val}"
    );
    assert_eq!(check(&cond(ConditionOperator::Lte, 50.0)), None);
    assert_eq!(check(&cond(ConditionOperator::Gte, 51.0)), None);
    assert!(check(&cond(ConditionOperator::Gt, 50.0)).is_some());
}

#[test]
fn test_percentile_0th_and_100th() {
    let values = &mut [5.0, 10.0, 15.0, 20.0];
    assert!((percentile_linear_interp(values, 0.0) - 5.0).abs() < f64::EPSILON);
    assert!((percentile_linear_interp(values, 100.0) - 20.0).abs() < f64::EPSILON);
}

#[test]
fn test_percentile_two_values() {
    let values = &mut [10.0, 20.0];
    // 50th percentile between 10 and 20 = 15
    assert!((percentile_linear_interp(values, 50.0) - 15.0).abs() < f64::EPSILON);
    // 25th percentile = 12.5
    assert!((percentile_linear_interp(values, 25.0) - 12.5).abs() < f64::EPSILON);
}

#[test]
fn test_percentile_clamps_out_of_range() {
    let values = &mut [1.0, 2.0, 3.0];
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
fn test_value_median_empty_window_returns_none() {
    // Regression: an empty median window used to return `0.0`, which
    // spuriously satisfied `lte: 0` / `eq: 0` predicates. It must mirror the
    // percentile branch and return `None` when there is no data to summarize.
    let state = WindowState::new_for(CorrelationType::ValueMedian);
    let cond = CompiledCondition {
        field: Some(vec!["latency".to_string()]),
        predicates: vec![(ConditionOperator::Lte, 0.0)],
        percentile: None,
    };
    assert!(
        state
            .check_condition(&cond, CorrelationType::ValueMedian, &[], None)
            .is_none(),
        "empty median window must not fire on lte: 0"
    );
}

#[test]
fn test_compile_correlation_rejects_multi_field_numeric_aggregations() {
    use rsigma_parser::parse_sigma_yaml;

    // value_sum, value_avg, value_percentile, and value_median expect a
    // single numeric field. The Sigma spec does not define how to combine
    // several numeric fields, so compile must fail rather than silently use
    // only the first field (the historical, data-losing behavior).
    let kinds = [
        // (correlation type, extra `condition:` lines).
        ("value_sum", ""),
        ("value_avg", ""),
        ("value_percentile", "        percentile: 95\n"),
        ("value_median", ""),
    ];
    for (corr_type, extra_condition) in kinds {
        let yaml = format!(
            r#"
title: Base Rule
id: 11111111-2222-3333-4444-555555555555
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: "s3.amazonaws.com"
    condition: selection
level: low
---
title: Multi-field numeric aggregation
id: 22222222-3333-4444-5555-666666666666
correlation:
    type: {corr_type}
    rules:
        - 11111111-2222-3333-4444-555555555555
    group-by:
        - userIdentity.arn
    timespan: 1h
    condition:
        field: [bytesIn, bytesOut]
{extra_condition}        gte: 100
level: high
"#
        );
        let collection =
            parse_sigma_yaml(&yaml).unwrap_or_else(|e| panic!("parse failed for {corr_type}: {e}"));
        assert_eq!(
            collection.correlations.len(),
            1,
            "no correlation parsed for {corr_type}; collected errors: {:?}",
            collection.diagnostics
        );
        let err = compile_correlation(&collection.correlations[0]).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("single numeric field"),
            "expected single-field error for `{corr_type}`, got: {msg}"
        );
    }
}

#[test]
fn test_compile_correlation_accepts_single_field_numeric_aggregations() {
    use rsigma_parser::parse_sigma_yaml;

    let yaml = r#"
title: Base Rule
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: "s3.amazonaws.com"
    condition: selection
level: low
---
title: Single-field median
id: bbbbbbbb-cccc-dddd-eeee-ffffffffffff
correlation:
    type: value_median
    rules:
        - aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    group-by:
        - userIdentity.arn
    timespan: 1h
    condition:
        field: latency
        gte: 100
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.correlations.len(), 1);
    let compiled = compile_correlation(&collection.correlations[0]).unwrap();
    assert_eq!(compiled.correlation_type, CorrelationType::ValueMedian);
    assert_eq!(compiled.condition.field, Some(vec!["latency".to_string()]));
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
// Sequenced buffer entries
// =========================================================================

#[test]
fn test_event_buffer_push_seq_and_retained() {
    let mut buf = EventBuffer::new(10);
    buf.push_seq(7, 1000, &json!({"idx": 0}), None);
    buf.push_seq(8, 1001, &json!({"idx": 1}), None);

    let Retained::Full(entries) = buf.retained() else {
        panic!("event buffer must retain full entries");
    };
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].seq, 7);
    assert_eq!(entries[0].ts, 1000);
    assert_eq!(entries[1].seq, 8);
    assert_eq!(
        decompress_event(&entries[1].data).unwrap(),
        json!({"idx": 1})
    );
}

#[test]
fn test_event_ref_buffer_push_seq_and_retained() {
    let mut buf = EventRefBuffer::new(10);
    buf.push_seq(4, 1000, &json!({"id": "e-1"}), None);
    buf.push_seq(5, 1001, &json!({"id": "e-2"}), None);

    let Retained::Refs(entries) = buf.retained() else {
        panic!("ref buffer must retain ref entries");
    };
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].seq, 4);
    assert_eq!(entries[0].r.id.as_deref(), Some("e-1"));
    assert_eq!(entries[1].seq, 5);
    assert_eq!(entries[1].r.timestamp, 1001);
}

#[test]
fn test_event_buffer_merge_skips_seen_seq_and_orders_by_seq() {
    let mut buf = EventBuffer::new(10);
    buf.push_seq(5, 1000, &json!({"idx": 5}), None);

    let entry = |seq: u64, idx: u64| FullEntry {
        seq,
        ts: 1000,
        data: compress_event(&json!({"idx": idx})).unwrap(),
        rule: None,
        via: None,
    };
    // Equal timestamps order by sequence number.
    buf.merge(&[entry(9, 9), entry(2, 2)], None);
    let seqs: Vec<u64> = match buf.retained() {
        Retained::Full(entries) => entries.iter().map(|e| e.seq).collect(),
        Retained::Refs(_) => panic!("wrong retention kind"),
    };
    assert_eq!(seqs, [2, 5, 9]);

    // A nonzero sequence already present is skipped, wherever it sits.
    buf.merge(&[entry(9, 99), entry(5, 55), entry(2, 22)], None);
    assert_eq!(buf.len(), 3);
    let events = buf.decompress_all();
    assert_eq!(
        events,
        [json!({"idx": 2}), json!({"idx": 5}), json!({"idx": 9})]
    );
}

#[test]
fn test_event_buffer_merge_keeps_unsequenced_entries_distinct() {
    let mut buf = EventBuffer::new(10);
    let zero = |idx: u64| FullEntry {
        seq: 0,
        ts: 1000,
        data: compress_event(&json!({"idx": idx})).unwrap(),
        rule: None,
        via: None,
    };
    buf.merge(&[zero(1)], None);
    buf.merge(&[zero(2)], None);
    assert_eq!(buf.len(), 2);
    let events = buf.decompress_all();
    assert_eq!(events[0], json!({"idx": 1}));
    assert_eq!(events[1], json!({"idx": 2}));
}

#[test]
fn test_event_buffer_merge_trims_to_cap_and_trims_readded_old_entry() {
    let mut buf = EventBuffer::new(2);
    buf.push_seq(1, 1000, &json!({"idx": 0}), None);
    buf.push_seq(2, 1001, &json!({"idx": 1}), None);

    let entry = |seq: u64, ts: i64, idx: u64| FullEntry {
        seq,
        ts,
        data: compress_event(&json!({"idx": idx})).unwrap(),
        rule: None,
        via: None,
    };
    // Adding a third entry trims the oldest.
    buf.merge(&[entry(3, 1002, 2)], None);
    assert_eq!(buf.len(), 2);
    assert_eq!(buf.decompress_all(), [json!({"idx": 1}), json!({"idx": 2})]);

    // Re-delivering the evicted entry inserts it and trims it again.
    buf.merge(&[entry(1, 1000, 0)], None);
    assert_eq!(buf.len(), 2);
    assert_eq!(buf.decompress_all(), [json!({"idx": 1}), json!({"idx": 2})]);
}

#[test]
fn test_event_ref_buffer_merge_skips_seen_seq_and_trims_to_cap() {
    let mut buf = EventRefBuffer::new(2);
    buf.push_seq(1, 1000, &json!({"id": "a"}), None);
    buf.push_seq(2, 1001, &json!({"id": "b"}), None);

    let entry = |seq: u64, ts: i64, id: &str| RefEntry {
        r: EventRef {
            timestamp: ts,
            id: Some(id.to_string()),
        },
        seq,
        rule: None,
        via: None,
    };
    buf.merge(&[entry(2, 1001, "dup"), entry(3, 1002, "c")], None);
    assert_eq!(buf.len(), 2);
    let refs = buf.refs();
    assert_eq!(refs[0].id.as_deref(), Some("b"));
    assert_eq!(refs[1].id.as_deref(), Some("c"));

    // Re-delivering an evicted sequence inserts it, then the cap trims it.
    buf.merge(&[entry(1, 1000, "a")], None);
    assert_eq!(buf.len(), 2);
    assert_eq!(buf.refs()[0].id.as_deref(), Some("b"));
}

#[test]
fn test_newest_events_and_refs_return_oldest_first_slice() {
    let mut buf = EventBuffer::new(10);
    for i in 0..4 {
        buf.push_seq(i + 1, 1000 + i as i64, &json!({"idx": i}), None);
    }
    let events = buf.newest_events(2).0;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0], json!({"idx": 2}));
    assert_eq!(events[1], json!({"idx": 3}));
    assert_eq!(buf.newest_events(10).0.len(), 4);

    let refs = buf.newest_refs(2).0;
    assert_eq!(refs.len(), 2);
    assert_eq!(refs[0].timestamp, 1002);
    assert_eq!(refs[1].timestamp, 1003);

    let mut ref_buf = EventRefBuffer::new(10);
    for i in 0..4 {
        ref_buf.push_seq(
            i + 1,
            1000 + i as i64,
            &json!({"id": format!("e-{i}")}),
            None,
        );
    }
    let refs = ref_buf.newest_refs(2).0;
    assert_eq!(refs.len(), 2);
    assert_eq!(refs[0].id.as_deref(), Some("e-2"));
    assert_eq!(refs[1].id.as_deref(), Some("e-3"));
    assert_eq!(ref_buf.newest_refs(10).0.len(), 4);
}

#[test]
fn test_full_entry_to_ref_matches_ref_buffer_push() {
    let event = json!({"_id": 42, "data": "hello"});
    let entry = FullEntry {
        seq: 9,
        ts: 1000,
        data: compress_event(&event).unwrap(),
        rule: None,
        via: None,
    };
    let converted = entry.to_ref().expect("entry decompresses");
    assert_eq!(converted.seq, 9);
    assert_eq!(converted.r.timestamp, 1000);

    let mut ref_buf = EventRefBuffer::new(10);
    ref_buf.push(1000, &event);
    let pushed = ref_buf.refs();
    assert_eq!(converted.r.id, pushed[0].id);
    assert_eq!(converted.r.id.as_deref(), Some("42"));
}

#[test]
fn test_buffer_json_without_seq_deserializes_with_seq_zero() {
    let mut buf = EventBuffer::new(10);
    buf.push_seq(5, 1000, &json!({"idx": 0}), None);
    let mut value = serde_json::to_value(&buf).unwrap();
    for entry in value["entries"].as_array_mut().unwrap() {
        entry.as_object_mut().unwrap().remove("seq");
    }
    let restored: EventBuffer = serde_json::from_value(value).unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored.max_seq(), 0);

    let mut ref_buf = EventRefBuffer::new(10);
    ref_buf.push_seq(6, 1001, &json!({"id": "e-1"}), None);
    let mut value = serde_json::to_value(&ref_buf).unwrap();
    for entry in value["entries"].as_array_mut().unwrap() {
        entry.as_object_mut().unwrap().remove("seq");
    }
    let restored: EventRefBuffer = serde_json::from_value(value).unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored.max_seq(), 0);
}

#[test]
fn test_serialized_buffers_carry_seq_but_event_refs_do_not() {
    let mut buf = EventBuffer::new(10);
    buf.push_seq(5, 1000, &json!({"idx": 0}), None);
    let json = serde_json::to_string(&buf).unwrap();
    assert!(json.contains("\"seq\":5"), "{json}");

    let mut ref_buf = EventRefBuffer::new(10);
    ref_buf.push_seq(6, 1001, &json!({"id": "e-1"}), None);
    let json = serde_json::to_string(&ref_buf).unwrap();
    assert!(json.contains("\"seq\":6"), "{json}");

    let json = serde_json::to_string(&EventRef {
        timestamp: 1001,
        id: Some("e-1".to_string()),
    })
    .unwrap();
    assert_eq!(json, r#"{"timestamp":1001,"id":"e-1"}"#);
    assert!(!json.contains("\"seq\""), "{json}");
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

    let mut custom_attributes: HashMap<String, yaml_serde::Value> =
        std::collections::HashMap::new();
    custom_attributes.insert(
        "rsigma.correlation_event_mode".to_string(),
        yaml_serde::Value::String("refs".to_string()),
    );
    custom_attributes.insert(
        "rsigma.max_correlation_events".to_string(),
        yaml_serde::Value::String("25".to_string()),
    );
    custom_attributes.insert(
        "rsigma.suppress".to_string(),
        yaml_serde::Value::String("5m".to_string()),
    );
    custom_attributes.insert(
        "rsigma.action".to_string(),
        yaml_serde::Value::String("reset".to_string()),
    );

    let rule = CorrelationRule {
        sigma_version: None,
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
        window: WindowMode::Sliding,
        gap: None,
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

// =========================================================================
// Window modes (apply_window_open)
// =========================================================================

#[test]
fn test_apply_window_open_sliding_evicts() {
    let mut state = WindowState::new_for(CorrelationType::EventCount);
    state.push_event_count(0);
    state.push_event_count(5);
    // Sliding 10s window at t=12 keeps entries with ts >= 2.
    let decision = apply_window_open(&mut state, 12, 10, rsigma_parser::WindowMode::Sliding, None);
    assert_eq!(decision, WindowDecision::Extend);
    assert_eq!(state.earliest_timestamp(), Some(5));
}

#[test]
fn test_apply_window_open_tumbling_resets_on_new_bucket() {
    let mut state = WindowState::new_for(CorrelationType::EventCount);
    state.push_event_count(8);
    state.push_event_count(9);
    // t=12 falls in bucket [10,20); retained entries are in [0,10) -> reset.
    let decision = apply_window_open(
        &mut state,
        12,
        10,
        rsigma_parser::WindowMode::Tumbling,
        None,
    );
    assert_eq!(decision, WindowDecision::Reset);
    assert!(state.is_empty());
}

#[test]
fn test_apply_window_open_tumbling_same_bucket_keeps() {
    let mut state = WindowState::new_for(CorrelationType::EventCount);
    state.push_event_count(1);
    state.push_event_count(2);
    let decision = apply_window_open(&mut state, 3, 10, rsigma_parser::WindowMode::Tumbling, None);
    assert_eq!(decision, WindowDecision::Extend);
    assert_eq!(state.earliest_timestamp(), Some(1));
}

#[test]
fn test_apply_window_open_tumbling_discards_late_event() {
    let mut state = WindowState::new_for(CorrelationType::EventCount);
    state.push_event_count(12);
    state.push_event_count(15);
    // t=9 falls in the earlier bucket [0,10); the active bucket [10,20) must
    // not be wiped by the late arrival, and the event itself is discarded.
    let decision = apply_window_open(&mut state, 9, 10, rsigma_parser::WindowMode::Tumbling, None);
    assert_eq!(decision, WindowDecision::Discard);
    assert_eq!(state.earliest_timestamp(), Some(12));
    assert_eq!(state.latest_timestamp(), Some(15));
}

#[test]
fn test_apply_window_open_session_extends_within_gap() {
    let mut state = WindowState::new_for(CorrelationType::EventCount);
    state.push_event_count(0);
    state.push_event_count(4);
    // 8 - 4 = 4 <= gap 5 and 8 - 0 = 8 <= timespan 100 -> extend.
    let decision = apply_window_open(
        &mut state,
        8,
        100,
        rsigma_parser::WindowMode::Session,
        Some(5),
    );
    assert_eq!(decision, WindowDecision::Extend);
    assert_eq!(state.earliest_timestamp(), Some(0));
}

#[test]
fn test_apply_window_open_session_resets_after_gap() {
    let mut state = WindowState::new_for(CorrelationType::EventCount);
    state.push_event_count(0);
    state.push_event_count(4);
    // 20 - 4 = 16 > gap 5 -> reset.
    let decision = apply_window_open(
        &mut state,
        20,
        100,
        rsigma_parser::WindowMode::Session,
        Some(5),
    );
    assert_eq!(decision, WindowDecision::Reset);
    assert!(state.is_empty());
}

#[test]
fn test_apply_window_open_session_caps_at_timespan() {
    let mut state = WindowState::new_for(CorrelationType::EventCount);
    state.push_event_count(0);
    state.push_event_count(5);
    // 12 - 5 = 7 <= gap 100, but 12 - 0 = 12 > timespan 10 -> reset on the cap.
    let decision = apply_window_open(
        &mut state,
        12,
        10,
        rsigma_parser::WindowMode::Session,
        Some(100),
    );
    assert_eq!(decision, WindowDecision::Reset);
    assert!(state.is_empty());
}

// =============================================================================
// Per-group entry cap: WindowState::truncate_oldest
// =============================================================================

#[test]
fn test_truncate_oldest_drops_oldest_entries() {
    let mut state = WindowState::new_for(CorrelationType::EventCount);
    for ts in 0..5 {
        state.push_event_count(ts);
    }
    state.truncate_oldest(3, false);
    // Oldest entries (0, 1) dropped; newest 3 retained.
    assert_eq!(state.earliest_timestamp(), Some(2));
    assert_eq!(state.latest_timestamp(), Some(4));
}

#[test]
fn test_truncate_oldest_noop_under_cap() {
    let mut state = WindowState::new_for(CorrelationType::EventCount);
    state.push_event_count(1);
    state.push_event_count(2);
    state.truncate_oldest(3, false);
    assert_eq!(state.earliest_timestamp(), Some(1));
    assert_eq!(state.latest_timestamp(), Some(2));
}

#[test]
fn test_truncate_oldest_preserve_front_keeps_session_anchor() {
    let mut state = WindowState::new_for(CorrelationType::EventCount);
    for ts in 0..5 {
        state.push_event_count(ts);
    }
    state.truncate_oldest(3, true);
    // The anchor (0) survives; the middle entries are dropped instead.
    assert_eq!(state.earliest_timestamp(), Some(0));
    assert_eq!(state.latest_timestamp(), Some(4));
}

#[test]
fn test_truncate_oldest_cap_clamps_to_one() {
    let mut state = WindowState::new_for(CorrelationType::EventCount);
    for ts in 0..4 {
        state.push_event_count(ts);
    }
    // A nonsensical cap of 0 is clamped to 1.
    state.truncate_oldest(0, false);
    assert_eq!(state.earliest_timestamp(), Some(3));
    assert_eq!(state.latest_timestamp(), Some(3));
}

#[test]
fn test_truncate_oldest_preserve_front_cap_one_keeps_anchor() {
    let mut state = WindowState::new_for(CorrelationType::EventCount);
    for ts in 0..4 {
        state.push_event_count(ts);
    }
    state.truncate_oldest(1, true);
    // Cap 1 with anchor preservation keeps exactly the anchor.
    assert_eq!(state.earliest_timestamp(), Some(0));
    assert_eq!(state.latest_timestamp(), Some(0));
}

#[test]
fn test_truncate_oldest_value_count_drops_oldest_values() {
    let mut state = WindowState::new_for(CorrelationType::ValueCount);
    for (ts, v) in [(1, "a"), (2, "b"), (3, "c"), (4, "d")] {
        state.push_value_count(ts, v.to_string());
    }
    state.truncate_oldest(2, false);
    let cond = CompiledCondition {
        field: Some(vec!["User".to_string()]),
        predicates: vec![(ConditionOperator::Gte, 1.0)],
        percentile: None,
    };
    // Only the two newest distinct values remain.
    let value = state.check_condition(&cond, CorrelationType::ValueCount, &[], None);
    assert_eq!(value, Some(2.0));
}

#[test]
fn test_truncate_oldest_temporal_caps_each_rule_deque() {
    let mut state = WindowState::new_for(CorrelationType::Temporal);
    for ts in 0..5 {
        state.push_temporal(ts, "rule_a");
    }
    state.push_temporal(10, "rule_b");
    state.truncate_oldest(2, false);
    // rule_a trimmed to its 2 newest hits; rule_b untouched (1 <= cap).
    assert_eq!(state.earliest_timestamp(), Some(3));
    assert_eq!(state.latest_timestamp(), Some(10));
}

/// The exhaustive search `check_temporal_ordered` used to run.
fn temporal_ordered_by_search(
    rule_refs: &[String],
    rule_hits: &HashMap<String, VecDeque<i64>>,
    idx: usize,
    min_ts: i64,
) -> bool {
    let Some(rule_ref) = rule_refs.get(idx) else {
        return true;
    };
    rule_hits.get(rule_ref).is_some_and(|hits| {
        hits.iter().any(|&ts| {
            ts >= min_ts && temporal_ordered_by_search(rule_refs, rule_hits, idx + 1, ts)
        })
    })
}

#[test]
fn test_temporal_ordered_matches_exhaustive_search() {
    let names = ["a", "b", "c", "d"];
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = |bound: u64| {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (x >> 33) % bound
    };
    let mut matched = 0;
    for _ in 0..5_000 {
        let rule_refs: Vec<String> = (0..1 + next(5))
            .map(|_| names[next(4) as usize].to_string())
            .collect();
        let mut rule_hits = HashMap::new();
        for name in names {
            if next(5) == 0 {
                continue;
            }
            let hits: VecDeque<i64> = (0..next(6)).map(|_| next(20) as i64).collect();
            rule_hits.insert(name.to_string(), hits);
        }
        let expected = temporal_ordered_by_search(&rule_refs, &rule_hits, 0, i64::MIN);
        assert_eq!(
            check_temporal_ordered(&rule_refs, &rule_hits),
            expected,
            "refs {rule_refs:?}, hits {rule_hits:?}"
        );
        matched += usize::from(expected);
    }
    assert!(
        matched > 500 && matched < 4_500,
        "the cases should mix both outcomes; {matched} matched"
    );
}

#[test]
fn test_temporal_ordered_with_many_hits_per_rule() {
    // Every earlier rule has many hits that each fit the order, and the last
    // rule fired too early for all of them, so an exhaustive search would try
    // every combination of the earlier hits before giving up.
    let rule_refs: Vec<String> = (0..8).map(|i| format!("r{i}")).collect();
    let mut rule_hits: HashMap<String, VecDeque<i64>> = rule_refs
        .iter()
        .take(7)
        .map(|r| (r.clone(), (1_000..1_200).collect()))
        .collect();
    rule_hits.insert("r7".to_string(), (0..200).collect());
    assert!(!check_temporal_ordered(&rule_refs, &rule_hits));

    rule_hits.insert("r7".to_string(), (0..1_200).collect());
    assert!(check_temporal_ordered(&rule_refs, &rule_hits));
}

#[test]
fn test_temporal_ordered_repeated_rule_can_reuse_a_hit() {
    let refs = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
    let rule_hits = HashMap::from([
        ("a".to_string(), VecDeque::from([5])),
        ("b".to_string(), VecDeque::from([3, 9])),
    ]);
    assert!(check_temporal_ordered(&refs(&["a", "a", "b"]), &rule_hits));
    assert!(check_temporal_ordered(&refs(&["b", "a", "b"]), &rule_hits));
    assert!(!check_temporal_ordered(&refs(&["a", "b", "a"]), &rule_hits));
    assert!(!check_temporal_ordered(
        &refs(&["a", "missing"]),
        &rule_hits
    ));
    assert!(check_temporal_ordered(&[], &rule_hits));
}
