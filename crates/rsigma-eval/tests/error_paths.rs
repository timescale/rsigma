mod helpers;

use rsigma_eval::{CorrelationConfig, CorrelationEngine, Engine, EvalError, Event};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

#[test]
fn invalid_regex_surfaces_at_compile_time() {
    let yaml = r#"
title: Bad Regex
logsource:
    product: test
detection:
    selection:
        CommandLine|re: '[unclosed'
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    let err = engine.add_collection(&collection).unwrap_err();
    assert!(
        matches!(err, EvalError::InvalidRegex(_)),
        "expected InvalidRegex, got: {err}"
    );
}

#[test]
fn invalid_cidr_surfaces_at_compile_time() {
    let yaml = r#"
title: Bad CIDR
logsource:
    product: test
detection:
    selection:
        SourceIP|cidr: 'not-a-cidr'
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    let err = engine.add_collection(&collection).unwrap_err();
    assert!(
        matches!(err, EvalError::InvalidCidr(_)),
        "expected InvalidCidr, got: {err}"
    );
}

#[test]
fn timestamp_part_with_non_numeric_string_is_incompatible() {
    let yaml = r#"
title: Bad Timestamp
logsource:
    product: test
detection:
    selection:
        EventTime|hour: three
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    let err = engine.add_collection(&collection).unwrap_err();
    assert!(
        matches!(err, EvalError::IncompatibleValue(_)),
        "expected IncompatibleValue, got: {err}"
    );
}

#[test]
fn numeric_comparison_with_non_numeric_value() {
    let yaml = r#"
title: Bad Numeric
logsource:
    product: test
detection:
    selection:
        Score|gt: not_a_number
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    let err = engine.add_collection(&collection).unwrap_err();
    assert!(
        matches!(err, EvalError::ExpectedNumeric(_)),
        "expected ExpectedNumeric, got: {err}"
    );
}

#[test]
fn extended_condition_on_non_temporal_type() {
    // The CorrelationError fires when the condition is a string expression
    // (like "rule-a and rule-b") on a non-temporal type. A mapping condition
    // {gte: 3} is fine; only the extended string form is rejected.
    let yaml2 = r#"
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
title: Bad Event Count
correlation:
    type: event_count
    rules:
        - rule-a
        - rule-b
    group-by:
        - User
    timespan: 60s
    condition: rule-a and rule-b
level: high
"#;
    let collection2 = parse_sigma_yaml(yaml2).unwrap();
    let mut engine2 = CorrelationEngine::new(CorrelationConfig::default());
    let err = engine2.add_collection(&collection2).unwrap_err();
    assert!(
        matches!(err, EvalError::CorrelationError(_)),
        "expected CorrelationError for extended condition on event_count, got: {err}"
    );
}

#[test]
fn correlation_cycle_detected_at_add_collection() {
    // A -> B -> C -> A creates a 3-node cycle
    let yaml = r#"
title: Detection
id: det-rule
logsource:
    category: test
detection:
    selection:
        type: event
    condition: selection
---
title: Corr A
id: corr-a
correlation:
    type: event_count
    rules:
        - corr-c
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
---
title: Corr B
id: corr-b
correlation:
    type: event_count
    rules:
        - corr-a
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
---
title: Corr C
id: corr-c
correlation:
    type: event_count
    rules:
        - corr-b
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    let err = engine.add_collection(&collection).unwrap_err();
    assert!(
        matches!(err, EvalError::CorrelationCycle(_)),
        "expected CorrelationCycle, got: {err}"
    );
}

#[test]
fn unknown_detection_in_condition_silently_returns_false() {
    // Condition references "selection_b" which doesn't exist.
    // The engine compiles successfully but the missing detection evaluates to false,
    // meaning the rule never matches. This is the current behavior -- no error is
    // raised at compile time.
    let yaml = r#"
title: Ghost Reference
logsource:
    product: test
detection:
    selection_a:
        EventType: test
    condition: selection_a and selection_b
level: low
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();

    let ev = json!({"EventType": "test"});
    let matches = engine.evaluate(&Event::from_value(&ev));
    assert!(
        matches.is_empty(),
        "rule with unknown detection reference should never match"
    );
}

#[test]
fn unknown_rule_ref_in_correlation_silently_ignored() {
    // Correlation references a rule ID that doesn't exist.
    // Currently no error -- the correlation compiles but never fires because
    // no detection match can feed into it.
    let yaml = r#"
title: Detection
id: det-rule
logsource:
    category: test
detection:
    selection:
        type: event
    condition: selection
---
title: Orphan Correlation
correlation:
    type: event_count
    rules:
        - nonexistent-rule-id
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

    let ev = json!({"type": "event", "User": "admin"});
    let event = Event::from_value(&ev);
    let r = engine.process_event_at(&event, 1000);
    assert!(
        r.correlations.is_empty(),
        "correlation referencing nonexistent rule should never fire"
    );
}
