use rsigma_parser::parse_sigma_yaml;

#[test]
fn simple_detection_rule() {
    let yaml = r#"
title: Simple Detection
id: 12345678-1234-1234-1234-123456789012
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "powershell"
    condition: selection
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 1);
    insta::assert_debug_snapshot!("simple_detection", &collection.rules[0]);
}

#[test]
fn complex_condition_with_or_and_not() {
    let yaml = r#"
title: Complex Condition
status: test
logsource:
    category: test
detection:
    sel1:
        FieldA: "alpha"
    sel2:
        FieldB: "beta"
    filter:
        FieldC: "gamma"
    condition: (sel1 or sel2) and not filter
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 1);
    let rule = &collection.rules[0];
    assert_eq!(rule.detection.named.len(), 3);
    insta::assert_debug_snapshot!("complex_condition", &rule.detection.conditions);
}

#[test]
fn correlation_event_count() {
    let yaml = r#"
title: Base Rule
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Brute Force Correlation
name: brute_force
status: experimental
correlation:
    type: event_count
    rules:
        - Base Rule
    group-by:
        - SourceIP
    timespan: 5m
    condition:
        gte: 10
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 1);
    assert_eq!(collection.correlations.len(), 1);
    insta::assert_debug_snapshot!("correlation_event_count", &collection.correlations[0]);
}

#[test]
fn filter_rule() {
    let yaml = r#"
title: Exclude Known Good
filter:
    rules:
        - 12345678-1234-1234-1234-123456789012
    selection:
        CommandLine|contains: "expected_tool.exe"
    condition: not selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.filters.len(), 1);
    insta::assert_debug_snapshot!("filter_rule", &collection.filters[0]);
}

#[test]
fn detection_with_multiple_values_and_modifiers() {
    let yaml = r#"
title: Multi-value Detection
status: test
logsource:
    category: proxy
    product: generic
detection:
    selection:
        c-uri|contains|all:
            - "/api/admin"
            - "token="
        cs-method:
            - POST
            - PUT
    condition: selection
level: critical
tags:
    - attack.initial_access
    - attack.t1190
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 1);
    insta::assert_debug_snapshot!("multi_value_modifiers", &collection.rules[0]);
}
