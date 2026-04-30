use super::*;

#[test]
fn test_parse_simple_rule() {
    let yaml = r#"
title: Test Rule
id: 12345678-1234-1234-1234-123456789012
status: test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 1);

    let rule = &collection.rules[0];
    assert_eq!(rule.title, "Test Rule");
    assert_eq!(rule.logsource.product, Some("windows".to_string()));
    assert_eq!(
        rule.logsource.category,
        Some("process_creation".to_string())
    );
    assert_eq!(rule.level, Some(Level::Medium));
    assert_eq!(rule.detection.conditions.len(), 1);
    assert_eq!(
        rule.detection.conditions[0],
        ConditionExpr::Identifier("selection".to_string())
    );
    assert!(rule.detection.named.contains_key("selection"));
}

#[test]
fn test_parse_field_modifiers() {
    let spec = parse_field_spec("TargetObject|endswith").unwrap();
    assert_eq!(spec.name, Some("TargetObject".to_string()));
    assert_eq!(spec.modifiers, vec![Modifier::EndsWith]);

    let spec = parse_field_spec("Destination|contains|all").unwrap();
    assert_eq!(spec.name, Some("Destination".to_string()));
    assert_eq!(spec.modifiers, vec![Modifier::Contains, Modifier::All]);

    let spec = parse_field_spec("Details|re").unwrap();
    assert_eq!(spec.name, Some("Details".to_string()));
    assert_eq!(spec.modifiers, vec![Modifier::Re]);

    let spec = parse_field_spec("Destination|base64offset|contains").unwrap();
    assert_eq!(
        spec.modifiers,
        vec![Modifier::Base64Offset, Modifier::Contains]
    );
}

#[test]
fn test_parse_complex_condition() {
    let yaml = r#"
title: Complex Rule
logsource:
    product: windows
    category: registry_set
detection:
    selection_main:
        TargetObject|contains: '\SOFTWARE\Microsoft\Windows Defender\'
    selection_dword_1:
        Details: 'DWORD (0x00000001)'
    filter_optional_symantec:
        Image|startswith: 'C:\Program Files\Symantec\'
    condition: selection_main and 1 of selection_dword_* and not 1 of filter_optional_*
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 1);

    let rule = &collection.rules[0];
    assert_eq!(rule.detection.named.len(), 3);

    let cond = &rule.detection.conditions[0];
    match cond {
        ConditionExpr::And(args) => {
            assert_eq!(args.len(), 3);
        }
        _ => panic!("Expected AND condition"),
    }
}

#[test]
fn test_parse_condition_list() {
    let yaml = r#"
title: Multi-condition Rule
logsource:
    category: test
detection:
    selection1:
        username: user1
    selection2:
        username: user2
    condition:
        - selection1
        - selection2
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let rule = &collection.rules[0];
    assert_eq!(rule.detection.conditions.len(), 2);
}

#[test]
fn test_parse_correlation_rule() {
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
    assert_eq!(collection.rules.len(), 1);
    assert_eq!(collection.correlations.len(), 1);

    let corr = &collection.correlations[0];
    assert_eq!(corr.correlation_type, CorrelationType::EventCount);
    assert_eq!(corr.timespan.seconds, 3600);
    assert_eq!(corr.group_by, vec!["userIdentity.arn"]);

    match &corr.condition {
        CorrelationCondition::Threshold { predicates, .. } => {
            assert_eq!(predicates.len(), 1);
            assert_eq!(predicates[0].0, ConditionOperator::Gte);
            assert_eq!(predicates[0].1, 100);
        }
        _ => panic!("Expected threshold condition"),
    }
}

#[test]
fn test_parse_correlation_rule_custom_attributes() {
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
    rsigma.suppress: 5m
    rsigma.action: reset
    rsigma.max_correlation_events: "25"
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
    assert_eq!(collection.correlations.len(), 1);

    let corr = &collection.correlations[0];
    assert_eq!(
        corr.custom_attributes
            .get("rsigma.correlation_event_mode")
            .and_then(Value::as_str),
        Some("refs")
    );
    assert_eq!(
        corr.custom_attributes
            .get("rsigma.suppress")
            .and_then(Value::as_str),
        Some("5m")
    );
    assert_eq!(
        corr.custom_attributes
            .get("rsigma.action")
            .and_then(Value::as_str),
        Some("reset")
    );
    assert_eq!(
        corr.custom_attributes
            .get("rsigma.max_correlation_events")
            .and_then(Value::as_str),
        Some("25")
    );
}

#[test]
fn test_parse_correlation_rule_no_custom_attributes() {
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
    let corr = &collection.correlations[0];
    assert!(corr.custom_attributes.is_empty());
}

#[test]
fn test_parse_detection_or_linked() {
    let yaml = r#"
title: OR-linked detections
logsource:
    product: windows
    category: wmi_event
detection:
    selection:
        - Destination|contains|all:
              - 'new-object'
              - 'net.webclient'
        - Destination|contains:
              - 'WScript.Shell'
    condition: selection
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let rule = &collection.rules[0];
    let detection = &rule.detection.named["selection"];

    match detection {
        Detection::AnyOf(subs) => {
            assert_eq!(subs.len(), 2);
        }
        _ => panic!("Expected AnyOf detection, got {detection:?}"),
    }
}

#[test]
fn test_parse_global_action() {
    let yaml = r#"
action: global
title: Global Rule
logsource:
    product: windows
---
detection:
    selection:
        EventID: 1
    condition: selection
level: high
---
detection:
    selection:
        EventID: 2
    condition: selection
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 2);
    assert_eq!(collection.rules[0].title, "Global Rule");
    assert_eq!(collection.rules[1].title, "Global Rule");
}

#[test]
fn test_unknown_modifier_error() {
    let result = parse_field_spec("field|foobar");
    assert!(result.is_err());
}

// ── Field modifier edge cases ────────────────────────────────────────

#[test]
fn test_parse_contains_re_combination() {
    let spec = parse_field_spec("CommandLine|contains|re").unwrap();
    assert_eq!(spec.modifiers, vec![Modifier::Contains, Modifier::Re]);
}

#[test]
fn test_parse_duplicate_modifiers() {
    let spec = parse_field_spec("Field|contains|contains").unwrap();
    assert_eq!(spec.modifiers, vec![Modifier::Contains, Modifier::Contains]);
}

#[test]
fn test_parse_conflicting_string_match_modifiers() {
    let spec = parse_field_spec("Field|contains|startswith").unwrap();
    assert_eq!(
        spec.modifiers,
        vec![Modifier::Contains, Modifier::StartsWith]
    );
}

#[test]
fn test_parse_conflicting_endswith_startswith() {
    let spec = parse_field_spec("Field|endswith|startswith").unwrap();
    assert_eq!(
        spec.modifiers,
        vec![Modifier::EndsWith, Modifier::StartsWith]
    );
}

#[test]
fn test_parse_re_with_contains() {
    let spec = parse_field_spec("Field|re|contains").unwrap();
    assert_eq!(spec.modifiers, vec![Modifier::Re, Modifier::Contains]);
}

#[test]
fn test_parse_cidr_with_contains() {
    let spec = parse_field_spec("Field|cidr|contains").unwrap();
    assert_eq!(spec.modifiers, vec![Modifier::Cidr, Modifier::Contains]);
}

#[test]
fn test_parse_multiple_encoding_modifiers() {
    let spec = parse_field_spec("Field|base64|wide|base64offset").unwrap();
    assert_eq!(
        spec.modifiers,
        vec![Modifier::Base64, Modifier::Wide, Modifier::Base64Offset]
    );
}

#[test]
fn test_parse_numeric_with_string_modifiers() {
    let spec = parse_field_spec("Field|gt|contains").unwrap();
    assert_eq!(spec.modifiers, vec![Modifier::Gt, Modifier::Contains]);
}

#[test]
fn test_parse_exists_with_other_modifiers() {
    let spec = parse_field_spec("Field|exists|contains").unwrap();
    assert_eq!(spec.modifiers, vec![Modifier::Exists, Modifier::Contains]);
}

#[test]
fn test_parse_re_with_regex_flags() {
    let spec = parse_field_spec("Field|re|i|m|s").unwrap();
    assert_eq!(
        spec.modifiers,
        vec![
            Modifier::Re,
            Modifier::IgnoreCase,
            Modifier::Multiline,
            Modifier::DotAll
        ]
    );
}

#[test]
fn test_parse_regex_flags_without_re() {
    let spec = parse_field_spec("Field|i|m").unwrap();
    assert_eq!(
        spec.modifiers,
        vec![Modifier::IgnoreCase, Modifier::Multiline]
    );
}

#[test]
fn test_keyword_detection() {
    let yaml = r#"
title: Keyword Rule
logsource:
    category: test
detection:
    keywords:
        - 'suspicious'
        - 'malware'
    condition: keywords
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let rule = &collection.rules[0];
    let det = &rule.detection.named["keywords"];
    match det {
        Detection::Keywords(vals) => assert_eq!(vals.len(), 2),
        _ => panic!("Expected Keywords detection"),
    }
}

#[test]
fn test_action_repeat() {
    let yaml = r#"
title: Base Rule
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
---
action: repeat
title: Repeated Rule
detection:
    selection:
        CommandLine|contains: 'ipconfig'
    condition: selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 2);
    assert!(
        collection.errors.is_empty(),
        "errors: {:?}",
        collection.errors
    );

    // First rule is the original
    assert_eq!(collection.rules[0].title, "Base Rule");
    assert_eq!(collection.rules[0].level, Some(crate::ast::Level::Medium));
    assert_eq!(
        collection.rules[0].logsource.product,
        Some("windows".to_string())
    );

    // Second rule inherits from first, but overrides title and detection
    assert_eq!(collection.rules[1].title, "Repeated Rule");
    // Logsource and level are inherited from the previous document
    assert_eq!(
        collection.rules[1].logsource.product,
        Some("windows".to_string())
    );
    assert_eq!(
        collection.rules[1].logsource.category,
        Some("process_creation".to_string())
    );
    assert_eq!(collection.rules[1].level, Some(crate::ast::Level::Medium));
}

#[test]
fn test_action_repeat_no_previous() {
    let yaml = r#"
action: repeat
title: Orphan Rule
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 0);
    assert_eq!(collection.errors.len(), 1);
    assert!(collection.errors[0].contains("without a previous document"));
}

#[test]
fn test_action_repeat_multiple_repeats() {
    // Base rule + two repeats producing three rules total
    let yaml = r#"
title: Base
logsource:
    product: windows
    category: process_creation
level: high
detection:
    selection:
        CommandLine|contains: 'cmd'
    condition: selection
---
action: repeat
title: Repeat One
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
---
action: repeat
title: Repeat Two
detection:
    selection:
        CommandLine|contains: 'wscript'
    condition: selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 3);
    assert!(collection.errors.is_empty());
    assert_eq!(collection.rules[0].title, "Base");
    assert_eq!(collection.rules[1].title, "Repeat One");
    assert_eq!(collection.rules[2].title, "Repeat Two");

    // All three should inherit logsource and level from the base
    for rule in &collection.rules {
        assert_eq!(rule.logsource.product, Some("windows".to_string()));
        assert_eq!(
            rule.logsource.category,
            Some("process_creation".to_string())
        );
        assert_eq!(rule.level, Some(crate::ast::Level::High));
    }
}

#[test]
fn test_action_repeat_chained_inherits_from_last() {
    // Repeat chains from the *last* document, not the original
    let yaml = r#"
title: First
logsource:
    product: linux
level: low
detection:
    selection:
        command|contains: 'ls'
    condition: selection
---
action: repeat
title: Second
level: medium
detection:
    selection:
        command|contains: 'cat'
    condition: selection
---
action: repeat
title: Third
detection:
    selection:
        command|contains: 'grep'
    condition: selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 3);

    // First: level low
    assert_eq!(collection.rules[0].level, Some(crate::ast::Level::Low));
    // Second: level overridden to medium
    assert_eq!(collection.rules[1].level, Some(crate::ast::Level::Medium));
    // Third: inherits from second (merged onto second), so level medium
    assert_eq!(collection.rules[2].level, Some(crate::ast::Level::Medium));
    // All should have linux product
    for rule in &collection.rules {
        assert_eq!(rule.logsource.product, Some("linux".to_string()));
    }
}

#[test]
fn test_action_repeat_with_global_template() {
    let yaml = r#"
action: global
logsource:
    product: windows
level: medium
---
title: Rule A
detection:
    selection:
        EventID: 1
    condition: selection
---
action: repeat
title: Rule B
detection:
    selection:
        EventID: 2
    condition: selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 2);
    assert!(collection.errors.is_empty());

    assert_eq!(collection.rules[0].title, "Rule A");
    assert_eq!(collection.rules[1].title, "Rule B");

    // Both should have the global logsource and level
    for rule in &collection.rules {
        assert_eq!(rule.logsource.product, Some("windows".to_string()));
        assert_eq!(rule.level, Some(crate::ast::Level::Medium));
    }
}

#[test]
fn test_correlation_condition_range() {
    let yaml = r#"
title: Base Rule
name: base_rule
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
level: low
---
title: Range Correlation
name: range_test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - User
    timespan: 1h
    condition:
        gt: 10
        lte: 100
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.correlations.len(), 1);
    let corr = &collection.correlations[0];

    match &corr.condition {
        CorrelationCondition::Threshold {
            predicates, field, ..
        } => {
            assert_eq!(predicates.len(), 2);
            // Check we got both operators (order doesn't matter, but they come from iteration)
            let has_gt = predicates
                .iter()
                .any(|(op, v)| *op == ConditionOperator::Gt && *v == 10);
            let has_lte = predicates
                .iter()
                .any(|(op, v)| *op == ConditionOperator::Lte && *v == 100);
            assert!(has_gt, "Expected gt: 10 predicate");
            assert!(has_lte, "Expected lte: 100 predicate");
            assert!(field.is_none());
        }
        _ => panic!("Expected threshold condition"),
    }
}

#[test]
fn test_correlation_condition_range_with_field() {
    let yaml = r#"
title: Base Rule
name: base_rule
logsource:
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
level: low
---
title: Range With Field
name: range_with_field
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 5
        lt: 50
        field: TargetUser
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let corr = &collection.correlations[0];

    match &corr.condition {
        CorrelationCondition::Threshold {
            predicates, field, ..
        } => {
            assert_eq!(predicates.len(), 2);
            assert_eq!(
                field.as_deref(),
                Some(["TargetUser".to_string()].as_slice())
            );
        }
        _ => panic!("Expected threshold condition"),
    }
}

#[test]
fn test_parse_neq_modifier() {
    let yaml = r#"
title: Neq Modifier
logsource:
    product: windows
detection:
    selection:
        Port|neq: 443
    condition: selection
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let rule = &collection.rules[0];
    let det = rule.detection.named.get("selection").unwrap();
    match det {
        crate::ast::Detection::AllOf(items) => {
            assert!(items[0].field.modifiers.contains(&Modifier::Neq));
        }
        _ => panic!("Expected AllOf detection"),
    }
}

#[test]
fn test_parse_utf16be_modifier() {
    let yaml = r#"
title: Utf16be Modifier
logsource:
    product: windows
detection:
    selection:
        Payload|utf16be|base64: 'data'
    condition: selection
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let rule = &collection.rules[0];
    let det = rule.detection.named.get("selection").unwrap();
    match det {
        crate::ast::Detection::AllOf(items) => {
            assert!(items[0].field.modifiers.contains(&Modifier::Utf16be));
            assert!(items[0].field.modifiers.contains(&Modifier::Base64));
        }
        _ => panic!("Expected AllOf detection"),
    }
}

#[test]
fn test_parse_utf16_modifier() {
    let yaml = r#"
title: Utf16 BOM Modifier
logsource:
    product: windows
detection:
    selection:
        Payload|utf16|base64: 'data'
    condition: selection
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let rule = &collection.rules[0];
    let det = rule.detection.named.get("selection").unwrap();
    match det {
        crate::ast::Detection::AllOf(items) => {
            assert!(items[0].field.modifiers.contains(&Modifier::Utf16));
            assert!(items[0].field.modifiers.contains(&Modifier::Base64));
        }
        _ => panic!("Expected AllOf detection"),
    }
}

// ── Multi-document YAML inheritance tests ─────────────────────────────

#[test]
fn test_action_reset_clears_global() {
    let yaml = r#"
action: global
title: Global Template
logsource:
    product: windows
level: high
---
detection:
    selection:
        EventID: 1
    condition: selection
---
action: reset
---
title: After Reset
logsource:
    product: linux
detection:
    selection:
        command: ls
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(
        collection.errors.is_empty(),
        "errors: {:?}",
        collection.errors
    );
    assert_eq!(collection.rules.len(), 2);

    // First rule inherits from global: title "Global Template", product windows
    assert_eq!(collection.rules[0].title, "Global Template");
    assert_eq!(
        collection.rules[0].logsource.product,
        Some("windows".to_string())
    );
    assert_eq!(collection.rules[0].level, Some(Level::High));

    // After reset, global is cleared — second rule is standalone
    assert_eq!(collection.rules[1].title, "After Reset");
    assert_eq!(
        collection.rules[1].logsource.product,
        Some("linux".to_string())
    );
    assert_eq!(collection.rules[1].level, Some(Level::Low));
}

#[test]
fn test_global_repeat_reset_combined() {
    let yaml = r#"
action: global
logsource:
    product: windows
level: medium
---
title: Rule A
detection:
    selection:
        EventID: 1
    condition: selection
---
action: repeat
title: Rule B
detection:
    selection:
        EventID: 2
    condition: selection
---
action: reset
---
title: Rule C
logsource:
    product: linux
detection:
    selection:
        command: cat
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(
        collection.errors.is_empty(),
        "errors: {:?}",
        collection.errors
    );
    assert_eq!(collection.rules.len(), 3);

    // Rule A: global applied
    assert_eq!(collection.rules[0].title, "Rule A");
    assert_eq!(
        collection.rules[0].logsource.product,
        Some("windows".to_string())
    );
    assert_eq!(collection.rules[0].level, Some(Level::Medium));

    // Rule B: repeat of Rule A + global
    assert_eq!(collection.rules[1].title, "Rule B");
    assert_eq!(
        collection.rules[1].logsource.product,
        Some("windows".to_string())
    );
    assert_eq!(collection.rules[1].level, Some(Level::Medium));

    // Rule C: after reset, no global — standalone
    assert_eq!(collection.rules[2].title, "Rule C");
    assert_eq!(
        collection.rules[2].logsource.product,
        Some("linux".to_string())
    );
    assert_eq!(collection.rules[2].level, Some(Level::Low));
}

#[test]
fn test_deep_repeat_chain() {
    let yaml = r#"
title: Base
logsource:
    product: windows
    category: process_creation
level: low
detection:
    selection:
        CommandLine|contains: 'cmd'
    condition: selection
---
action: repeat
title: Second
level: medium
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
---
action: repeat
title: Third
level: high
detection:
    selection:
        CommandLine|contains: 'wscript'
    condition: selection
---
action: repeat
title: Fourth
detection:
    selection:
        CommandLine|contains: 'cscript'
    condition: selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(
        collection.errors.is_empty(),
        "errors: {:?}",
        collection.errors
    );
    assert_eq!(collection.rules.len(), 4);

    assert_eq!(collection.rules[0].level, Some(Level::Low));
    assert_eq!(collection.rules[1].level, Some(Level::Medium));
    assert_eq!(collection.rules[2].level, Some(Level::High));
    // Fourth inherits from Third (which had level high)
    assert_eq!(collection.rules[3].level, Some(Level::High));

    // All should inherit logsource from the chain
    for rule in &collection.rules {
        assert_eq!(rule.logsource.product, Some("windows".to_string()));
        assert_eq!(
            rule.logsource.category,
            Some("process_creation".to_string())
        );
    }
}

#[test]
fn test_collect_errors_mixed_valid_invalid() {
    let yaml = r#"
title: Valid Rule
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: low
---
title: Invalid Rule
detection:
    selection:
        field: value
"#;
    // The second document is missing 'condition' — should generate an error
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 1);
    assert_eq!(collection.rules[0].title, "Valid Rule");
    assert!(
        !collection.errors.is_empty(),
        "Expected errors for invalid doc"
    );
}

#[test]
fn test_reset_followed_by_repeat_inherits_previous() {
    // `action: reset` only clears the global template — `previous`
    // is not affected, so a subsequent `repeat` still inherits from
    // the last non-action document.
    let yaml = r#"
title: Base
logsource:
    category: test
detection:
    selection:
        field: val
    condition: selection
level: low
---
action: reset
---
action: repeat
title: Repeated After Reset
detection:
    selection:
        field: val2
    condition: selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(
        collection.errors.is_empty(),
        "errors: {:?}",
        collection.errors
    );
    assert_eq!(collection.rules.len(), 2);
    assert_eq!(collection.rules[0].title, "Base");
    assert_eq!(collection.rules[1].title, "Repeated After Reset");
    // Inherits logsource from Base (previous), but no global
    assert_eq!(
        collection.rules[1].logsource.category,
        Some("test".to_string())
    );
    assert_eq!(collection.rules[1].level, Some(Level::Low));
}

#[test]
fn test_deep_merge_nested_maps() {
    let yaml = r#"
action: global
logsource:
    product: windows
    service: sysmon
    category: process_creation
---
title: Override Service
logsource:
    service: security
detection:
    selection:
        EventID: 1
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(
        collection.errors.is_empty(),
        "errors: {:?}",
        collection.errors
    );
    assert_eq!(collection.rules.len(), 1);

    let rule = &collection.rules[0];
    // Deep merge: product and category from global, service overridden
    assert_eq!(rule.logsource.product, Some("windows".to_string()));
    assert_eq!(rule.logsource.service, Some("security".to_string()));
    assert_eq!(
        rule.logsource.category,
        Some("process_creation".to_string())
    );
}

#[test]
fn test_line_feed_in_condition() {
    let yaml = r#"
title: Line Feed Condition rule
logsource:
    product: windows
detection:
    selection:
        Payload: 'data'
    replication_guid: 
        Payload: 'guid'
    filter_machine_account: 
        Payload: 'value'
    filter_known_service_accounts: 
        Payload: 'value'
    filter_msol_prefix: 
        Payload: 'value'
    filter_nt_authority_prefix: 
        Payload: 'value'
    condition: >-
        selection and replication_guid
        and not (filter_machine_account or filter_known_service_accounts
                or filter_msol_prefix or filter_nt_authority_prefix)
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(
        collection.errors.is_empty(),
        "errors: {:?}",
        collection.errors
    );
    assert_eq!(collection.rules.len(), 1);
}

#[test]
fn test_parse_detection_rule_custom_attributes_arbitrary_keys() {
    let yaml = r#"
title: Test Rule With Custom Attrs
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
my_custom_field: some_value
severity_score: 42
organization: ACME Corp
custom_list:
    - item1
    - item2
custom_object:
    key1: val1
    key2: val2
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 1);

    let rule = &collection.rules[0];
    assert_eq!(rule.title, "Test Rule With Custom Attrs");

    assert_eq!(
        rule.custom_attributes.get("my_custom_field"),
        Some(&Value::String("some_value".to_string()))
    );
    assert_eq!(
        rule.custom_attributes
            .get("severity_score")
            .and_then(|v| v.as_u64()),
        Some(42)
    );
    assert_eq!(
        rule.custom_attributes.get("organization"),
        Some(&Value::String("ACME Corp".to_string()))
    );

    let custom_list = rule.custom_attributes.get("custom_list").unwrap();
    assert!(custom_list.is_sequence());

    let custom_obj = rule.custom_attributes.get("custom_object").unwrap();
    assert!(custom_obj.is_mapping());

    assert!(!rule.custom_attributes.contains_key("title"));
    assert!(!rule.custom_attributes.contains_key("logsource"));
    assert!(!rule.custom_attributes.contains_key("detection"));
    assert!(!rule.custom_attributes.contains_key("level"));
    assert!(!rule.custom_attributes.contains_key("custom_attributes"));
}

#[test]
fn test_parse_detection_rule_no_custom_attributes() {
    let yaml = r#"
title: Standard Rule
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let rule = &collection.rules[0];
    assert!(rule.custom_attributes.is_empty());
}

#[test]
fn test_parse_detection_rule_custom_attributes_explicit_block() {
    let yaml = r#"
title: Rule With Custom Attrs
custom_attributes:
    rsigma.suppress: 5m
    rsigma.action: reset
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let rule = &collection.rules[0];
    assert_eq!(
        rule.custom_attributes
            .get("rsigma.suppress")
            .and_then(Value::as_str),
        Some("5m")
    );
    assert_eq!(
        rule.custom_attributes
            .get("rsigma.action")
            .and_then(Value::as_str),
        Some("reset")
    );
    // The reserved key itself must not be carried into the merged map.
    assert!(!rule.custom_attributes.contains_key("custom_attributes"));
}

#[test]
fn test_parse_detection_rule_custom_attributes_explicit_overrides_toplevel() {
    // Arbitrary top-level `priority: top` is captured first, then the
    // explicit `custom_attributes:` block overrides it.
    let yaml = r#"
title: Merge Test
priority: top
custom_attributes:
    priority: explicit
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let rule = &collection.rules[0];
    assert_eq!(
        rule.custom_attributes
            .get("priority")
            .and_then(Value::as_str),
        Some("explicit")
    );
}

#[test]
fn test_parse_correlation_rule_custom_attributes_arbitrary_keys() {
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
name: reserved_name
tags:
    - test.tag
taxonomy: test.taxonomy
falsepositives:
    - benign activity
generate: false
my_custom_correlation_field: custom_value
priority: high_priority
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
    assert_eq!(collection.correlations.len(), 1);

    let corr = &collection.correlations[0];
    assert_eq!(
        corr.custom_attributes.get("my_custom_correlation_field"),
        Some(&Value::String("custom_value".to_string()))
    );
    assert_eq!(
        corr.custom_attributes.get("priority"),
        Some(&Value::String("high_priority".to_string()))
    );

    assert!(!corr.custom_attributes.contains_key("title"));
    assert!(!corr.custom_attributes.contains_key("correlation"));
    assert!(!corr.custom_attributes.contains_key("level"));
    assert!(!corr.custom_attributes.contains_key("id"));
    assert!(!corr.custom_attributes.contains_key("name"));
    assert!(!corr.custom_attributes.contains_key("tags"));
    assert!(!corr.custom_attributes.contains_key("taxonomy"));
    assert!(!corr.custom_attributes.contains_key("falsepositives"));
    assert!(!corr.custom_attributes.contains_key("generate"));
    assert!(!corr.custom_attributes.contains_key("custom_attributes"));
}

#[test]
fn test_parse_correlation_rule_schema_top_level_metadata() {
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
name: bucket_enum_corr
tags:
    - attack.collection
taxonomy: enterprise_attack
falsepositives:
    - Scheduled backups
generate: true
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
    assert_eq!(collection.correlations.len(), 1);
    let corr = &collection.correlations[0];
    assert_eq!(corr.name.as_deref(), Some("bucket_enum_corr"));
    assert_eq!(corr.tags, vec!["attack.collection"]);
    assert_eq!(corr.taxonomy.as_deref(), Some("enterprise_attack"));
    assert_eq!(corr.falsepositives, vec!["Scheduled backups"]);
    assert!(corr.generate);
}

#[test]
fn test_parse_correlation_generate_nested_fallback() {
    let yaml = r#"
title: Nested Gen
correlation:
    type: temporal
    rules:
        - a
    group-by:
        - x
    timespan: 1m
    generate: true
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.correlations[0].generate);
}
