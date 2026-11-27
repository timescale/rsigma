use super::*;
use crate::{DiagnosticSeverity, SigmaParserErrorKind, parse_condition};

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
fn test_correlation_window_defaults_to_sliding() {
    let yaml = r#"
title: Corr
correlation:
    type: event_count
    rules:
        - base-1
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 10
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.correlations.len(), 1);
    let corr = &collection.correlations[0];
    assert_eq!(corr.window, WindowMode::Sliding);
    assert!(corr.gap.is_none());
}

#[test]
fn test_correlation_window_tumbling() {
    let yaml = r#"
title: Corr
correlation:
    type: event_count
    rules:
        - base-1
    group-by:
        - User
    timespan: 1h
    window: tumbling
    condition:
        gte: 100
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let corr = &collection.correlations[0];
    assert_eq!(corr.window, WindowMode::Tumbling);
    assert!(corr.gap.is_none());
}

#[test]
fn test_correlation_window_session_with_gap() {
    let yaml = r#"
title: Corr
correlation:
    type: temporal
    rules:
        - a
        - b
    group-by:
        - User
    window: session
    gap: 5m
    timespan: 2h
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let corr = &collection.correlations[0];
    assert_eq!(corr.window, WindowMode::Session);
    assert_eq!(corr.gap.as_ref().unwrap().seconds, 300);
    assert_eq!(corr.timespan.seconds, 7200);
}

#[test]
fn test_correlation_session_requires_gap() {
    let yaml = r#"
title: Corr
correlation:
    type: temporal
    rules:
        - a
        - b
    group-by:
        - User
    window: session
    timespan: 2h
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.correlations.is_empty());
    assert!(
        collection
            .diagnostics
            .iter()
            .any(|e| e.message.contains("gap"))
    );
}

#[test]
fn test_correlation_gap_without_session_is_error() {
    let yaml = r#"
title: Corr
correlation:
    type: event_count
    rules:
        - base-1
    group-by:
        - User
    timespan: 1h
    gap: 5m
    condition:
        gte: 10
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.correlations.is_empty());
    assert!(
        collection
            .diagnostics
            .iter()
            .any(|e| e.message.contains("gap"))
    );
}

#[test]
fn test_correlation_invalid_window_mode_is_error() {
    let yaml = r#"
title: Corr
correlation:
    type: event_count
    rules:
        - base-1
    group-by:
        - User
    timespan: 1h
    window: rolling
    condition:
        gte: 10
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.correlations.is_empty());
    assert!(
        collection
            .diagnostics
            .iter()
            .any(|e| e.message.contains("window mode"))
    );
}

#[test]
fn test_correlation_window_rsigma_namespace() {
    // The rsigma.* extension spelling is the primary form for window/gap.
    let yaml = r#"
title: Corr
correlation:
    type: temporal
    rules:
        - a
        - b
    group-by:
        - User
    timespan: 2h
rsigma.window: session
rsigma.gap: 5m
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let corr = &collection.correlations[0];
    assert_eq!(corr.window, WindowMode::Session);
    assert_eq!(corr.gap.as_ref().unwrap().seconds, 300);
    // The rsigma.* keys also remain available as custom attributes.
    assert!(corr.custom_attributes.contains_key("rsigma.window"));
}

#[test]
fn test_correlation_window_rsigma_overrides_first_class() {
    // When both spellings are present, rsigma.* wins.
    let yaml = r#"
title: Corr
correlation:
    type: event_count
    rules:
        - base-1
    group-by:
        - User
    timespan: 1h
    window: sliding
    condition:
        gte: 5
rsigma.window: tumbling
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.correlations[0].window, WindowMode::Tumbling);
}

#[test]
fn test_correlation_non_string_gap_is_typed_error() {
    // An unquoted numeric gap must error with a type hint, not be silently
    // treated as absent (which would surface as a misleading "missing gap").
    let yaml = r#"
title: Corr
correlation:
    type: temporal
    rules:
        - a
        - b
    group-by:
        - User
    window: session
    gap: 300
    timespan: 2h
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.correlations.is_empty());
    assert!(
        collection
            .diagnostics
            .iter()
            .any(|e| e.message.contains("must be a string")),
        "{:?}",
        collection.diagnostics
    );
}

#[test]
fn test_correlation_non_string_rsigma_window_is_typed_error() {
    let yaml = r#"
title: Corr
correlation:
    type: event_count
    rules:
        - base-1
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 10
rsigma.window: 5
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.correlations.is_empty());
    assert!(
        collection
            .diagnostics
            .iter()
            .any(|e| e.message.contains("rsigma.window") && e.message.contains("must be a string")),
        "{:?}",
        collection.diagnostics
    );
}

#[test]
fn test_correlation_rsigma_session_requires_gap() {
    let yaml = r#"
title: Corr
correlation:
    type: temporal
    rules:
        - a
        - b
    group-by:
        - User
    timespan: 2h
rsigma.window: session
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.correlations.is_empty());
    assert!(
        collection
            .diagnostics
            .iter()
            .any(|e| e.message.contains("gap"))
    );
}

#[test]
fn test_correlation_window_in_custom_attributes_block() {
    let yaml = r#"
title: Corr
correlation:
    type: event_count
    rules:
        - base-1
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 3
custom_attributes:
    rsigma.window: session
    rsigma.gap: 1m
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let corr = &collection.correlations[0];
    assert_eq!(corr.window, WindowMode::Session);
    assert_eq!(corr.gap.as_ref().unwrap().seconds, 60);
}

#[test]
fn test_correlation_window_block_overrides_top_level() {
    // The block wins over a top-level key, as for every custom attribute.
    let yaml = r#"
title: Corr
correlation:
    type: event_count
    rules:
        - base-1
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 3
rsigma.window: sliding
custom_attributes:
    rsigma.window: tumbling
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.correlations[0].window, WindowMode::Tumbling);
}

#[test]
fn test_correlation_window_block_errors_match_top_level() {
    for (attrs, needle) in [
        ("    rsigma.window: 5\n", "must be a string"),
        ("    rsigma.window: hopping\n", "Unknown window mode"),
        ("    rsigma.window: session\n", "requires a gap"),
        ("    rsigma.gap: 5m\n", "only valid with window: session"),
    ] {
        let yaml = format!(
            "title: Corr\ncorrelation:\n    type: event_count\n    rules:\n        - base-1\n    group-by:\n        - User\n    timespan: 1h\n    condition:\n        gte: 3\ncustom_attributes:\n{attrs}"
        );
        let collection = parse_sigma_yaml(&yaml).unwrap();
        assert!(collection.correlations.is_empty(), "{attrs}");
        assert!(
            collection
                .diagnostics
                .iter()
                .any(|e| e.message.contains(needle)),
            "{attrs}: {:?}",
            collection.diagnostics
        );
    }
}

#[test]
fn test_apply_window_attributes_follows_changed_attributes() {
    let yaml = r#"
title: Corr
correlation:
    type: event_count
    rules:
        - base-1
    group-by:
        - User
    timespan: 1h
    window: session
    gap: 5m
    condition:
        gte: 3
"#;
    let mut corr = parse_sigma_yaml(yaml).unwrap().correlations.remove(0);

    // Switching a session rule away from session drops the gap.
    corr.custom_attributes.insert(
        "rsigma.window".into(),
        yaml_serde::Value::String("tumbling".into()),
    );
    corr.apply_window_attributes().unwrap();
    assert_eq!(corr.window, WindowMode::Tumbling);
    assert!(corr.gap.is_none());

    // The emitted rule parses back to the same window.
    let emitted = crate::emit_correlation_yaml(&corr);
    let reparsed = parse_sigma_yaml(&emitted).unwrap();
    assert_eq!(
        reparsed.correlations[0].window,
        WindowMode::Tumbling,
        "{emitted}"
    );
    assert!(reparsed.correlations[0].gap.is_none(), "{emitted}");

    // Back to session, with a gap from the attributes.
    corr.custom_attributes.insert(
        "rsigma.window".into(),
        yaml_serde::Value::String("session".into()),
    );
    corr.custom_attributes
        .insert("rsigma.gap".into(), yaml_serde::Value::String("2m".into()));
    corr.apply_window_attributes().unwrap();
    assert_eq!(corr.window, WindowMode::Session);
    assert_eq!(corr.gap.as_ref().unwrap().seconds, 120);
}

#[test]
fn test_apply_window_attributes_without_attributes_is_a_no_op() {
    let yaml = r#"
title: Corr
correlation:
    type: event_count
    rules:
        - base-1
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 3
"#;
    let mut corr = parse_sigma_yaml(yaml).unwrap().correlations.remove(0);
    corr.gap = Some(crate::Timespan::parse("5m").unwrap());
    corr.apply_window_attributes().unwrap();
    assert_eq!(corr.window, WindowMode::Sliding);
    assert!(corr.gap.is_some());
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

#[test]
fn test_not_modifier_is_rejected_with_guidance() {
    // `field|not: value` is a common mistranslation of pySigma's
    // `not selection` condition idiom. The parser must reject it with a
    // dedicated error pointing the user at the correct workaround.
    let leaf = parse_field_spec("field|not");
    assert!(matches!(
        leaf,
        Err(crate::error::SigmaParserError::NotIsNotAModifier)
    ));

    // Also rejected when `not` is composed after another modifier.
    let composed = parse_field_spec("CommandLine|contains|not");
    assert!(matches!(
        composed,
        Err(crate::error::SigmaParserError::NotIsNotAModifier)
    ));

    // The error message names both alternatives so users can act on it.
    let msg = format!("{}", composed.unwrap_err());
    assert!(msg.contains("not selection"), "msg was: {msg}");
    assert!(msg.contains("filter"), "msg was: {msg}");
}

// ── Field modifier edge cases ────────────────────────────────────────

#[test]
fn test_parse_contains_re_combination() {
    let spec = parse_field_spec("CommandLine|contains|re").unwrap();
    assert_eq!(spec.modifiers, vec![Modifier::Contains, Modifier::Re]);
}

#[test]
fn test_parse_duplicate_modifiers() {
    for key in [
        "Field|contains|contains",
        "Field|neq|neq",
        "Field|base64|contains|base64",
    ] {
        assert!(
            matches!(
                parse_field_spec(key),
                Err(crate::error::SigmaParserError::DuplicateModifier(_))
            ),
            "{key} should be rejected"
        );
    }
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
        collection.diagnostics.is_empty(),
        "errors: {:?}",
        collection.diagnostics
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
    assert_eq!(collection.diagnostics.len(), 1);
    assert!(
        collection.diagnostics[0]
            .message
            .contains("without a previous document")
    );
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
    assert!(collection.diagnostics.is_empty());
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
    assert!(collection.diagnostics.is_empty());

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

fn temporal_correlation_yaml(corr_type: &str, rules: &str) -> String {
    format!(
        r#"
title: Temporal Without Condition
correlation:
    type: {corr_type}
    rules: {rules}
    group-by:
        - Host
    timespan: 5m
"#
    )
}

#[test]
fn test_temporal_without_condition_requires_every_rule() {
    for corr_type in ["temporal", "temporal_ordered"] {
        let yaml = temporal_correlation_yaml(corr_type, "[rule_a, rule_b, rule_c]");
        let collection = parse_sigma_yaml(&yaml).unwrap();
        assert!(
            collection.diagnostics.is_empty(),
            "{:?}",
            collection.diagnostics
        );
        match &collection.correlations[0].condition {
            CorrelationCondition::Threshold {
                predicates,
                field,
                percentile,
            } => {
                assert_eq!(predicates, &[(ConditionOperator::Gte, 3)], "{corr_type}");
                assert!(field.is_none());
                assert!(percentile.is_none());
            }
            other => panic!("Expected threshold condition, got {other:?}"),
        }
    }
}

#[test]
fn test_temporal_without_condition_counts_duplicate_rules_once() {
    let yaml = temporal_correlation_yaml("temporal", "[rule_a, rule_b, rule_a]");
    let collection = parse_sigma_yaml(&yaml).unwrap();
    match &collection.correlations[0].condition {
        CorrelationCondition::Threshold { predicates, .. } => {
            assert_eq!(predicates, &[(ConditionOperator::Gte, 2)]);
        }
        other => panic!("Expected threshold condition, got {other:?}"),
    }
}

#[test]
fn test_temporal_without_condition_or_rules_is_error() {
    let yaml = temporal_correlation_yaml("temporal", "[]");
    let collection = parse_sigma_yaml(&yaml).unwrap();
    assert!(collection.correlations.is_empty());
    assert!(
        collection
            .diagnostics
            .iter()
            .any(|e| e.message.contains("requires at least one rule")),
        "{:?}",
        collection.diagnostics
    );
}

#[test]
fn test_correlation_timespan_must_be_positive() {
    let yaml = r#"
title: Zero Window
correlation:
    type: event_count
    rules: [base]
    group-by: [Host]
    timespan: 0s
    condition:
        gte: 1
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.correlations.is_empty());
    assert!(
        collection
            .diagnostics
            .iter()
            .any(|e| e.message.contains("must be greater than zero")),
        "{:?}",
        collection.diagnostics
    );
}

#[test]
fn test_correlation_condition_rejects_unknown_keys() {
    let yaml = r#"
title: Unknown Condition Key
correlation:
    type: event_count
    rules: [base]
    group-by: [Host]
    timespan: 1m
    condition:
        gte: 1
        bogus: 2
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.correlations.is_empty());
    assert!(
        collection.diagnostics.iter().any(|e| e
            .message
            .contains("Unknown correlation condition key: bogus")),
        "{:?}",
        collection.diagnostics
    );
}

#[test]
fn test_value_count_requires_a_field() {
    let yaml = r#"
title: Missing Value Field
correlation:
    type: value_count
    rules: [base]
    group-by: [Host]
    timespan: 1m
    condition:
        gte: 1
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.correlations.is_empty());
    assert!(
        collection.diagnostics.iter().any(|e| e
            .message
            .contains("value_count correlation condition requires 'field'")),
        "{:?}",
        collection.diagnostics
    );
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
        collection.diagnostics.is_empty(),
        "errors: {:?}",
        collection.diagnostics
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
        collection.diagnostics.is_empty(),
        "errors: {:?}",
        collection.diagnostics
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
        collection.diagnostics.is_empty(),
        "errors: {:?}",
        collection.diagnostics
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
logsource:
    category: test
detection:
    selection:
        field: value
"#;
    // The second document is missing 'condition' — should generate an error
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 1);
    assert_eq!(collection.rules[0].title, "Valid Rule");
    assert!(
        !collection.diagnostics.is_empty(),
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
        collection.diagnostics.is_empty(),
        "errors: {:?}",
        collection.diagnostics
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
        collection.diagnostics.is_empty(),
        "errors: {:?}",
        collection.diagnostics
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
        collection.diagnostics.is_empty(),
        "errors: {:?}",
        collection.diagnostics
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

#[test]
fn deep_merge_handles_deeply_nested_global() {
    use yaml_serde::Value;

    fn nested_map(depth: usize) -> Value {
        let mut v = Value::String("leaf".into());
        for i in (0..depth).rev() {
            let mut map = yaml_serde::Mapping::new();
            map.insert(Value::String(format!("k{i}")), v);
            v = Value::Mapping(map);
        }
        v
    }

    let result = super::deep_merge(nested_map(200), nested_map(200));
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("maximum depth"),
        "expected MergeTooDeep, got: {err}"
    );
}

#[test]
fn deep_merge_succeeds_at_reasonable_depth() {
    use yaml_serde::Value;

    fn nested_map(depth: usize) -> Value {
        let mut v = Value::String("leaf".into());
        for i in (0..depth).rev() {
            let mut map = yaml_serde::Mapping::new();
            map.insert(Value::String(format!("k{i}")), v);
            v = Value::Mapping(map);
        }
        v
    }

    let result = super::deep_merge(nested_map(10), nested_map(10));
    assert!(result.is_ok());
}

// =============================================================================
// Array matching (object-scope quantifier blocks)
// =============================================================================

/// Parse a single-selection rule and return its `selection` detection.
///
/// The rule declares `sigma-version: 3` so array-matching bracket selectors are
/// enabled (they are gated off at the floor major 2).
fn parse_selection(detection_body: &str) -> Detection {
    let yaml = format!(
        "title: T\nsigma-version: 3\nlogsource:\n    category: test\ndetection:\n{detection_body}    condition: selection\n"
    );
    let collection =
        parse_sigma_yaml(&yaml).unwrap_or_else(|e| panic!("parse failed: {e}\n{yaml}"));
    collection.rules[0].detection.named["selection"].clone()
}

#[test]
fn sigma_version_parsed_as_major() {
    // Integer major, release string (major only), and absent (None -> floor).
    let v3 = "title: T\nsigma-version: 3\nlogsource:\n    category: test\ndetection:\n    selection:\n        a: b\n    condition: selection\n";
    assert_eq!(
        parse_sigma_yaml(v3).unwrap().rules[0].sigma_version,
        Some(3)
    );

    let release = "title: T\nsigma-version: \"3.2.1\"\nlogsource:\n    category: test\ndetection:\n    selection:\n        a: b\n    condition: selection\n";
    assert_eq!(
        parse_sigma_yaml(release).unwrap().rules[0].sigma_version,
        Some(3)
    );

    let absent = "title: T\nlogsource:\n    category: test\ndetection:\n    selection:\n        a: b\n    condition: selection\n";
    assert_eq!(
        parse_sigma_yaml(absent).unwrap().rules[0].sigma_version,
        None
    );
}

#[test]
fn array_brackets_are_literal_below_v3() {
    // Without sigma-version (floor major 2), a quantifier selector is NOT a
    // selector: `connections[any]` is a literal field name (escaped), so a
    // block body under it is a mapping value, which no field accepts.
    let yaml = "title: T\nlogsource:\n    category: test\ndetection:\n    selection:\n        connections[any]:\n            protocol: \"TCP\"\n    condition: selection\n";
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.rules.is_empty());
    assert!(
        collection.diagnostics[0]
            .message
            .contains("'connections\\[any\\]' takes a value or a list of values"),
        "{:?}",
        collection.diagnostics
    );

    let scalar = "title: T\nlogsource:\n    category: test\ndetection:\n    selection:\n        connections[any]: TCP\n    condition: selection\n";
    let det = parse_sigma_yaml(scalar).unwrap().rules[0].detection.named["selection"].clone();
    let Detection::AllOf(items) = det else {
        panic!("brackets must not be a selector below v3, got {det:?}");
    };
    assert_eq!(items[0].field.name.as_deref(), Some("connections\\[any\\]"));
}

#[test]
fn positional_index_is_literal_field_below_v3() {
    // Below v3 a positional `args[0]` is a literal field name; the brackets are
    // escaped so the escape-aware resolver treats them literally.
    let yaml = "title: T\nsigma-version: 2\nlogsource:\n    category: test\ndetection:\n    selection:\n        args[0]: \"cmd.exe\"\n    condition: selection\n";
    let collection = parse_sigma_yaml(yaml).unwrap();
    let det = collection.rules[0].detection.named["selection"].clone();
    let Detection::AllOf(items) = det else {
        panic!("expected AllOf, got {det:?}");
    };
    assert_eq!(items[0].field.name.as_deref(), Some("args\\[0\\]"));
}

#[test]
fn array_object_scope_block_any() {
    let det = parse_selection(
        "    selection:\n        connections[any]:\n            protocol: \"TCP\"\n            ip|cidr: \"10.0.0.0/8\"\n",
    );
    let Detection::ArrayMatch {
        field,
        quantifier,
        body,
    } = det
    else {
        panic!("expected ArrayMatch, got {det:?}");
    };
    assert_eq!(field, "connections");
    assert_eq!(quantifier, ArrayQuantifier::Any);
    let Detection::AllOf(items) = *body else {
        panic!("expected AllOf body");
    };
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].field.name.as_deref(), Some("protocol"));
    assert_eq!(items[1].field.name.as_deref(), Some("ip"));
    assert_eq!(items[1].field.modifiers, vec![Modifier::Cidr]);
}

#[test]
fn array_object_scope_block_all() {
    let det = parse_selection(
        "    selection:\n        connections[all]:\n            protocol: \"TCP\"\n",
    );
    let Detection::ArrayMatch {
        field, quantifier, ..
    } = det
    else {
        panic!("expected ArrayMatch, got {det:?}");
    };
    assert_eq!(field, "connections");
    assert_eq!(quantifier, ArrayQuantifier::All);
}

#[test]
fn array_extended_block_parses_condition_and_named() {
    let det = parse_selection(
        "    selection:\n        connections[any]:\n            condition: in_cidr and not is_tcp\n            in_cidr:\n                ip|cidr: \"123.1.0.0/16\"\n            is_tcp:\n                protocol: \"TCP\"\n",
    );
    let Detection::ArrayMatch {
        field,
        quantifier,
        body,
    } = det
    else {
        panic!("expected ArrayMatch, got {det:?}");
    };
    assert_eq!(field, "connections");
    assert_eq!(quantifier, ArrayQuantifier::Any);
    let Detection::Conditional { named, condition } = *body else {
        panic!("expected Conditional body");
    };
    assert_eq!(named.len(), 2);
    assert!(named.contains_key("in_cidr"));
    assert!(named.contains_key("is_tcp"));
    // `in_cidr and not is_tcp` -> And([Identifier, Not(Identifier)]).
    let ConditionExpr::And(parts) = condition else {
        panic!("expected And condition, got {condition:?}");
    };
    assert_eq!(parts.len(), 2);
    assert!(matches!(parts[1], ConditionExpr::Not(_)));
}

#[test]
fn array_extended_block_requires_named_selections() {
    // A `condition:` with no sibling selections is an error.
    let yaml = "title: T\nsigma-version: 3\nlogsource:\n    category: test\ndetection:\n    selection:\n        connections[any]:\n            condition: foo\n    condition: selection\n";
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.rules.is_empty());
    assert!(!collection.diagnostics.is_empty());
}

#[test]
fn array_scalar_element_marker_is_field_less() {
    // `.` inside a block body lowers to a field-less item (matches the member).
    let det =
        parse_selection("    selection:\n        tags[any]:\n            .|contains: \"admin\"\n");
    let Detection::ArrayMatch { body, .. } = det else {
        panic!("expected ArrayMatch, got {det:?}");
    };
    let Detection::AllOf(items) = *body else {
        panic!("expected AllOf body");
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].field.name, None);
    assert_eq!(items[0].field.modifiers, vec![Modifier::Contains]);
}

#[test]
fn array_object_scope_block_all_or_empty() {
    let det = parse_selection(
        "    selection:\n        connections[all_or_empty]:\n            protocol: \"TCP\"\n",
    );
    let Detection::ArrayMatch {
        field, quantifier, ..
    } = det
    else {
        panic!("expected ArrayMatch, got {det:?}");
    };
    assert_eq!(field, "connections");
    assert_eq!(quantifier, ArrayQuantifier::AllOrEmpty);
}

#[test]
fn array_object_scope_block_none() {
    let det = parse_selection(
        "    selection:\n        containers[none]:\n            privileged: \"true\"\n",
    );
    let Detection::ArrayMatch {
        field, quantifier, ..
    } = det
    else {
        panic!("expected ArrayMatch, got {det:?}");
    };
    assert_eq!(field, "containers");
    assert_eq!(quantifier, ArrayQuantifier::None);
}

#[test]
fn array_path_shorthand_desugars_to_block() {
    let det = parse_selection("    selection:\n        connections[any].ip: \"1.2.3.1\"\n");
    let Detection::ArrayMatch {
        field,
        quantifier,
        body,
    } = det
    else {
        panic!("expected ArrayMatch, got {det:?}");
    };
    assert_eq!(field, "connections");
    assert_eq!(quantifier, ArrayQuantifier::Any);
    let Detection::AllOf(items) = *body else {
        panic!("expected AllOf body");
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].field.name.as_deref(), Some("ip"));
}

#[test]
fn array_scalar_member_match_uses_selfless_item() {
    // `tags[all]: value` matches the array member itself; represented as a
    // body item with no field name.
    let det = parse_selection("    selection:\n        tags[all]: \"prod\"\n");
    let Detection::ArrayMatch {
        field,
        quantifier,
        body,
    } = det
    else {
        panic!("expected ArrayMatch, got {det:?}");
    };
    assert_eq!(field, "tags");
    assert_eq!(quantifier, ArrayQuantifier::All);
    let Detection::AllOf(items) = *body else {
        panic!("expected AllOf body");
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].field.name, None);
}

#[test]
fn array_scalar_member_match_keeps_modifier() {
    let det = parse_selection("    selection:\n        ip[all]|startswith: \"123\"\n");
    let Detection::ArrayMatch { body, .. } = det else {
        panic!("expected ArrayMatch, got {det:?}");
    };
    let Detection::AllOf(items) = *body else {
        panic!("expected AllOf body");
    };
    assert_eq!(items[0].field.name, None);
    assert_eq!(items[0].field.modifiers, vec![Modifier::StartsWith]);
}

#[test]
fn array_nested_quantifiers() {
    let det =
        parse_selection("    selection:\n        rules[any].ip[all]|startswith: \"123.1.1\"\n");
    let Detection::ArrayMatch {
        field,
        quantifier,
        body,
    } = det
    else {
        panic!("expected outer ArrayMatch, got {det:?}");
    };
    assert_eq!(field, "rules");
    assert_eq!(quantifier, ArrayQuantifier::Any);
    let Detection::ArrayMatch {
        field: inner_field,
        quantifier: inner_q,
        body: inner_body,
    } = *body
    else {
        panic!("expected inner ArrayMatch");
    };
    assert_eq!(inner_field, "ip");
    assert_eq!(inner_q, ArrayQuantifier::All);
    let Detection::AllOf(items) = *inner_body else {
        panic!("expected AllOf");
    };
    assert_eq!(items[0].field.name, None);
    assert_eq!(items[0].field.modifiers, vec![Modifier::StartsWith]);
}

#[test]
fn array_mixed_map_produces_and() {
    let det = parse_selection(
        "    selection:\n        EventName: \"AuthorizeSecurityGroupIngress\"\n        connections[any]:\n            protocol: \"TCP\"\n",
    );
    let Detection::And(parts) = det else {
        panic!("expected And, got {det:?}");
    };
    assert_eq!(parts.len(), 2);
    assert!(matches!(parts[0], Detection::AllOf(_)));
    assert!(matches!(parts[1], Detection::ArrayMatch { .. }));
}

#[test]
fn array_flattened_correlation_parses_as_independent_scopes() {
    // The declined shared-prefix form parses as two independent ArrayMatch
    // scopes (NOT same-element correlation). The linter warns about this; the
    // parser does not bind the two keys together.
    let det = parse_selection(
        "    selection:\n        connections[any].protocol: \"TCP\"\n        connections[any].ip: \"1.2.3.1\"\n",
    );
    let Detection::And(parts) = det else {
        panic!("expected And, got {det:?}");
    };
    assert_eq!(parts.len(), 2);
    assert!(
        parts
            .iter()
            .all(|p| matches!(p, Detection::ArrayMatch { .. }))
    );
}

#[test]
fn array_unknown_quantifier_is_error() {
    let yaml = "title: T\nsigma-version: 3\nlogsource:\n    category: test\ndetection:\n    selection:\n        connections[one]: \"x\"\n    condition: selection\n";
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.rules.is_empty());
    assert!(
        collection
            .diagnostics
            .iter()
            .any(|e| e.message.contains("unknown array selector")),
        "got: {:?}",
        collection.diagnostics
    );
}

/// Parse a `sigma-version: 3` rule with `detection_body` and return the
/// diagnostics it produced.
fn array_rule_diagnostics(detection_body: &str) -> Vec<String> {
    let yaml = format!(
        "title: T\nsigma-version: 3\nlogsource:\n    category: test\ndetection:\n{detection_body}    condition: selection\n"
    );
    let collection = parse_sigma_yaml(&yaml).unwrap();
    collection
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect()
}

fn is_scope_error(diagnostics: &[String]) -> bool {
    diagnostics
        .iter()
        .any(|m| m.contains("array quantifier scopes"))
}

fn quantified_key(scopes: usize) -> String {
    (0..scopes).map(|i| format!("a{i}[any].")).collect()
}

/// `depth` nested `aN[any]:` block keys under `selection`, around `inner`.
fn nested_array_blocks(depth: usize, inner: &str) -> String {
    let mut body = String::from("    selection:\n");
    for level in 0..depth {
        body.push_str(&format!("{}a{level}[any]:\n", "    ".repeat(level + 2)));
    }
    body.push_str(&format!("{}{inner}\n", "    ".repeat(depth + 2)));
    body
}

#[test]
fn array_quantifiers_in_one_key_are_capped() {
    let at_limit = format!("    selection:\n        {}x: 1\n", quantified_key(8));
    assert!(array_rule_diagnostics(&at_limit).is_empty());

    let over = format!("    selection:\n        {}x: 1\n", quantified_key(9));
    assert!(is_scope_error(&array_rule_diagnostics(&over)));
}

#[test]
fn nested_array_blocks_count_toward_the_cap() {
    assert!(array_rule_diagnostics(&nested_array_blocks(8, "x: 1")).is_empty());
    assert!(is_scope_error(&array_rule_diagnostics(
        &nested_array_blocks(9, "x: 1")
    )));

    // Quantifiers in a key inside a block body add to the enclosing blocks.
    let inner = format!("{}x: 1", quantified_key(2));
    assert!(array_rule_diagnostics(&nested_array_blocks(6, &inner)).is_empty());
    assert!(is_scope_error(&array_rule_diagnostics(
        &nested_array_blocks(7, &inner)
    )));
}

#[test]
fn inherited_array_prefixes_count_toward_the_cap() {
    // `a0[any]...a6[any]: {b[any]: 1}` expands `b[any]` under the remaining
    // six quantified segments, so the leaf sits inside eight scopes.
    let key = quantified_key(7);
    let at_limit = format!(
        "    selection:\n        {}:\n            b[any]: 1\n",
        key.trim_end_matches('.')
    );
    assert!(array_rule_diagnostics(&at_limit).is_empty());

    let over = format!(
        "    selection:\n        {}:\n            b[any].c[any]: 1\n",
        key.trim_end_matches('.')
    );
    assert!(is_scope_error(&array_rule_diagnostics(&over)));
}

#[test]
fn thousands_of_array_quantifiers_fail_without_overflow() {
    // YAML caps implicit keys at 1024 characters, so a longer key is explicit.
    let body = format!(
        "    selection:\n        ? {}x\n        : 1\n",
        quantified_key(5_000)
    );
    let diagnostics = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || array_rule_diagnostics(&body))
        .unwrap()
        .join()
        .unwrap();
    assert!(is_scope_error(&diagnostics), "{diagnostics:?}");
}

#[test]
fn chained_array_quantifiers_nest_in_key_order() {
    let det = parse_selection("    selection:\n        a[0].b[any].c.d[all].e|contains: x\n");
    let Detection::ArrayMatch {
        field,
        quantifier: ArrayQuantifier::Any,
        body,
    } = det
    else {
        panic!("expected an outer any block, got {det:?}");
    };
    assert_eq!(field, "a[0].b");
    let Detection::ArrayMatch {
        field,
        quantifier: ArrayQuantifier::All,
        body,
    } = *body
    else {
        panic!("expected an inner all block, got {body:?}");
    };
    assert_eq!(field, "c.d");
    let Detection::AllOf(items) = *body else {
        panic!("expected a leaf item, got {body:?}");
    };
    assert_eq!(items[0].field.name.as_deref(), Some("e"));
    assert_eq!(items[0].field.modifiers, vec![Modifier::Contains]);
}

#[test]
fn chained_array_quantifier_with_map_value_opens_a_block_per_key() {
    let det = parse_selection(
        "    selection:\n        a[any].b[any]:\n            x: 1\n            y: 2\n",
    );
    let Detection::ArrayMatch { field, body, .. } = det else {
        panic!("expected an outer block, got {det:?}");
    };
    assert_eq!(field, "a");
    let Detection::And(parts) = *body else {
        panic!("expected one inner block per key, got {body:?}");
    };
    assert_eq!(parts.len(), 2);
    assert!(
        parts
            .iter()
            .all(|p| matches!(p, Detection::ArrayMatch { field, .. } if field == "b"))
    );
}

#[test]
fn array_positional_index_scalar_is_plain_field() {
    // `args[0]: x` is a plain item whose field path keeps the index marker.
    let det = parse_selection("    selection:\n        args[0]: \"cmd.exe\"\n");
    let Detection::AllOf(items) = det else {
        panic!("expected AllOf, got {det:?}");
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].field.name.as_deref(), Some("args[0]"));
}

#[test]
fn array_escaped_brackets_are_literal_field() {
    // `args\[0\]` is a literal field name (escaped brackets), not index 0; it
    // must parse as a plain item, keeping the escape in the stored field name.
    let det = parse_selection("    selection:\n        args\\[0\\]: \"cmd.exe\"\n");
    let Detection::AllOf(items) = det else {
        panic!("expected AllOf, got {det:?}");
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].field.name.as_deref(), Some("args\\[0\\]"));
}

#[test]
fn array_negative_index_is_plain_field() {
    // `args[-1]: x` keeps the negative index marker in the literal field path.
    let det = parse_selection("    selection:\n        args[-1]: \"-enc\"\n");
    let Detection::AllOf(items) = det else {
        panic!("expected AllOf, got {det:?}");
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].field.name.as_deref(), Some("args[-1]"));
}

#[test]
fn array_positional_index_with_modifier_and_dotted_path() {
    let det = parse_selection("    selection:\n        connections[0].ip|cidr: \"10.0.0.0/8\"\n");
    let Detection::AllOf(items) = det else {
        panic!("expected AllOf, got {det:?}");
    };
    assert_eq!(items[0].field.name.as_deref(), Some("connections[0].ip"));
    assert_eq!(items[0].field.modifiers, vec![Modifier::Cidr]);
}

#[test]
fn array_positional_index_block_expands_under_prefix() {
    // `connections[0]:` with a map ANDs the items under the indexed path.
    let det = parse_selection(
        "    selection:\n        connections[0]:\n            protocol: \"TCP\"\n            ip: \"10.0.0.1\"\n",
    );
    let Detection::AllOf(items) = det else {
        panic!("expected AllOf, got {det:?}");
    };
    let names: Vec<Option<&str>> = items.iter().map(|i| i.field.name.as_deref()).collect();
    assert!(
        names.contains(&Some("connections[0].protocol")),
        "{names:?}"
    );
    assert!(names.contains(&Some("connections[0].ip")), "{names:?}");
}

#[test]
fn array_index_inside_quantifier_block() {
    // `rules[any].ip[0]` -> ArrayMatch over rules, body item field "ip[0]".
    let det = parse_selection("    selection:\n        rules[any].ip[0]: \"10.0.0.1\"\n");
    let Detection::ArrayMatch { field, body, .. } = det else {
        panic!("expected ArrayMatch, got {det:?}");
    };
    assert_eq!(field, "rules");
    let Detection::AllOf(items) = *body else {
        panic!("expected AllOf body");
    };
    assert_eq!(items[0].field.name.as_deref(), Some("ip[0]"));
}

#[test]
fn array_unknown_selector_is_error() {
    let yaml = "title: T\nsigma-version: 3\nlogsource:\n    category: test\ndetection:\n    selection:\n        connections[oops]: \"x\"\n    condition: selection\n";
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.rules.is_empty());
    assert!(
        collection
            .diagnostics
            .iter()
            .any(|e| e.message.contains("unknown array selector")),
        "got: {:?}",
        collection.diagnostics
    );
}

#[test]
fn plain_dotted_field_is_unchanged() {
    // No quantifier: behavior must be identical to before (a plain AllOf item
    // with the full dotted name).
    let det = parse_selection("    selection:\n        process.command_line: \"x\"\n");
    let Detection::AllOf(items) = det else {
        panic!("expected AllOf, got {det:?}");
    };
    assert_eq!(items[0].field.name.as_deref(), Some("process.command_line"));
}

#[test]
fn sigma_collection_has_errors_and_error_count_are_consistent() {
    let yaml = r#"
action: repeat
title: Orphan
detection:
    selection:
        Field: value
    condition: selection
"#;
    let c = parse_sigma_yaml(yaml).unwrap();
    assert!(c.has_errors());
    assert_eq!(c.error_count(), 1);
    assert_eq!(c.warning_count(), 0);
    let diagnostic = &c.diagnostics[0];
    assert_eq!(diagnostic.kind, DiagnosticKind::CollectionAction);
    assert_eq!(diagnostic.severity, DiagnosticSeverity::Error);
    assert_eq!(
        diagnostic.to_string(),
        "'action: repeat' without a previous document"
    );
}

#[test]
fn sigma_collection_into_result_promotes_errors_to_err() {
    let yaml = r#"
action: repeat
title: Orphan
detection:
    selection:
        Field: value
    condition: selection
"#;
    let c = parse_sigma_yaml(yaml).unwrap();
    match c.into_result() {
        Ok(_) => panic!("collection with errors must surface as Err"),
        Err(errors) => {
            assert_eq!(errors.len(), 1);
            assert!(errors[0].message.contains("without a previous document"));
        }
    }
}

const WARNING_ONLY: &str = r#"
title: Bogus status
logsource:
    product: test
status: bogus
level: cataclysmic
detection:
    selection:
        Field: value
    condition: selection
"#;

#[test]
fn warnings_do_not_count_as_errors() {
    let c = parse_sigma_yaml(WARNING_ONLY).unwrap();
    assert_eq!(c.rules.len(), 1);
    assert!(!c.has_errors());
    assert_eq!(c.error_count(), 0);
    assert_eq!(c.warning_count(), 2);
    assert!(
        c.warnings().all(
            |w| w.kind == DiagnosticKind::Metadata && w.severity == DiagnosticSeverity::Warning
        )
    );
    let c = c.into_result().expect("warnings alone are not a failure");
    assert_eq!(c.diagnostics.len(), 2, "warnings stay on the collection");
}

#[test]
fn into_result_returns_warnings_with_errors() {
    let yaml = format!(
        "{WARNING_ONLY}---
action: bogus
"
    );
    let errors = parse_sigma_yaml(&yaml).unwrap().into_result().unwrap_err();
    let severities: Vec<_> = errors.iter().map(|d| d.severity).collect();
    assert_eq!(
        severities,
        [
            DiagnosticSeverity::Warning,
            DiagnosticSeverity::Warning,
            DiagnosticSeverity::Error,
        ]
    );
}

#[test]
fn diagnostics_keep_today_strings() {
    let yaml = r#"
title: Bad condition
logsource:
    product: test
detection:
    selection:
        Field: value
    condition: selection and
---
- not a mapping
---
action: 3
---
title: Missing condition
logsource:
    product: test
detection:
    selection:
        Field: value
"#;
    let c = parse_sigma_yaml(yaml).unwrap();
    let messages: Vec<String> = c.diagnostics.iter().map(ToString::to_string).collect();
    let condition_error = parse_condition("selection and").unwrap_err().to_string();
    assert_eq!(messages[0], condition_error);
    assert_eq!(messages[1], "Document is not a YAML mapping");
    assert_eq!(
        messages[2],
        "collection 'action' must be a string, got: Number(3)"
    );
    assert_eq!(messages[3], "Missing required field 'condition'");
    assert_eq!(c.error_count(), 4);
}

#[test]
fn diagnostics_record_kind_document_and_location() {
    let yaml = r#"
title: Good
logsource:
    product: test
detection:
    selection:
        Field: value
    condition: selection
---
title: Bad condition
logsource:
    product: test
detection:
    selection:
        Field: value
    condition: selection and
---
- not a mapping
"#;
    let c = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(c.rules.len(), 1, "the good document survives");
    let [condition, mapping] = c.diagnostics.as_slice() else {
        panic!("expected two diagnostics: {:?}", c.diagnostics);
    };
    assert_eq!(
        condition.kind,
        DiagnosticKind::Document(SigmaParserErrorKind::Condition)
    );
    assert_eq!(condition.document, Some(1));
    assert!(condition.location.is_some(), "{condition:?}");
    assert_eq!(condition.path, None);
    assert_eq!(mapping.kind, DiagnosticKind::NotAMapping);
    assert_eq!(mapping.document, Some(2));
}

#[test]
fn yaml_syntax_error_has_location() {
    let c = parse_sigma_yaml(
        "title: ok
---
title: [unterminated
",
    )
    .unwrap();
    let diagnostic = c.diagnostics.last().unwrap();
    assert_eq!(diagnostic.kind, DiagnosticKind::YamlSyntax);
    assert_eq!(diagnostic.document, Some(1));
    assert!(diagnostic.message.starts_with("YAML parse error: "));
    assert!(diagnostic.location.is_some(), "{diagnostic:?}");
}

#[test]
fn directory_diagnostics_carry_file_paths() {
    let dir = tempfile::tempdir().unwrap();
    let warn = dir.path().join("warn.yml");
    std::fs::write(&warn, WARNING_ONLY).unwrap();
    let bad = dir.path().join("bad.yml");
    let good_then_bad = r#"
title: Good
logsource:
    product: test
detection:
    selection:
        Field: value
    condition: selection
---
action: bogus
"#;
    std::fs::write(&bad, good_then_bad).unwrap();

    let c = parse_sigma_directory(dir.path()).unwrap();
    assert_eq!(c.rules.len(), 2);
    assert_eq!(c.error_count(), 1, "{:?}", c.diagnostics);
    assert_eq!(c.warning_count(), 2);
    for diagnostic in c.warnings() {
        assert_eq!(diagnostic.path.as_deref(), Some(warn.as_path()));
        assert_eq!(diagnostic.document, Some(0));
    }
    let error = c.errors().next().unwrap();
    assert_eq!(error.path.as_deref(), Some(bad.as_path()));
    assert_eq!(error.document, Some(1));
}

#[test]
fn parse_surfaces_invalid_status_value() {
    let yaml = r#"
title: Bogus status
logsource:
    product: test
status: bogus
detection:
    selection:
        Field: value
    condition: selection
"#;
    let c = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(c.rules.len(), 1, "rule should still be accepted");
    assert!(c.rules[0].status.is_none(), "invalid status must be None");
    assert!(
        c.diagnostics
            .iter()
            .any(|e| e.message.contains("invalid status") && e.message.contains("'bogus'")),
        "warning should mention invalid status; got {:?}",
        c.diagnostics
    );
}

#[test]
fn parse_surfaces_invalid_level_value() {
    let yaml = r#"
title: Bogus level
logsource:
    product: test
level: cataclysmic
detection:
    selection:
        Field: value
    condition: selection
"#;
    let c = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(c.rules.len(), 1);
    assert!(c.rules[0].level.is_none());
    assert!(
        c.diagnostics
            .iter()
            .any(|e| e.message.contains("invalid level") && e.message.contains("'cataclysmic'")),
        "warning should mention invalid level; got {:?}",
        c.diagnostics
    );
}

#[test]
fn parse_surfaces_invalid_related_entries() {
    // Three intentional defects: a non-mapping entry, a missing
    // `id`, and an unknown `type`. The valid trailing entry must
    // still survive so a partial parse remains useful.
    let yaml = r#"
title: Mixed related
logsource:
    product: test
related:
    - "not-a-mapping"
    - type: derived
    - id: 11111111-2222-3333-4444-555555555555
      type: derved
    - id: 99999999-8888-7777-6666-555555555555
      type: derived
detection:
    selection:
        Field: value
    condition: selection
"#;
    let c = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(c.rules.len(), 1);
    let related = &c.rules[0].related;
    assert_eq!(
        related.len(),
        1,
        "only the well-formed related entry should be retained"
    );

    let errs = &c.diagnostics;
    assert!(
        errs.iter()
            .any(|e| e.message.contains("related[0]") && e.message.contains("not a mapping")),
        "should warn about the string entry; got {errs:?}"
    );
    assert!(
        errs.iter()
            .any(|e| e.message.contains("related[1]") && e.message.contains("missing 'id'")),
        "should warn about the missing id; got {errs:?}"
    );
    assert!(
        errs.iter().any(
            |e| e.message.contains("related[2]") && e.message.contains("invalid type 'derved'")
        ),
        "should warn about the unknown type; got {errs:?}"
    );
}

#[test]
fn parse_surfaces_invalid_related_top_level_shape() {
    let yaml = r#"
title: Wrong-shape related
logsource:
    product: test
related: "should be a sequence"
detection:
    selection:
        Field: value
    condition: selection
"#;
    let c = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(c.rules.len(), 1);
    assert!(c.rules[0].related.is_empty());
    assert!(
        c.diagnostics
            .iter()
            .any(|e| e.message.contains("'related' must be a sequence")),
        "should warn about the wrong-shape related field; got {:?}",
        c.diagnostics
    );
}

#[test]
fn sigma_collection_into_result_returns_ok_when_clean() {
    let yaml = r#"
title: Clean Rule
logsource:
    product: test
detection:
    selection:
        Field: value
    condition: selection
"#;
    let c = parse_sigma_yaml(yaml).unwrap();
    let promoted = c
        .into_result()
        .expect("clean collection should round-trip through into_result");
    assert_eq!(promoted.rules.len(), 1);
    assert!(!promoted.has_errors());
}

#[test]
fn correlation_condition_rules_are_derived_in_first_appearance_order() {
    let yaml = r#"
title: Derived
correlation:
    type: temporal
    group-by: [User]
    timespan: 5m
    condition: b and not a or c
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(
        collection.diagnostics.is_empty(),
        "{:?}",
        collection.diagnostics
    );
    assert_eq!(collection.correlations[0].rules, ["b", "a", "c"]);
}

#[test]
fn correlation_condition_duplicate_identifiers_are_deduplicated() {
    let yaml = r#"
title: Duplicate
correlation:
    type: temporal
    group-by: [User]
    timespan: 5m
    condition: a and a
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.correlations[0].rules, ["a"]);
}

#[test]
fn correlation_explicit_empty_rules_is_kept() {
    let yaml = r#"
title: Empty
correlation:
    type: event_count
    rules: []
    group-by: [User]
    timespan: 5m
    condition:
        gte: 1
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.correlations[0].rules.is_empty());
}

#[test]
fn correlation_selector_condition_without_rules_is_an_error() {
    let yaml = r#"
title: Selector
correlation:
    type: temporal
    group-by: [User]
    timespan: 5m
    condition: 1 of login_*
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.correlations.is_empty());
    assert!(
        collection.diagnostics.iter().any(|d| d
            .message
            .contains("rules is required when the condition uses a selector")),
        "{:?}",
        collection.diagnostics
    );
}

#[test]
fn correlation_condition_identifier_must_be_listed_in_rules() {
    for condition in ["a and b", "a and not b"] {
        let yaml = format!(
            r#"
title: Missing
correlation:
    type: temporal
    rules: [a]
    group-by: [User]
    timespan: 5m
    condition: {condition}
"#
        );
        let collection = parse_sigma_yaml(&yaml).unwrap();
        assert!(collection.correlations.is_empty(), "{condition}");
        assert!(
            collection.diagnostics.iter().any(|d| d
                .message
                .contains("condition references 'b', which is not in correlation.rules")),
            "{condition}: {:?}",
            collection.diagnostics
        );
    }
}

#[test]
fn correlation_threshold_condition_is_unaffected() {
    let yaml = r#"
title: Threshold
correlation:
    type: event_count
    rules: [a]
    group-by: [User]
    timespan: 5m
    condition:
        gte: 3
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(collection.diagnostics.is_empty());
    assert_eq!(collection.correlations[0].rules, ["a"]);
}
