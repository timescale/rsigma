use super::*;
use crate::event::JsonEvent;
use rsigma_parser::FieldSpec;
use serde_json::json;

fn make_field_spec(name: &str, modifiers: &[Modifier]) -> FieldSpec {
    FieldSpec::new(Some(name.to_string()), modifiers.to_vec())
}

fn make_item(name: &str, modifiers: &[Modifier], values: Vec<SigmaValue>) -> DetectionItem {
    DetectionItem {
        field: make_field_spec(name, modifiers),
        values,
    }
}

#[test]
fn test_compile_exact_match() {
    let item = make_item(
        "CommandLine",
        &[],
        vec![SigmaValue::String(SigmaString::new("whoami"))],
    );
    let compiled = compile_detection_item(&item).unwrap();
    assert_eq!(compiled.field, Some("CommandLine".into()));

    let ev = json!({"CommandLine": "whoami"});
    let event = JsonEvent::borrow(&ev);
    assert!(eval_detection_item(&compiled, &event));

    let ev2 = json!({"CommandLine": "WHOAMI"});
    let event2 = JsonEvent::borrow(&ev2);
    assert!(eval_detection_item(&compiled, &event2)); // case-insensitive
}

#[test]
fn test_compile_contains() {
    let item = make_item(
        "CommandLine",
        &[Modifier::Contains],
        vec![SigmaValue::String(SigmaString::new("whoami"))],
    );
    let compiled = compile_detection_item(&item).unwrap();

    let ev = json!({"CommandLine": "cmd /c whoami /all"});
    let event = JsonEvent::borrow(&ev);
    assert!(eval_detection_item(&compiled, &event));

    let ev2 = json!({"CommandLine": "ipconfig"});
    let event2 = JsonEvent::borrow(&ev2);
    assert!(!eval_detection_item(&compiled, &event2));
}

#[test]
fn test_compile_endswith() {
    let item = make_item(
        "Image",
        &[Modifier::EndsWith],
        vec![SigmaValue::String(SigmaString::new(".exe"))],
    );
    let compiled = compile_detection_item(&item).unwrap();

    let ev = json!({"Image": "C:\\Windows\\cmd.exe"});
    let event = JsonEvent::borrow(&ev);
    assert!(eval_detection_item(&compiled, &event));

    let ev2 = json!({"Image": "C:\\Windows\\cmd.bat"});
    let event2 = JsonEvent::borrow(&ev2);
    assert!(!eval_detection_item(&compiled, &event2));
}

#[test]
fn test_compile_contains_all() {
    let item = make_item(
        "CommandLine",
        &[Modifier::Contains, Modifier::All],
        vec![
            SigmaValue::String(SigmaString::new("net")),
            SigmaValue::String(SigmaString::new("user")),
        ],
    );
    let compiled = compile_detection_item(&item).unwrap();

    let ev = json!({"CommandLine": "net user admin"});
    let event = JsonEvent::borrow(&ev);
    assert!(eval_detection_item(&compiled, &event));

    let ev2 = json!({"CommandLine": "net localgroup"});
    let event2 = JsonEvent::borrow(&ev2);
    assert!(!eval_detection_item(&compiled, &event2)); // missing "user"
}

#[test]
fn test_all_modifier_single_value_rejected() {
    let item = make_item(
        "CommandLine",
        &[Modifier::Contains, Modifier::All],
        vec![SigmaValue::String(SigmaString::new("net"))],
    );
    let result = compile_detection_item(&item);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("|all modifier requires more than one value"));
}

#[test]
fn test_all_modifier_empty_values_rejected() {
    let item = make_item("CommandLine", &[Modifier::Contains, Modifier::All], vec![]);
    let result = compile_detection_item(&item);
    assert!(result.is_err());
}

#[test]
fn test_all_modifier_multiple_values_accepted() {
    // Two values with |all is valid
    let item = make_item(
        "CommandLine",
        &[Modifier::Contains, Modifier::All],
        vec![
            SigmaValue::String(SigmaString::new("net")),
            SigmaValue::String(SigmaString::new("user")),
        ],
    );
    assert!(compile_detection_item(&item).is_ok());
}

#[test]
fn test_compile_regex() {
    let item = make_item(
        "CommandLine",
        &[Modifier::Re],
        vec![SigmaValue::String(SigmaString::from_raw(r"cmd\.exe.*/c"))],
    );
    let compiled = compile_detection_item(&item).unwrap();

    let ev = json!({"CommandLine": "cmd.exe /c whoami"});
    let event = JsonEvent::borrow(&ev);
    assert!(eval_detection_item(&compiled, &event));
}

#[test]
fn test_regex_case_sensitive_by_default() {
    // Sigma spec: "|re" is case-sensitive by default
    let item = make_item(
        "User",
        &[Modifier::Re],
        vec![SigmaValue::String(SigmaString::from_raw("Admin"))],
    );
    let compiled = compile_detection_item(&item).unwrap();

    let ev_match = json!({"User": "Admin"});
    assert!(eval_detection_item(
        &compiled,
        &JsonEvent::borrow(&ev_match)
    ));

    let ev_no_match = json!({"User": "admin"});
    assert!(!eval_detection_item(
        &compiled,
        &JsonEvent::borrow(&ev_no_match)
    ));
}

#[test]
fn test_regex_case_insensitive_with_i_modifier() {
    // |re|i enables case-insensitive matching
    let item = make_item(
        "User",
        &[Modifier::Re, Modifier::IgnoreCase],
        vec![SigmaValue::String(SigmaString::from_raw("Admin"))],
    );
    let compiled = compile_detection_item(&item).unwrap();

    let ev_exact = json!({"User": "Admin"});
    assert!(eval_detection_item(
        &compiled,
        &JsonEvent::borrow(&ev_exact)
    ));

    let ev_lower = json!({"User": "admin"});
    assert!(eval_detection_item(
        &compiled,
        &JsonEvent::borrow(&ev_lower)
    ));
}

#[test]
fn test_compile_cidr() {
    let item = make_item(
        "SourceIP",
        &[Modifier::Cidr],
        vec![SigmaValue::String(SigmaString::new("10.0.0.0/8"))],
    );
    let compiled = compile_detection_item(&item).unwrap();

    let ev = json!({"SourceIP": "10.1.2.3"});
    let event = JsonEvent::borrow(&ev);
    assert!(eval_detection_item(&compiled, &event));

    let ev2 = json!({"SourceIP": "192.168.1.1"});
    let event2 = JsonEvent::borrow(&ev2);
    assert!(!eval_detection_item(&compiled, &event2));
}

#[test]
fn test_compile_exists() {
    let item = make_item(
        "SomeField",
        &[Modifier::Exists],
        vec![SigmaValue::Bool(true)],
    );
    let compiled = compile_detection_item(&item).unwrap();

    let ev = json!({"SomeField": "value"});
    let event = JsonEvent::borrow(&ev);
    assert!(eval_detection_item(&compiled, &event));

    let ev2 = json!({"OtherField": "value"});
    let event2 = JsonEvent::borrow(&ev2);
    assert!(!eval_detection_item(&compiled, &event2));
}

#[test]
fn test_compile_wildcard() {
    let item = make_item(
        "Image",
        &[],
        vec![SigmaValue::String(SigmaString::new(r"*\cmd.exe"))],
    );
    let compiled = compile_detection_item(&item).unwrap();

    let ev = json!({"Image": "C:\\Windows\\System32\\cmd.exe"});
    let event = JsonEvent::borrow(&ev);
    assert!(eval_detection_item(&compiled, &event));

    let ev2 = json!({"Image": "C:\\Windows\\powershell.exe"});
    let event2 = JsonEvent::borrow(&ev2);
    assert!(!eval_detection_item(&compiled, &event2));
}

#[test]
fn test_compile_numeric_comparison() {
    let item = make_item("EventID", &[Modifier::Gte], vec![SigmaValue::Integer(4688)]);
    let compiled = compile_detection_item(&item).unwrap();

    let ev = json!({"EventID": 4688});
    let event = JsonEvent::borrow(&ev);
    assert!(eval_detection_item(&compiled, &event));

    let ev2 = json!({"EventID": 1000});
    let event2 = JsonEvent::borrow(&ev2);
    assert!(!eval_detection_item(&compiled, &event2));
}

#[test]
fn test_windash_expansion() {
    // Two dashes → 5^2 = 25 variants
    let variants = expand_windash("-param -value").unwrap();
    assert_eq!(variants.len(), 25);
    // Original and slash variants
    assert!(variants.contains(&"-param -value".to_string()));
    assert!(variants.contains(&"/param -value".to_string()));
    assert!(variants.contains(&"-param /value".to_string()));
    assert!(variants.contains(&"/param /value".to_string()));
    // En dash (U+2013)
    assert!(variants.contains(&"\u{2013}param \u{2013}value".to_string()));
    // Em dash (U+2014)
    assert!(variants.contains(&"\u{2014}param \u{2014}value".to_string()));
    // Horizontal bar (U+2015)
    assert!(variants.contains(&"\u{2015}param \u{2015}value".to_string()));
    // Mixed: slash + en dash
    assert!(variants.contains(&"/param \u{2013}value".to_string()));
}

#[test]
fn test_windash_no_dash() {
    let variants = expand_windash("nodash").unwrap();
    assert_eq!(variants.len(), 1);
    assert_eq!(variants[0], "nodash");
}

#[test]
fn test_windash_single_dash() {
    // One dash → 5 variants
    let variants = expand_windash("-v").unwrap();
    assert_eq!(variants.len(), 5);
    assert!(variants.contains(&"-v".to_string()));
    assert!(variants.contains(&"/v".to_string()));
    assert!(variants.contains(&"\u{2013}v".to_string()));
    assert!(variants.contains(&"\u{2014}v".to_string()));
    assert!(variants.contains(&"\u{2015}v".to_string()));
}

#[test]
fn test_base64_offset_patterns() {
    let patterns = base64_offset_patterns(b"Test");
    assert!(!patterns.is_empty());
    // The first pattern should be the normal base64 encoding of "Test"
    assert!(
        patterns
            .iter()
            .any(|p| p.contains("VGVzdA") || p.contains("Rlc3"))
    );
}

#[test]
fn test_pattern_matches() {
    assert!(pattern_matches("selection_*", "selection_main"));
    assert!(pattern_matches("selection_*", "selection_"));
    assert!(!pattern_matches("selection_*", "filter_main"));
    assert!(pattern_matches("*", "anything"));
    assert!(pattern_matches("*_filter", "my_filter"));
    assert!(pattern_matches("exact", "exact"));
    assert!(!pattern_matches("exact", "other"));
}

#[test]
fn test_eval_condition_and() {
    let items_sel = vec![make_item(
        "CommandLine",
        &[Modifier::Contains],
        vec![SigmaValue::String(SigmaString::new("whoami"))],
    )];
    let items_filter = vec![make_item(
        "User",
        &[],
        vec![SigmaValue::String(SigmaString::new("SYSTEM"))],
    )];

    let mut detections = HashMap::new();
    detections.insert(
        "selection".into(),
        compile_detection(&Detection::AllOf(items_sel)).unwrap(),
    );
    detections.insert(
        "filter".into(),
        compile_detection(&Detection::AllOf(items_filter)).unwrap(),
    );

    let cond = ConditionExpr::And(vec![
        ConditionExpr::Identifier("selection".into()),
        ConditionExpr::Not(Box::new(ConditionExpr::Identifier("filter".into()))),
    ]);

    let ev = json!({"CommandLine": "whoami", "User": "admin"});
    let event = JsonEvent::borrow(&ev);
    let mut matched = Vec::new();
    assert!(eval_condition(&cond, &detections, &event, &mut matched));

    let ev2 = json!({"CommandLine": "whoami", "User": "SYSTEM"});
    let event2 = JsonEvent::borrow(&ev2);
    let mut matched2 = Vec::new();
    assert!(!eval_condition(&cond, &detections, &event2, &mut matched2));
}

#[test]
fn test_compile_expand_modifier() {
    let items = vec![make_item(
        "path",
        &[Modifier::Expand],
        vec![SigmaValue::String(SigmaString::new(
            "C:\\Users\\%username%\\Downloads",
        ))],
    )];
    let detection = compile_detection(&Detection::AllOf(items)).unwrap();

    let mut detections = HashMap::new();
    detections.insert("selection".into(), detection);

    let cond = ConditionExpr::Identifier("selection".into());

    // Match: field matches after placeholder resolution
    let ev = json!({
        "path": "C:\\Users\\admin\\Downloads",
        "username": "admin"
    });
    let event = JsonEvent::borrow(&ev);
    let mut matched = Vec::new();
    assert!(eval_condition(&cond, &detections, &event, &mut matched));

    // No match: different user
    let ev2 = json!({
        "path": "C:\\Users\\admin\\Downloads",
        "username": "guest"
    });
    let event2 = JsonEvent::borrow(&ev2);
    let mut matched2 = Vec::new();
    assert!(!eval_condition(&cond, &detections, &event2, &mut matched2));
}

#[test]
fn test_compile_timestamp_hour_modifier() {
    let items = vec![make_item(
        "timestamp",
        &[Modifier::Hour],
        vec![SigmaValue::Integer(3)],
    )];
    let detection = compile_detection(&Detection::AllOf(items)).unwrap();

    let mut detections = HashMap::new();
    detections.insert("selection".into(), detection);

    let cond = ConditionExpr::Identifier("selection".into());

    // Match: timestamp at 03:xx UTC
    let ev = json!({"timestamp": "2024-07-10T03:30:00Z"});
    let event = JsonEvent::borrow(&ev);
    let mut matched = Vec::new();
    assert!(eval_condition(&cond, &detections, &event, &mut matched));

    // No match: timestamp at 12:xx UTC
    let ev2 = json!({"timestamp": "2024-07-10T12:30:00Z"});
    let event2 = JsonEvent::borrow(&ev2);
    let mut matched2 = Vec::new();
    assert!(!eval_condition(&cond, &detections, &event2, &mut matched2));
}

#[test]
fn test_compile_timestamp_month_modifier() {
    let items = vec![make_item(
        "created",
        &[Modifier::Month],
        vec![SigmaValue::Integer(12)],
    )];
    let detection = compile_detection(&Detection::AllOf(items)).unwrap();

    let mut detections = HashMap::new();
    detections.insert("selection".into(), detection);

    let cond = ConditionExpr::Identifier("selection".into());

    // Match: December
    let ev = json!({"created": "2024-12-25T10:00:00Z"});
    let event = JsonEvent::borrow(&ev);
    let mut matched = Vec::new();
    assert!(eval_condition(&cond, &detections, &event, &mut matched));

    // No match: July
    let ev2 = json!({"created": "2024-07-10T10:00:00Z"});
    let event2 = JsonEvent::borrow(&ev2);
    let mut matched2 = Vec::new();
    assert!(!eval_condition(&cond, &detections, &event2, &mut matched2));
}

fn make_test_sigma_rule(
    title: &str,
    custom_attributes: HashMap<String, serde_yaml::Value>,
) -> SigmaRule {
    use rsigma_parser::{Detections, LogSource};
    SigmaRule {
        title: title.to_string(),
        id: Some("test-id".to_string()),
        name: None,
        related: vec![],
        taxonomy: None,
        status: None,
        level: Some(Level::Medium),
        description: None,
        license: None,
        author: None,
        references: vec![],
        date: None,
        modified: None,
        tags: vec![],
        scope: vec![],
        logsource: LogSource {
            category: Some("test".to_string()),
            product: None,
            service: None,
            definition: None,
            custom: HashMap::new(),
        },
        detection: Detections {
            named: {
                let mut m = HashMap::new();
                m.insert(
                    "selection".to_string(),
                    Detection::AllOf(vec![make_item(
                        "action",
                        &[],
                        vec![SigmaValue::String(SigmaString::new("login"))],
                    )]),
                );
                m
            },
            conditions: vec![ConditionExpr::Identifier("selection".to_string())],
            condition_strings: vec!["selection".to_string()],
            timeframe: None,
        },
        fields: vec![],
        falsepositives: vec![],
        custom_attributes,
    }
}

#[test]
fn test_include_event_custom_attribute() {
    let mut attrs = HashMap::new();
    attrs.insert(
        "rsigma.include_event".to_string(),
        serde_yaml::Value::String("true".to_string()),
    );
    let rule = make_test_sigma_rule("Include Event Test", attrs);

    let compiled = compile_rule(&rule).unwrap();
    assert!(compiled.include_event);

    let ev = json!({"action": "login", "user": "alice"});
    let event = JsonEvent::borrow(&ev);
    let result = evaluate_rule(&compiled, &event).unwrap();
    assert!(result.event.is_some());
    assert_eq!(result.event.unwrap(), ev);
}

#[test]
fn test_no_include_event_by_default() {
    let rule = make_test_sigma_rule("No Include Event Test", HashMap::new());

    let compiled = compile_rule(&rule).unwrap();
    assert!(!compiled.include_event);

    let ev = json!({"action": "login", "user": "alice"});
    let event = JsonEvent::borrow(&ev);
    let result = evaluate_rule(&compiled, &event).unwrap();
    assert!(result.event.is_none());
}

#[test]
fn test_custom_attributes_propagate_to_match_result() {
    let yaml = r#"
title: Rule With Custom Attrs
logsource:
    category: test
detection:
    selection:
        action: login
    condition: selection
level: medium
my_custom_field: some_value
severity_score: 42
"#;
    let collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();
    let rule = &collection.rules[0];

    let compiled = compile_rule(rule).unwrap();

    assert_eq!(
        compiled.custom_attributes.get("my_custom_field"),
        Some(&serde_json::Value::String("some_value".to_string()))
    );
    assert_eq!(
        compiled.custom_attributes.get("severity_score"),
        Some(&serde_json::json!(42))
    );

    assert!(!compiled.custom_attributes.contains_key("title"));
    assert!(!compiled.custom_attributes.contains_key("level"));

    let ev = json!({"action": "login"});
    let event = JsonEvent::borrow(&ev);
    let result = evaluate_rule(&compiled, &event).unwrap();

    assert_eq!(
        result.custom_attributes.get("my_custom_field"),
        Some(&serde_json::Value::String("some_value".to_string()))
    );
    assert_eq!(
        result.custom_attributes.get("severity_score"),
        Some(&serde_json::json!(42))
    );
}

#[test]
fn test_empty_custom_attributes() {
    let rule = make_test_sigma_rule("No Custom Attrs", HashMap::new());
    let compiled = compile_rule(&rule).unwrap();
    assert!(compiled.custom_attributes.is_empty());

    let ev = json!({"action": "login"});
    let event = JsonEvent::borrow(&ev);
    let result = evaluate_rule(&compiled, &event).unwrap();
    assert!(result.custom_attributes.is_empty());
}

#[test]
fn test_pipeline_set_custom_attribute_overrides_rule_yaml() {
    // The YAML sets `rsigma.include_event: false`; the pipeline then writes
    // "true" via `SetCustomAttribute` -- last-write-wins.
    let yaml = r#"
title: Override Test
logsource:
    category: test
detection:
    selection:
        action: login
    condition: selection
level: low
custom_attributes:
    rsigma.include_event: "false"
"#;
    let pipeline_yaml = r#"
name: override
transformations:
  - type: set_custom_attribute
    attribute: rsigma.include_event
    value: "true"
"#;
    let collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();
    let mut rule = collection.rules[0].clone();
    let pipeline = crate::pipeline::parse_pipeline(pipeline_yaml).unwrap();
    crate::pipeline::apply_pipelines(&[pipeline], &mut rule).unwrap();

    assert_eq!(
        rule.custom_attributes
            .get("rsigma.include_event")
            .and_then(|v| v.as_str()),
        Some("true")
    );

    let compiled = compile_rule(&rule).unwrap();
    assert!(compiled.include_event);
}

// =============================================================================
// Property-based tests
// =============================================================================

mod proptests {
    use super::*;
    use proptest::prelude::*;

    // -------------------------------------------------------------------------
    // 1. Windash expansion: count is always 5^n for n dashes
    // -------------------------------------------------------------------------
    proptest! {
        #[test]
        fn windash_count_is_5_pow_n(
            // Generate a string with 0-3 dashes embedded in alphabetic text
            prefix in "[a-z]{0,5}",
            dashes in prop::collection::vec(Just('-'), 0..=3),
            suffix in "[a-z]{0,5}",
        ) {
            let mut input = prefix;
            for d in &dashes {
                input.push(*d);
            }
            input.push_str(&suffix);

            let n = input.chars().filter(|c| *c == '-').count();
            let variants = expand_windash(&input).unwrap();
            let expected = 5usize.pow(n as u32);
            prop_assert_eq!(variants.len(), expected,
                "expand_windash({:?}) should produce {} variants, got {}",
                input, expected, variants.len());
        }
    }

    // -------------------------------------------------------------------------
    // 2. Windash expansion: no duplicates
    // -------------------------------------------------------------------------
    proptest! {
        #[test]
        fn windash_no_duplicates(
            prefix in "[a-z]{0,4}",
            dashes in prop::collection::vec(Just('-'), 0..=2),
            suffix in "[a-z]{0,4}",
        ) {
            let mut input = prefix;
            for d in &dashes {
                input.push(*d);
            }
            input.push_str(&suffix);

            let variants = expand_windash(&input).unwrap();
            let unique: std::collections::HashSet<&String> = variants.iter().collect();
            prop_assert_eq!(variants.len(), unique.len(),
                "expand_windash({:?}) produced duplicates", input);
        }
    }

    // -------------------------------------------------------------------------
    // 3. Windash expansion: original string is always in the output
    // -------------------------------------------------------------------------
    proptest! {
        #[test]
        fn windash_contains_original(
            prefix in "[a-z]{0,5}",
            dashes in prop::collection::vec(Just('-'), 0..=3),
            suffix in "[a-z]{0,5}",
        ) {
            let mut input = prefix;
            for d in &dashes {
                input.push(*d);
            }
            input.push_str(&suffix);

            let variants = expand_windash(&input).unwrap();
            prop_assert!(variants.contains(&input),
                "expand_windash({:?}) should contain the original", input);
        }
    }

    // -------------------------------------------------------------------------
    // 4. Windash expansion: all variants have same length minus multi-byte diffs
    //    (each dash position gets replaced by a char, non-dash parts stay the same)
    // -------------------------------------------------------------------------
    proptest! {
        #[test]
        fn windash_variants_preserve_non_dash_chars(
            prefix in "[a-z]{1,5}",
            suffix in "[a-z]{1,5}",
        ) {
            let input = format!("{prefix}-{suffix}");
            let variants = expand_windash(&input).unwrap();
            for variant in &variants {
                // The prefix and suffix parts should be preserved
                prop_assert!(variant.starts_with(&prefix),
                    "variant {:?} should start with {:?}", variant, prefix);
                prop_assert!(variant.ends_with(&suffix),
                    "variant {:?} should end with {:?}", variant, suffix);
            }
        }
    }

    // -------------------------------------------------------------------------
    // 5. Windash with no dashes: returns single-element vec with original
    // -------------------------------------------------------------------------
    proptest! {
        #[test]
        fn windash_no_dashes_passthrough(text in "[a-zA-Z0-9]{1,20}") {
            prop_assume!(!text.contains('-'));
            let variants = expand_windash(&text).unwrap();
            prop_assert_eq!(variants.len(), 1);
            prop_assert_eq!(&variants[0], &text);
        }
    }
}
