use rsigma_parser::{SigmaParserError, parse_condition, parse_field_spec, parse_sigma_yaml};

#[test]
fn field_spec_empty_field_name_with_modifier() {
    // "|contains" -- empty field name, valid modifier. Should parse to None field name.
    let spec = parse_field_spec("|contains").unwrap();
    assert!(spec.name.is_none());
    assert_eq!(spec.modifiers.len(), 1);
}

#[test]
fn field_spec_double_pipe_produces_unknown_modifier() {
    // "field||contains" -- splits to ["field", "", "contains"]; empty string is unknown modifier.
    let err = parse_field_spec("field||contains").unwrap_err();
    assert!(
        matches!(err, SigmaParserError::UnknownModifier(ref s) if s.is_empty()),
        "expected UnknownModifier for empty modifier string, got: {err}"
    );
}

#[test]
fn field_spec_trailing_pipe_produces_unknown_modifier() {
    // "field|" -- splits to ["field", ""]; empty string is unknown modifier.
    let err = parse_field_spec("field|").unwrap_err();
    assert!(
        matches!(err, SigmaParserError::UnknownModifier(ref s) if s.is_empty()),
        "expected UnknownModifier for trailing pipe, got: {err}"
    );
}

#[test]
fn condition_trailing_operator_fails_with_location() {
    // "selection and" -- dangling operator at end, should fail with location info.
    let err = parse_condition("selection and").unwrap_err();
    assert!(
        matches!(err, SigmaParserError::Condition(_, _)),
        "expected Condition error, got: {err}"
    );
}

#[test]
fn condition_unmatched_parens_fails() {
    let err = parse_condition("(selection and filter").unwrap_err();
    assert!(
        matches!(err, SigmaParserError::Condition(_, _)),
        "expected Condition error for unmatched paren, got: {err}"
    );
}

#[test]
fn condition_double_operator_fails() {
    let err = parse_condition("selection and or filter").unwrap_err();
    assert!(
        matches!(err, SigmaParserError::Condition(_, _)),
        "expected Condition error for 'and or', got: {err}"
    );
}

#[test]
fn multi_doc_mixed_valid_and_invalid_collects_both() {
    // First doc is a valid rule, second doc is malformed (missing title).
    // The collection should contain the valid rule AND report the error.
    let yaml = r#"
title: Valid Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: test
    condition: selection
level: low
---
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: test
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(
        collection.rules.len(),
        1,
        "first valid rule should be collected"
    );
    assert!(
        collection.has_errors(),
        "second doc's error should be reported"
    );
}

#[test]
fn correlation_missing_type_reports_clear_error() {
    let yaml = r#"
title: Bad Correlation
correlation:
    rules:
        - some-rule
    timespan: 60s
    condition:
        gte: 3
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(
        collection.has_errors(),
        "missing correlation type should produce an error"
    );
    assert!(
        collection.diagnostics[0].message.contains("type"),
        "error message should mention 'type', got: {}",
        collection.diagnostics[0]
    );
}

#[test]
fn correlation_missing_timespan_reports_clear_error() {
    let yaml = r#"
title: Bad Correlation
correlation:
    type: event_count
    rules:
        - some-rule
    condition:
        gte: 3
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(
        collection.has_errors(),
        "missing timespan should produce an error"
    );
    let err = &collection.diagnostics[0].message;
    assert!(
        err.contains("timespan") || err.contains("timeframe"),
        "error should mention timespan/timeframe, got: {err}"
    );
}

#[test]
fn over_deep_rules_are_reported_and_valid_rules_still_load() {
    let not_chain = format!("{}selection", "not ".repeat(16_000));
    let quantifiers: String = (0..5_000).map(|i| format!("a{i}[any].")).collect();
    let yaml = format!(
        "title: Not chain\nlogsource:\n    category: test\ndetection:\n    selection:\n        a: b\n    condition: {not_chain}\n---\n\
         title: Array scopes\nsigma-version: 3\nlogsource:\n    category: test\ndetection:\n    selection:\n        ? {quantifiers}x\n        : 1\n    condition: selection\n---\n\
         title: Valid\nlogsource:\n    category: test\ndetection:\n    selection:\n        a: b\n    condition: selection and not selection\n"
    );
    let collection = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || parse_sigma_yaml(&yaml).unwrap())
        .unwrap()
        .join()
        .unwrap();
    let titles: Vec<&str> = collection.rules.iter().map(|r| r.title.as_str()).collect();
    assert_eq!(titles, ["Valid"]);
    let messages: Vec<&str> = collection
        .diagnostics
        .iter()
        .map(|d| d.message.as_str())
        .collect();
    assert_eq!(messages.len(), 2, "{messages:?}");
    assert!(messages.iter().any(|m| m.contains("maximum depth")));
    assert!(
        messages
            .iter()
            .any(|m| m.contains("array quantifier scopes"))
    );
}
