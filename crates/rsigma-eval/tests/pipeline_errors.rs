mod helpers;

use rsigma_eval::{Engine, EvalError, parse_pipeline};
use rsigma_parser::parse_sigma_yaml;

#[test]
fn replace_string_with_invalid_regex_fails_at_rule_compilation() {
    // Pipeline parses fine, but the regex is invalid. The error surfaces
    // when the pipeline is applied to a rule during add_collection.
    let pipeline_yaml = r#"
name: Bad Replace
transformations:
  - type: replace_string
    regex: "[unclosed"
    replacement: "fixed"
"#;
    let pipeline = parse_pipeline(pipeline_yaml).unwrap();

    let rule_yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: test
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(rule_yaml).unwrap();
    let mut engine = Engine::new_with_pipeline(pipeline);
    let err = engine.add_collection(&collection).unwrap_err();
    assert!(
        matches!(err, EvalError::InvalidModifiers(ref s) if s.contains("bad regex")),
        "expected InvalidModifiers with bad regex message, got: {err}"
    );
}

#[test]
fn drop_detection_item_removing_all_items_fails_at_compilation() {
    // Pipeline drops ALL detection items (no conditions = match everything).
    // The resulting empty detection triggers InvalidModifiers at compile time.
    let pipeline_yaml = r#"
name: Drop Everything
transformations:
  - type: drop_detection_item
"#;
    let pipeline = parse_pipeline(pipeline_yaml).unwrap();

    let rule_yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: test
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(rule_yaml).unwrap();
    let mut engine = Engine::new_with_pipeline(pipeline);
    let err = engine.add_collection(&collection).unwrap_err();
    assert!(
        matches!(err, EvalError::InvalidModifiers(_)),
        "expected InvalidModifiers for empty detection, got: {err}"
    );
}

#[test]
fn unknown_transformation_type_names_the_type() {
    let pipeline_yaml = r#"
name: Bad Pipeline
transformations:
  - type: frobnicate
"#;
    let err = parse_pipeline(pipeline_yaml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("frobnicate"),
        "error should name the unknown type, got: {msg}"
    );
}

#[test]
fn unknown_rule_condition_type_fails_at_parse_time() {
    let pipeline_yaml = r#"
name: Bad Conditions
transformations:
  - type: field_name_mapping
    mapping:
      A: B
    rule_conditions:
      - type: nonexistent_condition_type
"#;
    let err = parse_pipeline(pipeline_yaml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("nonexistent_condition_type"),
        "error should name the unknown condition type, got: {msg}"
    );
}
