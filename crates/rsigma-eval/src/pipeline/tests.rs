use std::collections::HashMap;

use rsigma_parser::{CorrelationRule, Modifier, SigmaString, SigmaValue};

use super::*;

#[test]
fn test_parse_simple_pipeline() {
    let yaml = r#"
name: Test Pipeline
priority: 10
transformations:
  - id: map_fields
    type: field_name_mapping
    mapping:
      CommandLine: process.command_line
      ParentImage: process.parent.executable
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert_eq!(pipeline.name, "Test Pipeline");
    assert_eq!(pipeline.priority, 10);
    assert_eq!(pipeline.transformations.len(), 1);
    assert_eq!(
        pipeline.transformations[0].id,
        Some("map_fields".to_string())
    );
}

#[test]
fn test_parse_pipeline_with_conditions() {
    let yaml = r#"
name: Windows Pipeline
priority: 20
transformations:
  - id: sysmon_fields
    type: field_name_mapping
    mapping:
      CommandLine: winlog.event_data.CommandLine
    rule_conditions:
      - type: logsource
        product: windows
        category: process_creation
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert_eq!(pipeline.transformations.len(), 1);
    assert_eq!(
        pipeline.transformations[0].rule_conditions.conditions.len(),
        1
    );
}

#[test]
fn test_parse_pipeline_with_vars() {
    let yaml = r#"
name: Vars Pipeline
vars:
  admin_users:
    - root
    - admin
  log_index: windows-*
transformations: []
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert_eq!(pipeline.vars.len(), 2);
    assert_eq!(
        pipeline.vars["admin_users"],
        vec!["root".to_string(), "admin".to_string()]
    );
    assert_eq!(pipeline.vars["log_index"], vec!["windows-*".to_string()]);
}

#[test]
fn test_parse_pipeline_with_finalizers() {
    let yaml = r#"
name: Output Pipeline
transformations: []
finalizers:
  - type: concat
    separator: " OR "
  - type: json
    indent: 2
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert_eq!(pipeline.finalizers.len(), 2);
}

#[test]
fn test_apply_field_mapping_pipeline() {
    let yaml = r#"
name: Sysmon
transformations:
  - type: field_name_mapping
    mapping:
      CommandLine: process.command_line
    rule_conditions:
      - type: logsource
        product: windows
"#;
    let pipeline = parse_pipeline(yaml).unwrap();

    // Create a rule that matches the condition
    let mut rule = rsigma_parser::SigmaRule {
        sigma_version: None,
        title: "Test".to_string(),
        logsource: rsigma_parser::LogSource {
            product: Some("windows".to_string()),
            category: Some("process_creation".to_string()),
            ..Default::default()
        },
        detection: rsigma_parser::Detections {
            named: {
                let mut m = HashMap::new();
                m.insert(
                    "selection".to_string(),
                    rsigma_parser::Detection::AllOf(vec![rsigma_parser::DetectionItem {
                        field: rsigma_parser::FieldSpec::new(
                            Some("CommandLine".to_string()),
                            vec![rsigma_parser::Modifier::Contains],
                        ),
                        values: vec![SigmaValue::String(SigmaString::new("whoami"))],
                    }]),
                );
                m
            },
            conditions: vec![rsigma_parser::ConditionExpr::Identifier(
                "selection".to_string(),
            )],
            condition_strings: vec!["selection".to_string()],
            timeframe: None,
        },
        id: None,
        name: None,
        related: vec![],
        taxonomy: None,
        status: None,
        description: None,
        license: None,
        author: None,
        references: vec![],
        date: None,
        modified: None,
        fields: vec![],
        falsepositives: vec![],
        level: None,
        tags: vec![],
        scope: vec![],
        custom_attributes: std::collections::HashMap::new(),
    };

    let mut state = PipelineState::new(pipeline.vars.clone());
    pipeline.apply(&mut rule, &mut state).unwrap();

    // Check that field was renamed
    let det = &rule.detection.named["selection"];
    if let rsigma_parser::Detection::AllOf(items) = det {
        assert_eq!(
            items[0].field.name,
            Some("process.command_line".to_string())
        );
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_pipeline_skips_non_matching_rules() {
    let yaml = r#"
name: Windows Only
transformations:
  - type: field_name_prefix
    prefix: "win."
    rule_conditions:
      - type: logsource
        product: windows
"#;
    let pipeline = parse_pipeline(yaml).unwrap();

    // Create a Linux rule — should NOT be modified
    let mut rule = rsigma_parser::SigmaRule {
        sigma_version: None,
        title: "Linux Rule".to_string(),
        logsource: rsigma_parser::LogSource {
            product: Some("linux".to_string()),
            ..Default::default()
        },
        detection: rsigma_parser::Detections {
            named: {
                let mut m = HashMap::new();
                m.insert(
                    "sel".to_string(),
                    rsigma_parser::Detection::AllOf(vec![rsigma_parser::DetectionItem {
                        field: rsigma_parser::FieldSpec::new(
                            Some("CommandLine".to_string()),
                            vec![],
                        ),
                        values: vec![SigmaValue::String(SigmaString::new("test"))],
                    }]),
                );
                m
            },
            conditions: vec![rsigma_parser::ConditionExpr::Identifier("sel".to_string())],
            condition_strings: vec!["sel".to_string()],
            timeframe: None,
        },
        id: None,
        name: None,
        related: vec![],
        taxonomy: None,
        status: None,
        description: None,
        license: None,
        author: None,
        references: vec![],
        date: None,
        modified: None,
        fields: vec![],
        falsepositives: vec![],
        level: None,
        tags: vec![],
        scope: vec![],
        custom_attributes: std::collections::HashMap::new(),
    };

    let mut state = PipelineState::new(pipeline.vars.clone());
    pipeline.apply(&mut rule, &mut state).unwrap();

    // Field should NOT have been prefixed
    let det = &rule.detection.named["sel"];
    if let rsigma_parser::Detection::AllOf(items) = det {
        assert_eq!(items[0].field.name, Some("CommandLine".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_merge_pipelines_sorts_by_priority() {
    let mut pipelines = vec![
        Pipeline {
            name: "C".to_string(),
            priority: 30,
            vars: HashMap::new(),
            apply_modifiers: Default::default(),
            transformations: vec![],
            finalizers: vec![],
            source_refs: vec![],
        },
        Pipeline {
            name: "A".to_string(),
            priority: 10,
            vars: HashMap::new(),
            apply_modifiers: Default::default(),
            transformations: vec![],
            finalizers: vec![],
            source_refs: vec![],
        },
        Pipeline {
            name: "B".to_string(),
            priority: 20,
            vars: HashMap::new(),
            apply_modifiers: Default::default(),
            transformations: vec![],
            finalizers: vec![],
            source_refs: vec![],
        },
    ];

    merge_pipelines(&mut pipelines);

    assert_eq!(pipelines[0].name, "A");
    assert_eq!(pipelines[1].name, "B");
    assert_eq!(pipelines[2].name, "C");
}

#[test]
fn test_parse_all_transformation_types() {
    let yaml = r#"
name: All Types
transformations:
  - type: field_name_mapping
    mapping:
      a: b
  - type: field_name_prefix_mapping
    mapping:
      old_: new_
  - type: field_name_prefix
    prefix: "pfx."
  - type: field_name_suffix
    suffix: ".sfx"
  - type: drop_detection_item
  - type: add_condition
    conditions:
      index: test
  - type: change_logsource
    category: new_cat
  - type: replace_string
    regex: "old"
    replacement: "new"
  - type: value_placeholders
  - type: wildcard_placeholders
  - type: query_expression_placeholders
    expression: "{field}={value}"
  - type: set_state
    key: k
    value: v
  - type: rule_failure
    message: fail
  - type: detection_item_failure
    message: fail
  - type: field_name_transform
    transform_func: lower
  - type: hashes_fields
    valid_hash_algos:
      - MD5
      - SHA1
    field_prefix: File
  - type: map_string
    mapping:
      old_val: new_val
  - type: set_value
    value: fixed
  - type: convert_type
    target_type: int
  - type: regex
  - type: add_field
    field: EventID
  - type: remove_field
    field: OldField
  - type: set_field
    fields:
      - field1
      - field2
  - type: set_custom_attribute
    attribute: backend
    value: splunk
  - type: case_transformation
    case_type: lower
  - type: nest
    items:
      - type: field_name_prefix
        prefix: "inner."
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert_eq!(pipeline.transformations.len(), 26);
}

#[test]
fn test_parse_all_condition_types() {
    let yaml = r#"
name: Conditions
transformations:
  - type: field_name_prefix
    prefix: "x."
    rule_conditions:
      - type: logsource
        product: windows
      - type: contains_detection_item
        field: EventID
        value: "1"
      - type: processing_item_applied
        processing_item_id: prev_step
      - type: processing_state
        key: k
        val: v
      - type: is_sigma_rule
      - type: is_sigma_correlation_rule
      - type: rule_attribute
        attribute: level
        value: high
      - type: tag
        tag: attack.execution
    detection_item_conditions:
      - type: match_string
        pattern: "^test"
        negate: false
      - type: is_null
        negate: true
      - type: processing_item_applied
        processing_item_id: x
      - type: processing_state
        key: k
        val: v
    field_name_conditions:
      - type: include_fields
        fields:
          - CommandLine
      - type: exclude_fields
        fields:
          - Hostname
        match_type: regex
      - type: processing_item_applied
        processing_item_id: y
      - type: processing_state
        key: a
        val: b
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    let item = &pipeline.transformations[0];
    assert_eq!(item.rule_conditions.conditions.len(), 8);
    assert_eq!(item.detection_item_conditions.conditions.len(), 4);
    assert_eq!(item.field_name_conditions.conditions.len(), 4);
}

#[test]
fn test_named_condition_ids_in_rule_cond_expression() {
    let yaml = r#"
name: Named Conditions
transformations:
  - type: field_name_prefix
    prefix: "win."
    rule_conditions:
      - id: is_windows
        type: logsource
        product: windows
      - id: is_process
        type: logsource
        category: process_creation
    rule_cond_expression: "is_windows or is_process"
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    let item = &pipeline.transformations[0];
    assert_eq!(item.rule_conditions.conditions[0].id, "is_windows");
    assert_eq!(item.rule_conditions.conditions[1].id, "is_process");

    // Windows + process_creation => both match, OR is true => prefix applied
    let mut rule = rsigma_parser::SigmaRule {
        sigma_version: None,
        title: "Test".to_string(),
        logsource: rsigma_parser::LogSource {
            product: Some("windows".to_string()),
            category: Some("process_creation".to_string()),
            ..Default::default()
        },
        detection: rsigma_parser::Detections {
            named: {
                let mut m = HashMap::new();
                m.insert(
                    "sel".to_string(),
                    rsigma_parser::Detection::AllOf(vec![rsigma_parser::DetectionItem {
                        field: rsigma_parser::FieldSpec::new(
                            Some("CommandLine".to_string()),
                            vec![],
                        ),
                        values: vec![SigmaValue::String(SigmaString::new("test"))],
                    }]),
                );
                m
            },
            conditions: vec![rsigma_parser::ConditionExpr::Identifier("sel".to_string())],
            condition_strings: vec!["sel".to_string()],
            timeframe: None,
        },
        id: None,
        name: None,
        related: vec![],
        taxonomy: None,
        status: None,
        description: None,
        license: None,
        author: None,
        references: vec![],
        date: None,
        modified: None,
        fields: vec![],
        falsepositives: vec![],
        level: None,
        tags: vec![],
        scope: vec![],
        custom_attributes: HashMap::new(),
    };

    let mut state = PipelineState::new(pipeline.vars.clone());
    pipeline.apply(&mut rule, &mut state).unwrap();

    let det = &rule.detection.named["sel"];
    if let rsigma_parser::Detection::AllOf(items) = det {
        assert_eq!(items[0].field.name, Some("win.CommandLine".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_named_cond_expression_or_logic() {
    // Only is_process matches (linux, not windows), but OR means it still applies
    let yaml = r#"
name: OR Logic
transformations:
  - type: field_name_prefix
    prefix: "mapped."
    rule_conditions:
      - id: is_windows
        type: logsource
        product: windows
      - id: is_process
        type: logsource
        category: process_creation
    rule_cond_expression: "is_windows or is_process"
"#;
    let pipeline = parse_pipeline(yaml).unwrap();

    let mut rule = rsigma_parser::SigmaRule {
        sigma_version: None,
        title: "Linux Process".to_string(),
        logsource: rsigma_parser::LogSource {
            product: Some("linux".to_string()),
            category: Some("process_creation".to_string()),
            ..Default::default()
        },
        detection: rsigma_parser::Detections {
            named: {
                let mut m = HashMap::new();
                m.insert(
                    "sel".to_string(),
                    rsigma_parser::Detection::AllOf(vec![rsigma_parser::DetectionItem {
                        field: rsigma_parser::FieldSpec::new(Some("Image".to_string()), vec![]),
                        values: vec![SigmaValue::String(SigmaString::new("/bin/sh"))],
                    }]),
                );
                m
            },
            conditions: vec![rsigma_parser::ConditionExpr::Identifier("sel".to_string())],
            condition_strings: vec!["sel".to_string()],
            timeframe: None,
        },
        id: None,
        name: None,
        related: vec![],
        taxonomy: None,
        status: None,
        description: None,
        license: None,
        author: None,
        references: vec![],
        date: None,
        modified: None,
        fields: vec![],
        falsepositives: vec![],
        level: None,
        tags: vec![],
        scope: vec![],
        custom_attributes: HashMap::new(),
    };

    let mut state = PipelineState::new(pipeline.vars.clone());
    pipeline.apply(&mut rule, &mut state).unwrap();

    // is_windows=false, is_process=true => OR => applied
    let det = &rule.detection.named["sel"];
    if let rsigma_parser::Detection::AllOf(items) = det {
        assert_eq!(items[0].field.name, Some("mapped.Image".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_named_cond_expression_and_logic() {
    // AND: both must match
    let yaml = r#"
name: AND Logic
transformations:
  - type: field_name_prefix
    prefix: "win."
    rule_conditions:
      - id: is_windows
        type: logsource
        product: windows
      - id: is_process
        type: logsource
        category: process_creation
    rule_cond_expression: "is_windows and is_process"
"#;
    let pipeline = parse_pipeline(yaml).unwrap();

    // Linux + process_creation => is_windows=false => AND fails => no prefix
    let mut rule = rsigma_parser::SigmaRule {
        sigma_version: None,
        title: "Linux Rule".to_string(),
        logsource: rsigma_parser::LogSource {
            product: Some("linux".to_string()),
            category: Some("process_creation".to_string()),
            ..Default::default()
        },
        detection: rsigma_parser::Detections {
            named: {
                let mut m = HashMap::new();
                m.insert(
                    "sel".to_string(),
                    rsigma_parser::Detection::AllOf(vec![rsigma_parser::DetectionItem {
                        field: rsigma_parser::FieldSpec::new(Some("Image".to_string()), vec![]),
                        values: vec![SigmaValue::String(SigmaString::new("/bin/sh"))],
                    }]),
                );
                m
            },
            conditions: vec![rsigma_parser::ConditionExpr::Identifier("sel".to_string())],
            condition_strings: vec!["sel".to_string()],
            timeframe: None,
        },
        id: None,
        name: None,
        related: vec![],
        taxonomy: None,
        status: None,
        description: None,
        license: None,
        author: None,
        references: vec![],
        date: None,
        modified: None,
        fields: vec![],
        falsepositives: vec![],
        level: None,
        tags: vec![],
        scope: vec![],
        custom_attributes: HashMap::new(),
    };

    let mut state = PipelineState::new(pipeline.vars.clone());
    pipeline.apply(&mut rule, &mut state).unwrap();

    // is_windows=false => AND => not applied
    let det = &rule.detection.named["sel"];
    if let rsigma_parser::Detection::AllOf(items) = det {
        assert_eq!(items[0].field.name, Some("Image".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_unnamed_conditions_use_one_based_ids() {
    let yaml = r#"
name: Fallback IDs
transformations:
  - type: field_name_prefix
    prefix: "x."
    rule_conditions:
      - type: logsource
        product: windows
      - type: logsource
        category: process_creation
    rule_cond_expression: "1 or 2"
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert_eq!(
        pipeline.transformations[0].rule_conditions.conditions[0].id,
        "1"
    );
    assert_eq!(
        pipeline.transformations[0].rule_conditions.conditions[1].id,
        "2"
    );

    let mut rule = rsigma_parser::SigmaRule {
        sigma_version: None,
        title: "Test".to_string(),
        logsource: rsigma_parser::LogSource {
            product: Some("linux".to_string()),
            category: Some("process_creation".to_string()),
            ..Default::default()
        },
        detection: rsigma_parser::Detections {
            named: {
                let mut m = HashMap::new();
                m.insert(
                    "sel".to_string(),
                    rsigma_parser::Detection::AllOf(vec![rsigma_parser::DetectionItem {
                        field: rsigma_parser::FieldSpec::new(Some("Field".to_string()), vec![]),
                        values: vec![SigmaValue::String(SigmaString::new("val"))],
                    }]),
                );
                m
            },
            conditions: vec![rsigma_parser::ConditionExpr::Identifier("sel".to_string())],
            condition_strings: vec!["sel".to_string()],
            timeframe: None,
        },
        id: None,
        name: None,
        related: vec![],
        taxonomy: None,
        status: None,
        description: None,
        license: None,
        author: None,
        references: vec![],
        date: None,
        modified: None,
        fields: vec![],
        falsepositives: vec![],
        level: None,
        tags: vec![],
        scope: vec![],
        custom_attributes: HashMap::new(),
    };

    let mut state = PipelineState::new(pipeline.vars.clone());
    pipeline.apply(&mut rule, &mut state).unwrap();

    // 1 (windows)=false, 2 (process_creation)=true => OR => applied
    let det = &rule.detection.named["sel"];
    if let rsigma_parser::Detection::AllOf(items) = det {
        assert_eq!(items[0].field.name, Some("x.Field".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

// =========================================================================
// Correlation pipeline tests
// =========================================================================

fn make_test_correlation() -> CorrelationRule {
    CorrelationRule {
        sigma_version: None,
        title: "Test Correlation".to_string(),
        id: Some("corr-1".to_string()),
        name: Some("test_corr".to_string()),
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
        level: None,
        scope: vec![],
        correlation_type: rsigma_parser::CorrelationType::EventCount,
        rules: vec!["rule_a".to_string()],
        group_by: vec!["SourceIP".to_string(), "DestinationIP".to_string()],
        timespan: rsigma_parser::Timespan::parse("5m").unwrap(),
        window: rsigma_parser::WindowMode::Sliding,
        gap: None,
        condition: rsigma_parser::CorrelationCondition::Threshold {
            predicates: vec![(rsigma_parser::ConditionOperator::Gte, 10)],
            field: None,
            percentile: None,
        },
        aliases: vec![rsigma_parser::FieldAlias {
            alias: "src_ip".to_string(),
            mapping: {
                let mut m = HashMap::new();
                m.insert("rule_a".to_string(), "SourceIP".to_string());
                m
            },
        }],
        generate: true,
        custom_attributes: HashMap::new(),
    }
}

#[test]
fn test_correlation_pipeline_field_name_mapping() {
    let yaml = r#"
name: ECS Field Mapping
transformations:
  - type: field_name_mapping
    mapping:
      SourceIP: source.ip
      DestinationIP: destination.ip
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    let mut corr = make_test_correlation();

    let mut state = PipelineState::new(pipeline.vars.clone());
    pipeline
        .apply_to_correlation(&mut corr, &mut state)
        .unwrap();

    assert_eq!(corr.group_by, vec!["source.ip", "destination.ip"]);
    assert_eq!(corr.aliases[0].mapping["rule_a"], "source.ip");
}

#[test]
fn test_correlation_field_mapping_group_by_expands_all_alternatives() {
    let yaml = r#"
name: Multi-field
transformations:
  - type: field_name_mapping
    mapping:
      DestinationIP:
        - dst.ip
        - dest.address
      SourceIP: src.ip
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    let mut corr = make_test_correlation();
    let mut state = PipelineState::new(pipeline.vars.clone());
    pipeline
        .apply_to_correlation(&mut corr, &mut state)
        .unwrap();

    // SourceIP is 1:1 (and also in an alias), DestinationIP expands
    assert_eq!(
        corr.group_by,
        vec!["src.ip", "dst.ip", "dest.address"],
        "group_by should expand all alternatives for DestinationIP"
    );
    // alias SourceIP should be remapped 1:1
    assert_eq!(corr.aliases[0].mapping["rule_a"], "src.ip");
}

#[test]
fn test_correlation_field_mapping_alias_rejects_one_to_many() {
    let yaml = r#"
name: Alias conflict
transformations:
  - type: field_name_mapping
    mapping:
      SourceIP:
        - src.ip
        - source.address
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    let mut corr = make_test_correlation();
    let mut state = PipelineState::new(pipeline.vars.clone());
    let err = pipeline
        .apply_to_correlation(&mut corr, &mut state)
        .expect_err("alias with one-to-many must error");
    let msg = format!("{err}");
    assert!(msg.contains("alias"), "error should mention alias: {msg}");
}

#[test]
fn test_correlation_field_mapping_threshold_field_rejects_one_to_many() {
    let yaml = r#"
name: Threshold conflict
transformations:
  - type: field_name_mapping
    mapping:
      UserName:
        - user.name
        - user.id
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    let mut corr = make_test_correlation();
    corr.condition = rsigma_parser::CorrelationCondition::Threshold {
        predicates: vec![(rsigma_parser::ConditionOperator::Gte, 5)],
        field: Some(vec!["UserName".to_string()]),
        percentile: None,
    };
    let mut state = PipelineState::new(pipeline.vars.clone());
    let err = pipeline
        .apply_to_correlation(&mut corr, &mut state)
        .expect_err("threshold field with one-to-many must error");
    let msg = format!("{err}");
    assert!(
        msg.contains("condition field reference"),
        "error should mention condition field: {msg}"
    );
}

#[test]
fn test_correlation_pipeline_field_prefix() {
    let yaml = r#"
name: Prefix
transformations:
  - type: field_name_prefix
    prefix: "event."
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    let mut corr = make_test_correlation();

    let mut state = PipelineState::new(pipeline.vars.clone());
    pipeline
        .apply_to_correlation(&mut corr, &mut state)
        .unwrap();

    assert_eq!(corr.group_by, vec!["event.SourceIP", "event.DestinationIP"]);
}

#[test]
fn test_correlation_pipeline_set_custom_attribute() {
    let yaml = r#"
name: Custom Attr
transformations:
  - type: set_custom_attribute
    attribute: rsigma.action
    value: reset
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    let mut corr = make_test_correlation();

    let mut state = PipelineState::new(pipeline.vars.clone());
    pipeline
        .apply_to_correlation(&mut corr, &mut state)
        .unwrap();

    assert_eq!(
        corr.custom_attributes["rsigma.action"],
        yaml_serde::Value::String("reset".to_string())
    );
}

#[test]
fn test_correlation_pipeline_skips_detection_rules() {
    let yaml = r#"
name: Detection Only
transformations:
  - type: field_name_prefix
    prefix: "x."
    rule_conditions:
      - type: is_sigma_rule
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    let mut corr = make_test_correlation();

    let mut state = PipelineState::new(pipeline.vars.clone());
    pipeline
        .apply_to_correlation(&mut corr, &mut state)
        .unwrap();

    // is_sigma_rule => false for correlations => not applied
    assert_eq!(corr.group_by, vec!["SourceIP", "DestinationIP"]);
}

#[test]
fn test_correlation_pipeline_rule_failure() {
    let yaml = r#"
name: Block Correlations
transformations:
  - type: rule_failure
    message: "correlations not supported by this backend"
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    let mut corr = make_test_correlation();

    let mut state = PipelineState::new(pipeline.vars.clone());
    let result = pipeline.apply_to_correlation(&mut corr, &mut state);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("correlations not supported"));
}

#[test]
fn test_correlation_pipeline_condition_field_mapping() {
    let yaml = r#"
name: Condition Field Mapping
transformations:
  - type: field_name_mapping
    mapping:
      UserName: user.name
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
    let pipeline = parse_pipeline(yaml).unwrap();

    let mut corr = make_test_correlation();
    corr.condition = rsigma_parser::CorrelationCondition::Threshold {
        predicates: vec![(rsigma_parser::ConditionOperator::Gte, 5)],
        field: Some(vec!["UserName".to_string()]),
        percentile: None,
    };

    let mut state = PipelineState::new(pipeline.vars.clone());
    pipeline
        .apply_to_correlation(&mut corr, &mut state)
        .unwrap();

    if let rsigma_parser::CorrelationCondition::Threshold { field, .. } = &corr.condition {
        assert_eq!(field.as_deref(), Some(["user.name".to_string()].as_slice()));
    } else {
        panic!("Expected Threshold");
    }
}

#[test]
fn test_apply_pipelines_to_correlation_fn() {
    let yaml = r#"
name: ECS Mapping
priority: 10
transformations:
  - type: field_name_mapping
    mapping:
      SourceIP: source.ip
    rule_conditions:
      - type: is_sigma_correlation_rule
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    let mut corr = make_test_correlation();

    apply_pipelines_to_correlation(&[pipeline], &mut corr).unwrap();

    assert_eq!(corr.group_by[0], "source.ip");
}

// =============================================================================
// Dynamic pipeline tests
// =============================================================================

/// Parse the `sources:` node of a YAML document into source declarations,
/// mirroring what a standalone `--source` file yields. Source declarations no
/// longer live inside pipelines, so the declaration-parsing coverage exercises
/// the same [`parse_sources`](parsing::parse_sources) path an external file
/// uses. Only the `sources:` key is read; any surrounding keys are ignored.
fn parse_source_list(yaml: &str) -> crate::error::Result<Vec<sources::DynamicSource>> {
    let value: yaml_serde::Value = yaml_serde::from_str(yaml).unwrap();
    let node = value
        .as_mapping()
        .unwrap()
        .get(yaml_serde::Value::String("sources".to_string()))
        .expect("test YAML must have a top-level `sources:` key")
        .clone();
    parsing::parse_sources(&node)
}

#[test]
fn test_static_pipeline_is_not_dynamic() {
    let yaml = r#"
name: Static Pipeline
priority: 10
vars:
  admin_emails:
    - admin@example.com
transformations:
  - type: value_placeholders
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert!(!pipeline.is_dynamic());
    assert!(pipeline.source_refs.is_empty());
}

#[test]
fn test_inline_sources_block_is_rejected() {
    // Pipeline-embedded `sources:` was removed in v0.19.0; the parser rejects it
    // with a hint pointing at the migration tool.
    let yaml = r#"
name: Legacy Pipeline
sources:
  - id: threat_feed
    type: file
    path: /tmp/threat.json
    format: json
transformations:
  - type: value_placeholders
"#;
    let err = parse_pipeline(yaml).unwrap_err().to_string();
    assert!(
        err.contains("migrate-sources"),
        "error should point at the migration tool: {err}"
    );
    assert!(
        err.contains("--source"),
        "error should mention --source: {err}"
    );
}

#[test]
fn test_parse_taxii_source_and_stix_format() {
    let yaml = r#"
sources:
  - id: ti
    type: taxii
    url: https://taxii.example/api/
    collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116
    refresh: 5m
    page_size: 500
    auth:
      bearer_token_env: TAXII_TOKEN
    stix:
      min_confidence: 50
      observables: [ipv4, domain]
  - id: bundle
    type: file
    path: ./indicators.json
    format: stix
"#;
    let sources = parse_source_list(yaml).unwrap();
    match &sources[0].source_type {
        sources::SourceType::Taxii {
            url,
            collection,
            auth,
            page_size,
            stix,
        } => {
            assert_eq!(url, "https://taxii.example/api/");
            assert_eq!(collection, "91a7b528-80eb-42ed-a74d-c6fbd5a26116");
            assert_eq!(auth.bearer_token_env.as_deref(), Some("TAXII_TOKEN"));
            assert_eq!(*page_size, 500);
            assert_eq!(stix.min_confidence, Some(50));
            assert_eq!(stix.observables, ["ipv4", "domain"]);
        }
        other => panic!("expected Taxii, got {other:?}"),
    }
    assert!(matches!(
        sources[0].refresh,
        sources::RefreshPolicy::Interval(d) if d == std::time::Duration::from_secs(300)
    ));
    match &sources[1].source_type {
        sources::SourceType::File {
            format: sources::DataFormat::Stix,
            extract: None,
            stix: Some(stix),
            ..
        } => {
            assert_eq!(stix.observables, sources::STIX_OBSERVABLE_KEYS);
            assert_eq!(stix.max_indicators, 100_000);
        }
        other => panic!("expected a stix file source, got {other:?}"),
    }
}

#[test]
fn test_parse_taxii_and_stix_rejections() {
    let cases = [
        (
            "type: taxii\n    url: https://taxii.example/api/\n    collection: not-a-uuid\n",
            "collection must be a UUID",
        ),
        (
            "type: taxii\n    url: https://taxii.example/api/\n    collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116\n    refresh: watch\n",
            "does not accept refresh 'watch'",
        ),
        (
            "type: taxii\n    url: https://taxii.example/api/\n    collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116\n    refresh: push\n",
            "does not accept refresh 'push'",
        ),
        (
            "type: taxii\n    url: https://taxii.example/api/\n    collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116\n    extract: .[]\n",
            "field 'extract' does not apply to type 'taxii'",
        ),
        (
            "type: taxii\n    url: https://taxii.example/api/\n    collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116\n    format: stix\n",
            "field 'format' does not apply to type 'taxii'",
        ),
        (
            "type: taxii\n    url: https://taxii.example/api/\n    collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116\n    auth:\n      bearer_token_env: TAXII_TOKEN\n      api_key_env: TAXII_KEY\n",
            "exactly one TAXII auth method",
        ),
        (
            "type: taxii\n    url: https://taxii.example/api/\n    collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116\n    auth:\n      basic_user_env: TAXII_USER\n",
            "basic_user_env and basic_password_env",
        ),
        (
            "type: taxii\n    url: https://taxii.example/api/\n    collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116\n    stix:\n      observables: [ipv4, not-a-kind]\n",
            "unknown observable 'not-a-kind'",
        ),
        (
            "type: file\n    path: ./indicators.json\n    format: json\n    stix:\n      min_confidence: 10\n",
            "stix block requires format: stix",
        ),
        (
            "type: file\n    path: ./indicators.json\n    format: stix\n    extract: .[]\n",
            "does not accept 'extract'",
        ),
        (
            "type: http\n    url: https://example.test/bundle.json\n    format: stix\n    extract: .[]\n",
            "does not accept 'extract'",
        ),
        (
            "type: command\n    command: cat\n    format: stix\n",
            "does not accept format 'stix'",
        ),
    ];
    for (body, needle) in cases {
        let yaml = format!("sources:\n  - id: ti\n    {body}");
        let err = parse_source_list(&yaml).unwrap_err().to_string();
        assert!(
            err.contains("ti") && err.contains(needle),
            "expected '{needle}' naming ti, got: {err}"
        );
        if needle.starts_with("unknown observable") {
            assert!(
                err.contains("valid keys:"),
                "unknown observable error should list valid keys: {err}"
            );
        }
    }
}

#[test]
fn test_parse_watchlist_source_defaults_and_ttl() {
    let yaml = r#"
sources:
  - id: c2_ips
    type: watchlist
    default_ttl: 30d
"#;
    let src = &parse_source_list(yaml).unwrap()[0];
    assert_eq!(src.id, "c2_ips");
    match &src.source_type {
        sources::SourceType::Watchlist {
            max_indicators,
            max_value_length,
            default_ttl,
        } => {
            assert_eq!(*max_indicators, 100_000);
            assert_eq!(*max_value_length, 2048);
            assert_eq!(
                *default_ttl,
                Some(std::time::Duration::from_secs(30 * 86_400))
            );
        }
        other => panic!("expected Watchlist, got {other:?}"),
    }
}

#[test]
fn test_parse_watchlist_source_rejects_fetch_fields_and_reserved_ids() {
    let cases = [
        (
            "refresh: 5m\n",
            "field 'refresh' does not apply to type 'watchlist'",
        ),
        (
            "format: json\n",
            "field 'format' does not apply to type 'watchlist'",
        ),
        (
            "extract: .[]\n",
            "field 'extract' does not apply to type 'watchlist'",
        ),
        (
            "timeout: 10s\n",
            "field 'timeout' does not apply to type 'watchlist'",
        ),
        (
            "max_indicators: 0\n",
            "max_indicators must be greater than 0",
        ),
    ];
    for (extra, needle) in cases {
        let yaml = format!("sources:\n  - id: c2_ips\n    type: watchlist\n    {extra}");
        let err = parse_source_list(&yaml).unwrap_err().to_string();
        assert!(
            err.contains("c2_ips") && err.contains(needle),
            "expected '{needle}' naming c2_ips, got: {err}"
        );
    }
    for id in ["resolve", "cache"] {
        let yaml = format!("sources:\n  - id: {id}\n    type: watchlist\n");
        let err = parse_source_list(&yaml).unwrap_err().to_string();
        assert!(
            err.contains(id) && err.contains("reserved"),
            "expected reserved id '{id}', got: {err}"
        );
    }
}

#[test]
fn test_parse_http_source() {
    let yaml = r#"
name: Dynamic Pipeline
priority: 10
sources:
  - id: admin_emails
    type: http
    url: https://api.internal/v1/admin-emails
    format: json
    extract: ".emails[]"
    refresh: 5m
    timeout: 10s
    on_error: use_cached
    required: true
transformations:
  - type: value_placeholders
"#;
    let src_list = parse_source_list(yaml).unwrap();
    assert_eq!(src_list.len(), 1);

    let src = &src_list[0];
    assert_eq!(src.id, "admin_emails");
    assert!(src.required);
    assert_eq!(src.timeout, Some(std::time::Duration::from_secs(10)));
    assert_eq!(src.on_error, sources::ErrorPolicy::UseCached);

    match &src.refresh {
        sources::RefreshPolicy::Interval(d) => {
            assert_eq!(*d, std::time::Duration::from_secs(300));
        }
        other => panic!("expected Interval, got {other:?}"),
    }

    match &src.source_type {
        sources::SourceType::Http {
            url,
            format,
            extract,
            ..
        } => {
            assert_eq!(url, "https://api.internal/v1/admin-emails");
            assert_eq!(*format, sources::DataFormat::Json);
            assert_eq!(
                *extract,
                Some(sources::ExtractExpr::Jq(".emails[]".to_string()))
            );
        }
        other => panic!("expected Http, got {other:?}"),
    }
}

#[test]
fn test_parse_command_source() {
    let yaml = r#"
name: Command Source Pipeline
sources:
  - id: ioc_domains
    type: command
    command: ["/usr/local/bin/fetch-iocs", "--type", "domain"]
    format: lines
    refresh: 30m
    on_error: fail
    required: false
    default: []
transformations:
  - type: value_placeholders
"#;
    let src_list = parse_source_list(yaml).unwrap();
    let src = &src_list[0];
    assert_eq!(src.id, "ioc_domains");
    assert!(!src.required);
    assert_eq!(src.on_error, sources::ErrorPolicy::Fail);

    match &src.source_type {
        sources::SourceType::Command {
            command, format, ..
        } => {
            assert_eq!(
                command,
                &[
                    "/usr/local/bin/fetch-iocs".to_string(),
                    "--type".to_string(),
                    "domain".to_string()
                ]
            );
            assert_eq!(*format, sources::DataFormat::Lines);
        }
        other => panic!("expected Command, got {other:?}"),
    }
}

#[test]
fn test_parse_file_source() {
    let yaml = r#"
name: File Source Pipeline
sources:
  - id: watchlist
    type: file
    path: /etc/rsigma/watchlist.json
    format: json
    refresh: watch
transformations:
  - type: value_placeholders
"#;
    let src_list = parse_source_list(yaml).unwrap();
    let src = &src_list[0];
    assert_eq!(src.id, "watchlist");
    assert_eq!(src.refresh, sources::RefreshPolicy::Watch);

    match &src.source_type {
        sources::SourceType::File {
            path,
            format,
            extract,
            stix,
        } => {
            assert_eq!(path, std::path::Path::new("/etc/rsigma/watchlist.json"));
            assert_eq!(*format, sources::DataFormat::Json);
            assert_eq!(*extract, None);
            assert_eq!(*stix, None);
        }
        other => panic!("expected File, got {other:?}"),
    }
}

#[test]
fn test_parse_nats_source() {
    let yaml = r#"
name: NATS Source Pipeline
sources:
  - id: threat_intel
    type: nats
    subject: rsigma.sources.threat-intel
    format: json
    extract: ".iocs"
    refresh: push
transformations:
  - type: value_placeholders
"#;
    let src_list = parse_source_list(yaml).unwrap();
    let src = &src_list[0];
    assert_eq!(src.id, "threat_intel");
    assert_eq!(src.refresh, sources::RefreshPolicy::Push);

    match &src.source_type {
        sources::SourceType::Nats {
            subject, format, ..
        } => {
            assert_eq!(subject, "rsigma.sources.threat-intel");
            assert_eq!(*format, sources::DataFormat::Json);
        }
        other => panic!("expected Nats, got {other:?}"),
    }
}

#[test]
fn test_parse_extract_structured_jsonpath() {
    let yaml = r#"
name: JSONPath Extract Pipeline
sources:
  - id: config
    type: http
    url: https://api.internal/v1/config
    format: json
    extract:
      expr: "$.settings[*]"
      type: jsonpath
transformations:
  - type: value_placeholders
"#;
    let src_list = parse_source_list(yaml).unwrap();
    let src = &src_list[0];
    match &src.source_type {
        sources::SourceType::Http { extract, .. } => {
            assert_eq!(
                *extract,
                Some(sources::ExtractExpr::JsonPath("$.settings[*]".to_string()))
            );
        }
        other => panic!("expected Http, got {other:?}"),
    }
}

#[test]
fn test_parse_extract_structured_cel() {
    let yaml = r#"
name: CEL Extract Pipeline
sources:
  - id: emails
    type: file
    path: /etc/rsigma/emails.json
    format: json
    extract:
      expr: "data.emails.filter(e, e.endsWith('@corp.com'))"
      type: cel
transformations:
  - type: value_placeholders
"#;
    let src_list = parse_source_list(yaml).unwrap();
    let src = &src_list[0];
    match &src.source_type {
        sources::SourceType::File { extract, .. } => {
            assert_eq!(
                *extract,
                Some(sources::ExtractExpr::Cel(
                    "data.emails.filter(e, e.endsWith('@corp.com'))".to_string()
                ))
            );
        }
        other => panic!("expected File, got {other:?}"),
    }
}

#[test]
fn test_parse_extract_structured_jq_explicit() {
    let yaml = r#"
name: Explicit JQ Extract Pipeline
sources:
  - id: data
    type: http
    url: https://api.internal/v1/data
    format: json
    extract:
      expr: ".items[] | select(.active)"
      type: jq
transformations:
  - type: value_placeholders
"#;
    let src_list = parse_source_list(yaml).unwrap();
    let src = &src_list[0];
    match &src.source_type {
        sources::SourceType::Http { extract, .. } => {
            assert_eq!(
                *extract,
                Some(sources::ExtractExpr::Jq(
                    ".items[] | select(.active)".to_string()
                ))
            );
        }
        other => panic!("expected Http, got {other:?}"),
    }
}

#[test]
fn test_parse_extract_unknown_type_errors() {
    let yaml = r#"
name: Bad Extract Pipeline
sources:
  - id: data
    type: http
    url: https://api.internal/v1/data
    format: json
    extract:
      expr: "something"
      type: xpath
transformations:
  - type: value_placeholders
"#;
    let result = parse_source_list(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("xpath"), "error should mention 'xpath': {err}");
}

#[test]
fn test_parse_on_demand_refresh() {
    let yaml = r#"
sources:
  - id: compromised
    type: http
    url: https://api.internal/v1/compromised
    refresh: on_demand
"#;
    let src_list = parse_source_list(yaml).unwrap();
    assert_eq!(src_list[0].refresh, sources::RefreshPolicy::OnDemand);
}

#[test]
fn test_detect_source_refs_in_vars() {
    let yaml = r#"
name: Ref Detection
vars:
  admin_emails: "${source.admin_emails}"
  log_index: "${source.env_config.log_index}"
transformations:
  - type: value_placeholders
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert!(pipeline.is_dynamic());
    assert_eq!(pipeline.source_refs.len(), 2);

    let ref0 = &pipeline.source_refs[0];
    assert_eq!(ref0.source_id, "admin_emails");
    assert_eq!(ref0.sub_path, None);
    assert_eq!(ref0.raw_template, "${source.admin_emails}");
    assert!(matches!(ref0.location, sources::RefLocation::Var { .. }));

    let ref1 = &pipeline.source_refs[1];
    assert_eq!(ref1.source_id, "env_config");
    assert_eq!(ref1.sub_path.as_deref(), Some("log_index"));
}

#[test]
fn test_detect_source_refs_in_list_vars() {
    // A var whose value is a list of templates (the common `value_placeholders`
    // shape) must still register as a dynamic source reference.
    let yaml = r#"
name: List Var Refs
vars:
  malicious_commands:
    - "${source.cmd_list}"
transformations:
  - type: value_placeholders
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert!(
        pipeline.is_dynamic(),
        "list-valued var ref should be dynamic"
    );
    assert_eq!(pipeline.source_refs.len(), 1);
    assert_eq!(pipeline.source_refs[0].source_id, "cmd_list");
}

#[test]
fn test_detect_source_refs_in_transformation_fields() {
    let yaml = r#"
name: Transform Refs
transformations:
  - type: field_name_mapping
    mapping: "${source.env_config.field_mapping}"
  - type: add_condition
    conditions:
      ParentImage: "${source.env_config.critical_binaries}"
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert!(pipeline.is_dynamic());

    let mapping_refs: Vec<_> = pipeline
        .source_refs
        .iter()
        .filter(|r| matches!(&r.location, sources::RefLocation::TransformationField { field_name, .. } if field_name == "mapping"))
        .collect();
    assert_eq!(mapping_refs.len(), 1);
    assert_eq!(mapping_refs[0].source_id, "env_config");
    assert_eq!(mapping_refs[0].sub_path.as_deref(), Some("field_mapping"));

    let cond_refs: Vec<_> = pipeline
        .source_refs
        .iter()
        .filter(|r| matches!(&r.location, sources::RefLocation::TransformationField { field_name, .. } if field_name.contains("conditions")))
        .collect();
    assert_eq!(cond_refs.len(), 1);
    assert_eq!(cond_refs[0].sub_path.as_deref(), Some("critical_binaries"));
}

#[test]
fn test_detect_include_directive() {
    let yaml = r#"
name: Include Pipeline
transformations:
  - include: "${source.extra_transforms}"
  - type: value_placeholders
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert!(pipeline.is_dynamic());

    let include_refs: Vec<_> = pipeline
        .source_refs
        .iter()
        .filter(|r| matches!(r.location, sources::RefLocation::Include { .. }))
        .collect();
    assert_eq!(include_refs.len(), 1);
    assert_eq!(include_refs[0].source_id, "extra_transforms");
}

#[test]
fn test_source_refs_are_not_validated_at_parse_time() {
    // Source declarations live in external `--source` files, so a pipeline's
    // `${source.*}` references cannot be resolved at parse time. Parsing a
    // pipeline that references an unknown source must succeed; the reference
    // is validated later against the loaded external IDs.
    let yaml = r#"
name: Ref Only Pipeline
vars:
  emails: "${source.some_external_source}"
transformations:
  - type: value_placeholders
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert!(pipeline.is_dynamic());
    assert_eq!(pipeline.source_refs.len(), 1);
    assert_eq!(pipeline.source_refs[0].source_id, "some_external_source");
}

#[test]
fn test_digit_leading_and_hyphenated_source_refs_are_dynamic() {
    // Ids the runtime expands must also register as references here, or a
    // pipeline whose only reference uses one is treated as static and keeps
    // the literal template.
    let yaml = r#"
name: Id Shapes
vars:
  feed: "${source.1st_feed}"
  intel: "${source.threat-intel.ips}"
transformations:
  - type: value_placeholders
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert!(pipeline.is_dynamic());
    let ids: Vec<_> = pipeline
        .source_refs
        .iter()
        .map(|r| (r.source_id.as_str(), r.sub_path.as_deref()))
        .collect();
    assert_eq!(ids, [("1st_feed", None), ("threat-intel", Some("ips"))]);
}

#[test]
fn test_source_ids_templates_cannot_reference_are_rejected() {
    for id in ["bad.id", "has space", "\"\"", "café"] {
        let yaml = format!(
            "sources:\n  - id: {id}\n    type: file\n    path: /tmp/x.json\n    format: json\n"
        );
        let err = parse_source_list(&yaml)
            .expect_err(&format!("id {id} must be rejected"))
            .to_string();
        assert!(err.contains("is invalid"), "id {id}: {err}");
    }
    for id in ["threat-intel", "1st_feed", "ip_blocklist"] {
        let yaml = format!(
            "sources:\n  - id: {id}\n    type: file\n    path: /tmp/x.json\n    format: json\n"
        );
        assert_eq!(parse_source_list(&yaml).unwrap()[0].id, id);
    }
}

#[test]
fn test_unknown_source_type_fails() {
    let yaml = r#"
name: Bad Source Type
sources:
  - id: bad
    type: ftp
    url: ftp://example.com/data
transformations:
  - type: value_placeholders
"#;
    let result = parse_source_list(yaml);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("unknown type"), "got: {err_msg}");
}

#[test]
fn test_source_missing_id_fails() {
    let yaml = r#"
name: Missing ID
sources:
  - type: http
    url: https://api.internal/v1/data
transformations:
  - type: value_placeholders
"#;
    let result = parse_source_list(yaml);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("'id'"), "got: {err_msg}");
}

#[test]
fn test_http_source_missing_url_fails() {
    let yaml = r#"
name: Missing URL
sources:
  - id: no_url
    type: http
    format: json
transformations:
  - type: value_placeholders
"#;
    let result = parse_source_list(yaml);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("'url'"), "got: {err_msg}");
}

#[test]
fn test_command_source_missing_command_fails() {
    let yaml = r#"
name: Missing Command
sources:
  - id: no_cmd
    type: command
    format: lines
transformations:
  - type: value_placeholders
"#;
    let result = parse_source_list(yaml);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("non-empty 'command'"), "got: {err_msg}");
}

#[test]
fn test_required_defaults_to_true() {
    let yaml = r#"
name: Default Required
sources:
  - id: src
    type: http
    url: https://api.internal/v1/data
transformations:
  - type: value_placeholders
"#;
    let src_list = parse_source_list(yaml).unwrap();
    assert!(src_list[0].required);
}

#[test]
fn test_default_format_is_json() {
    let yaml = r#"
name: Default Format
sources:
  - id: src
    type: http
    url: https://api.internal/v1/data
transformations:
  - type: value_placeholders
"#;
    let src_list = parse_source_list(yaml).unwrap();
    match &src_list[0].source_type {
        sources::SourceType::Http { format, .. } => {
            assert_eq!(*format, sources::DataFormat::Json);
        }
        _ => panic!("expected Http"),
    }
}

#[test]
fn test_default_refresh_is_once() {
    let yaml = r#"
name: Default Refresh
sources:
  - id: src
    type: http
    url: https://api.internal/v1/data
transformations:
  - type: value_placeholders
"#;
    let src_list = parse_source_list(yaml).unwrap();
    assert_eq!(src_list[0].refresh, sources::RefreshPolicy::Once);
}

#[test]
fn test_default_error_policy_is_use_cached() {
    let yaml = r#"
name: Default Error Policy
sources:
  - id: src
    type: http
    url: https://api.internal/v1/data
transformations:
  - type: value_placeholders
"#;
    let src_list = parse_source_list(yaml).unwrap();
    assert_eq!(src_list[0].on_error, sources::ErrorPolicy::UseCached);
}

#[test]
fn test_multiple_sources_parse() {
    let yaml = r#"
sources:
  - id: emails
    type: http
    url: https://api.internal/v1/emails
    format: json
    refresh: 5m
  - id: config
    type: file
    path: /etc/rsigma/config.yaml
    format: yaml
    refresh: watch
    required: false
"#;
    let src_list = parse_source_list(yaml).unwrap();
    assert_eq!(src_list.len(), 2);
    assert_eq!(src_list[0].id, "emails");
    assert_eq!(src_list[1].id, "config");
    assert!(!src_list[1].required);
}

#[test]
fn test_multiple_refs() {
    let yaml = r#"
name: Multi Source
priority: 5
vars:
  admin_emails: "${source.emails}"
  log_level: "${source.config.log_level}"
transformations:
  - type: value_placeholders
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert!(pipeline.is_dynamic());
    assert_eq!(pipeline.source_refs.len(), 2);
    assert_eq!(pipeline.dynamic_references().len(), 2);
}

#[test]
fn test_source_status_tracking() {
    let mut state = PipelineState::new(HashMap::new());
    state.init_sources(["src_a".to_string(), "src_b".to_string()]);

    assert!(!state.all_sources_resolved());
    assert_eq!(state.pending_sources().len(), 2);

    state.mark_source_resolved("src_a");
    assert!(!state.all_sources_resolved());
    assert_eq!(state.pending_sources(), vec!["src_b"]);

    state.mark_source_resolved("src_b");
    assert!(state.all_sources_resolved());
    assert!(state.pending_sources().is_empty());
}

#[test]
fn test_source_status_failed() {
    let mut state = PipelineState::new(HashMap::new());
    state.init_sources(["src_a".to_string()]);

    state.mark_source_failed("src_a");
    assert_eq!(
        state.source_status("src_a"),
        Some(sources::SourceStatus::Failed)
    );
    assert!(!state.all_sources_resolved());
}

#[test]
fn test_no_sources_no_refs_pipeline_not_dynamic() {
    let yaml = r#"
name: Plain Pipeline
transformations:
  - type: field_name_prefix
    prefix: "log."
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert!(!pipeline.is_dynamic());
    assert!(pipeline.source_refs.is_empty());
}

#[test]
fn test_parse_multiple_refresh_durations() {
    let test_cases = [
        ("1h", std::time::Duration::from_secs(3600)),
        ("30m", std::time::Duration::from_secs(1800)),
        ("10s", std::time::Duration::from_secs(10)),
        ("500ms", std::time::Duration::from_millis(500)),
    ];

    for (duration_str, expected) in test_cases {
        let yaml = format!(
            r#"
sources:
  - id: src
    type: http
    url: https://api.internal/data
    refresh: {duration_str}
"#
        );
        let src_list = parse_source_list(&yaml).unwrap();
        match &src_list[0].refresh {
            sources::RefreshPolicy::Interval(d) => {
                assert_eq!(*d, expected, "failed for '{duration_str}'");
            }
            other => panic!("expected Interval for '{duration_str}', got {other:?}"),
        }
    }
}

#[test]
fn test_source_with_headers() {
    let yaml = r#"
name: Headers Pipeline
sources:
  - id: auth_source
    type: http
    url: https://api.internal/v1/data
    headers:
      Authorization: "Bearer ${API_TOKEN}"
      Accept: application/json
transformations:
  - type: value_placeholders
"#;
    let src_list = parse_source_list(yaml).unwrap();
    match &src_list[0].source_type {
        sources::SourceType::Http { headers, .. } => {
            assert_eq!(headers.len(), 2);
            assert_eq!(headers.get("Authorization").unwrap(), "Bearer ${API_TOKEN}");
            assert_eq!(headers.get("Accept").unwrap(), "application/json");
        }
        _ => panic!("expected Http"),
    }
}

#[test]
fn test_source_with_http_method() {
    let yaml = r#"
name: POST Source
sources:
  - id: post_source
    type: http
    url: https://api.internal/v1/query
    method: POST
    format: json
transformations:
  - type: value_placeholders
"#;
    let src_list = parse_source_list(yaml).unwrap();
    match &src_list[0].source_type {
        sources::SourceType::Http { method, .. } => {
            assert_eq!(method.as_deref(), Some("POST"));
        }
        _ => panic!("expected Http"),
    }
}

#[test]
fn test_source_with_http_body() {
    let yaml = r#"
name: Query Source
sources:
  - id: query_source
    type: http
    url: https://api.internal/api/v1/query
    headers:
      Content-Type: application/json
    body: |
      {"query": [{"_name": "listCase"}]}
    format: json
transformations:
  - type: value_placeholders
"#;
    let src_list = parse_source_list(yaml).unwrap();
    match &src_list[0].source_type {
        sources::SourceType::Http { method, body, .. } => {
            // The method stays unset in the parse; the POST default is applied
            // by the resolver when a body is present.
            assert_eq!(method.as_deref(), None);
            assert_eq!(
                body.as_deref(),
                Some("{\"query\": [{\"_name\": \"listCase\"}]}\n")
            );
        }
        _ => panic!("expected Http"),
    }
}

#[test]
fn test_source_with_default_value() {
    let yaml = r#"
name: Default Value
sources:
  - id: optional
    type: http
    url: https://api.internal/v1/data
    on_error: use_default
    required: false
    default:
      - fallback_value
transformations:
  - type: value_placeholders
"#;
    let src_list = parse_source_list(yaml).unwrap();
    let src = &src_list[0];
    assert_eq!(src.on_error, sources::ErrorPolicy::UseDefault);
    assert!(src.default.is_some());
}

// =============================================================================
// External source file parsing
// =============================================================================

#[test]
fn test_parse_sources_file() {
    let dir = tempfile::tempdir().unwrap();
    let sources_path = dir.path().join("sources.yml");
    std::fs::write(
        &sources_path,
        r#"
sources:
  - id: test_source
    type: file
    path: /tmp/test.json
    format: json
  - id: another_source
    type: http
    url: https://example.com/data
    format: json
    refresh: 1h
"#,
    )
    .unwrap();

    let sources = parsing::parse_sources_file(&sources_path).unwrap();
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].id, "test_source");
    assert_eq!(sources[1].id, "another_source");
}

#[test]
fn test_parse_sources_file_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.yml");
    std::fs::write(&path, "name: not_sources\n").unwrap();

    let err = parsing::parse_sources_file(&path).unwrap_err();
    assert!(err.to_string().contains("sources:"));
}

#[test]
fn test_parse_sources_file_rejects_other_top_level_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sources.yml");
    std::fs::write(
        &path,
        "sources:\n  - id: a\n    type: file\n    path: a.json\nsource:\n  - id: b\n",
    )
    .unwrap();
    let err = parsing::parse_sources_file(&path).unwrap_err().to_string();
    assert!(
        err.contains("does not accept top-level key 'source'"),
        "got: {err}"
    );
}

/// The minimal valid body for each source type, indented under the entry.
const MINIMAL_SOURCES: &[(&str, &str)] = &[
    ("http", "url: https://example.test/data\n"),
    ("command", "command: [cat, data.json]\n"),
    ("file", "path: ./data.json\n"),
    ("nats", "subject: data\n"),
    ("watchlist", "max_indicators: 100\n"),
    (
        "taxii",
        "url: https://taxii.example/api/\n    collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116\n",
    ),
];

fn source_yaml(type_name: &str, body: &str, extra: &str) -> String {
    format!("sources:\n  - id: src\n    type: {type_name}\n    {body}    {extra}")
}

#[test]
fn test_parse_source_rejects_unknown_keys_for_every_type() {
    for (type_name, body) in MINIMAL_SOURCES {
        let yaml = source_yaml(type_name, body, "fromat: json\n");
        let err = parse_source_list(&yaml).unwrap_err().to_string();
        assert!(
            err.contains(&format!(
                "source 'src' (type: {type_name}): unknown field 'fromat'"
            )) && err.contains("supported: id, type"),
            "type {type_name}: {err}"
        );
    }
}

#[test]
fn test_parse_source_rejects_keys_from_other_types() {
    let cases = [
        ("http", "path: ./data.json\n", "path"),
        ("file", "collection: x\n", "collection"),
        ("command", "url: https://example.test/\n", "url"),
        ("nats", "default_ttl: 1d\n", "default_ttl"),
        ("watchlist", "url: https://example.test/\n", "url"),
        ("taxii", "headers: { a: b }\n", "headers"),
    ];
    for (type_name, extra, field) in cases {
        let body = MINIMAL_SOURCES
            .iter()
            .find(|(t, _)| *t == type_name)
            .unwrap()
            .1;
        let err = parse_source_list(&source_yaml(type_name, body, extra))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&format!(
                "field '{field}' does not apply to type '{type_name}'"
            )),
            "type {type_name}: {err}"
        );
    }
}

#[test]
fn test_parse_source_rejects_unknown_nested_keys() {
    let cases = [
        (
            "file",
            "path: ./data.json\n    format: stix\n    stix:\n      min_confidense: 10\n",
            "stix block does not accept 'min_confidense'",
        ),
        (
            "taxii",
            "url: https://taxii.example/api/\n    collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116\n    auth:\n      bearer_token: X\n",
            "auth does not accept 'bearer_token'",
        ),
        (
            "file",
            "path: ./data.json\n    extract:\n      expr: .a\n      kind: jq\n",
            "extract does not accept 'kind'",
        ),
    ];
    for (type_name, body, needle) in cases {
        let err = parse_source_list(&source_yaml(type_name, body, ""))
            .unwrap_err()
            .to_string();
        assert!(err.contains(needle), "{needle}: {err}");
    }
}

#[test]
fn test_parse_source_rejects_unknown_values() {
    let cases = [
        (
            "format: jsn\n",
            "unknown format 'jsn'",
            "json, yaml, yml, lines, csv, stix",
        ),
        ("format: 5\n", "format must be a string", "json, yaml"),
        (
            "on_error: fial\n",
            "unknown on_error 'fial'",
            "use_cached, fail, use_default",
        ),
        (
            "refresh: sometimes\n",
            "unknown refresh 'sometimes'",
            "once, watch, push, on_demand",
        ),
        ("refresh: 5\n", "refresh must be a string", "once, watch"),
        ("timeout: soon\n", "invalid timeout 'soon'", "30s"),
        ("required: \"no\"\n", "required must be true or false", ""),
    ];
    for (extra, needle, supported) in cases {
        let err = parse_source_list(&source_yaml("file", "path: ./data.json\n", extra))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("source 'src'") && err.contains(needle) && err.contains(supported),
            "{extra}: {err}"
        );
    }
}

#[test]
fn test_parse_source_size_caps() {
    let http = |cap: &str| {
        source_yaml(
            "http",
            "url: https://example.test/data\n    format: json\n",
            &format!("max_body_size: {cap}\n"),
        )
    };
    let command = |cap: &str| {
        source_yaml(
            "command",
            "command: [cat, data.json]\n    format: json\n",
            &format!("max_stdout: {cap}\n"),
        )
    };

    let sources = parse_source_list(&http("2048")).unwrap();
    assert!(matches!(
        sources[0].source_type,
        sources::SourceType::Http {
            max_body_size: Some(2048),
            ..
        }
    ));
    let sources = parse_source_list(&command("4096")).unwrap();
    assert!(matches!(
        sources[0].source_type,
        sources::SourceType::Command {
            max_stdout: Some(4096),
            ..
        }
    ));

    for bad in ["0", "-1", "10MiB", "1.5"] {
        for (yaml, key) in [(http(bad), "max_body_size"), (command(bad), "max_stdout")] {
            let err = parse_source_list(&yaml).unwrap_err().to_string();
            assert!(
                err.contains(&format!(
                    "source 'src' {key} must be a positive integer number of bytes"
                )),
                "{key}: {bad}: {err}"
            );
        }
    }

    for (type_name, body, key) in [
        ("http", "url: https://example.test/data\n", "max_stdout"),
        ("command", "command: [cat, data.json]\n", "max_body_size"),
        ("file", "path: ./data.json\n", "max_body_size"),
        ("nats", "subject: data\n", "max_body_size"),
    ] {
        let err = parse_source_list(&source_yaml(type_name, body, &format!("{key}: 1024\n")))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&format!(
                "field '{key}' does not apply to type '{type_name}'"
            )),
            "{type_name}: {err}"
        );
    }
}

#[test]
fn test_parse_source_accepts_every_refresh_mode_and_interval() {
    for refresh in [
        "once",
        "watch",
        "push",
        "on_demand",
        "30s",
        "5m",
        "1h",
        "1d",
    ] {
        let yaml = source_yaml(
            "file",
            "path: ./data.json\n",
            &format!("refresh: {refresh}\n"),
        );
        parse_source_list(&yaml).unwrap_or_else(|e| panic!("refresh {refresh}: {e}"));
    }
}

#[test]
fn test_parse_source_accepts_every_key_its_type_lists() {
    let cases = [
        (
            "http",
            "url: https://example.test/data\n    method: POST\n    headers: { A: b }\n    body: \"{}\"\n    format: stix\n    stix: { min_confidence: 10 }\n    refresh: 5m\n    timeout: 10s\n",
        ),
        (
            "http",
            "url: https://example.test/data\n    format: json\n    extract: .a\n    max_body_size: 1048576\n",
        ),
        (
            "command",
            "command: [cat, data.json]\n    format: lines\n    extract: .a\n    refresh: once\n    timeout: 5s\n    max_stdout: 1048576\n",
        ),
        (
            "file",
            "path: ./data.json\n    format: stix\n    stix: { observables: [ipv4] }\n    refresh: watch\n    timeout: 5s\n",
        ),
        (
            "nats",
            "url: nats://localhost:4222\n    subject: data\n    format: json\n    extract: .a\n    refresh: push\n    timeout: 5s\n",
        ),
        (
            "watchlist",
            "max_indicators: 10\n    max_value_length: 64\n    default_ttl: 1d\n",
        ),
        (
            "taxii",
            "url: https://taxii.example/api/\n    collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116\n    auth: { bearer_token_env: TOKEN }\n    page_size: 100\n    stix: { max_indicators: 10 }\n    refresh: 1h\n    timeout: 30s\n",
        ),
    ];
    let common = "on_error: use_default\n    required: false\n    default: []\n";
    for (type_name, body) in cases {
        let yaml = source_yaml(type_name, body, common);
        parse_source_list(&yaml).unwrap_or_else(|e| panic!("type {type_name}: {e}"));
    }
}

#[test]
fn test_parse_sources_dir() {
    let dir = tempfile::tempdir().unwrap();

    std::fs::write(
        dir.path().join("01-infra.yml"),
        r#"
sources:
  - id: infra_src
    type: file
    path: /tmp/infra.json
    format: json
"#,
    )
    .unwrap();

    std::fs::write(
        dir.path().join("02-threat.yaml"),
        r#"
sources:
  - id: threat_src
    type: http
    url: https://example.com/iocs
    format: json
"#,
    )
    .unwrap();

    // Non-YAML files should be ignored
    std::fs::write(dir.path().join("readme.txt"), "not yaml").unwrap();

    let sources = parsing::parse_sources_dir(dir.path()).unwrap();
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].id, "infra_src");
    assert_eq!(sources[1].id, "threat_src");
}

// =============================================================================
// validate_source_refs with external IDs
// =============================================================================

#[test]
fn test_validate_source_refs_with_external_ids() {
    let yaml = r#"
name: test
transformations:
  - type: value_placeholders
    include: "${source.ext_lookup}"
"#;
    // Parsing succeeds: references are validated later against external IDs,
    // not at parse time.
    let pipeline = parse_pipeline(yaml);
    assert!(pipeline.is_ok(), "parse should defer reference validation");

    let value: yaml_serde::Value = yaml_serde::from_str(yaml).unwrap();
    let obj = value.as_mapping().unwrap();
    let source_refs = super::parsing::scan_source_refs(obj);

    let mut external = std::collections::HashSet::new();
    external.insert("ext_lookup".to_string());

    assert!(parsing::validate_source_refs(&source_refs, Some(&external)).is_ok());
}

// =============================================================================
// transform_rule / transform_collection
// =============================================================================

/// Sysmon-shaped routing: inject an EventID per category, then unify the
/// logsource onto the sysmon service.
fn sysmon_routing_pipeline() -> Pipeline {
    parse_pipeline(
        r#"
name: sysmon routing
priority: 10
transformations:
  - id: sysmon_process_creation
    type: add_condition
    conditions:
      EventID: 1
    rule_conditions:
      - type: logsource
        category: process_creation
        product: windows
  - id: sysmon_logsource
    type: change_logsource
    product: windows
    service: sysmon
    rule_conditions:
      - type: logsource
        product: windows
"#,
    )
    .unwrap()
}

fn process_creation_rule_yaml() -> &'static str {
    r#"
title: Whoami Execution
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"#
}

#[test]
fn test_transform_rule_reports_rewritten_logsource_and_applied_ids() {
    let pipeline = sysmon_routing_pipeline();
    let collection = rsigma_parser::parse_sigma_yaml(process_creation_rule_yaml()).unwrap();

    let transformed = transform_rule(&[pipeline], &collection.rules[0]).unwrap();

    assert_eq!(
        transformed.rule.logsource.service.as_deref(),
        Some("sysmon"),
        "change_logsource should be visible on the returned rule"
    );
    assert_eq!(
        transformed.applied_items,
        vec![
            "sysmon_logsource".to_string(),
            "sysmon_process_creation".to_string()
        ],
        "applied ids are sorted"
    );

    // The injected EventID condition reaches the detection block.
    let named = &transformed.rule.detection.named;
    let has_event_id = named.values().any(|detection| {
        format!("{detection:?}").contains("EventID")
            || format!("{detection:?}").contains("event_id")
    });
    assert!(has_event_id, "add_condition should inject the EventID item");
}

#[test]
fn test_transform_rule_leaves_input_untouched() {
    let pipeline = sysmon_routing_pipeline();
    let collection = rsigma_parser::parse_sigma_yaml(process_creation_rule_yaml()).unwrap();
    let original = &collection.rules[0];

    let transformed = transform_rule(&[pipeline], original).unwrap();

    assert_eq!(original.logsource.service, None);
    assert_eq!(
        transformed.rule.logsource.service.as_deref(),
        Some("sysmon")
    );
}

#[test]
fn test_transform_rule_without_pipelines_is_a_passthrough() {
    let collection = rsigma_parser::parse_sigma_yaml(process_creation_rule_yaml()).unwrap();

    let transformed = transform_rule(&[], &collection.rules[0]).unwrap();

    assert!(transformed.applied_items.is_empty());
    assert_eq!(transformed.rule.logsource.service, None);
    assert_eq!(transformed.rule.title, collection.rules[0].title);
}

/// Two pipelines that only compose one way: `second` renames the field
/// `first` produces, so `process.command_line` in the output proves that
/// `first` ran before `second`.
fn chained_rename_pipelines() -> (Pipeline, Pipeline) {
    let first = parse_pipeline(
        r#"
name: first
priority: 10
transformations:
  - id: to_intermediate
    type: field_name_mapping
    mapping:
      CommandLine: intermediate.command_line
"#,
    )
    .unwrap();
    let second = parse_pipeline(
        r#"
name: second
priority: 20
transformations:
  - id: to_final
    type: field_name_mapping
    mapping:
      intermediate.command_line: process.command_line
"#,
    )
    .unwrap();
    (first, second)
}

#[test]
fn test_transform_rule_applies_pipelines_in_slice_order() {
    let (first, second) = chained_rename_pipelines();
    let collection = rsigma_parser::parse_sigma_yaml(process_creation_rule_yaml()).unwrap();

    let transformed = transform_rule(&[first, second], &collection.rules[0]).unwrap();

    assert_eq!(
        transformed.applied_items,
        vec!["to_final".to_string(), "to_intermediate".to_string()]
    );
    let rendered = format!("{:?}", transformed.rule.detection.named);
    assert!(
        rendered.contains("process.command_line"),
        "second pipeline should see the first pipeline's output: {rendered}"
    );
}

#[test]
fn test_transform_rule_honors_priority_after_merge_pipelines() {
    // Handed to transform_rule out of priority order, the chain cannot compose:
    // `second` runs against a field that does not exist yet.
    let (first, second) = chained_rename_pipelines();
    let collection = rsigma_parser::parse_sigma_yaml(process_creation_rule_yaml()).unwrap();

    let unsorted = transform_rule(&[second.clone(), first.clone()], &collection.rules[0]).unwrap();
    assert!(
        !format!("{:?}", unsorted.rule.detection.named).contains("process.command_line"),
        "slice order is honored as-is, so the reversed chain does not compose"
    );

    // merge_pipelines sorts by priority, which is how an Engine holds them.
    let mut pipelines = vec![second, first];
    merge_pipelines(&mut pipelines);
    let sorted = transform_rule(&pipelines, &collection.rules[0]).unwrap();
    assert!(
        format!("{:?}", sorted.rule.detection.named).contains("process.command_line"),
        "after sorting, the chain composes again"
    );
}

#[test]
fn test_transform_collection_covers_every_detection_rule() {
    let pipeline = sysmon_routing_pipeline();
    let yaml = r#"
title: First
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
---
title: Second
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains: id
    condition: selection
"#;
    let collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();

    let transformed = transform_collection(&[pipeline], &collection).unwrap();

    assert_eq!(transformed.len(), 2);
    assert_eq!(transformed[0].rule.title, "First");
    assert_eq!(
        transformed[0].rule.logsource.service.as_deref(),
        Some("sysmon")
    );
    // The linux rule matches neither rule_condition, so nothing fires.
    assert_eq!(transformed[1].rule.title, "Second");
    assert_eq!(transformed[1].rule.logsource.service, None);
    assert!(transformed[1].applied_items.is_empty());
}

#[test]
fn test_transform_collection_scopes_state_per_rule() {
    // Fires only for the windows rule, so the linux rule's result must not
    // inherit either the applied id or the state key.
    let pipeline = parse_pipeline(
        r#"
name: windows only
transformations:
  - id: set_windows_index
    type: set_state
    key: index
    value: windows-sysmon
    rule_conditions:
      - type: logsource
        product: windows
"#,
    )
    .unwrap();
    let yaml = r#"
title: Windows
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
---
title: Linux
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains: id
    condition: selection
"#;
    let collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();

    let transformed = transform_collection(&[pipeline], &collection).unwrap();

    assert_eq!(
        transformed[0]
            .state
            .get_state("index")
            .and_then(|v| v.as_str()),
        Some("windows-sysmon")
    );
    assert_eq!(
        transformed[0].applied_items,
        vec!["set_windows_index".to_string()]
    );

    assert!(
        transformed[1].state.get_state("index").is_none(),
        "state must not leak from the previous rule"
    );
    assert!(
        transformed[1].applied_items.is_empty(),
        "applied ids must not leak from the previous rule"
    );
}

#[test]
fn test_transform_rule_exposes_pipeline_state() {
    let pipeline = parse_pipeline(
        r#"
name: stateful
transformations:
  - id: set_index
    type: set_state
    key: index
    value: windows-sysmon
"#,
    )
    .unwrap();
    let collection = rsigma_parser::parse_sigma_yaml(process_creation_rule_yaml()).unwrap();

    let transformed = transform_rule(&[pipeline], &collection.rules[0]).unwrap();

    assert_eq!(
        transformed
            .state
            .get_state("index")
            .and_then(|v| v.as_str()),
        Some("windows-sysmon")
    );
}

#[test]
fn test_validate_source_refs_undeclared_even_with_externals() {
    let refs = vec![sources::SourceRef {
        source_id: "missing".to_string(),
        sub_path: None,
        location: sources::RefLocation::Var {
            var_name: "x".to_string(),
        },
        raw_template: "${source.missing}".to_string(),
    }];
    let mut external = std::collections::HashSet::new();
    external.insert("other_id".to_string());

    let result = parsing::validate_source_refs(&refs, Some(&external));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("missing"));
}

fn conformance_rule(detection: &str) -> rsigma_parser::SigmaRule {
    let yaml = format!(
        "title: Pipeline conformance\nlogsource:\n  category: test\n  product: conformance\n\
         detection:\n{detection}\n  condition: sel\n"
    );
    rsigma_parser::parse_sigma_yaml(&yaml)
        .unwrap()
        .rules
        .remove(0)
}

fn conformance_items(rule: &rsigma_parser::SigmaRule) -> &[rsigma_parser::DetectionItem] {
    match &rule.detection.named["sel"] {
        rsigma_parser::Detection::AllOf(items) => items,
        other => panic!("expected AllOf, got {other:?}"),
    }
}

#[test]
fn pysigma_rule_condition_linking_and_negation_apply() {
    let rule = conformance_rule("  sel:\n    F: x");
    let or_pipeline = parse_pipeline(
        r#"
name: condition or
transformations:
  - type: field_name_mapping
    mapping: {F: A}
    rule_conditions:
      - type: logsource
        product: nope
      - type: logsource
        category: test
    rule_cond_op: or
"#,
    )
    .unwrap();
    let transformed = transform_rule(&[or_pipeline], &rule).unwrap();
    assert_eq!(
        conformance_items(&transformed.rule)[0]
            .field
            .name
            .as_deref(),
        Some("A")
    );

    let not_pipeline = parse_pipeline(
        r#"
name: condition not
transformations:
  - type: field_name_mapping
    mapping: {F: A}
    rule_conditions:
      - type: logsource
        category: test
    rule_cond_not: true
"#,
    )
    .unwrap();
    let transformed = transform_rule(&[not_pipeline], &rule).unwrap();
    assert_eq!(
        conformance_items(&transformed.rule)[0]
            .field
            .name
            .as_deref(),
        Some("F")
    );
}

#[test]
fn pysigma_condition_expressions_accept_dict_form_and_canonical_keys() {
    let rule = conformance_rule("  sel:\n    F: drop_me\n    G: keep");
    let pipeline = parse_pipeline(
        r#"
name: condition expressions
transformations:
  - type: drop_detection_item
    rule_conditions:
      category:
        type: logsource
        category: test
      wrong_product:
        type: logsource
        product: nope
    rule_cond_expr: category and not wrong_product
    detection_item_conditions:
      drop:
        type: match_string
        pattern: "^drop"
      other:
        type: match_string
        pattern: "^other"
    detection_item_cond_expr: drop or other
"#,
    )
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    let fields: Vec<&str> = conformance_items(&transformed.rule)
        .iter()
        .filter_map(|item| item.field.name.as_deref())
        .collect();
    assert_eq!(fields, ["G"]);
}

#[test]
fn pysigma_field_condition_expression_controls_mapping() {
    let rule = conformance_rule("  sel:\n    F: x\n    G: y");
    let pipeline = parse_pipeline(
        r#"
name: field expression
transformations:
  - type: field_name_prefix
    prefix: mapped.
    field_name_conditions:
      selected:
        type: include_fields
        fields: [F]
      allowed:
        type: exclude_fields
        fields: [Never]
    field_name_cond_expr: selected and allowed
"#,
    )
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    let fields: Vec<&str> = conformance_items(&transformed.rule)
        .iter()
        .filter_map(|item| item.field.name.as_deref())
        .collect();
    assert_eq!(fields, ["mapped.F", "G"]);
}

#[test]
fn set_state_val_and_processing_state_operators_are_typed() {
    let rule = conformance_rule("  sel:\n    F: x");
    let pipeline = parse_pipeline(
        r#"
name: state comparison
transformations:
  - type: set_state
    key: score
    val: 5
  - type: field_name_mapping
    mapping: {F: A}
    rule_conditions:
      - type: processing_state
        key: score
        val: 3
        op: gt
"#,
    )
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    assert_eq!(
        transformed.state.get_state("score"),
        Some(&serde_json::json!(5))
    );
    assert_eq!(
        conformance_items(&transformed.rule)[0]
            .field
            .name
            .as_deref(),
        Some("A")
    );
}

#[test]
fn processing_state_operators_apply_at_detection_and_field_scope() {
    let rule = conformance_rule("  sel:\n    F: x");
    let pipeline = parse_pipeline(
        r#"
name: scoped state comparisons
transformations:
  - type: set_state
    key: score
    val: 5
  - type: drop_detection_item
    detection_item_conditions:
      - type: processing_state
        key: score
        val: 6
        op: gte
  - type: field_name_mapping
    mapping: {F: A}
    field_name_conditions:
      - type: processing_state
        key: score
        val: 5
        op: gte
"#,
    )
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    assert_eq!(
        conformance_items(&transformed.rule)[0]
            .field
            .name
            .as_deref(),
        Some("A")
    );
}

#[test]
fn field_transformations_map_field_reference_targets() {
    let rule = conformance_rule("  sel:\n    F|fieldref: G");
    let cases = [
        ("type: field_name_mapping\n    mapping: {G: B}", "B"),
        ("type: field_name_prefix_mapping\n    mapping: {G: B}", "B"),
        ("type: field_name_prefix\n    prefix: x.", "x.G"),
        ("type: field_name_suffix\n    suffix: .x", "G.x"),
    ];

    for (transformation, expected) in cases {
        let pipeline = parse_pipeline(&format!(
            "name: fieldref\ntransformations:\n  - {transformation}\n"
        ))
        .unwrap();
        let transformed = transform_rule(&[pipeline], &rule).unwrap();
        let value = &conformance_items(&transformed.rule)[0].values[0];
        let SigmaValue::String(value) = value else {
            panic!("expected string field reference");
        };
        assert_eq!(value.as_plain().as_deref(), Some(expected));
    }
}

#[test]
fn detection_item_conditions_gate_field_transformations() {
    let rule = conformance_rule("  sel:\n    F|fieldref: G");
    let transformations = [
        "type: field_name_mapping\n    mapping: {F: A, G: B}",
        "type: field_name_prefix_mapping\n    mapping: {F: A, G: B}",
        "type: field_name_prefix\n    prefix: x.",
        "type: field_name_suffix\n    suffix: .x",
        "type: field_name_transform\n    transform_func: lower",
    ];

    for transformation in transformations {
        let pipeline = parse_pipeline(&format!(
            "name: gated\ntransformations:\n  - {transformation}\n    detection_item_conditions:\n      - type: match_string\n        pattern: '^never$'\n"
        ))
        .unwrap();
        let transformed = transform_rule(&[pipeline], &rule).unwrap();
        let item = &conformance_items(&transformed.rule)[0];
        assert_eq!(item.field.name.as_deref(), Some("F"));
        let SigmaValue::String(value) = &item.values[0] else {
            panic!("expected field reference string");
        };
        assert_eq!(value.as_plain().as_deref(), Some("G"));
    }

    // Field references are not strings, so only the negated pattern holds.
    let pipeline = parse_pipeline(
        "name: unmatched\ntransformations:\n  - type: field_name_mapping\n    mapping: {F: A, G: B}\n    detection_item_conditions:\n      - type: match_string\n        pattern: '^G$'\n",
    )
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    assert_eq!(
        conformance_items(&transformed.rule)[0]
            .field
            .name
            .as_deref(),
        Some("F")
    );

    let pipeline = parse_pipeline(
        "name: matched\ntransformations:\n  - type: field_name_mapping\n    mapping: {F: A, G: B}\n    detection_item_conditions:\n      - type: match_string\n        pattern: '^G$'\n        negate: true\n",
    )
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    let item = &conformance_items(&transformed.rule)[0];
    assert_eq!(item.field.name.as_deref(), Some("A"));
    let SigmaValue::String(value) = &item.values[0] else {
        panic!("expected field reference string");
    };
    assert_eq!(value.as_plain().as_deref(), Some("B"));
}

#[test]
fn empty_condition_negation_follows_scope_semantics() {
    let rule = conformance_rule("  sel:\n    F: value");
    let cases = [
        ("rule_conditions: []\n    rule_cond_not: true", Some("A")),
        (
            "detection_item_conditions: []\n    detection_item_cond_not: true",
            Some("F"),
        ),
        (
            "field_name_conditions: []\n    field_name_cond_not: true",
            Some("F"),
        ),
    ];

    for (conditions, expected) in cases {
        let pipeline = parse_pipeline(&format!(
            "name: empty\ntransformations:\n  - type: field_name_mapping\n    mapping: {{F: A}}\n    {conditions}\n"
        ))
        .unwrap();
        let transformed = transform_rule(&[pipeline], &rule).unwrap();
        assert_eq!(
            conformance_items(&transformed.rule)[0]
                .field
                .name
                .as_deref(),
            expected
        );
    }
}

#[test]
fn value_placeholders_expand_cartesian_product_only_on_expand_values() {
    let rule = conformance_rule("  sel:\n    A|expand: '%x%-%y%'\n    B: '%x%'");
    let pipeline = parse_pipeline(
        r#"
name: placeholders
vars:
  x: [a, b]
  y: [1, 2]
transformations:
  - type: value_placeholders
"#,
    )
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    let items = conformance_items(&transformed.rule);
    let expanded_item = items
        .iter()
        .find(|item| item.field.name.as_deref() == Some("A"))
        .unwrap();
    let expanded: Vec<String> = expanded_item
        .values
        .iter()
        .filter_map(|value| match value {
            SigmaValue::String(value) => value.as_plain(),
            _ => None,
        })
        .collect();
    assert_eq!(expanded, ["a-1", "a-2", "b-1", "b-2"]);
    let literal_item = items
        .iter()
        .find(|item| item.field.name.as_deref() == Some("B"))
        .unwrap();
    let SigmaValue::String(literal) = &literal_item.values[0] else {
        panic!("expected literal string");
    };
    assert_eq!(literal.original, "%x%");
}

#[test]
fn unresolved_value_placeholder_fails_but_wildcard_resolves_it() {
    let rule = conformance_rule("  sel:\n    F|expand: '%missing%'");
    let value_pipeline =
        parse_pipeline("name: unresolved\ntransformations:\n  - type: value_placeholders\n")
            .unwrap();
    let error = transform_rule(&[value_pipeline], &rule).unwrap_err();
    assert!(error.to_string().contains("missing"));

    let wildcard_pipeline =
        parse_pipeline("name: wildcard\ntransformations:\n  - type: wildcard_placeholders\n")
            .unwrap();
    let transformed = transform_rule(&[wildcard_pipeline], &rule).unwrap();
    let SigmaValue::String(value) = &conformance_items(&transformed.rule)[0].values[0] else {
        panic!("expected wildcard string");
    };
    assert_eq!(value.original, "*");
}

#[test]
fn placeholder_include_and_exclude_limit_expansion() {
    let rule = conformance_rule("  sel:\n    F|expand: '%x%-%y%'");
    for filter in ["include: [x]", "exclude: [y]"] {
        let pipeline = parse_pipeline(&format!(
            "name: filtered\nvars:\n  x: [a, b]\ntransformations:\n  - type: value_placeholders\n    {filter}\n"
        ))
        .unwrap();
        let transformed = transform_rule(&[pipeline], &rule).unwrap();
        let values: Vec<_> = conformance_items(&transformed.rule)[0]
            .values
            .iter()
            .map(|value| match value {
                SigmaValue::String(value) => value.original.as_str(),
                _ => panic!("expected string"),
            })
            .collect();
        assert_eq!(values, ["a-%y%", "b-%y%"]);
    }
}

#[test]
fn skipped_placeholders_do_not_consume_expansion_depth() {
    let skipped = (0..64)
        .map(|index| format!("%skip{index}%"))
        .collect::<String>();
    let rule = conformance_rule(&format!("  sel:\n    F|expand: '{skipped}%x%'"));
    let pipeline = parse_pipeline(
        "name: filtered\nvars:\n  x: done\ntransformations:\n  - type: value_placeholders\n    include: [x]\n",
    )
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    let SigmaValue::String(value) = &conformance_items(&transformed.rule)[0].values[0] else {
        panic!("expected string");
    };
    assert_eq!(value.original, format!("{skipped}done"));
}

#[test]
fn placeholder_include_and_exclude_are_mutually_exclusive() {
    let error = parse_pipeline(
        "name: invalid\ntransformations:\n  - type: value_placeholders\n    include: [x]\n    exclude: [y]\n",
    )
    .unwrap_err();
    assert!(error.to_string().contains("both include and exclude"));
}

#[test]
fn query_expression_placeholder_filters_are_rejected() {
    for filter in [
        "mapping: {users: allowed_users}",
        "include: [users]",
        "exclude: [users]",
    ] {
        let error = parse_pipeline(&format!(
            "name: query\ntransformations:\n  - type: query_expression_placeholders\n    expression: '{{field}} IN ({{id}})'\n    {filter}\n"
        ))
        .unwrap_err();
        let key = filter.split(':').next().unwrap();
        assert!(
            error.to_string().contains(&format!(
                "query_expression_placeholders '{key}' is not supported"
            )),
            "{error}"
        );
    }
}

#[test]
fn unknown_transformation_item_key_is_rejected() {
    let error = parse_pipeline(
        "name: typo\ntransformations:\n  - type: field_name_mapping\n    mapping: {F: A}\n    rule_cond_opp: or\n",
    )
    .unwrap_err();
    assert!(error.to_string().contains("rule_cond_opp"));
}

fn renamed_fields(rule: &rsigma_parser::SigmaRule, suffix: &str) -> Vec<String> {
    let mut renamed: Vec<String> = conformance_items(rule)
        .iter()
        .filter_map(|item| item.field.name.as_deref())
        .filter_map(|name| name.strip_suffix(suffix))
        .map(str::to_string)
        .collect();
    renamed.sort();
    renamed
}

fn suffix_where(condition: &str) -> Pipeline {
    parse_pipeline(&format!(
        "name: gated\ntransformations:\n  - type: field_name_suffix\n    suffix: _s\n    detection_item_conditions:\n      - {condition}\n"
    ))
    .unwrap()
}

#[test]
fn match_string_matches_pysigma_value_text_from_the_start() {
    let rule = conformance_rule(
        "  sel:\n    F|contains: who\n    G: 'a\\*b'\n    H|fieldref: F\n    N: 5",
    );
    let cases = [
        (r"pattern: '\*who\*'", vec!["F"]),
        ("pattern: 'who'", vec![]),
        (r"pattern: 'a\\\*b'", vec!["G"]),
        ("pattern: '.*'\n        negate: true", vec!["H", "N"]),
    ];
    for (pattern, expected) in cases {
        let pipeline = suffix_where(&format!("type: match_string\n        {pattern}"));
        let transformed = transform_rule(&[pipeline], &rule).unwrap();
        assert_eq!(
            renamed_fields(&transformed.rule, "_s"),
            expected,
            "{pattern}"
        );
    }
}

#[test]
fn value_conditions_combine_values_with_cond() {
    let rule = conformance_rule("  sel:\n    F: [x, y]\n    G: [null, x]\n    H: [null]");
    let cases = [
        (
            "type: match_string\n        pattern: '[xy]'\n        cond: all",
            vec!["F"],
        ),
        (
            "type: match_string\n        pattern: '[xy]'\n        cond: any",
            vec!["F", "G"],
        ),
        ("type: is_null\n        cond: all", vec!["H"]),
        ("type: is_null\n        cond: any", vec!["G", "H"]),
        (
            "type: is_null\n        cond: all\n        negate: true",
            vec!["F", "G"],
        ),
    ];
    for (condition, expected) in cases {
        let transformed = transform_rule(&[suffix_where(condition)], &rule).unwrap();
        assert_eq!(
            renamed_fields(&transformed.rule, "_s"),
            expected,
            "{condition}"
        );
    }

    let error = parse_pipeline(
        "name: bad\ntransformations:\n  - type: field_name_suffix\n    suffix: _s\n    detection_item_conditions:\n      - type: is_null\n        cond: some\n",
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("expected 'any' or 'all'"),
        "{error}"
    );
}

#[test]
fn processing_state_equality_compares_numbers_by_value() {
    let rule = conformance_rule("  sel:\n    F: x");
    for (op, expected) in [("eq", vec!["F"]), ("ne", vec![])] {
        let pipeline = parse_pipeline(&format!(
            "name: state\ntransformations:\n  - type: set_state\n    key: k\n    val: 1\n  - type: field_name_suffix\n    suffix: _s\n    rule_conditions:\n      - type: processing_state\n        key: k\n        val: 1.0\n        op: {op}\n"
        ))
        .unwrap();
        let transformed = transform_rule(&[pipeline], &rule).unwrap();
        assert_eq!(renamed_fields(&transformed.rule, "_s"), expected, "{op}");
    }
}

#[test]
fn field_name_regex_conditions_match_from_the_start() {
    let rule = conformance_rule("  sel:\n    CommandLine: x");
    for (pattern, expected) in [("Line", vec![]), ("Command", vec!["CommandLine"])] {
        let pipeline = parse_pipeline(&format!(
            "name: re\ntransformations:\n  - type: field_name_suffix\n    suffix: _s\n    field_name_conditions:\n      - type: include_fields\n        mode: re\n        fields: ['{pattern}']\n"
        ))
        .unwrap();
        let transformed = transform_rule(&[pipeline], &rule).unwrap();
        assert_eq!(
            renamed_fields(&transformed.rule, "_s"),
            expected,
            "{pattern}"
        );
    }
}

#[test]
fn field_name_conditions_select_items_through_field_reference_targets() {
    let rule = conformance_rule("  sel:\n    F|fieldref: G\n    H: x");
    let pipeline = parse_pipeline(
        "name: drop\ntransformations:\n  - type: drop_detection_item\n    field_name_conditions:\n      - type: include_fields\n        fields: [G]\n",
    )
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    let names: Vec<_> = conformance_items(&transformed.rule)
        .iter()
        .map(|item| item.field.name.as_deref().unwrap())
        .collect();
    assert_eq!(names, ["H"]);

    for (fields, fails) in [("[Other]", false), ("[G]", true)] {
        let pipeline = parse_pipeline(&format!(
            "name: failure\ntransformations:\n  - type: detection_item_failure\n    message: unsupported\n    field_name_conditions:\n      - type: include_fields\n        fields: {fields}\n"
        ))
        .unwrap();
        assert_eq!(
            transform_rule(&[pipeline], &rule).is_err(),
            fails,
            "{fields}"
        );
    }
}

#[test]
fn detection_item_processing_item_applied_follows_changed_items() {
    let rule = conformance_rule("  sel:\n    F: xa\n    H: ya");
    for (id, expected) in [("map", vec!["G"]), ("repl", vec!["G", "H"])] {
        let pipeline = parse_pipeline(&format!(
            "name: applied\ntransformations:\n  - id: map\n    type: field_name_mapping\n    mapping: {{F: G}}\n  - id: repl\n    type: replace_string\n    regex: a\n    replacement: b\n  - type: field_name_suffix\n    suffix: _s\n    detection_item_conditions:\n      - type: processing_item_applied\n        processing_item_id: {id}\n"
        ))
        .unwrap();
        let transformed = transform_rule(&[pipeline], &rule).unwrap();
        assert_eq!(renamed_fields(&transformed.rule, "_s"), expected, "{id}");
    }
}

#[test]
fn field_name_processing_item_applied_tracks_renamed_fields() {
    let rule = rsigma_parser::parse_sigma_yaml(
        "title: Fields\nlogsource:\n  category: test\nfields: [G, K]\ndetection:\n  sel:\n    F|fieldref: G\n  condition: sel\n",
    )
    .unwrap()
    .rules
    .remove(0);
    let pipeline = parse_pipeline(
        "name: applied\ntransformations:\n  - id: map\n    type: field_name_mapping\n    mapping: {G: G2, K: [K1, K2]}\n  - type: field_name_suffix\n    suffix: _s\n    field_name_conditions:\n      - type: processing_item_applied\n        processing_item_id: map\n",
    )
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    assert_eq!(transformed.rule.fields, ["G2_s", "K1_s", "K2_s"]);
    let item = &conformance_items(&transformed.rule)[0];
    assert_eq!(item.field.name.as_deref(), Some("F"));
    let SigmaValue::String(target) = &item.values[0] else {
        panic!("expected field reference");
    };
    assert_eq!(target.as_plain().as_deref(), Some("G2_s"));
}

#[test]
fn nest_applies_inner_items_under_their_own_conditions() {
    let rule = conformance_rule("  sel:\n    F: x\n    G: y");
    let pipeline = parse_pipeline(
        r#"
name: nest
transformations:
  - type: nest
    detection_item_conditions:
      - type: match_string
        pattern: '^never$'
    items:
      - type: field_name_suffix
        suffix: _s
        field_name_conditions:
          - type: include_fields
            fields: [G]
"#,
    )
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    assert_eq!(renamed_fields(&transformed.rule, "_s"), ["G"]);
}

#[test]
fn correlation_field_renames_honor_field_name_conditions_and_nest() {
    let collection = rsigma_parser::parse_sigma_yaml(
        r#"
title: Base
name: base
logsource:
  category: test
detection:
  sel:
    A: x
  condition: sel
---
title: Count
correlation:
  type: event_count
  rules: [base]
  group-by: [A, B]
  timespan: 5m
  condition:
    gte: 2
"#,
    )
    .unwrap();
    let pipeline = parse_pipeline(
        r#"
name: correlation
transformations:
  - type: field_name_prefix
    prefix: x.
    field_name_conditions:
      - type: include_fields
        fields: [A]
  - type: nest
    items:
      - type: field_name_suffix
        suffix: _s
        field_name_conditions:
          - type: include_fields
            fields: [B]
"#,
    )
    .unwrap();
    let mut correlation = collection.correlations[0].clone();
    let mut state = PipelineState::new(pipeline.vars.clone());
    pipeline
        .apply_to_correlation(&mut correlation, &mut state)
        .unwrap();
    assert_eq!(correlation.group_by, ["x.A", "B_s"]);
}

#[test]
fn transformation_parameters_follow_pysigma() {
    let rule = conformance_rule("  sel:\n    F: x");
    for (force_type, value, expected) in [
        ("str", "5", SigmaValue::String(SigmaString::new("5"))),
        ("num", "'42'", SigmaValue::Integer(42)),
    ] {
        let pipeline = parse_pipeline(&format!(
            "name: set\ntransformations:\n  - type: set_value\n    value: {value}\n    force_type: {force_type}\n"
        ))
        .unwrap();
        let transformed = transform_rule(&[pipeline], &rule).unwrap();
        assert_eq!(conformance_items(&transformed.rule)[0].values, [expected]);
    }

    let rejected = [
        (
            "type: set_value\n    value: abc\n    force_type: num",
            "can't be converted to a number",
        ),
        (
            "type: set_value\n    value: abc\n    force_type: bool",
            "expected 'str' or 'num'",
        ),
        (
            "type: regex\n    method: plain",
            "regex method 'plain' is not supported",
        ),
        ("type: regex\n    method: nope", "invalid regex 'method'"),
        (
            "type: field_name_transform\n    transform_func: lower\n    apply_keyword: true",
            "'apply_keyword' is not supported",
        ),
        ("type: hashes_fields", "requires 'valid_hash_algos'"),
    ];
    for (transformation, message) in rejected {
        let error = parse_pipeline(&format!(
            "name: rejected\ntransformations:\n  - {transformation}\n"
        ))
        .unwrap_err();
        assert!(
            error.to_string().contains(message),
            "{transformation}: {error}"
        );
    }

    for transformation in [
        "type: regex\n    method: ignore_case_flag",
        "type: field_name_transform\n    transform_func: lower\n    apply_keyword: false",
    ] {
        parse_pipeline(&format!(
            "name: accepted\ntransformations:\n  - {transformation}\n"
        ))
        .unwrap();
    }
}

#[test]
fn hashes_fields_parses_field_to_parse_and_defaults() {
    let rule = conformance_rule("  sel:\n    Hash: MD5=abc\n    Hashes: SHA1=def");
    let pipeline = parse_pipeline(
        "name: hashes\ntransformations:\n  - type: hashes_fields\n    valid_hash_algos: [MD5, SHA1]\n    field_to_parse: Hash\n",
    )
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    let rsigma_parser::Detection::And(parts) = &transformed.rule.detection.named["sel"] else {
        panic!("expected the hash group next to the kept item");
    };
    let rsigma_parser::Detection::AllOf(kept) = &parts[0] else {
        panic!("expected kept items");
    };
    assert_eq!(kept[0].field.name.as_deref(), Some("Hashes"));
    let rsigma_parser::Detection::AnyOf(group) = &parts[1] else {
        panic!("expected an OR group");
    };
    let rsigma_parser::Detection::AllOf(md5) = &group[0] else {
        panic!("expected one item per algorithm");
    };
    assert_eq!(md5[0].field.name.as_deref(), Some("MD5"));
}

#[test]
fn add_condition_name_and_template() {
    let rule = conformance_rule("  sel:\n    F: x");
    let pipeline = parse_pipeline(
        r#"
name: add
transformations:
  - type: add_condition
    name: scope
    template: true
    conditions:
      Index: '$category-${product}-$service-$$'
"#,
    )
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    let rsigma_parser::Detection::AllOf(items) = &transformed.rule.detection.named["scope"] else {
        panic!("expected the named condition");
    };
    let SigmaValue::String(value) = &items[0].values[0] else {
        panic!("expected string");
    };
    assert_eq!(value.original, "test-conformance-$service-$");

    let colliding = parse_pipeline(
        "name: add\ntransformations:\n  - type: add_condition\n    name: sel\n    conditions:\n      G: y\n",
    )
    .unwrap();
    let error = transform_rule(&[colliding], &rule).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("collides with an existing detection"),
        "{error}"
    );
}

#[test]
fn replace_string_interpret_special_parses_wildcards_in_the_result() {
    let rule = conformance_rule("  sel:\n    F: 'a-b'");
    for (interpret, expected_wildcard) in [(false, false), (true, true)] {
        let pipeline = parse_pipeline(&format!(
            "name: replace\ntransformations:\n  - type: replace_string\n    regex: '-'\n    replacement: '*'\n    skip_special: true\n    interpret_special: {interpret}\n"
        ))
        .unwrap();
        let transformed = transform_rule(&[pipeline], &rule).unwrap();
        let SigmaValue::String(value) = &conformance_items(&transformed.rule)[0].values[0] else {
            panic!("expected string");
        };
        assert_eq!(value.contains_wildcards(), expected_wildcard, "{interpret}");
    }
}

#[test]
fn escaped_percent_stays_literal_after_expansion() {
    let collection = rsigma_parser::parse_sigma_yaml(
        "title: Escaped\nlogsource:\n  category: test\ndetection:\n  sel:\n    F|expand: 'q\\%a\\%-%a%'\n  condition: sel\n",
    )
    .unwrap();
    let pipeline = parse_pipeline(
        "name: placeholders\nvars:\n  a: [x]\ntransformations:\n  - type: value_placeholders\n",
    )
    .unwrap();
    let mut engine = crate::Engine::new();
    engine.add_pipeline(pipeline);
    engine.add_collection(&collection).unwrap();
    let matches = |value: &str| {
        let event = serde_json::json!({ "F": value });
        !engine
            .evaluate(&crate::event::JsonEvent::borrow(&event))
            .is_empty()
    };
    assert!(matches("q%a%-x"));
    assert!(!matches("qx-x"));
}

#[test]
fn invalid_condition_sets_are_rejected() {
    let logsource = "{type: logsource, category: test}";
    let cases = [
        (
            format!("rule_conditions:\n      a: {logsource}\n    rule_cond_expr: a and b"),
            "references unknown condition identifier(s): b",
        ),
        (
            format!(
                "rule_conditions:\n      a: {logsource}\n      b: {logsource}\n    rule_cond_expr: a"
            ),
            "leaves condition identifier(s) unreferenced: b",
        ),
        (
            format!(
                "rule_conditions:\n      a: {logsource}\n    rule_cond_expr: a\n    rule_cond_op: or"
            ),
            "rule_cond_expr is mutually exclusive with rule_cond_op",
        ),
        (
            format!("rule_conditions:\n      - {logsource}\n    rule_cond_op: xor"),
            "condition operator must be 'and' or 'or', got 'xor'",
        ),
        (
            format!("rule_conditions:\n      a: {logsource}\n    rule_cond_expr: 1 of a*"),
            "must contain only condition identifiers and boolean operators",
        ),
    ];
    for (conditions, message) in cases {
        let error = parse_pipeline(&format!(
            "name: invalid\ntransformations:\n  - type: field_name_mapping\n    mapping: {{F: A}}\n    {conditions}\n"
        ))
        .unwrap_err();
        assert!(error.to_string().contains(message), "{conditions}: {error}");
    }
}

#[test]
fn negated_field_name_conditions_apply_to_the_whole_item() {
    let rule = conformance_rule("  sel:\n    A|fieldref: B");
    let pipeline = parse_pipeline(
        "name: negated\ntransformations:\n  - type: field_name_mapping\n    mapping: {A: A2, B: B2}\n    field_name_conditions:\n      - type: include_fields\n        fields: [A]\n    field_name_cond_not: true\n",
    )
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    let item = &conformance_items(&transformed.rule)[0];
    assert_eq!(item.field.name.as_deref(), Some("A"));
    let SigmaValue::String(target) = &item.values[0] else {
        panic!("expected field reference");
    };
    assert_eq!(target.as_plain().as_deref(), Some("B"));
}

#[test]
fn placeholder_expansion_is_capped_at_4096_values() {
    let rule = conformance_rule("  sel:\n    F|expand: '%x%%y%'");
    let values = |count: usize| {
        (0..count)
            .map(|index| index.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    for (y_count, fails) in [(64, false), (65, true)] {
        let pipeline = parse_pipeline(&format!(
            "name: cap\nvars:\n  x: [{}]\n  y: [{}]\ntransformations:\n  - type: value_placeholders\n",
            values(64),
            values(y_count)
        ))
        .unwrap();
        match transform_rule(&[pipeline], &rule) {
            Ok(transformed) => {
                assert!(!fails);
                assert_eq!(conformance_items(&transformed.rule)[0].values.len(), 4096);
            }
            Err(error) => {
                assert!(fails, "{error}");
                assert!(
                    error
                        .to_string()
                        .contains("would produce 4160 values, exceeding the limit of 4096"),
                    "{error}"
                );
            }
        }
    }
}

#[test]
fn field_name_processing_item_applied_survives_later_renames() {
    let rule = rsigma_parser::parse_sigma_yaml(
        "title: Fields\nlogsource:\n  category: test\nfields: [G, H]\ndetection:\n  sel:\n    F: x\n  condition: sel\n",
    )
    .unwrap()
    .rules
    .remove(0);
    let pipeline = parse_pipeline(
        "name: applied\ntransformations:\n  - id: map\n    type: field_name_mapping\n    mapping: {G: G2}\n  - type: field_name_prefix\n    prefix: p.\n  - type: field_name_suffix\n    suffix: _s\n    field_name_conditions:\n      - type: processing_item_applied\n        processing_item_id: map\n",
    )
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    assert_eq!(transformed.rule.fields, ["p.G2_s", "p.H"]);
}

fn apply_first(detection: &str, transformations: &str) -> rsigma_parser::SigmaRule {
    let pipeline = parse_pipeline(&format!(
        "name: first\napply_modifiers: first\ntransformations:\n{transformations}"
    ))
    .unwrap();
    transform_rule(&[pipeline], &conformance_rule(detection))
        .unwrap()
        .rule
}

fn item_texts(item: &rsigma_parser::DetectionItem) -> Vec<String> {
    item.values
        .iter()
        .map(|value| match value {
            SigmaValue::String(s) => s.original.clone(),
            other => panic!("expected a string, got {other:?}"),
        })
        .collect()
}

const NO_TRANSFORMATIONS: &str = "  - type: field_name_suffix\n    suffix: ''\n";

#[test]
fn apply_modifiers_parses_first_and_last_and_defaults_to_last() {
    let parse = |line: &str| parse_pipeline(&format!("name: p\n{line}transformations: []\n"));
    assert_eq!(parse("").unwrap().apply_modifiers, ApplyModifiers::Last);
    assert_eq!(
        parse("apply_modifiers: last\n").unwrap().apply_modifiers,
        ApplyModifiers::Last
    );
    assert_eq!(
        parse("apply_modifiers: first\n").unwrap().apply_modifiers,
        ApplyModifiers::First
    );
    for invalid in ["early", "true", "[first]"] {
        let error = parse(&format!("apply_modifiers: {invalid}\n")).unwrap_err();
        assert!(
            error.to_string().contains("(supported: first, last)"),
            "{invalid}: {error}"
        );
    }
}

#[test]
fn apply_modifiers_last_keeps_modifiers_on_the_item() {
    let rule = conformance_rule("  sel:\n    F|contains: foo");
    let pipeline = parse_pipeline(&format!(
        "name: last\ntransformations:\n{NO_TRANSFORMATIONS}"
    ))
    .unwrap();
    let transformed = transform_rule(&[pipeline], &rule).unwrap();
    let item = &conformance_items(&transformed.rule)[0];
    assert_eq!(item.field.modifiers, [Modifier::Contains]);
    assert_eq!(item_texts(item), ["foo"]);
}

#[test]
fn apply_modifiers_first_turns_string_operators_into_wildcards() {
    let cases = [
        ("F|contains: foo", vec!["*foo*"], vec![]),
        ("F|startswith: foo", vec!["foo*"], vec![]),
        ("F|endswith: foo", vec!["*foo"], vec![]),
        (
            "F|contains|cased: Foo",
            vec!["*Foo*"],
            vec![Modifier::Cased],
        ),
        ("F|contains|neq: foo", vec!["*foo*"], vec![Modifier::Neq]),
        (
            "F|contains|all: [a, b]",
            vec!["*a*", "*b*"],
            vec![Modifier::All],
        ),
        ("F|contains: 'a\\*b?'", vec!["*a\\*b?*"], vec![]),
        ("F|contains: ''", vec!["*"], vec![]),
        ("F|contains: '*'", vec!["*"], vec![]),
        ("F|contains: 'foo*'", vec!["*foo*"], vec![]),
        ("F|startswith: '*a'", vec!["*a*"], vec![]),
        ("F|endswith: '*a'", vec!["*a"], vec![]),
        ("F|contains: 'a\\*'", vec!["*a\\**"], vec![]),
        ("F|endswith: '\\\\'", vec!["*\\\\"], vec![]),
    ];
    for (detection, values, modifiers) in cases {
        let rule = apply_first(&format!("  sel:\n    {detection}"), NO_TRANSFORMATIONS);
        let item = &conformance_items(&rule)[0];
        assert_eq!(item_texts(item), values, "{detection}");
        assert_eq!(item.field.modifiers, modifiers, "{detection}");
    }
}

#[test]
fn apply_modifiers_first_encodes_values() {
    let cases = [
        ("F|base64: foo", vec!["Zm9v"]),
        ("F|base64|contains: foo", vec!["*Zm9v*"]),
        (
            "F|base64offset|contains: foo",
            vec!["*Zm9v*", "*Zvb*", "*mb2*"],
        ),
        ("F|utf16be|base64: ab", vec!["AGEAYg=="]),
        ("F|wide|contains: ab", vec!["*a\u{0}b\u{0}*"]),
        (
            "F|windash|contains: ' -a'",
            vec![
                "* -a*",
                "* /a*",
                "* \u{2013}a*",
                "* \u{2014}a*",
                "* \u{2015}a*",
            ],
        ),
    ];
    for (detection, values) in cases {
        let rule = apply_first(&format!("  sel:\n    {detection}"), NO_TRANSFORMATIONS);
        let item = &conformance_items(&rule)[0];
        assert_eq!(item_texts(item), values, "{detection}");
        assert!(item.field.modifiers.is_empty(), "{detection}");
    }
}

#[test]
fn apply_modifiers_first_splits_all_when_values_have_several_variants() {
    let rule = apply_first(
        "  sel:\n    F|base64offset|contains|all: [foo, bar]",
        NO_TRANSFORMATIONS,
    );
    let items = conformance_items(&rule);
    assert_eq!(items.len(), 2);
    assert_eq!(item_texts(&items[0]), ["*Zm9v*", "*Zvb*", "*mb2*"]);
    assert_eq!(item_texts(&items[1]), ["*YmFy*", "*Jhc*", "*iYX*"]);
    assert!(items.iter().all(|item| item.field.modifiers.is_empty()));
}

#[test]
fn apply_modifiers_first_leaves_items_it_cannot_express() {
    for detection in [
        "F: foo",
        "F|re: 'f.o'",
        "F|cidr: 10.0.0.0/8",
        "F|fieldref|contains: G",
        "F|contains|expand: '%x%'",
        "F|exists: true",
        "F|gt: 5",
        "'|contains': foo",
        "'|endswith': foo",
        "'|base64offset|contains': foo",
        "F|base64offset|contains|all|neq: [foo, bar]",
    ] {
        let original = conformance_rule(&format!("  sel:\n    {detection}"));
        let rule = apply_first(&format!("  sel:\n    {detection}"), NO_TRANSFORMATIONS);
        assert_eq!(
            conformance_items(&rule),
            conformance_items(&original),
            "{detection}"
        );
    }
}

#[test]
fn apply_modifiers_first_lets_value_transformations_see_the_modified_value() {
    let replaced = apply_first(
        "  sel:\n    F|contains: foo",
        "  - type: replace_string\n    regex: '^f'\n    replacement: b\n",
    );
    assert_eq!(item_texts(&conformance_items(&replaced)[0]), ["*foo*"]);

    let set = apply_first(
        "  sel:\n    F|contains: foo",
        "  - type: set_value\n    value: bar\n",
    );
    let item = &conformance_items(&set)[0];
    assert_eq!(item_texts(item), ["bar"]);
    assert!(item.field.modifiers.is_empty());

    let encoded = apply_first(
        "  sel:\n    F|base64: foo",
        "  - type: replace_string\n    regex: Zm\n    replacement: XX\n",
    );
    assert_eq!(item_texts(&conformance_items(&encoded)[0]), ["XX9v"]);
}

#[test]
fn apply_modifiers_first_matches_the_same_events_without_transformations() {
    let detections = [
        "F|contains: foo",
        "F|startswith|cased: Foo",
        "F|endswith|neq: foo",
        "F|contains|all: [foo, bar]",
        "F|base64offset|contains|all: [foo, bar]",
        "F|base64|contains: foo",
        "F|windash|contains: ' -a'",
        "F|wide|base64offset|contains: foo",
        "F|contains: ''",
        "F|startswith: 'f*'",
    ];
    let events = [
        "foo",
        "Foo bar",
        "xfoobarx",
        "barfoo",
        "Zm9vYmFy",
        "xxZm9vxx",
        "cmd /a",
        "cmd \u{2013}a",
        "ZgBvAG8A",
        "",
    ];
    for detection in detections {
        let collection = rsigma_parser::parse_sigma_yaml(&format!(
            "title: t\nlogsource:\n  category: test\ndetection:\n  sel:\n    {detection}\n  condition: sel\n"
        ))
        .unwrap();
        let matches = |mode: &str| {
            let pipeline = parse_pipeline(&format!(
                "name: p\napply_modifiers: {mode}\ntransformations:\n{NO_TRANSFORMATIONS}"
            ))
            .unwrap();
            let mut engine = crate::Engine::new();
            engine.add_pipeline(pipeline);
            engine.add_collection(&collection).unwrap();
            events
                .iter()
                .map(|value| {
                    let event = serde_json::json!({ "F": value });
                    !engine
                        .evaluate(&crate::event::JsonEvent::borrow(&event))
                        .is_empty()
                })
                .collect::<Vec<_>>()
        };
        let last = matches("last");
        assert!(last.contains(&true), "{detection} matches nothing");
        assert_eq!(matches("first"), last, "{detection}");
    }
}

#[test]
fn apply_modifiers_first_leaves_values_an_encoding_cannot_represent() {
    let rule = conformance_rule("  sel:\n    F|base64|contains: ab\n    G|wide: ab");
    let earlier = parse_pipeline(
        "name: earlier\ntransformations:\n  - type: replace_string\n    regex: b\n    replacement: '*'\n    field_name_conditions:\n      - type: include_fields\n        fields: [F]\n  - type: replace_string\n    regex: b\n    replacement: é\n    field_name_conditions:\n      - type: include_fields\n        fields: [G]\n",
    )
    .unwrap();
    let first = parse_pipeline(&format!(
        "name: first\napply_modifiers: first\ntransformations:\n{NO_TRANSFORMATIONS}"
    ))
    .unwrap();
    let transformed = transform_rule(&[earlier, first], &rule).unwrap();
    let items = conformance_items(&transformed.rule);
    assert_eq!(
        items[0].field.modifiers,
        [Modifier::Base64, Modifier::Contains]
    );
    assert_eq!(item_texts(&items[0]), ["a*"]);
    assert_eq!(items[1].field.modifiers, [Modifier::Wide]);
    assert_eq!(item_texts(&items[1]), ["aé"]);
}
