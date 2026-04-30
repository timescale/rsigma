use std::collections::HashMap;

use rsigma_parser::{CorrelationRule, SigmaString, SigmaValue};

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
    assert_eq!(pipeline.transformations[0].rule_conditions.len(), 1);
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
            transformations: vec![],
            finalizers: vec![],
        },
        Pipeline {
            name: "A".to_string(),
            priority: 10,
            vars: HashMap::new(),
            transformations: vec![],
            finalizers: vec![],
        },
        Pipeline {
            name: "B".to_string(),
            priority: 20,
            vars: HashMap::new(),
            transformations: vec![],
            finalizers: vec![],
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
    assert_eq!(item.rule_conditions.len(), 8);
    assert_eq!(item.detection_item_conditions.len(), 4);
    assert_eq!(item.field_name_conditions.len(), 4);
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
    assert_eq!(item.rule_conditions[0].id, Some("is_windows".to_string()));
    assert_eq!(item.rule_conditions[1].id, Some("is_process".to_string()));

    // Windows + process_creation => both match, OR is true => prefix applied
    let mut rule = rsigma_parser::SigmaRule {
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
fn test_unnamed_conditions_fallback_to_cond_n() {
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
    rule_cond_expression: "cond_0 or cond_1"
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert!(pipeline.transformations[0].rule_conditions[0].id.is_none());
    assert!(pipeline.transformations[0].rule_conditions[1].id.is_none());

    let mut rule = rsigma_parser::SigmaRule {
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

    // cond_0 (windows)=false, cond_1 (process_creation)=true => OR => applied
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
        serde_yaml::Value::String("reset".to_string())
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
