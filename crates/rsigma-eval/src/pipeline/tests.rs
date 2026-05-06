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
            sources: vec![],
            source_refs: vec![],
        },
        Pipeline {
            name: "A".to_string(),
            priority: 10,
            vars: HashMap::new(),
            transformations: vec![],
            finalizers: vec![],
            sources: vec![],
            source_refs: vec![],
        },
        Pipeline {
            name: "B".to_string(),
            priority: 20,
            vars: HashMap::new(),
            transformations: vec![],
            finalizers: vec![],
            sources: vec![],
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

// =============================================================================
// Dynamic pipeline tests
// =============================================================================

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
    assert!(pipeline.sources.is_empty());
    assert!(pipeline.source_refs.is_empty());
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
    let pipeline = parse_pipeline(yaml).unwrap();
    assert!(pipeline.is_dynamic());
    assert_eq!(pipeline.sources.len(), 1);

    let src = &pipeline.sources[0];
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
            assert_eq!(extract.as_deref(), Some(".emails[]"));
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
    let pipeline = parse_pipeline(yaml).unwrap();
    let src = &pipeline.sources[0];
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
    let pipeline = parse_pipeline(yaml).unwrap();
    let src = &pipeline.sources[0];
    assert_eq!(src.id, "watchlist");
    assert_eq!(src.refresh, sources::RefreshPolicy::Watch);

    match &src.source_type {
        sources::SourceType::File { path, format } => {
            assert_eq!(path, std::path::Path::new("/etc/rsigma/watchlist.json"));
            assert_eq!(*format, sources::DataFormat::Json);
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
    let pipeline = parse_pipeline(yaml).unwrap();
    let src = &pipeline.sources[0];
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
fn test_parse_on_demand_refresh() {
    let yaml = r#"
name: On Demand Pipeline
sources:
  - id: compromised
    type: http
    url: https://api.internal/v1/compromised
    refresh: on_demand
transformations:
  - type: value_placeholders
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert_eq!(
        pipeline.sources[0].refresh,
        sources::RefreshPolicy::OnDemand
    );
}

#[test]
fn test_detect_source_refs_in_vars() {
    let yaml = r#"
name: Ref Detection
sources:
  - id: admin_emails
    type: http
    url: https://api.internal/v1/emails
    format: json
  - id: env_config
    type: http
    url: https://cmdb.internal/v1/config
    format: json
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
fn test_detect_source_refs_in_transformation_fields() {
    let yaml = r#"
name: Transform Refs
sources:
  - id: env_config
    type: http
    url: https://cmdb.internal/v1/config
    format: json
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
sources:
  - id: extra_transforms
    type: http
    url: https://compliance.internal/v1/transforms
    format: yaml
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
fn test_cross_validation_undeclared_source_fails() {
    let yaml = r#"
name: Bad Refs Pipeline
sources:
  - id: declared_source
    type: http
    url: https://api.internal/v1/data
vars:
  emails: "${source.undeclared_source}"
transformations:
  - type: value_placeholders
"#;
    let result = parse_pipeline(yaml);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("undeclared_source"), "got: {err_msg}");
}

#[test]
fn test_cross_validation_declared_source_passes() {
    let yaml = r#"
name: Good Refs Pipeline
sources:
  - id: my_source
    type: http
    url: https://api.internal/v1/data
    format: json
vars:
  data: "${source.my_source}"
transformations:
  - type: value_placeholders
"#;
    let result = parse_pipeline(yaml);
    assert!(result.is_ok());
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
    let result = parse_pipeline(yaml);
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
    let result = parse_pipeline(yaml);
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
    let result = parse_pipeline(yaml);
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
    let result = parse_pipeline(yaml);
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
    let pipeline = parse_pipeline(yaml).unwrap();
    assert!(pipeline.sources[0].required);
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
    let pipeline = parse_pipeline(yaml).unwrap();
    match &pipeline.sources[0].source_type {
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
    let pipeline = parse_pipeline(yaml).unwrap();
    assert_eq!(pipeline.sources[0].refresh, sources::RefreshPolicy::Once);
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
    let pipeline = parse_pipeline(yaml).unwrap();
    assert_eq!(
        pipeline.sources[0].on_error,
        sources::ErrorPolicy::UseCached
    );
}

#[test]
fn test_multiple_sources_and_refs() {
    let yaml = r#"
name: Multi Source
priority: 5
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
vars:
  admin_emails: "${source.emails}"
  log_level: "${source.config.log_level}"
transformations:
  - type: value_placeholders
"#;
    let pipeline = parse_pipeline(yaml).unwrap();
    assert!(pipeline.is_dynamic());
    assert_eq!(pipeline.sources.len(), 2);
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
    assert!(pipeline.sources.is_empty());
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
name: Duration Test
sources:
  - id: src
    type: http
    url: https://api.internal/data
    refresh: {duration_str}
transformations:
  - type: value_placeholders
"#
        );
        let pipeline = parse_pipeline(&yaml).unwrap();
        match &pipeline.sources[0].refresh {
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
    let pipeline = parse_pipeline(yaml).unwrap();
    match &pipeline.sources[0].source_type {
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
    let pipeline = parse_pipeline(yaml).unwrap();
    match &pipeline.sources[0].source_type {
        sources::SourceType::Http { method, .. } => {
            assert_eq!(method.as_deref(), Some("POST"));
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
    let pipeline = parse_pipeline(yaml).unwrap();
    let src = &pipeline.sources[0];
    assert_eq!(src.on_error, sources::ErrorPolicy::UseDefault);
    assert!(src.default.is_some());
}
