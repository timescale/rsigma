use super::*;
use rsigma_parser::{
    ConditionExpr, Detection, DetectionItem, Detections, FieldSpec, LogSource, Modifier,
    SigmaString,
};

fn make_test_rule() -> SigmaRule {
    let mut named = HashMap::new();
    named.insert(
        "selection".to_string(),
        Detection::AllOf(vec![
            DetectionItem {
                field: FieldSpec::new(Some("CommandLine".to_string()), vec![Modifier::Contains]),
                values: vec![SigmaValue::String(SigmaString::new("whoami"))],
            },
            DetectionItem {
                field: FieldSpec::new(Some("ParentImage".to_string()), vec![Modifier::EndsWith]),
                values: vec![SigmaValue::String(SigmaString::new("\\cmd.exe"))],
            },
        ]),
    );

    SigmaRule {
        title: "Test Rule".to_string(),
        logsource: LogSource {
            category: Some("process_creation".to_string()),
            product: Some("windows".to_string()),
            service: None,
            definition: None,
            custom: HashMap::new(),
        },
        detection: Detections {
            named,
            conditions: vec![ConditionExpr::Identifier("selection".to_string())],
            condition_strings: vec!["selection".to_string()],
            timeframe: None,
        },
        id: Some("test-001".to_string()),
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
        level: Some(rsigma_parser::Level::Medium),
        tags: vec![],
        scope: vec![],
        custom_attributes: HashMap::new(),
    }
}

#[test]
fn test_field_name_mapping() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let mut mapping = HashMap::new();
    mapping.insert(
        "CommandLine".to_string(),
        vec!["process.command_line".to_string()],
    );
    mapping.insert(
        "ParentImage".to_string(),
        vec!["process.parent.executable".to_string()],
    );

    let t = Transformation::FieldNameMapping { mapping };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert_eq!(
            items[0].field.name,
            Some("process.command_line".to_string())
        );
        assert_eq!(
            items[1].field.name,
            Some("process.parent.executable".to_string())
        );
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_field_name_mapping_one_to_many_expands_to_anyof() {
    // CommandLine maps to two alternatives; the surrounding AllOf should
    // be restructured into AnyOf of AllOf so semantics become
    //   (cmd_a = ... AND ParentImage = ...) OR (cmd_b = ... AND ParentImage = ...)
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let mut mapping = HashMap::new();
    mapping.insert(
        "CommandLine".to_string(),
        vec!["cmd_a".to_string(), "cmd_b".to_string()],
    );

    let t = Transformation::FieldNameMapping { mapping };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    let Detection::AnyOf(branches) = det else {
        panic!("Expected AnyOf, got {det:?}");
    };
    assert_eq!(branches.len(), 2);

    let mut seen_first_fields: Vec<Option<String>> = Vec::new();
    for branch in branches {
        let Detection::AllOf(items) = branch else {
            panic!("Expected AllOf in each branch, got {branch:?}");
        };
        assert_eq!(items.len(), 2);
        // Other (untouched) item is preserved across both branches.
        assert_eq!(items[1].field.name, Some("ParentImage".to_string()));
        seen_first_fields.push(items[0].field.name.clone());
    }
    seen_first_fields.sort();
    assert_eq!(
        seen_first_fields,
        vec![Some("cmd_a".to_string()), Some("cmd_b".to_string())]
    );
}

#[test]
fn test_field_name_mapping_one_to_many_cartesian_when_two_items_expand() {
    // Both items expand → 2 × 2 Cartesian product.
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let mut mapping = HashMap::new();
    mapping.insert(
        "CommandLine".to_string(),
        vec!["cmd_a".to_string(), "cmd_b".to_string()],
    );
    mapping.insert(
        "ParentImage".to_string(),
        vec!["parent_x".to_string(), "parent_y".to_string()],
    );

    let t = Transformation::FieldNameMapping { mapping };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    let Detection::AnyOf(branches) = det else {
        panic!("Expected AnyOf, got {det:?}");
    };
    assert_eq!(branches.len(), 4);

    let mut combos: Vec<(Option<String>, Option<String>)> = branches
        .iter()
        .map(|b| {
            let Detection::AllOf(items) = b else {
                panic!("Expected AllOf");
            };
            (items[0].field.name.clone(), items[1].field.name.clone())
        })
        .collect();
    combos.sort();
    assert_eq!(
        combos,
        vec![
            (Some("cmd_a".to_string()), Some("parent_x".to_string())),
            (Some("cmd_a".to_string()), Some("parent_y".to_string())),
            (Some("cmd_b".to_string()), Some("parent_x".to_string())),
            (Some("cmd_b".to_string()), Some("parent_y".to_string())),
        ]
    );
}

#[test]
fn test_field_name_mapping_cartesian_expansion_capped() {
    // 2 detection items × 7 alternatives each = 49 < 4096 — fine.
    // Bump to 5 items × 7 alts = 16807 > 4096 → must be rejected.
    // We construct that detection inline so the test is independent of
    // make_test_rule's shape.
    use rsigma_parser::{Detection, Detections, FieldSpec, LogSource, Modifier};
    let alts: Vec<String> = (0..7).map(|i| format!("alt_{i}")).collect();
    let mut mapping = HashMap::new();
    let mut items = Vec::new();
    for i in 0..5 {
        let name = format!("Field{i}");
        mapping.insert(name.clone(), alts.clone());
        items.push(DetectionItem {
            field: FieldSpec::new(Some(name), vec![Modifier::Contains]),
            values: vec![SigmaValue::String(SigmaString::new("x"))],
        });
    }
    let mut named = HashMap::new();
    named.insert("selection".to_string(), Detection::AllOf(items));
    let mut rule = SigmaRule {
        title: "Cartesian Bomb".to_string(),
        logsource: LogSource {
            category: None,
            product: None,
            service: None,
            definition: None,
            custom: HashMap::new(),
        },
        detection: Detections {
            named,
            conditions: vec![ConditionExpr::Identifier("selection".to_string())],
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
        custom_attributes: HashMap::new(),
    };

    let mut state = PipelineState::default();
    let t = Transformation::FieldNameMapping { mapping };
    let err = t
        .apply(&mut rule, &mut state, &[], &[], false)
        .expect_err("expansion above cap must error");
    let msg = format!("{err}");
    assert!(msg.contains("16807"), "expected total in error: {msg}");
    assert!(msg.contains("4096"), "expected limit in error: {msg}");
    assert!(
        msg.contains("Cartesian Bomb"),
        "expected rule title in error: {msg}"
    );
}

#[test]
fn test_field_name_mapping_single_alternative_in_list_uses_fast_path() {
    // A single-element Vec should behave identically to a string mapping —
    // the fast path stays in AllOf rather than promoting to AnyOf.
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let mut mapping = HashMap::new();
    mapping.insert("CommandLine".to_string(), vec!["cmd".to_string()]);

    let t = Transformation::FieldNameMapping { mapping };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    let Detection::AllOf(items) = det else {
        panic!("Expected AllOf (no expansion), got {det:?}");
    };
    assert_eq!(items[0].field.name, Some("cmd".to_string()));
}

#[test]
fn test_field_name_prefix() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::FieldNamePrefix {
        prefix: "winlog.event_data.".to_string(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert_eq!(
            items[0].field.name,
            Some("winlog.event_data.CommandLine".to_string())
        );
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_field_name_suffix() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::FieldNameSuffix {
        suffix: ".keyword".to_string(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert_eq!(items[0].field.name, Some("CommandLine.keyword".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_change_logsource() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::ChangeLogsource {
        category: Some("endpoint".to_string()),
        product: Some("elastic".to_string()),
        service: None,
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    assert_eq!(rule.logsource.category, Some("endpoint".to_string()));
    assert_eq!(rule.logsource.product, Some("elastic".to_string()));
}

#[test]
fn test_replace_string() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::ReplaceString {
        regex: r"whoami".to_string(),
        replacement: "REPLACED".to_string(),
        skip_special: false,
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert_eq!(s.original, "REPLACED");
        } else {
            panic!("Expected String value");
        }
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_add_condition() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let mut conds = HashMap::new();
    conds.insert(
        "index".to_string(),
        SigmaValue::String(SigmaString::new("windows-*")),
    );
    let t = Transformation::AddCondition {
        conditions: conds,
        negated: false,
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    // Check that a new detection was added
    assert!(
        rule.detection
            .named
            .keys()
            .any(|k| k.starts_with("__pipeline_cond_"))
    );
    // Check that conditions were wrapped
    assert_eq!(rule.detection.conditions.len(), 1);
    if let ConditionExpr::And(parts) = &rule.detection.conditions[0] {
        assert_eq!(parts.len(), 2);
    } else {
        panic!("Expected And condition");
    }
}

#[test]
fn test_set_state() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::SetState {
        key: "index".to_string(),
        value: "windows".to_string(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
    assert!(state.state_matches("index", "windows"));
}

#[test]
fn test_drop_detection_item_with_field_condition() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();

    let field_conds = vec![FieldNameCondition::IncludeFields {
        matcher: super::super::conditions::FieldMatcher::Plain(vec!["ParentImage".to_string()]),
    }];

    let t = Transformation::DropDetectionItem;
    t.apply(&mut rule, &mut state, &[], &field_conds, false)
        .unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert_eq!(items.len(), 1); // ParentImage was dropped
        assert_eq!(items[0].field.name, Some("CommandLine".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_field_name_mapping_with_conditions() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();

    // Only map CommandLine, not ParentImage
    let field_conds = vec![FieldNameCondition::IncludeFields {
        matcher: super::super::conditions::FieldMatcher::Plain(vec!["CommandLine".to_string()]),
    }];

    let mut mapping = HashMap::new();
    mapping.insert("CommandLine".to_string(), vec!["process.args".to_string()]);
    mapping.insert(
        "ParentImage".to_string(),
        vec!["process.parent".to_string()],
    );

    let t = Transformation::FieldNameMapping { mapping };
    t.apply(&mut rule, &mut state, &[], &field_conds, false)
        .unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert_eq!(items[0].field.name, Some("process.args".to_string()));
        // ParentImage should NOT have been mapped (field condition didn't match)
        assert_eq!(items[1].field.name, Some("ParentImage".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_rule_failure() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::RuleFailure {
        message: "Unsupported rule".to_string(),
    };
    let result = t.apply(&mut rule, &mut state, &[], &[], false);
    assert!(result.is_err());
}

#[test]
fn test_value_placeholders() {
    let mut named = HashMap::new();
    named.insert(
        "selection".to_string(),
        Detection::AllOf(vec![DetectionItem {
            field: FieldSpec::new(Some("User".to_string()), vec![]),
            values: vec![SigmaValue::String(SigmaString::new("%admin_users%"))],
        }]),
    );

    let mut rule = SigmaRule {
        title: "Test".to_string(),
        logsource: LogSource::default(),
        detection: Detections {
            named,
            conditions: vec![ConditionExpr::Identifier("selection".to_string())],
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
        custom_attributes: HashMap::new(),
    };

    let mut state = PipelineState::default();
    state.vars.insert(
        "admin_users".to_string(),
        vec!["root".to_string(), "admin".to_string()],
    );

    let t = Transformation::ValuePlaceholders;
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        // Should have expanded to 2 values
        assert_eq!(items[0].values.len(), 2);
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_field_name_transform_lowercase() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::FieldNameTransform {
        transform_func: "lower".to_string(),
        mapping: HashMap::new(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert_eq!(items[0].field.name, Some("commandline".to_string()));
        assert_eq!(items[1].field.name, Some("parentimage".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_field_name_transform_with_mapping_override() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let mut mapping = HashMap::new();
    mapping.insert("CommandLine".to_string(), "cmd_line".to_string());
    let t = Transformation::FieldNameTransform {
        transform_func: "lower".to_string(),
        mapping,
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        // CommandLine → override from mapping
        assert_eq!(items[0].field.name, Some("cmd_line".to_string()));
        // ParentImage → lowercase (no override)
        assert_eq!(items[1].field.name, Some("parentimage".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_field_name_transform_snake_case() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::FieldNameTransform {
        transform_func: "snake_case".to_string(),
        mapping: HashMap::new(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert_eq!(items[0].field.name, Some("command_line".to_string()));
        assert_eq!(items[1].field.name, Some("parent_image".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_hashes_fields_decomposition() {
    let mut named = HashMap::new();
    named.insert(
        "selection".to_string(),
        Detection::AllOf(vec![DetectionItem {
            field: FieldSpec::new(Some("Hashes".to_string()), vec![]),
            values: vec![SigmaValue::String(SigmaString::new(
                "SHA1=abc123,MD5=def456",
            ))],
        }]),
    );

    let mut rule = make_test_rule();
    rule.detection.named = named;

    let mut state = PipelineState::default();
    let t = Transformation::HashesFields {
        valid_hash_algos: vec!["SHA1".to_string(), "MD5".to_string()],
        field_prefix: "File".to_string(),
        drop_algo_prefix: false,
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].field.name, Some("FileSHA1".to_string()));
        assert_eq!(items[1].field.name, Some("FileMD5".to_string()));
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert_eq!(s.original, "abc123");
        }
        if let SigmaValue::String(s) = &items[1].values[0] {
            assert_eq!(s.original, "def456");
        }
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_map_string() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let mut mapping = HashMap::new();
    mapping.insert("whoami".to_string(), vec!["who_am_i".to_string()]);
    let t = Transformation::MapString { mapping };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert_eq!(s.original, "who_am_i");
        } else {
            panic!("Expected String value");
        }
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_map_string_no_match() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let mut mapping = HashMap::new();
    mapping.insert("nonexistent".to_string(), vec!["replaced".to_string()]);
    let t = Transformation::MapString { mapping };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    // Values should be unchanged
    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det
        && let SigmaValue::String(s) = &items[0].values[0]
    {
        assert_eq!(s.original, "whoami");
    }
}

#[test]
fn test_set_value() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::SetValue {
        value: SigmaValue::String(SigmaString::new("FIXED")),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        for item in items {
            assert_eq!(item.values.len(), 1);
            if let SigmaValue::String(s) = &item.values[0] {
                assert_eq!(s.original, "FIXED");
            }
        }
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_convert_type_string_to_int() {
    let mut named = HashMap::new();
    named.insert(
        "selection".to_string(),
        Detection::AllOf(vec![DetectionItem {
            field: FieldSpec::new(Some("EventID".to_string()), vec![]),
            values: vec![SigmaValue::String(SigmaString::new("4688"))],
        }]),
    );
    let mut rule = make_test_rule();
    rule.detection.named = named;

    let mut state = PipelineState::default();
    let t = Transformation::ConvertType {
        target_type: "int".to_string(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert!(matches!(items[0].values[0], SigmaValue::Integer(4688)));
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_convert_type_int_to_string() {
    let mut named = HashMap::new();
    named.insert(
        "selection".to_string(),
        Detection::AllOf(vec![DetectionItem {
            field: FieldSpec::new(Some("EventID".to_string()), vec![]),
            values: vec![SigmaValue::Integer(4688)],
        }]),
    );
    let mut rule = make_test_rule();
    rule.detection.named = named;

    let mut state = PipelineState::default();
    let t = Transformation::ConvertType {
        target_type: "str".to_string(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert_eq!(s.original, "4688");
        } else {
            panic!("Expected String");
        }
    }
}

#[test]
fn test_convert_type_to_bool() {
    let mut named = HashMap::new();
    named.insert(
        "selection".to_string(),
        Detection::AllOf(vec![DetectionItem {
            field: FieldSpec::new(Some("Enabled".to_string()), vec![]),
            values: vec![SigmaValue::String(SigmaString::new("true"))],
        }]),
    );
    let mut rule = make_test_rule();
    rule.detection.named = named;

    let mut state = PipelineState::default();
    let t = Transformation::ConvertType {
        target_type: "bool".to_string(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert!(matches!(items[0].values[0], SigmaValue::Bool(true)));
    }
}

#[test]
fn test_regex_noop() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::Regex;
    let result = t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
    assert!(!result); // no-op returns false
}

#[test]
fn test_add_field() {
    let mut rule = make_test_rule();
    assert!(rule.fields.is_empty());

    let mut state = PipelineState::default();
    let t = Transformation::AddField {
        field: "EventID".to_string(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
    assert_eq!(rule.fields, vec!["EventID".to_string()]);

    // Adding again should not duplicate
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
    assert_eq!(rule.fields, vec!["EventID".to_string()]);
}

#[test]
fn test_remove_field() {
    let mut rule = make_test_rule();
    rule.fields = vec!["EventID".to_string(), "CommandLine".to_string()];

    let mut state = PipelineState::default();
    let t = Transformation::RemoveField {
        field: "EventID".to_string(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
    assert_eq!(rule.fields, vec!["CommandLine".to_string()]);
}

#[test]
fn test_set_field() {
    let mut rule = make_test_rule();
    rule.fields = vec!["old".to_string()];

    let mut state = PipelineState::default();
    let t = Transformation::SetField {
        fields: vec!["new1".to_string(), "new2".to_string()],
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
    assert_eq!(rule.fields, vec!["new1".to_string(), "new2".to_string()]);
}

#[test]
fn test_set_custom_attribute() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::SetCustomAttribute {
        attribute: "custom.key".to_string(),
        value: "custom_value".to_string(),
    };
    let result = t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
    assert!(result);
    assert_eq!(
        rule.custom_attributes
            .get("custom.key")
            .and_then(|v| v.as_str()),
        Some("custom_value")
    );
}

#[test]
fn test_case_transformation_lower() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::CaseTransformation {
        case_type: "lower".to_string(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        // "whoami" is already lowercase
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert_eq!(s.original, "whoami");
        }
        // "\\cmd.exe" stays the same
        if let SigmaValue::String(s) = &items[1].values[0] {
            assert_eq!(s.original, "\\cmd.exe");
        }
    }
}

#[test]
fn test_case_transformation_upper() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::CaseTransformation {
        case_type: "upper".to_string(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert_eq!(s.original, "WHOAMI");
        }
        if let SigmaValue::String(s) = &items[1].values[0] {
            assert_eq!(s.original, "\\CMD.EXE");
        }
    }
}

#[test]
fn test_nest_transformation() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();

    // Create a nested pipeline: prefix + suffix in one nest
    let items = vec![
        super::super::TransformationItem {
            id: Some("inner_prefix".to_string()),
            transformation: Transformation::FieldNamePrefix {
                prefix: "winlog.".to_string(),
            },
            rule_conditions: vec![],
            rule_cond_expr: None,
            detection_item_conditions: vec![],
            field_name_conditions: vec![],
            field_name_cond_not: false,
        },
        super::super::TransformationItem {
            id: Some("inner_suffix".to_string()),
            transformation: Transformation::FieldNameSuffix {
                suffix: ".keyword".to_string(),
            },
            rule_conditions: vec![],
            rule_cond_expr: None,
            detection_item_conditions: vec![],
            field_name_conditions: vec![],
            field_name_cond_not: false,
        },
    ];

    let t = Transformation::Nest { items };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert_eq!(
            items[0].field.name,
            Some("winlog.CommandLine.keyword".to_string())
        );
        assert_eq!(
            items[1].field.name,
            Some("winlog.ParentImage.keyword".to_string())
        );
    } else {
        panic!("Expected AllOf");
    }

    // Check inner items were tracked
    assert!(state.was_applied("inner_prefix"));
    assert!(state.was_applied("inner_suffix"));
}

// =========================================================================
// Untested transformation types
// =========================================================================

#[test]
fn test_field_name_prefix_mapping() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let mut mapping = HashMap::new();
    mapping.insert("Command".to_string(), "process.".to_string());
    mapping.insert("Parent".to_string(), "process.parent.".to_string());

    let t = Transformation::FieldNamePrefixMapping { mapping };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        // "CommandLine" starts with "Command" → "process." + "Line"
        assert_eq!(items[0].field.name, Some("process.Line".to_string()));
        // "ParentImage" starts with "Parent" → "process.parent." + "Image"
        assert_eq!(
            items[1].field.name,
            Some("process.parent.Image".to_string())
        );
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_field_name_prefix_mapping_no_match() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let mut mapping = HashMap::new();
    mapping.insert("NoMatch".to_string(), "replaced.".to_string());

    let t = Transformation::FieldNamePrefixMapping { mapping };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    // Fields should be unchanged — no prefix matched
    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert_eq!(items[0].field.name, Some("CommandLine".to_string()));
        assert_eq!(items[1].field.name, Some("ParentImage".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_wildcard_placeholders_replaces_unresolved() {
    let mut named = HashMap::new();
    named.insert(
        "selection".to_string(),
        Detection::AllOf(vec![DetectionItem {
            field: FieldSpec::new(Some("User".to_string()), vec![]),
            values: vec![SigmaValue::String(SigmaString::new("%unknown_var%"))],
        }]),
    );

    let mut rule = SigmaRule {
        title: "Test".to_string(),
        logsource: LogSource::default(),
        detection: Detections {
            named,
            conditions: vec![ConditionExpr::Identifier("selection".to_string())],
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
        custom_attributes: HashMap::new(),
    };

    let mut state = PipelineState::default();
    // No vars set — placeholder should be replaced with wildcard
    let t = Transformation::WildcardPlaceholders;
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert_eq!(s.original, "*", "unresolved placeholder should become *");
        } else {
            panic!("Expected String value");
        }
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_wildcard_placeholders_with_known_var() {
    let mut named = HashMap::new();
    named.insert(
        "selection".to_string(),
        Detection::AllOf(vec![DetectionItem {
            field: FieldSpec::new(Some("User".to_string()), vec![]),
            values: vec![SigmaValue::String(SigmaString::new("%admin%"))],
        }]),
    );

    let mut rule = SigmaRule {
        title: "Test".to_string(),
        logsource: LogSource::default(),
        detection: Detections {
            named,
            conditions: vec![ConditionExpr::Identifier("selection".to_string())],
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
        custom_attributes: HashMap::new(),
    };

    let mut state = PipelineState::default();
    state
        .vars
        .insert("admin".to_string(), vec!["root".to_string()]);

    // WildcardPlaceholders should still expand known vars
    let t = Transformation::WildcardPlaceholders;
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert_eq!(s.original, "root");
        } else {
            panic!("Expected String value");
        }
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_detection_item_failure_fires_on_match() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();

    // Condition that matches the "whoami" value in CommandLine
    let det_conds = vec![DetectionItemCondition::MatchString {
        regex: regex::Regex::new("whoami").unwrap(),
        negate: false,
    }];

    let t = Transformation::DetectionItemFailure {
        message: "Unsupported detection item".to_string(),
    };
    let result = t.apply(&mut rule, &mut state, &det_conds, &[], false);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("Unsupported detection item"));
}

#[test]
fn test_detection_item_failure_skips_on_no_match() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();

    // Condition that does NOT match any value
    let det_conds = vec![DetectionItemCondition::MatchString {
        regex: regex::Regex::new("nonexistent_value").unwrap(),
        negate: false,
    }];

    let t = Transformation::DetectionItemFailure {
        message: "Should not fire".to_string(),
    };
    let result = t.apply(&mut rule, &mut state, &det_conds, &[], false);
    assert!(result.is_ok());
    assert!(!result.unwrap()); // returns false (not applied)
}

#[test]
fn test_query_expression_placeholders_stores_in_state() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::QueryExpressionPlaceholders {
        expression: "{field}={value}".to_string(),
    };
    let result = t.apply(&mut rule, &mut state, &[], &[], false).unwrap();
    assert!(result);
    let stored = state.get_state("query_expression_template").unwrap();
    assert_eq!(stored.as_str().unwrap(), "{field}={value}");
}

// =========================================================================
// Edge cases: add_condition negated
// =========================================================================

#[test]
fn test_add_condition_negated() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let mut conds = HashMap::new();
    conds.insert(
        "User".to_string(),
        SigmaValue::String(SigmaString::new("SYSTEM")),
    );
    let t = Transformation::AddCondition {
        conditions: conds,
        negated: true,
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    // The condition should be AND NOT (negated)
    assert_eq!(rule.detection.conditions.len(), 1);
    if let ConditionExpr::And(parts) = &rule.detection.conditions[0] {
        assert_eq!(parts.len(), 2);
        // Second part should be Not(...)
        assert!(
            matches!(&parts[1], ConditionExpr::Not(_)),
            "Expected negated condition, got: {:?}",
            parts[1]
        );
    } else {
        panic!("Expected And condition");
    }
}

// =========================================================================
// Edge cases: detection_item_conditions with transformations
// =========================================================================

#[test]
fn test_replace_string_with_detection_item_condition() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();

    // Only replace in items where value matches "whoami"
    let det_conds = vec![DetectionItemCondition::MatchString {
        regex: regex::Regex::new("whoami").unwrap(),
        negate: false,
    }];

    let t = Transformation::ReplaceString {
        regex: r"whoami".to_string(),
        replacement: "REPLACED".to_string(),
        skip_special: false,
    };
    t.apply(&mut rule, &mut state, &det_conds, &[], false)
        .unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        // CommandLine value matches → replaced
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert_eq!(s.original, "REPLACED");
        }
        // ParentImage value "\\cmd.exe" does NOT match → unchanged
        if let SigmaValue::String(s) = &items[1].values[0] {
            assert_eq!(s.original, "\\cmd.exe");
        }
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_set_value_with_is_null_condition() {
    // Create a rule with a null value
    let mut named = HashMap::new();
    named.insert(
        "selection".to_string(),
        Detection::AllOf(vec![
            DetectionItem {
                field: FieldSpec::new(Some("FieldA".to_string()), vec![]),
                values: vec![SigmaValue::Null],
            },
            DetectionItem {
                field: FieldSpec::new(Some("FieldB".to_string()), vec![]),
                values: vec![SigmaValue::String(SigmaString::new("value"))],
            },
        ]),
    );

    let mut rule = make_test_rule();
    rule.detection.named = named;
    let mut state = PipelineState::default();

    // Only apply set_value to items with null values
    let det_conds = vec![DetectionItemCondition::IsNull { negate: false }];

    let t = Transformation::SetValue {
        value: SigmaValue::String(SigmaString::new("DEFAULT")),
    };
    t.apply(&mut rule, &mut state, &det_conds, &[], false)
        .unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        // FieldA had null → should be replaced
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert_eq!(s.original, "DEFAULT");
        } else {
            panic!("Expected String after set_value on null");
        }
        // FieldB had "value" → should be unchanged
        if let SigmaValue::String(s) = &items[1].values[0] {
            assert_eq!(s.original, "value");
        }
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_drop_detection_item_with_match_string_condition() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();

    // Drop items where values match "whoami"
    let det_conds = vec![DetectionItemCondition::MatchString {
        regex: regex::Regex::new("whoami").unwrap(),
        negate: false,
    }];

    let t = Transformation::DropDetectionItem;
    t.apply(&mut rule, &mut state, &det_conds, &[], false)
        .unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert_eq!(items.len(), 1);
        // Only ParentImage should remain
        assert_eq!(items[0].field.name, Some("ParentImage".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

// =========================================================================
// Edge case: field_name_cond_not (negated field name conditions)
// =========================================================================

#[test]
fn test_field_name_mapping_with_cond_not() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();

    // IncludeFields for CommandLine, but negated → apply to everything EXCEPT CommandLine
    let field_conds = vec![FieldNameCondition::IncludeFields {
        matcher: super::super::conditions::FieldMatcher::Plain(vec!["CommandLine".to_string()]),
    }];

    let mut mapping = HashMap::new();
    mapping.insert("CommandLine".to_string(), vec!["cmd".to_string()]);
    mapping.insert("ParentImage".to_string(), vec!["parent".to_string()]);

    let t = Transformation::FieldNameMapping { mapping };
    // field_name_cond_not = true → negate the field condition
    t.apply(&mut rule, &mut state, &[], &field_conds, true)
        .unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        // CommandLine should NOT be mapped (negated: included fields are excluded)
        assert_eq!(items[0].field.name, Some("CommandLine".to_string()));
        // ParentImage SHOULD be mapped (not in include list, negated = applies)
        assert_eq!(items[1].field.name, Some("parent".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

// =========================================================================
// Edge cases: empty inputs
// =========================================================================

#[test]
fn test_field_name_mapping_empty() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::FieldNameMapping {
        mapping: HashMap::new(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    // Fields should be unchanged
    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert_eq!(items[0].field.name, Some("CommandLine".to_string()));
        assert_eq!(items[1].field.name, Some("ParentImage".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_field_name_prefix_mapping_empty() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::FieldNamePrefixMapping {
        mapping: HashMap::new(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert_eq!(items[0].field.name, Some("CommandLine".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_map_string_empty_mapping() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::MapString {
        mapping: HashMap::new(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det
        && let SigmaValue::String(s) = &items[0].values[0]
    {
        assert_eq!(s.original, "whoami");
    }
}

#[test]
fn test_hashes_fields_empty_algos() {
    // When valid_hash_algos is empty, all algorithms should be accepted
    let mut named = HashMap::new();
    named.insert(
        "selection".to_string(),
        Detection::AllOf(vec![DetectionItem {
            field: FieldSpec::new(Some("Hashes".to_string()), vec![]),
            values: vec![SigmaValue::String(SigmaString::new(
                "SHA256=abc123,IMPHASH=def456",
            ))],
        }]),
    );

    let mut rule = make_test_rule();
    rule.detection.named = named;

    let mut state = PipelineState::default();
    let t = Transformation::HashesFields {
        valid_hash_algos: vec![], // empty = accept all
        field_prefix: "File".to_string(),
        drop_algo_prefix: false,
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].field.name, Some("FileSHA256".to_string()));
        assert_eq!(items[1].field.name, Some("FileIMPHASH".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_hashes_fields_drop_algo_prefix() {
    let mut named = HashMap::new();
    named.insert(
        "selection".to_string(),
        Detection::AllOf(vec![DetectionItem {
            field: FieldSpec::new(Some("Hashes".to_string()), vec![]),
            values: vec![SigmaValue::String(SigmaString::new("MD5=abc123"))],
        }]),
    );

    let mut rule = make_test_rule();
    rule.detection.named = named;
    let mut state = PipelineState::default();

    let t = Transformation::HashesFields {
        valid_hash_algos: vec!["MD5".to_string()],
        field_prefix: "Hash".to_string(),
        drop_algo_prefix: true,
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        assert_eq!(items.len(), 1);
        // drop_algo_prefix = true → field name is just the prefix
        assert_eq!(items[0].field.name, Some("Hash".to_string()));
    } else {
        panic!("Expected AllOf");
    }
}

// =========================================================================
// Edge case: invalid regex in replace_string
// =========================================================================

#[test]
fn test_replace_string_invalid_regex() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::ReplaceString {
        regex: r"[invalid".to_string(), // unclosed bracket
        replacement: "x".to_string(),
        skip_special: false,
    };
    let result = t.apply(&mut rule, &mut state, &[], &[], false);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("bad regex"),
        "error should mention regex: {err}"
    );
}

// =========================================================================
// Edge case: detection_item_conditions with negate
// =========================================================================

#[test]
fn test_case_transformation_with_negated_match_string() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();

    // Negate: transform items that do NOT match "whoami"
    let det_conds = vec![DetectionItemCondition::MatchString {
        regex: regex::Regex::new("whoami").unwrap(),
        negate: true,
    }];

    let t = Transformation::CaseTransformation {
        case_type: "upper".to_string(),
    };
    t.apply(&mut rule, &mut state, &det_conds, &[], false)
        .unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        // CommandLine has "whoami" → negate means NOT matched → unchanged
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert_eq!(s.original, "whoami");
        }
        // ParentImage has "\\cmd.exe" → negate means matched → uppercased
        if let SigmaValue::String(s) = &items[1].values[0] {
            assert_eq!(s.original, "\\CMD.EXE");
        }
    } else {
        panic!("Expected AllOf");
    }
}

// =========================================================================
// Integration: multi-transformation chaining pipeline (YAML)
// =========================================================================

#[test]
fn test_multi_transformation_chaining_pipeline() {
    use crate::pipeline::parse_pipeline;

    let yaml = r#"
name: Multi-step Pipeline
transformations:
  - id: step1_map
    type: field_name_mapping
    mapping:
      CommandLine: process.command_line
      ParentImage: process.parent.executable
  - id: step2_prefix
    type: field_name_prefix
    prefix: "winlog."
    rule_conditions:
      - type: logsource
        product: windows
  - id: step3_case
    type: case_transformation
    case_type: upper
    field_name_conditions:
      - type: include_fields
        fields:
          - winlog.process.command_line
  - id: step4_attr
    type: set_custom_attribute
    attribute: rsigma.processed
    value: "true"
"#;
    let pipeline = parse_pipeline(yaml).unwrap();

    let mut rule = make_test_rule(); // Windows process_creation rule
    let mut state = PipelineState::new(pipeline.vars.clone());
    pipeline.apply(&mut rule, &mut state).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        // step1: CommandLine → process.command_line
        // step2: process.command_line → winlog.process.command_line
        assert_eq!(
            items[0].field.name,
            Some("winlog.process.command_line".to_string())
        );
        // step3: case upper only on winlog.process.command_line
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert_eq!(s.original, "WHOAMI");
        }

        // ParentImage → process.parent.executable → winlog.process.parent.executable
        assert_eq!(
            items[1].field.name,
            Some("winlog.process.parent.executable".to_string())
        );
        // step3 does NOT apply to this field → value unchanged
        if let SigmaValue::String(s) = &items[1].values[0] {
            assert_eq!(s.original, "\\cmd.exe");
        }
    } else {
        panic!("Expected AllOf");
    }

    // step4: custom attribute was set
    assert_eq!(
        rule.custom_attributes
            .get("rsigma.processed")
            .and_then(|v| v.as_str()),
        Some("true")
    );

    // All steps should be tracked
    assert!(state.was_applied("step1_map"));
    assert!(state.was_applied("step2_prefix"));
    assert!(state.was_applied("step3_case"));
    assert!(state.was_applied("step4_attr"));
}

// =========================================================================
// MapString one-to-many tests
// =========================================================================

#[test]
fn test_map_string_one_to_many() {
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let mut mapping = HashMap::new();
    mapping.insert(
        "whoami".to_string(),
        vec!["who".to_string(), "am_i".to_string(), "test".to_string()],
    );
    let t = Transformation::MapString { mapping };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        // Original single value should expand to 3 values
        assert_eq!(items[0].values.len(), 3);
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert_eq!(s.original, "who");
        }
        if let SigmaValue::String(s) = &items[0].values[1] {
            assert_eq!(s.original, "am_i");
        }
        if let SigmaValue::String(s) = &items[0].values[2] {
            assert_eq!(s.original, "test");
        }
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_map_string_one_to_many_mixed() {
    // Test that non-matching values remain and only matching ones expand
    let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine:
            - whoami
            - ipconfig
    condition: selection
level: medium
"#;
    let collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();
    let mut rule = collection.rules[0].clone();
    let mut state = PipelineState::default();
    let mut mapping = HashMap::new();
    mapping.insert(
        "whoami".to_string(),
        vec!["who".to_string(), "am_i".to_string()],
    );
    // ipconfig is not in the mapping, should remain unchanged
    let t = Transformation::MapString { mapping };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        // "whoami" expanded to 2 + "ipconfig" stays = 3 total
        assert_eq!(items[0].values.len(), 3);
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert_eq!(s.original, "who");
        }
        if let SigmaValue::String(s) = &items[0].values[1] {
            assert_eq!(s.original, "am_i");
        }
        if let SigmaValue::String(s) = &items[0].values[2] {
            assert_eq!(s.original, "ipconfig");
        }
    } else {
        panic!("Expected AllOf");
    }
}

// =========================================================================
// ReplaceString skip_special tests
// =========================================================================

#[test]
fn test_replace_string_skip_special_preserves_wildcards() {
    // Value with wildcards written directly in YAML: "*whoami*"
    let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine: '*whoami*'
    condition: selection
level: medium
"#;
    let collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();
    let mut rule = collection.rules[0].clone();
    let mut state = PipelineState::default();
    let t = Transformation::ReplaceString {
        regex: r"whoami".to_string(),
        replacement: "REPLACED".to_string(),
        skip_special: true,
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        let s = match &items[0].values[0] {
            SigmaValue::String(s) => s,
            _ => panic!("Expected String"),
        };
        // Wildcards should be preserved, plain part replaced
        assert!(s.contains_wildcards(), "Wildcards should be preserved");
        assert!(
            s.original.contains("REPLACED"),
            "Plain part should be replaced, got: {}",
            s.original
        );
        assert!(
            !s.original.contains("whoami"),
            "Original text should be gone"
        );
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_replace_string_skip_special_false_replaces_whole() {
    // Without skip_special, the entire original is replaced (wildcards treated as text)
    let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine: '*whoami*'
    condition: selection
level: medium
"#;
    let collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();
    let mut rule = collection.rules[0].clone();
    let mut state = PipelineState::default();
    let t = Transformation::ReplaceString {
        regex: r"\*".to_string(),
        replacement: "STAR".to_string(),
        skip_special: false,
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        let s = match &items[0].values[0] {
            SigmaValue::String(s) => s,
            _ => panic!("Expected String"),
        };
        // skip_special=false replaces on the original string (which has literal * chars)
        assert!(
            s.original.contains("STAR"),
            "Wildcards in original should be replaced as text, got: {}",
            s.original
        );
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_replace_string_skip_special_plain_string() {
    // Plain string (no wildcards) with skip_special=true → should still replace
    let mut rule = make_test_rule();
    let mut state = PipelineState::default();
    let t = Transformation::ReplaceString {
        regex: r"whoami".to_string(),
        replacement: "REPLACED".to_string(),
        skip_special: true,
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det
        && let SigmaValue::String(s) = &items[0].values[0]
    {
        assert_eq!(s.original, "REPLACED");
    }
}

// =========================================================================
// CaseTransformation snake_case tests
// =========================================================================

#[test]
fn test_case_transformation_snake_case() {
    let yaml = r#"
title: Test Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine: CommandAndControl
    condition: selection
level: medium
"#;
    let collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();
    let mut rule = collection.rules[0].clone();
    let mut state = PipelineState::default();
    let t = Transformation::CaseTransformation {
        case_type: "snake_case".to_string(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det {
        if let SigmaValue::String(s) = &items[0].values[0] {
            assert_eq!(s.original, "command_and_control");
        } else {
            panic!("Expected String");
        }
    } else {
        panic!("Expected AllOf");
    }
}

#[test]
fn test_case_transformation_snake_case_already_lowercase() {
    let mut rule = make_test_rule(); // "whoami" is already lowercase
    let mut state = PipelineState::default();
    let t = Transformation::CaseTransformation {
        case_type: "snake_case".to_string(),
    };
    t.apply(&mut rule, &mut state, &[], &[], false).unwrap();

    let det = &rule.detection.named["selection"];
    if let Detection::AllOf(items) = det
        && let SigmaValue::String(s) = &items[0].values[0]
    {
        assert_eq!(s.original, "whoami"); // unchanged
    }
}
