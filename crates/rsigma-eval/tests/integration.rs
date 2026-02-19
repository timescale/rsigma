mod helpers;

use helpers::{corr_engine, eval, process};
use rsigma_eval::{Engine, Event, parse_pipeline};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

#[test]
fn correlation_engine_event_count_e2e() {
    let yaml = r#"
title: Failed Login
id: failed-login
logsource:
    category: auth
detection:
    selection:
        EventType: failed_login
    condition: selection
---
title: Brute Force
correlation:
    type: event_count
    rules:
        - failed-login
    group-by:
        - User
    timespan: 300s
    condition:
        gte: 5
level: critical
"#;
    let mut engine = corr_engine(yaml);

    for i in 0..4 {
        let r = process(
            &mut engine,
            json!({"EventType": "failed_login", "User": "admin"}),
            1000 + i,
        );
        assert!(
            r.correlations.is_empty(),
            "should not fire before threshold"
        );
    }

    let r = process(
        &mut engine,
        json!({"EventType": "failed_login", "User": "admin"}),
        1004,
    );
    assert_eq!(r.correlations.len(), 1);
    assert_eq!(r.correlations[0].rule_title, "Brute Force");
    assert_eq!(
        r.correlations[0].group_key,
        vec![("User".to_string(), "admin".to_string())]
    );
    assert!((r.correlations[0].aggregated_value - 5.0).abs() < f64::EPSILON);

    // Different user should not fire (independent group)
    let r2 = process(
        &mut engine,
        json!({"EventType": "failed_login", "User": "guest"}),
        1010,
    );
    assert!(r2.correlations.is_empty());
}

#[test]
fn correlation_engine_value_count_e2e() {
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
title: Login From Many Sources
correlation:
    type: value_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 600s
    condition:
        field: SourceIP
        gte: 3
level: high
"#;
    let mut engine = corr_engine(yaml);

    let base_ts = 1000;
    // Two distinct IPs -- should not fire
    process(
        &mut engine,
        json!({"EventType": "login", "User": "admin", "SourceIP": "10.0.0.1"}),
        base_ts,
    );
    let r = process(
        &mut engine,
        json!({"EventType": "login", "User": "admin", "SourceIP": "10.0.0.2"}),
        base_ts + 1,
    );
    assert!(r.correlations.is_empty());

    // Third distinct IP -- fires
    let r = process(
        &mut engine,
        json!({"EventType": "login", "User": "admin", "SourceIP": "10.0.0.3"}),
        base_ts + 2,
    );
    assert_eq!(r.correlations.len(), 1);
    assert!((r.correlations[0].aggregated_value - 3.0).abs() < f64::EPSILON);
}

#[test]
fn pipeline_transforms_then_evaluates() {
    let pipeline_yaml = r#"
name: ECS mapping
transformations:
  - type: field_name_mapping
    mapping:
      CommandLine: process.command_line
      User: user.name
    rule_conditions:
      - type: logsource
        product: windows
"#;
    let pipeline = parse_pipeline(pipeline_yaml).unwrap();

    let rule_yaml = r#"
title: Detect Whoami
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        CommandLine|contains: 'whoami'
    filter:
        User: 'SYSTEM'
    condition: sel and not filter
level: medium
"#;
    let collection = parse_sigma_yaml(rule_yaml).unwrap();
    let mut engine = Engine::new_with_pipeline(pipeline);
    engine.add_collection(&collection).unwrap();

    // After pipeline, rule expects ECS fields
    let ev = json!({"process.command_line": "cmd /c whoami", "user.name": "attacker"});
    let matches = engine.evaluate(&Event::from_value(&ev));
    assert_eq!(matches.len(), 1);

    // Filter still works through the mapped field name
    let ev2 = json!({"process.command_line": "cmd /c whoami", "user.name": "SYSTEM"});
    assert!(engine.evaluate(&Event::from_value(&ev2)).is_empty());

    // Original field names should not match
    let ev3 = json!({"CommandLine": "cmd /c whoami", "User": "attacker"});
    assert!(engine.evaluate(&Event::from_value(&ev3)).is_empty());
}

#[test]
fn matched_fields_contain_correct_values() {
    let matches = eval(
        r#"
title: Port Scan
logsource:
    product: firewall
detection:
    selection:
        DestinationPort: 22
        Protocol: TCP
    condition: selection
level: medium
"#,
        json!({"DestinationPort": 22, "Protocol": "TCP", "SourceIP": "10.0.0.1"}),
    );
    assert_eq!(matches.len(), 1);
    let m = &matches[0];
    assert_eq!(m.rule_title, "Port Scan");
    assert_eq!(m.matched_selections, vec!["selection"]);

    let field_names: Vec<&str> = m.matched_fields.iter().map(|f| f.field.as_str()).collect();
    assert!(field_names.contains(&"DestinationPort"));
    assert!(field_names.contains(&"Protocol"));
    // SourceIP was not part of detection, should not appear
    assert!(!field_names.contains(&"SourceIP"));
}

#[test]
fn nested_dot_notation_through_full_chain() {
    let matches = eval(
        r#"
title: Admin Actor
logsource:
    product: cloud
detection:
    selection:
        actor.id: admin
        actor.type: User
    condition: selection
level: high
"#,
        json!({"actor": {"id": "admin", "type": "User"}}),
    );
    assert_eq!(matches.len(), 1);
}

#[test]
fn flat_key_overrides_nested_in_evaluation() {
    // Event has both a flat "actor.id" key and nested {"actor":{"id":...}}
    // Flat key should win per Event semantics
    let matches = eval(
        r#"
title: Flat Key Match
logsource:
    product: test
detection:
    selection:
        actor.id: flat-value
    condition: selection
level: low
"#,
        json!({"actor.id": "flat-value", "actor": {"id": "nested-value"}}),
    );
    assert_eq!(matches.len(), 1, "flat key should override nested");

    // If rule expects the nested value, it should NOT match
    let matches2 = eval(
        r#"
title: Nested Key Match
logsource:
    product: test
detection:
    selection:
        actor.id: nested-value
    condition: selection
level: low
"#,
        json!({"actor.id": "flat-value", "actor": {"id": "nested-value"}}),
    );
    assert!(
        matches2.is_empty(),
        "nested value should be shadowed by flat key"
    );
}

#[test]
fn multi_rule_with_shared_and_targeted_filters() {
    let yaml = r#"
title: Rule A
id: rule-a
logsource:
    product: windows
detection:
    sel:
        EventID: 1
    condition: sel
---
title: Rule B
id: rule-b
logsource:
    product: windows
detection:
    sel:
        EventID: 4688
    condition: sel
---
title: Rule C
id: rule-c
logsource:
    product: windows
detection:
    sel:
        EventID: 7
    condition: sel
---
title: Global Filter
filter:
    rules: []
    env_match:
        Environment: test
    condition: env_match
---
title: Targeted Filter
filter:
    rules:
        - rule-a
    svc_match:
        User: svc_account
    condition: svc_match
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();

    // In test environment: global filter blocks everything
    let ev = json!({"EventID": 1, "Environment": "test", "User": "admin"});
    assert!(engine.evaluate(&Event::from_value(&ev)).is_empty());

    // Rule A as svc_account in prod: targeted filter blocks
    let ev2 = json!({"EventID": 1, "Environment": "prod", "User": "svc_account"});
    assert!(engine.evaluate(&Event::from_value(&ev2)).is_empty());

    // Rule B as svc_account in prod: targeted filter does NOT apply to rule-b
    let ev3 = json!({"EventID": 4688, "Environment": "prod", "User": "svc_account"});
    assert_eq!(engine.evaluate(&Event::from_value(&ev3)).len(), 1);

    // Rule A as admin in prod: no filter applies
    let ev4 = json!({"EventID": 1, "Environment": "prod", "User": "admin"});
    assert_eq!(engine.evaluate(&Event::from_value(&ev4)).len(), 1);
}

#[test]
fn filters_with_same_detection_name_do_not_collide() {
    // Regression: two filters both using "selection" as detection name used to
    // overwrite each other's `__filter_selection` key. With the filter_counter
    // fix, they get distinct keys (`__filter_0_selection`, `__filter_1_selection`).
    let yaml = r#"
title: Rule A
id: rule-a
logsource:
    product: test
detection:
    sel:
        EventType: login
    condition: sel
---
title: Filter Env
filter:
    rules:
        - rule-a
    selection:
        Environment: test
    condition: selection
---
title: Filter User
filter:
    rules:
        - rule-a
    selection:
        User: bot
    condition: selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();

    // Both filters should apply: env=test is excluded
    let ev1 = json!({"EventType": "login", "Environment": "test", "User": "admin"});
    assert!(engine.evaluate(&Event::from_value(&ev1)).is_empty());

    // User=bot is excluded
    let ev2 = json!({"EventType": "login", "Environment": "prod", "User": "bot"});
    assert!(engine.evaluate(&Event::from_value(&ev2)).is_empty());

    // Neither filter matches: rule fires
    let ev3 = json!({"EventType": "login", "Environment": "prod", "User": "admin"});
    assert_eq!(engine.evaluate(&Event::from_value(&ev3)).len(), 1);
}

#[test]
fn global_repeat_through_correlation_engine() {
    let yaml = r#"
action: global
logsource:
    product: windows
    category: process_creation
level: medium
---
title: Detect Cmd
id: detect-cmd
detection:
    selection:
        CommandLine|contains: 'cmd'
    condition: selection
---
action: repeat
title: Detect Powershell
id: detect-ps
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
---
title: Recon Burst
correlation:
    type: event_count
    rules:
        - detect-cmd
        - detect-ps
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
level: high
"#;
    let mut engine = corr_engine(yaml);

    let base_ts = 1000;
    // Mix of cmd and powershell from same user
    process(
        &mut engine,
        json!({"CommandLine": "cmd.exe", "User": "attacker"}),
        base_ts,
    );
    process(
        &mut engine,
        json!({"CommandLine": "powershell -enc", "User": "attacker"}),
        base_ts + 1,
    );

    let r = process(
        &mut engine,
        json!({"CommandLine": "cmd /c whoami", "User": "attacker"}),
        base_ts + 2,
    );
    assert_eq!(
        r.correlations.len(),
        1,
        "3 events from two rules should trigger correlation"
    );
    assert_eq!(r.correlations[0].rule_title, "Recon Burst");
}
