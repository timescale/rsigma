mod helpers;

use helpers::{corr_engine, eval, process};
use rsigma_eval::{Engine, JsonEvent, ProcessResultExt, parse_pipeline};
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
            r.correlation_count() == 0,
            "should not fire before threshold"
        );
    }

    let r = process(
        &mut engine,
        json!({"EventType": "failed_login", "User": "admin"}),
        1004,
    );
    assert_eq!(r.correlation_count(), 1);
    assert_eq!(
        r.correlations().next().unwrap().header.rule_title,
        "Brute Force"
    );
    assert_eq!(
        r.correlations()
            .next()
            .unwrap()
            .as_correlation()
            .unwrap()
            .group_key,
        vec![("User".to_string(), "admin".to_string())]
    );
    assert!(
        (r.correlations()
            .next()
            .unwrap()
            .as_correlation()
            .unwrap()
            .aggregated_value
            - 5.0)
            .abs()
            < f64::EPSILON
    );

    // Different user should not fire (independent group)
    let r2 = process(
        &mut engine,
        json!({"EventType": "failed_login", "User": "guest"}),
        1010,
    );
    assert!(r2.correlation_count() == 0);
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
    assert!(r.correlation_count() == 0);

    // Third distinct IP -- fires
    let r = process(
        &mut engine,
        json!({"EventType": "login", "User": "admin", "SourceIP": "10.0.0.3"}),
        base_ts + 2,
    );
    assert_eq!(r.correlation_count(), 1);
    assert!(
        (r.correlations()
            .next()
            .unwrap()
            .as_correlation()
            .unwrap()
            .aggregated_value
            - 3.0)
            .abs()
            < f64::EPSILON
    );
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
    let matches = engine.evaluate(&JsonEvent::borrow(&ev));
    assert_eq!(matches.len(), 1);

    // Filter still works through the mapped field name
    let ev2 = json!({"process.command_line": "cmd /c whoami", "user.name": "SYSTEM"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev2)).is_empty());

    // Original field names should not match
    let ev3 = json!({"CommandLine": "cmd /c whoami", "User": "attacker"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev3)).is_empty());
}

#[test]
fn pipeline_one_to_many_field_mapping_matches_any_alternative() {
    // Single logical field name `Hashes` is mapped to several real fields;
    // the rule's selector should match an event that populates any one of
    // them (and none of the others).
    let pipeline_yaml = r#"
name: Hashes mapping
transformations:
  - type: field_name_mapping
    mapping:
      Hashes:
        - file.hash.md5
        - file.hash.sha1
        - file.hash.sha256
"#;
    let pipeline = parse_pipeline(pipeline_yaml).unwrap();

    let rule_yaml = r#"
title: Known-bad hash
logsource: {product: test}
detection:
    sel:
        Hashes: 'abc123'
    condition: sel
"#;
    let collection = parse_sigma_yaml(rule_yaml).unwrap();
    let mut engine = Engine::new_with_pipeline(pipeline);
    engine.add_collection(&collection).unwrap();

    // Each alternative on its own should fire.
    for field in ["file.hash.md5", "file.hash.sha1", "file.hash.sha256"] {
        let ev = json!({ field: "abc123" });
        assert_eq!(
            engine.evaluate(&JsonEvent::borrow(&ev)).len(),
            1,
            "expected a hit for field {field}"
        );
    }

    // The original logical field name must NOT match (was rewritten away).
    let ev = json!({"Hashes": "abc123"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev)).is_empty());

    // A non-matching value on a real alternative should not fire.
    let ev = json!({"file.hash.md5": "different"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev)).is_empty());
}

#[test]
fn pipeline_add_condition_modifier_key_matches_then_maps() {
    // A negated `IpAddress|cidr` exclusion must apply the modifier to the
    // `IpAddress` field, and a later field mapping must rename that field.
    let pipeline_yaml = r#"
name: Exclusion
transformations:
  - type: add_condition
    name: exclusion_range
    negated: true
    conditions:
      IpAddress|cidr: 209.0.0.0/16
      Workstation|re: '^WS-.*\d$'
  - type: field_name_mapping
    mapping:
      IpAddress: source.ip
"#;
    let pipeline = parse_pipeline(pipeline_yaml).unwrap();

    let rule_yaml = r#"
title: External Remote SMB Logon from Public IP
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
    filter_main_local_ranges:
        IpAddress|cidr:
            - '10.0.0.0/8'
            - '192.168.0.0/16'
    condition: selection and not 1 of filter_main_*
level: high
"#;
    let collection = parse_sigma_yaml(rule_yaml).unwrap();
    let mut engine = Engine::new_with_pipeline(pipeline);
    engine.add_collection(&collection).unwrap();

    let fires = |ip: &str, workstation: &str| {
        let ev = json!({
            "EventID": 4624,
            "LogonType": 3,
            "source.ip": ip,
            "Workstation": workstation,
        });
        !engine.evaluate(&JsonEvent::borrow(&ev)).is_empty()
    };

    // Inside the excluded range, from a matching workstation: excluded.
    assert!(!fires("209.0.221.130", "WS-01"));
    // Outside the range, or the workstation fails the regex: still fires.
    assert!(fires("8.8.8.8", "WS-01"));
    assert!(fires("209.0.221.130", "LAPTOP"));
    // The network literal and an invalid address are not inside the range.
    assert!(fires("209.0.0.0/16", "WS-01"));
    assert!(fires("271.0.221.130", "WS-01"));
    // The rule's own filter still applies.
    assert!(!fires("10.1.2.3", "LAPTOP"));
}

#[test]
fn pipeline_one_to_many_field_mapping_preserves_other_and_clauses() {
    // A selection contains TWO items; only one is multi-mapped. The other
    // (single-field) item must continue to AND with each expansion branch.
    let pipeline_yaml = r#"
name: Multi-field
transformations:
  - type: field_name_mapping
    mapping:
      Path:
        - file.path
        - process.executable
"#;
    let pipeline = parse_pipeline(pipeline_yaml).unwrap();

    let rule_yaml = r#"
title: Path + user
logsource: {product: test}
detection:
    sel:
        Path: '/tmp/evil'
        User: 'alice'
    condition: sel
"#;
    let collection = parse_sigma_yaml(rule_yaml).unwrap();
    let mut engine = Engine::new_with_pipeline(pipeline);
    engine.add_collection(&collection).unwrap();

    // Hit via `file.path` AND matching User.
    let ev = json!({"file.path": "/tmp/evil", "User": "alice"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);

    // Hit via `process.executable` AND matching User.
    let ev = json!({"process.executable": "/tmp/evil", "User": "alice"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);

    // Path matches but User doesn't — the AND must still gate the rule.
    let ev = json!({"file.path": "/tmp/evil", "User": "bob"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev)).is_empty());

    // User matches but no path alternative — no hit.
    let ev = json!({"User": "alice"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev)).is_empty());
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
    let det = m.as_detection().unwrap();
    assert_eq!(m.header.rule_title, "Port Scan");
    assert_eq!(det.matched_selections, vec!["selection"]);

    let field_names: Vec<&str> = det
        .matched_fields
        .iter()
        .map(|f| f.field.as_str())
        .collect();
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
logsource:
    product: windows
filter:
    rules: []
    env_match:
        Environment: test
    condition: not env_match
---
title: Targeted Filter
logsource:
    product: windows
filter:
    rules:
        - rule-a
    svc_match:
        User: svc_account
    condition: not svc_match
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();

    // In test environment: global filter blocks everything
    let ev = json!({"EventID": 1, "Environment": "test", "User": "admin"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev)).is_empty());

    // Rule A as svc_account in prod: targeted filter blocks
    let ev2 = json!({"EventID": 1, "Environment": "prod", "User": "svc_account"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev2)).is_empty());

    // Rule B as svc_account in prod: targeted filter does NOT apply to rule-b
    let ev3 = json!({"EventID": 4688, "Environment": "prod", "User": "svc_account"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev3)).len(), 1);

    // Rule A as admin in prod: no filter applies
    let ev4 = json!({"EventID": 1, "Environment": "prod", "User": "admin"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev4)).len(), 1);
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
logsource:
    product: test
filter:
    rules:
        - rule-a
    selection:
        Environment: test
    condition: not selection
---
title: Filter User
logsource:
    product: test
filter:
    rules:
        - rule-a
    selection:
        User: bot
    condition: not selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();

    // Both filters should apply: env=test is excluded
    let ev1 = json!({"EventType": "login", "Environment": "test", "User": "admin"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev1)).is_empty());

    // User=bot is excluded
    let ev2 = json!({"EventType": "login", "Environment": "prod", "User": "bot"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev2)).is_empty());

    // Neither filter matches: rule fires
    let ev3 = json!({"EventType": "login", "Environment": "prod", "User": "admin"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev3)).len(), 1);
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
        r.correlation_count(),
        1,
        "3 events from two rules should trigger correlation"
    );
    assert_eq!(
        r.correlations().next().unwrap().header.rule_title,
        "Recon Burst"
    );
}

/// One rule and `count` filters that all target it, each excluding one user.
fn rule_with_filters(count: usize) -> rsigma_parser::SigmaCollection {
    let mut yaml = String::from(
        "title: Rule A\nid: rule-a\nlogsource:\n    product: test\ndetection:\n    selection:\n        EventID: 1\n    condition: selection\n",
    );
    for i in 0..count {
        yaml.push_str(&format!(
            "---\ntitle: Filter {i}\nlogsource:\n    product: test\nfilter:\n    rules:\n        - rule-a\n    selection:\n        User: user-{i}\n    condition: not selection\n"
        ));
    }
    parse_sigma_yaml(&yaml).unwrap()
}

fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

const MANY_FILTERS: usize = 10_000;

#[test]
fn thousands_of_filters_on_one_rule_evaluate_on_small_stack() {
    let collection = rule_with_filters(MANY_FILTERS);
    let (kept, filtered) = on_small_stack(move || {
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();
        let kept = json!({"EventID": 1, "User": "admin"});
        let filtered = json!({"EventID": 1, "User": format!("user-{}", MANY_FILTERS - 1)});
        (
            engine.evaluate(&JsonEvent::borrow(&kept)).len(),
            engine.evaluate(&JsonEvent::borrow(&filtered)).len(),
        )
    });
    assert_eq!(kept, 1);
    assert_eq!(filtered, 0);
}

#[test]
fn thousands_of_filters_on_one_rule_render_on_small_stack() {
    let collection = rule_with_filters(MANY_FILTERS);
    let condition = on_small_stack(move || {
        let rules = rsigma_eval::apply_filters(&collection);
        assert_eq!(rules.len(), 1);
        rules[0].detection.condition_strings[0].clone()
    });
    assert_eq!(condition.matches(" and not ").count(), MANY_FILTERS);
}

#[test]
fn filters_append_to_the_rule_condition() {
    let rules = rsigma_eval::apply_filters(&rule_with_filters(3));
    assert_eq!(
        rules[0].detection.condition_strings,
        [
            "(selection and not __filter_0_v_selection and not __filter_1_v_selection and not __filter_2_v_selection)"
        ]
    );
}

#[test]
fn thousands_of_added_conditions_evaluate_on_small_stack() {
    let count = 10_000;
    let mut pipeline_yaml = String::from("name: Many conditions\ntransformations:\n");
    for i in 0..count {
        pipeline_yaml.push_str(&format!(
            "  - type: add_condition\n    negated: true\n    prepend: {}\n    conditions:\n      User: user-{i}\n",
            i % 2 == 0
        ));
    }
    let pipeline = parse_pipeline(&pipeline_yaml).unwrap();
    let collection = rule_with_filters(0);
    let (kept, excluded) = on_small_stack(move || {
        let mut engine = Engine::new_with_pipeline(pipeline);
        engine.add_collection(&collection).unwrap();
        let kept = json!({"EventID": 1, "User": "admin"});
        let excluded = json!({"EventID": 1, "User": format!("user-{}", count - 1)});
        (
            engine.evaluate(&JsonEvent::borrow(&kept)).len(),
            engine.evaluate(&JsonEvent::borrow(&excluded)).len(),
        )
    });
    assert_eq!(kept, 1);
    assert_eq!(excluded, 0);
}
