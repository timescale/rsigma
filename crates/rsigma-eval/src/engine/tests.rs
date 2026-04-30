use super::*;
use crate::event::JsonEvent;
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

fn make_engine_with_rule(yaml: &str) -> Engine {
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();
    engine
}

#[test]
fn test_simple_match() {
    let engine = make_engine_with_rule(
        r#"
title: Detect Whoami
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#,
    );

    let ev = json!({"CommandLine": "cmd /c whoami /all"});
    let event = JsonEvent::borrow(&ev);
    let matches = engine.evaluate(&event);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_title, "Detect Whoami");
}

#[test]
fn test_no_match() {
    let engine = make_engine_with_rule(
        r#"
title: Detect Whoami
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#,
    );

    let ev = json!({"CommandLine": "ipconfig /all"});
    let event = JsonEvent::borrow(&ev);
    let matches = engine.evaluate(&event);
    assert!(matches.is_empty());
}

#[test]
fn test_and_not_filter() {
    let engine = make_engine_with_rule(
        r#"
title: Suspicious Process
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    filter:
        User: 'SYSTEM'
    condition: selection and not filter
level: high
"#,
    );

    // Match: whoami by non-SYSTEM user
    let ev = json!({"CommandLine": "whoami", "User": "admin"});
    let event = JsonEvent::borrow(&ev);
    assert_eq!(engine.evaluate(&event).len(), 1);

    // No match: whoami by SYSTEM
    let ev2 = json!({"CommandLine": "whoami", "User": "SYSTEM"});
    let event2 = JsonEvent::borrow(&ev2);
    assert!(engine.evaluate(&event2).is_empty());
}

#[test]
fn test_multiple_values_or() {
    let engine = make_engine_with_rule(
        r#"
title: Recon Commands
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'whoami'
            - 'ipconfig'
            - 'net user'
    condition: selection
level: medium
"#,
    );

    let ev = json!({"CommandLine": "ipconfig /all"});
    let event = JsonEvent::borrow(&ev);
    assert_eq!(engine.evaluate(&event).len(), 1);

    let ev2 = json!({"CommandLine": "dir"});
    let event2 = JsonEvent::borrow(&ev2);
    assert!(engine.evaluate(&event2).is_empty());
}

#[test]
fn test_logsource_routing() {
    let engine = make_engine_with_rule(
        r#"
title: Windows Process
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#,
    );

    let ev = json!({"CommandLine": "whoami"});
    let event = JsonEvent::borrow(&ev);

    // Matching logsource
    let ls_match = LogSource {
        product: Some("windows".into()),
        category: Some("process_creation".into()),
        ..Default::default()
    };
    assert_eq!(engine.evaluate_with_logsource(&event, &ls_match).len(), 1);

    // Non-matching logsource
    let ls_nomatch = LogSource {
        product: Some("linux".into()),
        category: Some("process_creation".into()),
        ..Default::default()
    };
    assert!(
        engine
            .evaluate_with_logsource(&event, &ls_nomatch)
            .is_empty()
    );
}

#[test]
fn test_selector_1_of() {
    let engine = make_engine_with_rule(
        r#"
title: Multiple Selections
logsource:
    product: windows
detection:
    selection_cmd:
        CommandLine|contains: 'cmd'
    selection_ps:
        CommandLine|contains: 'powershell'
    condition: 1 of selection_*
level: medium
"#,
    );

    let ev = json!({"CommandLine": "powershell.exe -enc"});
    let event = JsonEvent::borrow(&ev);
    assert_eq!(engine.evaluate(&event).len(), 1);
}

#[test]
fn test_filter_rule_application() {
    // A filter rule that excludes SYSTEM user from the detection
    let yaml = r#"
title: Suspicious Process
id: rule-001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: high
---
title: Filter SYSTEM
filter:
    rules:
        - rule-001
    selection:
        User: 'SYSTEM'
    condition: not selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 1);
    assert_eq!(collection.filters.len(), 1);

    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();

    // Match: whoami by non-SYSTEM user
    let ev = json!({"CommandLine": "whoami", "User": "admin"});
    let event = JsonEvent::borrow(&ev);
    assert_eq!(engine.evaluate(&event).len(), 1);

    // No match: whoami by SYSTEM (filtered out)
    let ev2 = json!({"CommandLine": "whoami", "User": "SYSTEM"});
    let event2 = JsonEvent::borrow(&ev2);
    assert!(engine.evaluate(&event2).is_empty());
}

#[test]
fn test_filter_rule_no_ref_applies_to_all() {
    // A filter rule with empty `rules` applies to all rules
    let yaml = r#"
title: Detection A
id: det-a
logsource:
    product: windows
detection:
    sel:
        EventType: alert
    condition: sel
---
title: Filter Out Test Env
filter:
    rules: []
    selection:
        Environment: 'test'
    condition: not selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();

    let ev = json!({"EventType": "alert", "Environment": "prod"});
    let event = JsonEvent::borrow(&ev);
    assert_eq!(engine.evaluate(&event).len(), 1);

    let ev2 = json!({"EventType": "alert", "Environment": "test"});
    let event2 = JsonEvent::borrow(&ev2);
    assert!(engine.evaluate(&event2).is_empty());
}

#[test]
fn test_multiple_rules() {
    let yaml = r#"
title: Rule A
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: low
---
title: Rule B
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'ipconfig'
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();
    assert_eq!(engine.rule_count(), 2);

    // Only Rule A matches
    let ev = json!({"CommandLine": "whoami"});
    let event = JsonEvent::borrow(&ev);
    let matches = engine.evaluate(&event);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_title, "Rule A");
}

// =========================================================================
// Filter rule edge cases
// =========================================================================

#[test]
fn test_filter_by_rule_name() {
    // Filter that references a rule by title (not ID)
    let yaml = r#"
title: Detect Mimikatz
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
level: critical
---
title: Exclude Admin Tools
filter:
    rules:
        - Detect Mimikatz
    selection:
        ParentImage|endswith: '\admin_toolkit.exe'
    condition: not selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();

    // Match: mimikatz not launched by admin toolkit
    let ev = json!({"CommandLine": "mimikatz.exe", "ParentImage": "C:\\cmd.exe"});
    let event = JsonEvent::borrow(&ev);
    assert_eq!(engine.evaluate(&event).len(), 1);

    // No match: mimikatz launched by admin toolkit (filtered)
    let ev2 = json!({"CommandLine": "mimikatz.exe", "ParentImage": "C:\\admin_toolkit.exe"});
    let event2 = JsonEvent::borrow(&ev2);
    assert!(engine.evaluate(&event2).is_empty());
}

#[test]
fn test_filter_multiple_detections() {
    // Filter with multiple detection items (AND exclusion)
    let yaml = r#"
title: Suspicious Network
id: net-001
logsource:
    product: windows
detection:
    selection:
        DestinationPort: 443
    condition: selection
level: medium
---
title: Exclude Trusted
filter:
    rules:
        - net-001
    trusted_dst:
        DestinationIp|startswith: '10.'
    trusted_user:
        User: 'svc_account'
    condition: not (trusted_dst and trusted_user)
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();

    // Match: port 443 to external IP
    let ev = json!({"DestinationPort": 443, "DestinationIp": "8.8.8.8", "User": "admin"});
    let event = JsonEvent::borrow(&ev);
    assert_eq!(engine.evaluate(&event).len(), 1);

    // Match: port 443 to internal IP but different user (filter needs both)
    let ev2 = json!({"DestinationPort": 443, "DestinationIp": "10.0.0.1", "User": "admin"});
    let event2 = JsonEvent::borrow(&ev2);
    assert_eq!(engine.evaluate(&event2).len(), 1);

    // No match: port 443 to internal IP by svc_account (both filter conditions met)
    let ev3 = json!({"DestinationPort": 443, "DestinationIp": "10.0.0.1", "User": "svc_account"});
    let event3 = JsonEvent::borrow(&ev3);
    assert!(engine.evaluate(&event3).is_empty());
}

#[test]
fn test_filter_applied_to_multiple_rules() {
    // Filter with empty rules list applies to all rules
    let yaml = r#"
title: Rule One
id: r1
logsource:
    product: windows
detection:
    sel:
        EventID: 1
    condition: sel
---
title: Rule Two
id: r2
logsource:
    product: windows
detection:
    sel:
        EventID: 2
    condition: sel
---
title: Exclude Test
filter:
    rules: []
    selection:
        Environment: 'test'
    condition: not selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();

    // In prod: both rules should fire
    let ev1 = json!({"EventID": 1, "Environment": "prod"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev1)).len(), 1);
    let ev2 = json!({"EventID": 2, "Environment": "prod"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev2)).len(), 1);

    // In test: both filtered out
    let ev3 = json!({"EventID": 1, "Environment": "test"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev3)).is_empty());
    let ev4 = json!({"EventID": 2, "Environment": "test"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev4)).is_empty());
}

// =========================================================================
// Expand modifier end-to-end
// =========================================================================

#[test]
fn test_expand_modifier_yaml() {
    let yaml = r#"
title: User Profile Access
logsource:
    product: windows
detection:
    selection:
        TargetFilename|expand: 'C:\Users\%username%\AppData\sensitive.dat'
    condition: selection
level: high
"#;
    let engine = make_engine_with_rule(yaml);

    // Match: path matches after expanding %username% from the event
    let ev = json!({
        "TargetFilename": "C:\\Users\\admin\\AppData\\sensitive.dat",
        "username": "admin"
    });
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);

    // No match: different user
    let ev2 = json!({
        "TargetFilename": "C:\\Users\\admin\\AppData\\sensitive.dat",
        "username": "guest"
    });
    assert!(engine.evaluate(&JsonEvent::borrow(&ev2)).is_empty());
}

#[test]
fn test_expand_modifier_multiple_placeholders() {
    let yaml = r#"
title: Registry Path
logsource:
    product: windows
detection:
    selection:
        RegistryKey|expand: 'HKLM\SOFTWARE\%vendor%\%product%'
    condition: selection
level: medium
"#;
    let engine = make_engine_with_rule(yaml);

    let ev = json!({
        "RegistryKey": "HKLM\\SOFTWARE\\Acme\\Widget",
        "vendor": "Acme",
        "product": "Widget"
    });
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);

    let ev2 = json!({
        "RegistryKey": "HKLM\\SOFTWARE\\Acme\\Widget",
        "vendor": "Other",
        "product": "Widget"
    });
    assert!(engine.evaluate(&JsonEvent::borrow(&ev2)).is_empty());
}

// =========================================================================
// Timestamp modifier end-to-end
// =========================================================================

#[test]
fn test_timestamp_hour_modifier_yaml() {
    let yaml = r#"
title: Off-Hours Login
logsource:
    product: windows
detection:
    selection:
        EventType: 'login'
    time_filter:
        Timestamp|hour: 3
    condition: selection and time_filter
level: high
"#;
    let engine = make_engine_with_rule(yaml);

    // Match: login at 03:xx UTC
    let ev = json!({"EventType": "login", "Timestamp": "2024-07-10T03:45:00Z"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);

    // No match: login at 14:xx UTC
    let ev2 = json!({"EventType": "login", "Timestamp": "2024-07-10T14:45:00Z"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev2)).is_empty());
}

#[test]
fn test_timestamp_day_modifier_yaml() {
    let yaml = r#"
title: Weekend Activity
logsource:
    product: windows
detection:
    selection:
        EventType: 'access'
    day_check:
        CreatedAt|day: 25
    condition: selection and day_check
level: medium
"#;
    let engine = make_engine_with_rule(yaml);

    let ev = json!({"EventType": "access", "CreatedAt": "2024-12-25T10:00:00Z"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);

    let ev2 = json!({"EventType": "access", "CreatedAt": "2024-12-26T10:00:00Z"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev2)).is_empty());
}

#[test]
fn test_timestamp_year_modifier_yaml() {
    let yaml = r#"
title: Legacy System
logsource:
    product: windows
detection:
    selection:
        EventType: 'auth'
    old_events:
        EventTime|year: 2020
    condition: selection and old_events
level: low
"#;
    let engine = make_engine_with_rule(yaml);

    let ev = json!({"EventType": "auth", "EventTime": "2020-06-15T10:00:00Z"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);

    let ev2 = json!({"EventType": "auth", "EventTime": "2024-06-15T10:00:00Z"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev2)).is_empty());
}

// =========================================================================
// action: repeat through engine
// =========================================================================

#[test]
fn test_action_repeat_evaluates_correctly() {
    // Two rules via repeat: same logsource, different detections
    let yaml = r#"
title: Detect Whoami
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
title: Detect Ipconfig
detection:
    selection:
        CommandLine|contains: 'ipconfig'
    condition: selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 2);

    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();
    assert_eq!(engine.rule_count(), 2);

    // First rule matches whoami
    let ev1 = json!({"CommandLine": "whoami /all"});
    let matches1 = engine.evaluate(&JsonEvent::borrow(&ev1));
    assert_eq!(matches1.len(), 1);
    assert_eq!(matches1[0].rule_title, "Detect Whoami");

    // Second rule matches ipconfig (inherited logsource/level)
    let ev2 = json!({"CommandLine": "ipconfig /all"});
    let matches2 = engine.evaluate(&JsonEvent::borrow(&ev2));
    assert_eq!(matches2.len(), 1);
    assert_eq!(matches2[0].rule_title, "Detect Ipconfig");

    // Neither matches dir
    let ev3 = json!({"CommandLine": "dir"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev3)).is_empty());
}

#[test]
fn test_action_repeat_with_global() {
    // Global + repeat: global sets logsource, first doc sets detection,
    // repeat overrides title and detection
    let yaml = r#"
action: global
logsource:
    product: windows
    category: process_creation
level: high
---
title: Detect Net User
detection:
    selection:
        CommandLine|contains: 'net user'
    condition: selection
---
action: repeat
title: Detect Net Group
detection:
    selection:
        CommandLine|contains: 'net group'
    condition: selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 2);

    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();

    let ev1 = json!({"CommandLine": "net user admin"});
    let m1 = engine.evaluate(&JsonEvent::borrow(&ev1));
    assert_eq!(m1.len(), 1);
    assert_eq!(m1[0].rule_title, "Detect Net User");

    let ev2 = json!({"CommandLine": "net group admins"});
    let m2 = engine.evaluate(&JsonEvent::borrow(&ev2));
    assert_eq!(m2.len(), 1);
    assert_eq!(m2[0].rule_title, "Detect Net Group");
}

// =========================================================================
// |neq modifier
// =========================================================================

#[test]
fn test_neq_modifier_yaml() {
    let yaml = r#"
title: Non-Standard Port
logsource:
    product: windows
detection:
    selection:
        Protocol: TCP
    filter:
        DestinationPort|neq: 443
    condition: selection and filter
level: medium
"#;
    let engine = make_engine_with_rule(yaml);

    // Match: TCP on port 80 (neq 443 is true)
    let ev = json!({"Protocol": "TCP", "DestinationPort": "80"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);

    // No match: TCP on port 443 (neq 443 is false)
    let ev2 = json!({"Protocol": "TCP", "DestinationPort": "443"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev2)).is_empty());
}

#[test]
fn test_neq_modifier_integer() {
    let yaml = r#"
title: Non-Standard Port Numeric
logsource:
    product: windows
detection:
    selection:
        DestinationPort|neq: 443
    condition: selection
level: medium
"#;
    let engine = make_engine_with_rule(yaml);

    let ev = json!({"DestinationPort": 80});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);

    let ev2 = json!({"DestinationPort": 443});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev2)).is_empty());
}

// =========================================================================
// 1 of them / all of them: underscore exclusion
// =========================================================================

#[test]
fn test_selector_them_excludes_underscore() {
    // Sigma spec: `1 of them` / `all of them` excludes identifiers starting with _
    let yaml = r#"
title: Underscore Test
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    _helper:
        User: 'SYSTEM'
    condition: all of them
level: medium
"#;
    let engine = make_engine_with_rule(yaml);

    // With `all of them` excluding `_helper`, only `selection` needs to match
    let ev = json!({"CommandLine": "whoami", "User": "admin"});
    assert_eq!(
        engine.evaluate(&JsonEvent::borrow(&ev)).len(),
        1,
        "all of them should exclude _helper, so only selection is required"
    );
}

#[test]
fn test_selector_them_includes_non_underscore() {
    let yaml = r#"
title: Multiple Selections
logsource:
    product: windows
detection:
    sel_cmd:
        CommandLine|contains: 'cmd'
    sel_ps:
        CommandLine|contains: 'powershell'
    _private:
        User: 'admin'
    condition: 1 of them
level: medium
"#;
    let engine = make_engine_with_rule(yaml);

    // `1 of them` excludes `_private`, so only sel_cmd and sel_ps are considered
    let ev = json!({"CommandLine": "cmd.exe", "User": "guest"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);

    // _private alone should not count
    let ev2 = json!({"CommandLine": "notepad", "User": "admin"});
    assert!(
        engine.evaluate(&JsonEvent::borrow(&ev2)).is_empty(),
        "_private should be excluded from 'them'"
    );
}

// =========================================================================
// UTF-16 encoding modifiers
// =========================================================================

#[test]
fn test_utf16le_modifier_yaml() {
    // |wide is an alias for |utf16le
    let yaml = r#"
title: Wide String
logsource:
    product: windows
detection:
    selection:
        Payload|wide|base64: 'Test'
    condition: selection
level: medium
"#;
    let engine = make_engine_with_rule(yaml);

    // "Test" in UTF-16LE, then base64 encoded
    // T=0x54,0x00 e=0x65,0x00 s=0x73,0x00 t=0x74,0x00
    // base64 of [0x54,0x00,0x65,0x00,0x73,0x00,0x74,0x00] = "VABlAHMAdAA="
    let ev = json!({"Payload": "VABlAHMAdAA="});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);
}

#[test]
fn test_utf16be_modifier_yaml() {
    let yaml = r#"
title: UTF16BE String
logsource:
    product: windows
detection:
    selection:
        Payload|utf16be|base64: 'AB'
    condition: selection
level: medium
"#;
    let engine = make_engine_with_rule(yaml);

    // "AB" in UTF-16BE: A=0x00,0x41 B=0x00,0x42
    // base64 of [0x00,0x41,0x00,0x42] = "AEEAQg=="
    let ev = json!({"Payload": "AEEAQg=="});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);
}

#[test]
fn test_utf16_bom_modifier_yaml() {
    let yaml = r#"
title: UTF16 BOM String
logsource:
    product: windows
detection:
    selection:
        Payload|utf16|base64: 'A'
    condition: selection
level: medium
"#;
    let engine = make_engine_with_rule(yaml);

    // "A" in UTF-16 with BOM: FF FE (BOM) + 41 00 (A in UTF-16LE)
    // base64 of [0xFF,0xFE,0x41,0x00] = "//5BAA=="
    let ev = json!({"Payload": "//5BAA=="});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);
}

// =========================================================================
// Pipeline integration (end-to-end)
// =========================================================================

#[test]
fn test_pipeline_field_mapping_e2e() {
    use crate::pipeline::parse_pipeline;

    let pipeline_yaml = r#"
name: Sysmon to ECS
transformations:
  - type: field_name_mapping
    mapping:
      CommandLine: process.command_line
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
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;
    let collection = parse_sigma_yaml(rule_yaml).unwrap();

    let mut engine = Engine::new_with_pipeline(pipeline);
    engine.add_collection(&collection).unwrap();

    // After pipeline: field is renamed to process.command_line
    // So the event must use the original Sigma field name — the pipeline
    // maps rule fields, not event fields. Events still use their native schema.
    // Actually, after pipeline transforms the rule's field names,
    // the rule now looks for "process.command_line" in the event.
    let ev = json!({"process.command_line": "cmd /c whoami"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);

    // Old field name should no longer match
    let ev2 = json!({"CommandLine": "cmd /c whoami"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev2)).is_empty());
}

#[test]
fn test_pipeline_add_condition_e2e() {
    use crate::pipeline::parse_pipeline;

    let pipeline_yaml = r#"
name: Add index condition
transformations:
  - type: add_condition
    conditions:
      source: windows
    rule_conditions:
      - type: logsource
        product: windows
"#;
    let pipeline = parse_pipeline(pipeline_yaml).unwrap();

    let rule_yaml = r#"
title: Detect Cmd
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'cmd'
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(rule_yaml).unwrap();

    let mut engine = Engine::new_with_pipeline(pipeline);
    engine.add_collection(&collection).unwrap();

    // Must have both the original match AND source=windows
    let ev = json!({"CommandLine": "cmd.exe", "source": "windows"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);

    // Missing source field: should not match (pipeline added condition)
    let ev2 = json!({"CommandLine": "cmd.exe"});
    assert!(engine.evaluate(&JsonEvent::borrow(&ev2)).is_empty());
}

#[test]
fn test_pipeline_change_logsource_e2e() {
    use crate::pipeline::parse_pipeline;

    let pipeline_yaml = r#"
name: Change logsource
transformations:
  - type: change_logsource
    product: elastic
    category: endpoint
    rule_conditions:
      - type: logsource
        product: windows
"#;
    let pipeline = parse_pipeline(pipeline_yaml).unwrap();

    let rule_yaml = r#"
title: Test Rule
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        action: test
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(rule_yaml).unwrap();

    let mut engine = Engine::new_with_pipeline(pipeline);
    engine.add_collection(&collection).unwrap();

    // Rule still evaluates based on detection logic
    let ev = json!({"action": "test"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);

    // But with logsource routing, the original windows logsource no longer matches
    let ls = LogSource {
        product: Some("windows".to_string()),
        category: Some("process_creation".to_string()),
        ..Default::default()
    };
    assert!(
        engine
            .evaluate_with_logsource(&JsonEvent::borrow(&ev), &ls)
            .is_empty(),
        "logsource was changed; windows/process_creation should not match"
    );

    let ls2 = LogSource {
        product: Some("elastic".to_string()),
        category: Some("endpoint".to_string()),
        ..Default::default()
    };
    assert_eq!(
        engine
            .evaluate_with_logsource(&JsonEvent::borrow(&ev), &ls2)
            .len(),
        1,
        "elastic/endpoint should match the transformed logsource"
    );
}

#[test]
fn test_pipeline_replace_string_e2e() {
    use crate::pipeline::parse_pipeline;

    let pipeline_yaml = r#"
name: Replace backslash
transformations:
  - type: replace_string
    regex: "\\\\"
    replacement: "/"
"#;
    let pipeline = parse_pipeline(pipeline_yaml).unwrap();

    let rule_yaml = r#"
title: Path Detection
logsource:
    product: windows
detection:
    selection:
        FilePath|contains: 'C:\Windows'
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(rule_yaml).unwrap();

    let mut engine = Engine::new_with_pipeline(pipeline);
    engine.add_collection(&collection).unwrap();

    // After replace: rule looks for "C:/Windows" instead of "C:\Windows"
    let ev = json!({"FilePath": "C:/Windows/System32/cmd.exe"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);
}

#[test]
fn test_pipeline_skips_non_matching_rules() {
    use crate::pipeline::parse_pipeline;

    let pipeline_yaml = r#"
name: Windows Only
transformations:
  - type: field_name_prefix
    prefix: "win."
    rule_conditions:
      - type: logsource
        product: windows
"#;
    let pipeline = parse_pipeline(pipeline_yaml).unwrap();

    // Two rules: one Windows, one Linux
    let rule_yaml = r#"
title: Windows Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: low
---
title: Linux Rule
logsource:
    product: linux
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(rule_yaml).unwrap();
    assert_eq!(collection.rules.len(), 2);

    let mut engine = Engine::new_with_pipeline(pipeline);
    engine.add_collection(&collection).unwrap();

    // Windows rule: field was prefixed to win.CommandLine
    let ev_win = json!({"win.CommandLine": "whoami"});
    let m = engine.evaluate(&JsonEvent::borrow(&ev_win));
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].rule_title, "Windows Rule");

    // Linux rule: field was NOT prefixed (still CommandLine)
    let ev_linux = json!({"CommandLine": "whoami"});
    let m2 = engine.evaluate(&JsonEvent::borrow(&ev_linux));
    assert_eq!(m2.len(), 1);
    assert_eq!(m2[0].rule_title, "Linux Rule");
}

#[test]
fn test_multiple_pipelines_e2e() {
    use crate::pipeline::parse_pipeline;

    let p1_yaml = r#"
name: First Pipeline
priority: 10
transformations:
  - type: field_name_mapping
    mapping:
      CommandLine: process.args
"#;
    let p2_yaml = r#"
name: Second Pipeline
priority: 20
transformations:
  - type: field_name_suffix
    suffix: ".keyword"
"#;
    let p1 = parse_pipeline(p1_yaml).unwrap();
    let p2 = parse_pipeline(p2_yaml).unwrap();

    let rule_yaml = r#"
title: Test
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(rule_yaml).unwrap();

    let mut engine = Engine::new();
    engine.add_pipeline(p1);
    engine.add_pipeline(p2);
    engine.add_collection(&collection).unwrap();

    // After p1: CommandLine -> process.args
    // After p2: process.args -> process.args.keyword
    let ev = json!({"process.args.keyword": "testing"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);
}

#[test]
fn test_pipeline_drop_detection_item_e2e() {
    use crate::pipeline::parse_pipeline;

    let pipeline_yaml = r#"
name: Drop EventID
transformations:
  - type: drop_detection_item
    field_name_conditions:
      - type: include_fields
        fields:
          - EventID
"#;
    let pipeline = parse_pipeline(pipeline_yaml).unwrap();

    let rule_yaml = r#"
title: Sysmon Process
logsource:
    product: windows
detection:
    selection:
        EventID: 1
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;
    let collection = parse_sigma_yaml(rule_yaml).unwrap();

    let mut engine = Engine::new_with_pipeline(pipeline);
    engine.add_collection(&collection).unwrap();

    // EventID detection item was dropped, so only CommandLine matters
    let ev = json!({"CommandLine": "whoami"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);

    // Without pipeline, EventID=1 would also be required
    let mut engine2 = Engine::new();
    engine2.add_collection(&collection).unwrap();
    // Without EventID, should not match
    assert!(engine2.evaluate(&JsonEvent::borrow(&ev)).is_empty());
}

#[test]
fn test_pipeline_set_state_and_conditional() {
    use crate::pipeline::parse_pipeline;

    let pipeline_yaml = r#"
name: Stateful Pipeline
transformations:
  - id: mark_windows
    type: set_state
    key: is_windows
    value: "true"
    rule_conditions:
      - type: logsource
        product: windows
  - type: field_name_prefix
    prefix: "winlog."
    rule_conditions:
      - type: processing_state
        key: is_windows
        val: "true"
"#;
    let pipeline = parse_pipeline(pipeline_yaml).unwrap();

    let rule_yaml = r#"
title: Windows Detect
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
level: low
"#;
    let collection = parse_sigma_yaml(rule_yaml).unwrap();

    let mut engine = Engine::new_with_pipeline(pipeline);
    engine.add_collection(&collection).unwrap();

    // State was set → prefix was applied
    let ev = json!({"winlog.CommandLine": "testing"});
    assert_eq!(engine.evaluate(&JsonEvent::borrow(&ev)).len(), 1);
}

#[test]
fn test_evaluate_batch_matches_sequential() {
    let yaml = r#"
title: Login
logsource:
    product: windows
detection:
    selection:
        EventType: 'login'
    condition: selection
---
title: Process Create
logsource:
    product: windows
detection:
    selection:
        EventType: 'process_create'
    condition: selection
---
title: Keyword
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();

    let vals = [
        json!({"EventType": "login", "User": "admin"}),
        json!({"EventType": "process_create", "CommandLine": "whoami"}),
        json!({"EventType": "file_create"}),
        json!({"CommandLine": "whoami /all"}),
    ];
    let events: Vec<JsonEvent> = vals.iter().map(JsonEvent::borrow).collect();

    // Sequential
    let sequential: Vec<Vec<_>> = events.iter().map(|e| engine.evaluate(e)).collect();

    // Batch
    let refs: Vec<&JsonEvent> = events.iter().collect();
    let batch = engine.evaluate_batch(&refs);

    assert_eq!(sequential.len(), batch.len());
    for (seq, bat) in sequential.iter().zip(batch.iter()) {
        assert_eq!(seq.len(), bat.len());
        for (s, b) in seq.iter().zip(bat.iter()) {
            assert_eq!(s.rule_title, b.rule_title);
        }
    }
}
