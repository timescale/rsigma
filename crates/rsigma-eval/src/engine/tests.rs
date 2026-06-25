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
    assert_eq!(matches[0].header.rule_title, "Detect Whoami");
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

/// Build a `LogSource` from optional product/service/category for the
/// conflict-predicate and extractor tests.
fn ls(product: Option<&str>, service: Option<&str>, category: Option<&str>) -> LogSource {
    LogSource {
        product: product.map(String::from),
        service: service.map(String::from),
        category: category.map(String::from),
        ..Default::default()
    }
}

#[test]
fn test_logsource_compatible_matrix() {
    // Both set and equal: keep.
    assert!(logsource_compatible(
        &ls(Some("windows"), None, None),
        &ls(Some("windows"), None, None)
    ));
    // Both set and differ: skip.
    assert!(!logsource_compatible(
        &ls(Some("linux"), None, None),
        &ls(Some("windows"), None, None)
    ));
    // Rule set, event unset on category: keep (event never asserted it).
    assert!(logsource_compatible(
        &ls(Some("windows"), None, Some("process_creation")),
        &ls(Some("windows"), None, None)
    ));
    // Rule unset, event set: keep.
    assert!(logsource_compatible(
        &ls(None, None, None),
        &ls(Some("windows"), None, None)
    ));
    // Both unset: keep.
    assert!(logsource_compatible(
        &ls(None, None, None),
        &ls(None, None, None)
    ));
    // Case-insensitive equality: keep.
    assert!(logsource_compatible(
        &ls(Some("Windows"), None, None),
        &ls(Some("windows"), None, None)
    ));
    // Service conflict: skip.
    assert!(!logsource_compatible(
        &ls(None, Some("sysmon"), None),
        &ls(None, Some("security"), None)
    ));
    // Category conflict: skip.
    assert!(!logsource_compatible(
        &ls(None, None, Some("process_creation")),
        &ls(None, None, Some("network_connection"))
    ));
}

#[test]
fn test_logsource_extractor_reads_fields() {
    let extractor = crate::logsource::LogSourceExtractor::new();
    let ev = json!({
        "product": "windows",
        "service": "sysmon",
        "category": "process_creation",
        "CommandLine": "whoami"
    });
    let event = JsonEvent::borrow(&ev);
    let extracted = extractor.extract(&event);
    assert_eq!(extracted.product.as_deref(), Some("windows"));
    assert_eq!(extracted.service.as_deref(), Some("sysmon"));
    assert_eq!(extracted.category.as_deref(), Some("process_creation"));
}

#[test]
fn test_logsource_extractor_static_default() {
    let extractor =
        crate::logsource::LogSourceExtractor::new().with_defaults(ls(Some("windows"), None, None));
    let ev = json!({"CommandLine": "whoami"});
    let event = JsonEvent::borrow(&ev);
    let extracted = extractor.extract(&event);
    assert_eq!(extracted.product.as_deref(), Some("windows"));
    assert_eq!(extracted.category, None);
}

#[test]
fn test_logsource_extractor_field_overrides_default() {
    let extractor = crate::logsource::LogSourceExtractor::new().with_defaults(ls(
        Some("linux"),
        None,
        Some("process_creation"),
    ));
    let ev = json!({"product": "windows"});
    let event = JsonEvent::borrow(&ev);
    let extracted = extractor.extract(&event);
    // Explicit field wins for product; default fills the absent category.
    assert_eq!(extracted.product.as_deref(), Some("windows"));
    assert_eq!(extracted.category.as_deref(), Some("process_creation"));
    assert_eq!(extracted.service, None);
}

#[test]
fn test_logsource_extractor_fail_open() {
    let extractor = crate::logsource::LogSourceExtractor::new();
    // Missing fields and a blank product value all stay unset.
    let ev = json!({"CommandLine": "whoami", "product": "   "});
    let event = JsonEvent::borrow(&ev);
    let extracted = extractor.extract(&event);
    assert_eq!(extracted.product, None);
    assert_eq!(extracted.service, None);
    assert_eq!(extracted.category, None);
}

#[test]
fn test_logsource_extractor_custom_field_names() {
    let extractor =
        crate::logsource::LogSourceExtractor::new().with_field_names("os", "svc", "cat");
    let ev = json!({"os": "windows", "svc": "sysmon", "cat": "process_creation"});
    let event = JsonEvent::borrow(&ev);
    let extracted = extractor.extract(&event);
    assert_eq!(extracted.product.as_deref(), Some("windows"));
    assert_eq!(extracted.service.as_deref(), Some("sysmon"));
    assert_eq!(extracted.category.as_deref(), Some("process_creation"));
}

#[test]
fn test_logsource_pruning_skips_conflicting_product() {
    let yaml = r#"
title: Linux Rule
logsource:
    product: linux
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
---
title: Windows Process Rule
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
---
title: Generic Rule
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;
    let mut engine = make_engine_with_rule(yaml);

    let ev = json!({"CommandLine": "whoami", "product": "windows"});
    let event = JsonEvent::borrow(&ev);

    // Without pruning, all three rules match on content.
    assert_eq!(engine.evaluate(&event).len(), 3);

    // With pruning, the conflicting linux rule is dropped; the windows rule
    // (event has no category, so no conflict) and the product-less generic
    // rule still fire.
    engine.set_logsource_extractor(Some(crate::logsource::LogSourceExtractor::new()));
    let titles: Vec<String> = engine
        .evaluate(&event)
        .into_iter()
        .map(|m| m.header.rule_title.clone())
        .collect();
    assert_eq!(titles.len(), 2, "got: {titles:?}");
    assert!(titles.contains(&"Windows Process Rule".to_string()));
    assert!(titles.contains(&"Generic Rule".to_string()));
    assert!(!titles.contains(&"Linux Rule".to_string()));

    // The bloom path prunes identically.
    engine.set_bloom_prefilter(true);
    assert_eq!(engine.evaluate(&event).len(), 2);
}

#[test]
fn test_logsource_pruning_fails_open_without_event_logsource() {
    let yaml = r#"
title: Linux Rule
logsource:
    product: linux
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
---
title: Windows Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;
    let mut engine = make_engine_with_rule(yaml);
    engine.set_logsource_extractor(Some(crate::logsource::LogSourceExtractor::new()));

    // Event carries no logsource fields: pruning fails open, both fire.
    let ev = json!({"CommandLine": "whoami"});
    let event = JsonEvent::borrow(&ev);
    assert_eq!(engine.evaluate(&event).len(), 2);
}

#[test]
fn test_logsource_pruning_applies_to_evaluate_batch() {
    let yaml = r#"
title: Linux Rule
logsource:
    product: linux
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
---
title: Windows Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;
    let mut engine = make_engine_with_rule(yaml);
    engine.set_logsource_extractor(Some(crate::logsource::LogSourceExtractor::new()));

    let ev1 = json!({"CommandLine": "whoami", "product": "windows"});
    let ev2 = json!({"CommandLine": "whoami", "product": "windows"});
    let e1 = JsonEvent::borrow(&ev1);
    let e2 = JsonEvent::borrow(&ev2);
    let results = engine.evaluate_batch(&[&e1, &e2]);
    assert_eq!(results.len(), 2);
    for per_event in &results {
        assert_eq!(per_event.len(), 1);
        assert_eq!(per_event[0].header.rule_title, "Windows Rule");
    }
}

#[test]
fn test_logsource_pruning_inherited_by_correlation_engine() {
    let yaml = r#"
title: Linux Only
logsource:
    product: linux
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = crate::CorrelationEngine::new(crate::CorrelationConfig::default());
    engine.add_collection(&collection).unwrap();
    engine.set_logsource_extractor(Some(crate::logsource::LogSourceExtractor::new()));

    // The linux rule conflicts with a windows event, so correlation's inner
    // detection evaluation prunes it: no detection fires.
    let ev = json!({"CommandLine": "whoami", "product": "windows"});
    let event = JsonEvent::borrow(&ev);
    let result = engine.process_event(&event);
    assert_eq!(result.iter().filter(|r| r.is_detection()).count(), 0);
    assert_eq!(engine.logsource_pruned_total(), 1);
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
    assert_eq!(matches[0].header.rule_title, "Rule A");
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
    assert_eq!(matches1[0].header.rule_title, "Detect Whoami");

    // Second rule matches ipconfig (inherited logsource/level)
    let ev2 = json!({"CommandLine": "ipconfig /all"});
    let matches2 = engine.evaluate(&JsonEvent::borrow(&ev2));
    assert_eq!(matches2.len(), 1);
    assert_eq!(matches2[0].header.rule_title, "Detect Ipconfig");

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
    assert_eq!(m1[0].header.rule_title, "Detect Net User");

    let ev2 = json!({"CommandLine": "net group admins"});
    let m2 = engine.evaluate(&JsonEvent::borrow(&ev2));
    assert_eq!(m2.len(), 1);
    assert_eq!(m2[0].header.rule_title, "Detect Net Group");
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
    assert_eq!(m[0].header.rule_title, "Windows Rule");

    // Linux rule: field was NOT prefixed (still CommandLine)
    let ev_linux = json!({"CommandLine": "whoami"});
    let m2 = engine.evaluate(&JsonEvent::borrow(&ev_linux));
    assert_eq!(m2.len(), 1);
    assert_eq!(m2[0].header.rule_title, "Linux Rule");
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
fn test_add_rules_matches_per_rule_loop() {
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

    let mut per_rule = Engine::new();
    for rule in &collection.rules {
        per_rule.add_rule(rule).unwrap();
    }

    let mut batched = Engine::new();
    let errors = batched.add_rules(&collection.rules);
    assert!(errors.is_empty());

    assert_eq!(per_rule.rules().len(), batched.rules().len());

    let evs = [
        json!({"EventType": "login"}),
        json!({"EventType": "process_create", "CommandLine": "whoami"}),
        json!({"CommandLine": "whoami /all"}),
        json!({"EventType": "file_create"}),
    ];
    for v in &evs {
        let event = JsonEvent::borrow(v);
        let a: Vec<_> = per_rule
            .evaluate(&event)
            .into_iter()
            .map(|m| m.header.rule_title)
            .collect();
        let b: Vec<_> = batched
            .evaluate(&event)
            .into_iter()
            .map(|m| m.header.rule_title)
            .collect();
        assert_eq!(a, b, "verdicts diverge for event {v}");
    }
}

#[test]
fn test_add_rules_collects_errors_without_aborting() {
    let good = r#"
title: Login
logsource:
    product: windows
detection:
    selection:
        EventType: 'login'
    condition: selection
"#;
    let bad = r#"
title: Broken Reference
logsource:
    product: windows
detection:
    selection:
        EventType: 'x'
    condition: unknown_identifier
"#;
    let good_rule = parse_sigma_yaml(good).unwrap().rules.remove(0);
    let bad_rule = parse_sigma_yaml(bad).unwrap().rules.remove(0);

    let mut engine = Engine::new();
    let errors = engine.add_rules([&good_rule, &bad_rule, &good_rule]);

    // The bad rule fails; the two good rules still land in the engine.
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].0, 1);
    assert_eq!(engine.rules().len(), 2);

    let ev = json!({"EventType": "login"});
    let matches = engine.evaluate(&JsonEvent::borrow(&ev));
    assert_eq!(matches.len(), 2);
}

/// Regression: loading a multi-thousand rule corpus must stay linear in
/// the rule count. The previous `add_rule` per-rule loop rebuilt the
/// inverted index after every push, turning a 3K-rule load into a
/// multi-minute O(N²) stall. Generating 2000 trivial rules and timing the
/// batched load gives us a cheap, deterministic guard: even on a slow
/// debug build this completes in well under a second, and the old
/// per-rule path would blow well past the 30s ceiling.
#[test]
fn test_add_rules_scales_linearly_on_large_corpus() {
    use std::time::Instant;

    let mut yaml = String::new();
    let n = 2000;
    for i in 0..n {
        if i > 0 {
            yaml.push_str("---\n");
        }
        // Mix of exact-match (indexable) and substring (bloom-eligible)
        // rules so both the rule index and the bloom rebuild are exercised.
        yaml.push_str(&format!(
            "title: Rule {i}\nlogsource:\n    product: windows\ndetection:\n    selection:\n        EventID: '{i}'\n        CommandLine|contains: 'needle{i}'\n    condition: selection\n"
        ));
    }
    let collection = parse_sigma_yaml(&yaml).unwrap();
    assert_eq!(collection.rules.len(), n);

    let started = Instant::now();
    let mut engine = Engine::new();
    let errors = engine.add_rules(&collection.rules);
    let elapsed = started.elapsed();

    assert!(errors.is_empty());
    assert_eq!(engine.rules().len(), n);
    // 30s is a coarse ceiling that the linear path clears by ~100x but
    // the old O(N²) rebuild would not get close to. Stay conservative so
    // the test never flakes on overloaded CI runners.
    assert!(
        elapsed.as_secs() < 30,
        "loading {n} rules took {elapsed:?}; suspect quadratic regression"
    );
}

/// Regression: a tight loop of `add_rule` calls must also stay linear in
/// the rule count. Before incremental indexing this path was O(N²)
/// because every call rebuilt the inverted index and bloom filter; the
/// equivalent of [`test_add_rules_scales_linearly_on_large_corpus`] for
/// the single-rule entry point.
#[test]
fn test_add_rule_loop_scales_linearly_on_large_corpus() {
    use std::time::Instant;

    let mut yaml = String::new();
    let n = 2000;
    for i in 0..n {
        if i > 0 {
            yaml.push_str("---\n");
        }
        yaml.push_str(&format!(
            "title: Rule {i}\nlogsource:\n    product: windows\ndetection:\n    selection:\n        EventID: '{i}'\n        CommandLine|contains: 'needle{i}'\n    condition: selection\n"
        ));
    }
    let collection = parse_sigma_yaml(&yaml).unwrap();
    assert_eq!(collection.rules.len(), n);

    let started = Instant::now();
    let mut engine = Engine::new();
    for rule in &collection.rules {
        engine.add_rule(rule).unwrap();
    }
    let elapsed = started.elapsed();

    assert_eq!(engine.rules().len(), n);
    assert!(
        elapsed.as_secs() < 30,
        "loading {n} rules one at a time took {elapsed:?}; suspect quadratic regression"
    );
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
            assert_eq!(s.header.rule_title, b.header.rule_title);
        }
    }
}

// =============================================================================
// Array matching (object-scope quantifier blocks + implicit any-member)
// =============================================================================

/// Whether a rule matches an event value.
fn matches(engine: &Engine, ev: &serde_json::Value) -> bool {
    !engine.evaluate(&JsonEvent::borrow(ev)).is_empty()
}

#[test]
fn array_implicit_any_flat_scalar_array() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections: '123.1.1.1'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"connections": ["123.1.2.2", "123.1.1.1", "123.3.3.3"]})
    ));
    assert!(!matches(
        &engine,
        &json!({"connections": ["10.0.0.1", "10.0.0.2"]})
    ));
}

#[test]
fn array_implicit_any_through_object_array_fans_out() {
    // Regression for the first-match-wins traversal bug: the matching element
    // is NOT first, so this only passes with full fan-out.
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections.ip: '123.1.1.1'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"connections": [{"ip": "10.0.0.1"}, {"ip": "123.1.1.1"}]})
    ));
}

#[test]
fn array_brackets_literal_field_below_v3() {
    // Without sigma-version (floor major 2), `args[0]` is a literal field name,
    // not a positional index: it matches an event whose key is literally
    // "args[0]" and does NOT index into an `args` array.
    let engine = make_engine_with_rule(
        r#"
title: T
logsource: { category: test }
detection:
    selection:
        args[0]: 'cmd.exe'
    condition: selection
"#,
    );
    assert!(matches(&engine, &json!({"args[0]": "cmd.exe"})));
    assert!(!matches(&engine, &json!({"args": ["cmd.exe", "-flag"]})));
}

#[test]
fn array_object_scope_any_correlates_same_element() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[any]:
            protocol: 'TCP'
            ip|cidr: '123.1.0.0/16'
    condition: selection
"#,
    );
    // One element is both TCP and in-CIDR -> match.
    assert!(matches(
        &engine,
        &json!({"connections": [
            {"protocol": "UDP", "ip": "123.1.5.5"},
            {"protocol": "TCP", "ip": "123.1.9.9"}
        ]})
    ));
    // TCP and in-CIDR exist, but on DIFFERENT elements -> no match
    // (this is the property the flattened form cannot express).
    assert!(!matches(
        &engine,
        &json!({"connections": [
            {"protocol": "TCP", "ip": "10.0.0.1"},
            {"protocol": "UDP", "ip": "123.1.9.9"}
        ]})
    ));
}

#[test]
fn array_object_scope_all_requires_every_member_and_nonempty() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[all]:
            protocol: 'TCP'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"connections": [{"protocol": "TCP"}, {"protocol": "TCP"}]})
    ));
    assert!(!matches(
        &engine,
        &json!({"connections": [{"protocol": "TCP"}, {"protocol": "UDP"}]})
    ));
    // Empty / missing array must not match `all`.
    assert!(!matches(&engine, &json!({"connections": []})));
    assert!(!matches(&engine, &json!({"other": 1})));
}

#[test]
fn array_scalar_member_all_with_modifier() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        ips[all]|startswith: '123.'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"ips": ["123.1.1.1", "123.9.9.9"]})
    ));
    assert!(!matches(
        &engine,
        &json!({"ips": ["123.1.1.1", "10.0.0.1"]})
    ));
}

#[test]
fn array_nested_quantifiers() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        rules[any]:
            type: 'allow'
            ip[all]|startswith: '123.1.1'
    condition: selection
"#,
    );
    // There is an allow rule whose ip array members all start with 123.1.1.
    assert!(matches(
        &engine,
        &json!({"rules": [
            {"type": "block", "ip": ["124.0.0.1"]},
            {"type": "allow", "ip": ["123.1.1.2", "123.1.1.3"]}
        ]})
    ));
    // The allow rule has a non-conforming ip -> no match.
    assert!(!matches(
        &engine,
        &json!({"rules": [
            {"type": "allow", "ip": ["123.1.1.2", "10.0.0.1"]}
        ]})
    ));
}

#[test]
fn array_mixed_map_and_semantics() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        eventName: 'AuthorizeSecurityGroupIngress'
        ipPermissions[any]:
            ipRanges|contains: '0.0.0.0/0'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({
            "eventName": "AuthorizeSecurityGroupIngress",
            "ipPermissions": [{"ipRanges": "0.0.0.0/0"}]
        })
    ));
    // Array matches but the sibling scalar does not -> AND fails.
    assert!(!matches(
        &engine,
        &json!({
            "eventName": "RunInstances",
            "ipPermissions": [{"ipRanges": "0.0.0.0/0"}]
        })
    ));
}

#[test]
fn array_okta_scopes_cloud_shape() {
    let engine = make_engine_with_rule(
        r#"
title: Okta high-priv scope grant
sigma-version: 3
logsource: { product: okta, service: system }
detection:
    selection:
        target[any]:
            type: 'PUBLIC_CLIENT_APP'
            scopes|contains: 'okta.users.manage'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"target": [
            {"type": "USER", "scopes": "okta.users.read"},
            {"type": "PUBLIC_CLIENT_APP", "scopes": "okta.users.manage okta.apps.read"}
        ]})
    ));
}

#[test]
fn array_positional_index_scalar() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        args[0]|endswith: '\powershell.exe'
        args[1]: '-enc'
    condition: selection
"#,
    );
    // Positional disambiguation: image at [0], first parameter at [1].
    assert!(matches(
        &engine,
        &json!({"args": ["C:\\Windows\\System32\\powershell.exe", "-enc", "ZQ=="]})
    ));
    // '-enc' present but NOT at index 1 -> no match (index is exact, not any).
    assert!(!matches(
        &engine,
        &json!({"args": ["C:\\Windows\\System32\\powershell.exe", "-noprofile", "-enc"]})
    ));
}

#[test]
fn array_positional_index_does_not_fan_out() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        ips[0]: '10.0.0.1'
    condition: selection
"#,
    );
    assert!(matches(&engine, &json!({"ips": ["10.0.0.1", "8.8.8.8"]})));
    // 10.0.0.1 present but at index 1, not 0 -> no match.
    assert!(!matches(&engine, &json!({"ips": ["8.8.8.8", "10.0.0.1"]})));
    // Out of range / non-array -> no match.
    assert!(!matches(&engine, &json!({"ips": []})));
    assert!(!matches(&engine, &json!({"ips": "10.0.0.1"})));
}

#[test]
fn array_positional_index_dotted_path() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[0].ip|cidr: '10.0.0.0/8'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"connections": [{"ip": "10.1.2.3"}, {"ip": "192.168.1.1"}]})
    ));
    // The in-CIDR ip is at index 1, not 0 -> no match.
    assert!(!matches(
        &engine,
        &json!({"connections": [{"ip": "192.168.1.1"}, {"ip": "10.1.2.3"}]})
    ));
}

#[test]
fn array_escaped_brackets_match_literal_field() {
    // `args\[0\]` matches a field literally named "args[0]", not index 0 of an
    // `args` array.
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        args\[0\]: 'cmd.exe'
    condition: selection
"#,
    );
    // Literal field present -> match.
    assert!(matches(&engine, &json!({"args[0]": "cmd.exe"})));
    // An `args` array does NOT satisfy the escaped (literal) field.
    assert!(!matches(&engine, &json!({"args": ["cmd.exe", "x"]})));
}

#[test]
fn array_negative_index_counts_from_end() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        args[-1]: '-enc'
    condition: selection
"#,
    );
    // -1 is the last element.
    assert!(matches(
        &engine,
        &json!({"args": ["powershell.exe", "-noprofile", "-enc"]})
    ));
    // '-enc' present but not last -> no match (index is exact).
    assert!(!matches(
        &engine,
        &json!({"args": ["powershell.exe", "-enc", "ZQ=="]})
    ));
    // Out of range (|index| > len) and non-array -> no match.
    assert!(!matches(&engine, &json!({"args": []})));
    assert!(!matches(&engine, &json!({"args": "-enc"})));
}

#[test]
fn array_negative_index_dotted_path() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        events[-1].action: 'delete'
    condition: selection
"#,
    );
    // The last event's action is what matters.
    assert!(matches(
        &engine,
        &json!({"events": [{"action": "create"}, {"action": "delete"}]})
    ));
    assert!(!matches(
        &engine,
        &json!({"events": [{"action": "delete"}, {"action": "create"}]})
    ));
}

#[test]
fn array_index_inside_quantifier() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        rules[any].ip[0]: '10.0.0.1'
    condition: selection
"#,
    );
    // Some rule whose FIRST ip is 10.0.0.1.
    assert!(matches(
        &engine,
        &json!({"rules": [
            {"ip": ["8.8.8.8"]},
            {"ip": ["10.0.0.1", "1.1.1.1"]}
        ]})
    ));
    // 10.0.0.1 appears, but never at index 0 -> no match.
    assert!(!matches(
        &engine,
        &json!({"rules": [{"ip": ["8.8.8.8", "10.0.0.1"]}]})
    ));
}

#[test]
fn array_object_scope_none_is_dual_of_any() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        containers[none]:
            image|startswith: 'evil/'
    condition: selection
"#,
    );
    // No container runs an evil image -> match.
    assert!(matches(
        &engine,
        &json!({"containers": [{"image": "nginx"}, {"image": "redis"}]})
    ));
    // One container runs an evil image -> no match.
    assert!(!matches(
        &engine,
        &json!({"containers": [{"image": "nginx"}, {"image": "evil/miner"}]})
    ));
    // An empty or missing array matches `none` (no member satisfies the body).
    assert!(matches(&engine, &json!({"containers": []})));
    assert!(matches(&engine, &json!({"other": 1})));
}

#[test]
fn array_object_scope_all_or_empty_matches_empty() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[all_or_empty]:
            protocol: 'TCP'
    condition: selection
"#,
    );
    // Like `all` when non-empty: every member must satisfy.
    assert!(matches(
        &engine,
        &json!({"connections": [{"protocol": "TCP"}, {"protocol": "TCP"}]})
    ));
    assert!(!matches(
        &engine,
        &json!({"connections": [{"protocol": "TCP"}, {"protocol": "UDP"}]})
    ));
    // Unlike `all`, an empty or missing array matches (vacuously true).
    assert!(matches(&engine, &json!({"connections": []})));
    assert!(matches(&engine, &json!({"other": 1})));
}

#[test]
fn array_extended_block_per_element_negation() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[any]:
            condition: in_cidr and not is_tcp
            in_cidr:
                ip|cidr: '123.1.0.0/16'
            is_tcp:
                protocol: 'TCP'
    condition: selection
"#,
    );
    // One element is in-CIDR and UDP (not TCP) -> match.
    assert!(matches(
        &engine,
        &json!({"connections": [
            {"protocol": "TCP", "ip": "10.0.0.1"},
            {"protocol": "UDP", "ip": "123.1.9.9"}
        ]})
    ));
    // In-CIDR only on the TCP element; the UDP element is out of CIDR. No
    // single element is both in-CIDR and non-TCP -> no match (per-element bind).
    assert!(!matches(
        &engine,
        &json!({"connections": [
            {"protocol": "TCP", "ip": "123.1.9.9"},
            {"protocol": "UDP", "ip": "10.0.0.1"}
        ]})
    ));
}

#[test]
fn array_extended_block_per_element_disjunction() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        events[any]:
            condition: is_delete or is_drop
            is_delete:
                action: 'delete'
            is_drop:
                action: 'drop'
    condition: selection
"#,
    );
    assert!(matches(
        &engine,
        &json!({"events": [{"action": "create"}, {"action": "drop"}]})
    ));
    assert!(!matches(
        &engine,
        &json!({"events": [{"action": "create"}, {"action": "update"}]})
    ));
}

#[test]
fn array_extended_block_all_quantifier() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        mounts[all]:
            condition: readonly and not is_proc
            readonly:
                mode: 'ro'
            is_proc:
                path|startswith: '/proc'
    condition: selection
"#,
    );
    // Every mount is read-only and none under /proc -> match.
    assert!(matches(
        &engine,
        &json!({"mounts": [
            {"mode": "ro", "path": "/data"},
            {"mode": "ro", "path": "/etc"}
        ]})
    ));
    // One mount is read-write -> no match (all required).
    assert!(!matches(
        &engine,
        &json!({"mounts": [
            {"mode": "ro", "path": "/data"},
            {"mode": "rw", "path": "/etc"}
        ]})
    ));
}

#[test]
fn array_extended_block_scalar_element_marker() {
    // `.` references the current scalar member inside an extended block body:
    // "any 5xx response code that is not 504".
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        rcodes[any]:
            condition: server_error and not gateway_timeout
            server_error:
                .|gte: 500
                .|lte: 599
            gateway_timeout:
                .: 504
    condition: selection
"#,
    );
    assert!(matches(&engine, &json!({"rcodes": [502, 504, 200]})));
    // Only a 504 and a non-5xx -> no element is a 5xx that is not 504.
    assert!(!matches(&engine, &json!({"rcodes": [504, 200]})));
    assert!(matches(&engine, &json!({"rcodes": [503]})));
    assert!(!matches(&engine, &json!({"rcodes": [200, 301]})));
}

#[test]
fn array_scalar_element_marker_basic_block() {
    // `.` in a basic block: every member satisfies the predicate.
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        ports[all]:
            .|gte: 1024
    condition: selection
"#,
    );
    assert!(matches(&engine, &json!({"ports": [1080, 8443]})));
    assert!(!matches(&engine, &json!({"ports": [1080, 80]})));
}

#[test]
fn array_scalar_member_none() {
    let engine = make_engine_with_rule(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        tags[none]: 'admin'
    condition: selection
"#,
    );
    assert!(matches(&engine, &json!({"tags": ["user", "guest"]})));
    assert!(!matches(&engine, &json!({"tags": ["user", "admin"]})));
    assert!(matches(&engine, &json!({"tags": []})));
    assert!(matches(&engine, &json!({"other": 1})));
}
