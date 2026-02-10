//! Rule evaluation engine with logsource routing.
//!
//! The `Engine` manages a set of compiled Sigma rules and evaluates events
//! against them. It supports optional logsource-based pre-filtering to
//! reduce the number of rules evaluated per event.

use rsigma_parser::{ConditionExpr, FilterRule, LogSource, SigmaCollection, SigmaRule};

use crate::compiler::{CompiledRule, compile_detection, compile_rule, evaluate_rule};
use crate::error::Result;
use crate::event::Event;
use crate::result::MatchResult;

/// The main rule evaluation engine.
///
/// Holds a set of compiled rules and provides methods to evaluate events
/// against them. Supports optional logsource routing for performance.
///
/// # Example
///
/// ```rust
/// use rsigma_parser::parse_sigma_yaml;
/// use rsigma_eval::{Engine, Event};
/// use serde_json::json;
///
/// let yaml = r#"
/// title: Detect Whoami
/// logsource:
///     product: windows
///     category: process_creation
/// detection:
///     selection:
///         CommandLine|contains: 'whoami'
///     condition: selection
/// level: medium
/// "#;
///
/// let collection = parse_sigma_yaml(yaml).unwrap();
/// let mut engine = Engine::new();
/// engine.add_collection(&collection).unwrap();
///
/// let event_val = json!({"CommandLine": "cmd /c whoami"});
/// let event = Event::from_value(&event_val);
/// let matches = engine.evaluate(&event);
/// assert_eq!(matches.len(), 1);
/// assert_eq!(matches[0].rule_title, "Detect Whoami");
/// ```
pub struct Engine {
    rules: Vec<CompiledRule>,
}

impl Engine {
    /// Create a new empty engine.
    pub fn new() -> Self {
        Engine { rules: Vec::new() }
    }

    /// Add a single parsed Sigma rule.
    pub fn add_rule(&mut self, rule: &SigmaRule) -> Result<()> {
        let compiled = compile_rule(rule)?;
        self.rules.push(compiled);
        Ok(())
    }

    /// Add all detection rules from a parsed collection, then apply filters.
    ///
    /// Filter rules modify referenced detection rules by appending exclusion
    /// conditions. Correlation rules are handled by `CorrelationEngine`.
    pub fn add_collection(&mut self, collection: &SigmaCollection) -> Result<()> {
        for rule in &collection.rules {
            self.add_rule(rule)?;
        }
        // Apply filter rules after all detection rules are loaded
        for filter in &collection.filters {
            self.apply_filter(filter)?;
        }
        Ok(())
    }

    /// Apply a filter rule to all referenced detection rules.
    ///
    /// For each detection in the filter, compile it and inject it into matching
    /// rules as `AND NOT filter_condition`.
    pub fn apply_filter(&mut self, filter: &FilterRule) -> Result<()> {
        // Compile filter detections
        let mut filter_detections = Vec::new();
        for (name, detection) in &filter.detection.named {
            let compiled = compile_detection(detection)?;
            filter_detections.push((name.clone(), compiled));
        }

        if filter_detections.is_empty() {
            return Ok(());
        }

        // Build the filter condition expression: AND of all filter detections
        let filter_cond = if filter_detections.len() == 1 {
            ConditionExpr::Identifier(format!("__filter_{}", filter_detections[0].0))
        } else {
            ConditionExpr::And(
                filter_detections
                    .iter()
                    .map(|(name, _)| ConditionExpr::Identifier(format!("__filter_{name}")))
                    .collect(),
            )
        };

        // Find and modify referenced rules
        for rule in &mut self.rules {
            let rule_matches = filter.rules.is_empty() // empty = applies to all
                || filter.rules.iter().any(|r| {
                    rule.id.as_deref() == Some(r.as_str())
                        || rule.title == *r
                });

            // Also check logsource compatibility if the filter specifies one
            if rule_matches {
                if let Some(ref filter_ls) = filter.logsource
                    && !logsource_matches(&rule.logsource, filter_ls)
                    && !logsource_matches(filter_ls, &rule.logsource)
                {
                    continue;
                }

                // Inject filter detections into the rule
                for (name, compiled) in &filter_detections {
                    rule.detections
                        .insert(format!("__filter_{name}"), compiled.clone());
                }

                // Wrap each existing condition: original AND NOT filter
                rule.conditions = rule
                    .conditions
                    .iter()
                    .map(|cond| {
                        ConditionExpr::And(vec![
                            cond.clone(),
                            ConditionExpr::Not(Box::new(filter_cond.clone())),
                        ])
                    })
                    .collect();
            }
        }

        Ok(())
    }

    /// Add a pre-compiled rule directly.
    pub fn add_compiled_rule(&mut self, rule: CompiledRule) {
        self.rules.push(rule);
    }

    /// Evaluate an event against all rules, returning matches.
    pub fn evaluate(&self, event: &Event) -> Vec<MatchResult> {
        let mut results = Vec::new();
        for rule in &self.rules {
            if let Some(m) = evaluate_rule(rule, event) {
                results.push(m);
            }
        }
        results
    }

    /// Evaluate an event against rules matching the given logsource.
    ///
    /// Only rules whose logsource is compatible with `event_logsource` are
    /// evaluated. A rule's logsource is compatible if every field it specifies
    /// (category, product, service) matches the corresponding field in the
    /// event logsource.
    pub fn evaluate_with_logsource(
        &self,
        event: &Event,
        event_logsource: &LogSource,
    ) -> Vec<MatchResult> {
        let mut results = Vec::new();
        for rule in &self.rules {
            if logsource_matches(&rule.logsource, event_logsource)
                && let Some(m) = evaluate_rule(rule, event)
            {
                results.push(m);
            }
        }
        results
    }

    /// Number of rules loaded in the engine.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Access the compiled rules.
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a rule's logsource is compatible with an event's logsource.
///
/// The rule matches if every non-`None` field in the rule's logsource has
/// the same value in the event's logsource. Fields the rule doesn't specify
/// are ignored (wildcard).
fn logsource_matches(rule_ls: &LogSource, event_ls: &LogSource) -> bool {
    if let Some(ref cat) = rule_ls.category {
        match &event_ls.category {
            Some(ec) if ec.eq_ignore_ascii_case(cat) => {}
            _ => return false,
        }
    }
    if let Some(ref prod) = rule_ls.product {
        match &event_ls.product {
            Some(ep) if ep.eq_ignore_ascii_case(prod) => {}
            _ => return false,
        }
    }
    if let Some(ref svc) = rule_ls.service {
        match &event_ls.service {
            Some(es) if es.eq_ignore_ascii_case(svc) => {}
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let event = Event::from_value(&ev);
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
        let event = Event::from_value(&ev);
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
        let event = Event::from_value(&ev);
        assert_eq!(engine.evaluate(&event).len(), 1);

        // No match: whoami by SYSTEM
        let ev2 = json!({"CommandLine": "whoami", "User": "SYSTEM"});
        let event2 = Event::from_value(&ev2);
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
        let event = Event::from_value(&ev);
        assert_eq!(engine.evaluate(&event).len(), 1);

        let ev2 = json!({"CommandLine": "dir"});
        let event2 = Event::from_value(&ev2);
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
        let event = Event::from_value(&ev);

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
        let event = Event::from_value(&ev);
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
detection:
    filter_system:
        User: 'SYSTEM'
    condition: filter_system
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert_eq!(collection.rules.len(), 1);
        assert_eq!(collection.filters.len(), 1);

        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();

        // Match: whoami by non-SYSTEM user
        let ev = json!({"CommandLine": "whoami", "User": "admin"});
        let event = Event::from_value(&ev);
        assert_eq!(engine.evaluate(&event).len(), 1);

        // No match: whoami by SYSTEM (filtered out)
        let ev2 = json!({"CommandLine": "whoami", "User": "SYSTEM"});
        let event2 = Event::from_value(&ev2);
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
detection:
    exclude:
        Environment: 'test'
    condition: exclude
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();

        let ev = json!({"EventType": "alert", "Environment": "prod"});
        let event = Event::from_value(&ev);
        assert_eq!(engine.evaluate(&event).len(), 1);

        let ev2 = json!({"EventType": "alert", "Environment": "test"});
        let event2 = Event::from_value(&ev2);
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
        let event = Event::from_value(&ev);
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
detection:
    exclude:
        ParentImage|endswith: '\admin_toolkit.exe'
    condition: exclude
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();

        // Match: mimikatz not launched by admin toolkit
        let ev = json!({"CommandLine": "mimikatz.exe", "ParentImage": "C:\\cmd.exe"});
        let event = Event::from_value(&ev);
        assert_eq!(engine.evaluate(&event).len(), 1);

        // No match: mimikatz launched by admin toolkit (filtered)
        let ev2 = json!({"CommandLine": "mimikatz.exe", "ParentImage": "C:\\admin_toolkit.exe"});
        let event2 = Event::from_value(&ev2);
        assert!(engine.evaluate(&event2).is_empty());
    }

    #[test]
    fn test_filter_multiple_detections() {
        // Filter with multiple detection items (AND)
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
detection:
    trusted_dst:
        DestinationIp|startswith: '10.'
    trusted_user:
        User: 'svc_account'
    condition: trusted_dst and trusted_user
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();

        // Match: port 443 to external IP
        let ev = json!({"DestinationPort": 443, "DestinationIp": "8.8.8.8", "User": "admin"});
        let event = Event::from_value(&ev);
        assert_eq!(engine.evaluate(&event).len(), 1);

        // Match: port 443 to internal IP but different user (filter needs both)
        let ev2 = json!({"DestinationPort": 443, "DestinationIp": "10.0.0.1", "User": "admin"});
        let event2 = Event::from_value(&ev2);
        assert_eq!(engine.evaluate(&event2).len(), 1);

        // No match: port 443 to internal IP by svc_account (both filter conditions met)
        let ev3 =
            json!({"DestinationPort": 443, "DestinationIp": "10.0.0.1", "User": "svc_account"});
        let event3 = Event::from_value(&ev3);
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
detection:
    exclude:
        Environment: 'test'
    condition: exclude
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();

        // In prod: both rules should fire
        let ev1 = json!({"EventID": 1, "Environment": "prod"});
        assert_eq!(engine.evaluate(&Event::from_value(&ev1)).len(), 1);
        let ev2 = json!({"EventID": 2, "Environment": "prod"});
        assert_eq!(engine.evaluate(&Event::from_value(&ev2)).len(), 1);

        // In test: both filtered out
        let ev3 = json!({"EventID": 1, "Environment": "test"});
        assert!(engine.evaluate(&Event::from_value(&ev3)).is_empty());
        let ev4 = json!({"EventID": 2, "Environment": "test"});
        assert!(engine.evaluate(&Event::from_value(&ev4)).is_empty());
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
        assert_eq!(engine.evaluate(&Event::from_value(&ev)).len(), 1);

        // No match: different user
        let ev2 = json!({
            "TargetFilename": "C:\\Users\\admin\\AppData\\sensitive.dat",
            "username": "guest"
        });
        assert!(engine.evaluate(&Event::from_value(&ev2)).is_empty());
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
        assert_eq!(engine.evaluate(&Event::from_value(&ev)).len(), 1);

        let ev2 = json!({
            "RegistryKey": "HKLM\\SOFTWARE\\Acme\\Widget",
            "vendor": "Other",
            "product": "Widget"
        });
        assert!(engine.evaluate(&Event::from_value(&ev2)).is_empty());
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
        assert_eq!(engine.evaluate(&Event::from_value(&ev)).len(), 1);

        // No match: login at 14:xx UTC
        let ev2 = json!({"EventType": "login", "Timestamp": "2024-07-10T14:45:00Z"});
        assert!(engine.evaluate(&Event::from_value(&ev2)).is_empty());
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
        assert_eq!(engine.evaluate(&Event::from_value(&ev)).len(), 1);

        let ev2 = json!({"EventType": "access", "CreatedAt": "2024-12-26T10:00:00Z"});
        assert!(engine.evaluate(&Event::from_value(&ev2)).is_empty());
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
        assert_eq!(engine.evaluate(&Event::from_value(&ev)).len(), 1);

        let ev2 = json!({"EventType": "auth", "EventTime": "2024-06-15T10:00:00Z"});
        assert!(engine.evaluate(&Event::from_value(&ev2)).is_empty());
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
        let matches1 = engine.evaluate(&Event::from_value(&ev1));
        assert_eq!(matches1.len(), 1);
        assert_eq!(matches1[0].rule_title, "Detect Whoami");

        // Second rule matches ipconfig (inherited logsource/level)
        let ev2 = json!({"CommandLine": "ipconfig /all"});
        let matches2 = engine.evaluate(&Event::from_value(&ev2));
        assert_eq!(matches2.len(), 1);
        assert_eq!(matches2[0].rule_title, "Detect Ipconfig");

        // Neither matches dir
        let ev3 = json!({"CommandLine": "dir"});
        assert!(engine.evaluate(&Event::from_value(&ev3)).is_empty());
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
        let m1 = engine.evaluate(&Event::from_value(&ev1));
        assert_eq!(m1.len(), 1);
        assert_eq!(m1[0].rule_title, "Detect Net User");

        let ev2 = json!({"CommandLine": "net group admins"});
        let m2 = engine.evaluate(&Event::from_value(&ev2));
        assert_eq!(m2.len(), 1);
        assert_eq!(m2[0].rule_title, "Detect Net Group");
    }
}
