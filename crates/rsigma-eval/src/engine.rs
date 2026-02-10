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
}
