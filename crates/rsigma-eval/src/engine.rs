//! Rule evaluation engine with logsource routing.
//!
//! The `Engine` manages a set of compiled Sigma rules and evaluates events
//! against them. It supports optional logsource-based pre-filtering to
//! reduce the number of rules evaluated per event.

use rsigma_parser::{LogSource, SigmaCollection, SigmaRule};

use crate::compiler::{compile_rule, evaluate_rule, CompiledRule};
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

    /// Add all detection rules from a parsed collection.
    ///
    /// Correlation and filter rules are skipped (Phase 2).
    pub fn add_collection(&mut self, collection: &SigmaCollection) -> Result<()> {
        for rule in &collection.rules {
            self.add_rule(rule)?;
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
                && let Some(m) = evaluate_rule(rule, event) {
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
        assert!(engine.evaluate_with_logsource(&event, &ls_nomatch).is_empty());
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
