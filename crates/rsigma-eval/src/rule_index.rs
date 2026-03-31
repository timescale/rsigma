//! Inverted index for rule pre-filtering.
//!
//! At rule load time, builds a mapping from `(field_name, exact_value)` to
//! rule indices. At evaluation time, the event's field values are used to
//! look up candidate rules, avoiding the O(n_rules) linear scan.
//!
//! The index is an **over-approximation**: it may return rules that don't
//! actually match (false positives filtered by `evaluate_rule`), but never
//! misses a rule that should match (no false negatives).

use std::collections::HashMap;

use serde_json::Value;

use crate::compiler::{CompiledDetection, CompiledDetectionItem, CompiledRule};
use crate::event::Event;
use crate::matcher::CompiledMatcher;

/// Pre-computed inverted index over compiled rules.
///
/// Maps `field_name -> { lowercase_value -> [rule_indices] }` for exact-match
/// detection items. Rules with no indexable exact-match fields are tracked in
/// `unindexable` and always evaluated.
pub(crate) struct RuleIndex {
    /// Maps field_name -> { lowercase_value -> sorted rule indices }.
    field_index: HashMap<String, HashMap<String, Vec<usize>>>,
    /// Rule indices that must always be evaluated (no exact-match fields,
    /// or at least one detection branch has no exact-match coverage).
    unindexable: Vec<usize>,
    /// Total number of rules (for candidate dedup bitvec sizing).
    rule_count: usize,
}

impl RuleIndex {
    /// Build an empty index.
    pub(crate) fn empty() -> Self {
        RuleIndex {
            field_index: HashMap::new(),
            unindexable: Vec::new(),
            rule_count: 0,
        }
    }

    /// Build an index from a slice of compiled rules.
    ///
    /// For each rule, walks all detections and extracts `(field, exact_value)`
    /// pairs from `CompiledMatcher::Exact` variants. A rule is fully indexable
    /// only if **every** named detection has at least one exact-match item.
    /// Otherwise, the rule is placed in the unindexable set to avoid false
    /// negatives from OR conditions that reach an unindexable branch.
    pub(crate) fn build(rules: &[CompiledRule]) -> Self {
        let mut field_index: HashMap<String, HashMap<String, Vec<usize>>> = HashMap::new();
        let mut unindexable: Vec<usize> = Vec::new();

        for (rule_idx, rule) in rules.iter().enumerate() {
            let mut all_pairs: Vec<(String, String)> = Vec::new();
            let mut every_detection_has_pairs = true;

            for detection in rule.detections.values() {
                let pairs = extract_exact_pairs(detection);
                if pairs.is_empty() {
                    every_detection_has_pairs = false;
                }
                all_pairs.extend(pairs);
            }

            if all_pairs.is_empty() || !every_detection_has_pairs {
                unindexable.push(rule_idx);
            } else {
                for (field, value) in all_pairs {
                    field_index
                        .entry(field)
                        .or_default()
                        .entry(value)
                        .or_default()
                        .push(rule_idx);
                }
            }
        }

        RuleIndex {
            field_index,
            unindexable,
            rule_count: rules.len(),
        }
    }

    /// Return candidate rule indices for the given event.
    ///
    /// Looks up each indexed field name in the event, then checks the field's
    /// value against the index. Returns the union of all matching rule indices
    /// plus all unindexable rules, deduplicated.
    pub(crate) fn candidates(&self, event: &Event) -> Vec<usize> {
        if self.field_index.is_empty() {
            return (0..self.rule_count).collect();
        }

        let mut seen = vec![false; self.rule_count];
        let mut result = Vec::new();

        for (field_name, value_map) in &self.field_index {
            if let Some(event_value) = event.get_field(field_name)
                && let Some(search_key) = value_to_lowercase_string(event_value)
                && let Some(rule_indices) = value_map.get(&search_key)
            {
                for &idx in rule_indices {
                    if !seen[idx] {
                        seen[idx] = true;
                        result.push(idx);
                    }
                }
            }
        }

        for &idx in &self.unindexable {
            if !seen[idx] {
                seen[idx] = true;
                result.push(idx);
            }
        }

        result
    }

    /// Number of rules tracked by the index.
    #[cfg(test)]
    pub(crate) fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Number of rules that are always evaluated (not indexable).
    #[cfg(test)]
    pub(crate) fn unindexable_count(&self) -> usize {
        self.unindexable.len()
    }

    /// Number of unique indexed field names.
    #[cfg(test)]
    pub(crate) fn indexed_field_count(&self) -> usize {
        self.field_index.len()
    }
}

/// Extract all `(lowercase_field, lowercase_value)` pairs from a compiled detection.
fn extract_exact_pairs(detection: &CompiledDetection) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    match detection {
        CompiledDetection::AllOf(items) => {
            for item in items {
                extract_from_item(item, &mut pairs);
            }
        }
        CompiledDetection::AnyOf(subs) => {
            for sub in subs {
                pairs.extend(extract_exact_pairs(sub));
            }
        }
        CompiledDetection::Keywords(_) => {}
    }
    pairs
}

/// Extract exact-match values from a single detection item.
///
/// Field names are stored in their original case because `Event::get_field()`
/// performs case-sensitive JSON key lookups.
fn extract_from_item(item: &CompiledDetectionItem, out: &mut Vec<(String, String)>) {
    let field = match &item.field {
        Some(f) => f.as_str(),
        None => return,
    };
    extract_from_matcher(&item.matcher, field, out);
}

/// Recursively extract exact string values from a compiled matcher.
fn extract_from_matcher(matcher: &CompiledMatcher, field: &str, out: &mut Vec<(String, String)>) {
    match matcher {
        CompiledMatcher::Exact { value, .. } => {
            out.push((field.to_string(), value.to_lowercase()));
        }
        CompiledMatcher::AnyOf(children) => {
            for child in children {
                extract_from_matcher(child, field, out);
            }
        }
        CompiledMatcher::AllOf(children) => {
            for child in children {
                extract_from_matcher(child, field, out);
            }
        }
        _ => {}
    }
}

/// Convert a JSON value to a lowercase string for index lookup.
///
/// Returns `None` for null, objects, and arrays (not meaningful for exact match).
fn value_to_lowercase_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.to_lowercase()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;
    use rsigma_parser::parse_sigma_yaml;
    use serde_json::json;

    fn build_index(yaml: &str) -> (Engine, RuleIndex) {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();
        let index = RuleIndex::build(engine.rules());
        (engine, index)
    }

    #[test]
    fn test_exact_match_indexed() {
        let (_, index) = build_index(
            r#"
title: Login Event
logsource:
    product: windows
detection:
    selection:
        EventType: 'login'
    condition: selection
"#,
        );

        assert_eq!(index.rule_count(), 1);
        assert_eq!(index.unindexable_count(), 0);
        assert_eq!(index.indexed_field_count(), 1);
    }

    #[test]
    fn test_contains_only_unindexable() {
        let (_, index) = build_index(
            r#"
title: Whoami Detection
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#,
        );

        assert_eq!(index.rule_count(), 1);
        assert_eq!(index.unindexable_count(), 1);
        assert_eq!(index.indexed_field_count(), 0);
    }

    #[test]
    fn test_mixed_items_in_allof_detection() {
        let (_, index) = build_index(
            r#"
title: Process Create
logsource:
    product: windows
detection:
    selection:
        EventType: 'process_create'
        CommandLine|contains: 'whoami'
    condition: selection
"#,
        );

        // The single AllOf detection has exact + contains items.
        // The detection HAS exact pairs, so the rule is indexed.
        assert_eq!(index.unindexable_count(), 0);
        assert!(index.indexed_field_count() > 0);
    }

    #[test]
    fn test_candidates_returns_matching_rule() {
        let (_, index) = build_index(
            r#"
title: Login Event
logsource:
    product: windows
detection:
    selection:
        EventType: 'login'
    condition: selection
"#,
        );

        let ev = json!({"EventType": "login", "User": "admin"});
        let event = Event::from_value(&ev);
        let candidates = index.candidates(&event);
        assert_eq!(candidates, vec![0]);
    }

    #[test]
    fn test_candidates_skips_non_matching() {
        let (_, index) = build_index(
            r#"
title: Login Event
logsource:
    product: windows
detection:
    selection:
        EventType: 'login'
    condition: selection
"#,
        );

        let ev = json!({"EventType": "file_create", "User": "admin"});
        let event = Event::from_value(&ev);
        let candidates = index.candidates(&event);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_unindexable_always_returned() {
        let (_, index) = build_index(
            r#"
title: Wildcard Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#,
        );

        let ev = json!({"SomeField": "whatever"});
        let event = Event::from_value(&ev);
        let candidates = index.candidates(&event);
        assert_eq!(candidates, vec![0]);
    }

    #[test]
    fn test_case_insensitive_lookup() {
        let (_, index) = build_index(
            r#"
title: Login Event
logsource:
    product: windows
detection:
    selection:
        EventType: 'LOGIN'
    condition: selection
"#,
        );

        let ev = json!({"EventType": "login"});
        let event = Event::from_value(&ev);
        let candidates = index.candidates(&event);
        assert_eq!(candidates, vec![0]);
    }

    #[test]
    fn test_multiple_rules_selective_candidates() {
        let yaml = r#"
title: Login
logsource:
    product: windows
detection:
    selection:
        EventType: 'login'
    condition: selection
---
title: File Create
logsource:
    product: windows
detection:
    selection:
        EventType: 'file_create'
    condition: selection
---
title: Process Create
logsource:
    product: windows
detection:
    selection:
        EventType: 'process_create'
    condition: selection
"#;
        let (_, index) = build_index(yaml);

        assert_eq!(index.rule_count(), 3);
        assert_eq!(index.unindexable_count(), 0);

        let ev = json!({"EventType": "login"});
        let event = Event::from_value(&ev);
        let candidates = index.candidates(&event);
        assert_eq!(candidates, vec![0]);

        let ev2 = json!({"EventType": "process_create"});
        let event2 = Event::from_value(&ev2);
        let candidates2 = index.candidates(&event2);
        assert_eq!(candidates2, vec![2]);
    }

    #[test]
    fn test_or_with_mixed_indexable_unindexable_detections() {
        let (_, index) = build_index(
            r#"
title: Mixed OR
logsource:
    product: windows
detection:
    selection_a:
        EventType: 'login'
    selection_b:
        CommandLine|contains: 'whoami'
    condition: 1 of selection_*
"#,
        );

        // selection_b has no exact pairs, so the rule is unindexable
        // (conservatively correct for OR conditions).
        assert_eq!(index.unindexable_count(), 1);
    }

    #[test]
    fn test_anyof_exact_values_indexed() {
        let (_, index) = build_index(
            r#"
title: Multi Value
logsource:
    product: windows
detection:
    selection:
        EventType:
            - 'login'
            - 'logout'
    condition: selection
"#,
        );

        assert_eq!(index.unindexable_count(), 0);

        let ev_login = json!({"EventType": "login"});
        let ev_logout = json!({"EventType": "logout"});
        let ev_other = json!({"EventType": "file_create"});

        assert_eq!(index.candidates(&Event::from_value(&ev_login)), vec![0]);
        assert_eq!(index.candidates(&Event::from_value(&ev_logout)), vec![0]);
        assert!(index.candidates(&Event::from_value(&ev_other)).is_empty());
    }

    #[test]
    fn test_numeric_event_value_lookup() {
        let (_, index) = build_index(
            r#"
title: Port Check
logsource:
    product: windows
detection:
    selection:
        DestinationPort: '443'
    condition: selection
"#,
        );

        let ev = json!({"DestinationPort": 443});
        let event = Event::from_value(&ev);
        let candidates = index.candidates(&event);
        assert_eq!(candidates, vec![0]);
    }

    #[test]
    fn test_empty_index_returns_all() {
        let index = RuleIndex::empty();
        assert_eq!(index.rule_count(), 0);
    }

    #[test]
    fn test_dedup_candidates() {
        let yaml = r#"
title: Multi Field
logsource:
    product: windows
detection:
    selection:
        EventType: 'login'
        Protocol: 'TCP'
    condition: selection
"#;
        let (_, index) = build_index(yaml);

        // Event matches BOTH indexed fields for the same rule.
        // Candidate should appear only once.
        let ev = json!({"EventType": "login", "Protocol": "TCP"});
        let event = Event::from_value(&ev);
        let candidates = index.candidates(&event);
        assert_eq!(candidates, vec![0]);
    }

    #[test]
    fn test_keyword_detection_unindexable() {
        let (_, index) = build_index(
            r#"
title: Keyword Rule
logsource:
    product: windows
detection:
    keywords:
        - 'suspicious'
        - 'malware'
    condition: keywords
"#,
        );

        assert_eq!(index.unindexable_count(), 1);
    }

    #[test]
    fn test_regex_only_unindexable() {
        let (_, index) = build_index(
            r#"
title: Regex Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|re: '(?i)whoami.*'
    condition: selection
"#,
        );

        assert_eq!(index.unindexable_count(), 1);
        assert_eq!(index.indexed_field_count(), 0);
    }
}
