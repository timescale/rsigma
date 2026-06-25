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

use crate::compiler::{CompiledDetection, CompiledDetectionItem, CompiledRule};
use crate::event::{Event, EventValue};
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
    /// The `unindexable` set partitioned by the rule's lowercased logsource
    /// `product` (`None` for product-less rules), preserving each bucket's
    /// ascending rule-index order. Used by [`candidates_with_logsource`] to
    /// skip always-evaluated rules whose product conflicts with the event,
    /// the rules that a value-index lookup can never narrow away.
    ///
    /// [`candidates_with_logsource`]: RuleIndex::candidates_with_logsource
    unindexable_by_product: HashMap<Option<String>, Vec<usize>>,
    /// Total number of rules (for candidate dedup bitvec sizing).
    rule_count: usize,
}

impl RuleIndex {
    /// Build an empty index.
    pub(crate) fn empty() -> Self {
        RuleIndex {
            field_index: HashMap::new(),
            unindexable: Vec::new(),
            unindexable_by_product: HashMap::new(),
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
        let mut index = Self::empty();
        for (rule_idx, rule) in rules.iter().enumerate() {
            index.append_rule(rule_idx, rule);
        }
        // `build` is called with a fresh slice; trust `rules.len()` even if
        // some indices in the tail had no pairs and so did not bump
        // `rule_count` via `append_rule`'s `max` logic.
        index.rule_count = rules.len();
        index
    }

    /// Incrementally fold a single rule into the index.
    ///
    /// Cost is bounded by the number of `(field, exact_value)` pairs in the
    /// rule's detection tree, not by the total rule count. Callers must
    /// invoke this with strictly increasing `rule_idx` values for the rule
    /// indices within each `(field, value)` bucket to stay ascending, which
    /// keeps the bucket layout identical to the batched `build` path.
    pub(crate) fn append_rule(&mut self, rule_idx: usize, rule: &CompiledRule) {
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
            self.unindexable.push(rule_idx);
            // Mirror into the product-partitioned view for logsource pruning.
            // Strictly increasing `rule_idx` keeps each bucket ascending.
            let product_key = rule.logsource.product.as_deref().map(str::to_lowercase);
            self.unindexable_by_product
                .entry(product_key)
                .or_default()
                .push(rule_idx);
        } else {
            for (field, value) in all_pairs {
                self.field_index
                    .entry(field)
                    .or_default()
                    .entry(value)
                    .or_default()
                    .push(rule_idx);
            }
        }

        if rule_idx + 1 > self.rule_count {
            self.rule_count = rule_idx + 1;
        }
    }

    /// Return candidate rule indices for the given event.
    ///
    /// Looks up each indexed field name in the event, then checks the field's
    /// value against the index. Returns the union of all matching rule indices
    /// plus all unindexable rules, deduplicated.
    pub(crate) fn candidates(&self, event: &impl Event) -> Vec<usize> {
        if self.field_index.is_empty() {
            return (0..self.rule_count).collect();
        }

        let mut seen = vec![false; self.rule_count];
        let mut result = Vec::new();

        let mut keys: Vec<String> = Vec::new();
        for (field_name, value_map) in &self.field_index {
            if let Some(event_value) = event.get_field(field_name) {
                keys.clear();
                collect_lowercase_keys(&event_value, &mut keys);
                for key in &keys {
                    if let Some(rule_indices) = value_map.get(key) {
                        for &idx in rule_indices {
                            if !seen[idx] {
                                seen[idx] = true;
                                result.push(idx);
                            }
                        }
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

    /// Like [`candidates`], but prunes always-evaluated rules whose logsource
    /// `product` conflicts with `event_product`.
    ///
    /// Value-index hits are returned regardless of product; the caller applies
    /// the residual `logsource_compatible` filter, which drops value hits of a
    /// conflicting product and also enforces `service`/`category`. Only the
    /// `unindexable` set is partitioned here: an event with product `P` adds
    /// the product-less (`None`) bucket and the `P` bucket, never a `Q != P`
    /// bucket, so conflicting always-evaluated rules are never iterated.
    ///
    /// Falls back to [`candidates`] when `event_product` is `None` (sound:
    /// every rule is a candidate).
    ///
    /// [`candidates`]: RuleIndex::candidates
    pub(crate) fn candidates_with_logsource(
        &self,
        event: &impl Event,
        event_product: Option<&str>,
    ) -> Vec<usize> {
        let product = match event_product {
            Some(p) => p.to_lowercase(),
            None => return self.candidates(event),
        };

        let mut seen = vec![false; self.rule_count];
        let mut result = Vec::new();

        // Value-index hits, identical to `candidates` (product-agnostic).
        let mut keys: Vec<String> = Vec::new();
        for (field_name, value_map) in &self.field_index {
            if let Some(event_value) = event.get_field(field_name) {
                keys.clear();
                collect_lowercase_keys(&event_value, &mut keys);
                for key in &keys {
                    if let Some(rule_indices) = value_map.get(key) {
                        for &idx in rule_indices {
                            if !seen[idx] {
                                seen[idx] = true;
                                result.push(idx);
                            }
                        }
                    }
                }
            }
        }

        // Always-evaluated rules whose product cannot conflict: the
        // product-less bucket and the matching-product bucket.
        for bucket in [
            self.unindexable_by_product.get(&None),
            self.unindexable_by_product.get(&Some(product)),
        ]
        .into_iter()
        .flatten()
        {
            for &idx in bucket {
                if !seen[idx] {
                    seen[idx] = true;
                    result.push(idx);
                }
            }
        }

        result
    }

    /// Number of always-evaluated rules pruned for an event with
    /// `event_product`: the rules in conflicting-product buckets that
    /// [`candidates_with_logsource`] never iterates. `O(1)` (bucket-length
    /// arithmetic); returns `0` when `event_product` is `None`.
    ///
    /// [`candidates_with_logsource`]: RuleIndex::candidates_with_logsource
    pub(crate) fn conflicting_unindexable_count(&self, event_product: Option<&str>) -> usize {
        let product = match event_product {
            Some(p) => p.to_lowercase(),
            None => return 0,
        };
        let none_len = self.unindexable_by_product.get(&None).map_or(0, Vec::len);
        let match_len = self
            .unindexable_by_product
            .get(&Some(product))
            .map_or(0, Vec::len);
        // Every unindexable rule lives in exactly one product bucket, so the
        // conflicting count is the total minus the two kept buckets.
        self.unindexable.len() - none_len - match_len
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
        CompiledDetection::And(subs) => {
            for sub in subs {
                pairs.extend(extract_exact_pairs(sub));
            }
        }
        // Array object-scope predicates are on member sub-fields, not
        // top-level fields, so they yield no top-level exact pairs. A rule
        // with only array matching falls back to the always-evaluated set.
        CompiledDetection::ArrayMatch { .. } => {}
        // Extended array body: member-scoped, no top-level exact pairs.
        CompiledDetection::Conditional { .. } => {}
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
        CompiledMatcher::AnyOf(children) | CompiledMatcher::AllOf(children) => {
            for child in children {
                extract_from_matcher(child, field, out);
            }
        }
        CompiledMatcher::CaseInsensitiveGroup { children, .. } => {
            for child in children {
                extract_from_matcher(child, field, out);
            }
        }
        _ => {}
    }
}

/// Collect lowercase index-lookup keys from an [`EventValue`].
///
/// Scalars contribute one key. Arrays contribute one key per (scalar) member
/// so that an array-valued event field still selects rules keyed on any of its
/// members (otherwise array fields would be silently pruned from candidates).
/// Objects and nulls contribute nothing.
fn collect_lowercase_keys(value: &EventValue, out: &mut Vec<String>) {
    match value {
        EventValue::Str(s) => out.push(s.to_lowercase()),
        EventValue::Int(n) => out.push(n.to_string()),
        EventValue::Float(f) => out.push(f.to_string()),
        EventValue::Bool(b) => out.push(b.to_string()),
        EventValue::Array(arr) => {
            for v in arr {
                collect_lowercase_keys(v, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;
    use crate::event::JsonEvent;
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
        let event = JsonEvent::borrow(&ev);
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
        let event = JsonEvent::borrow(&ev);
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
        let event = JsonEvent::borrow(&ev);
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
        let event = JsonEvent::borrow(&ev);
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
        let event = JsonEvent::borrow(&ev);
        let candidates = index.candidates(&event);
        assert_eq!(candidates, vec![0]);

        let ev2 = json!({"EventType": "process_create"});
        let event2 = JsonEvent::borrow(&ev2);
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

        assert_eq!(index.candidates(&JsonEvent::borrow(&ev_login)), vec![0]);
        assert_eq!(index.candidates(&JsonEvent::borrow(&ev_logout)), vec![0]);
        assert!(index.candidates(&JsonEvent::borrow(&ev_other)).is_empty());
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
        let event = JsonEvent::borrow(&ev);
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
        let event = JsonEvent::borrow(&ev);
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

    /// Folding rules one at a time via `append_rule` must produce the same
    /// candidate verdicts as the batched `build` path. This pins the
    /// equivalence the engine wiring in P2 will rely on.
    #[test]
    fn test_append_rule_matches_build() {
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
        Protocol: 'TCP'
    condition: selection
---
title: Keyword Rule
logsource:
    product: windows
detection:
    keywords:
        - 'malware'
    condition: keywords
---
title: Multi Value
logsource:
    product: windows
detection:
    selection:
        EventType:
            - 'logon'
            - 'logoff'
    condition: selection
---
title: Regex Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|re: '(?i)whoami.*'
    condition: selection
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();
        let rules = engine.rules();

        let batched = RuleIndex::build(rules);
        let mut incremental = RuleIndex::empty();
        for (rule_idx, rule) in rules.iter().enumerate() {
            incremental.append_rule(rule_idx, rule);
        }

        assert_eq!(incremental.rule_count(), batched.rule_count());
        assert_eq!(incremental.unindexable_count(), batched.unindexable_count());
        assert_eq!(
            incremental.indexed_field_count(),
            batched.indexed_field_count()
        );

        let events = [
            json!({"EventType": "login"}),
            json!({"EventType": "logoff"}),
            json!({"EventType": "file_create", "Protocol": "TCP"}),
            json!({"CommandLine": "whoami /all"}),
            json!({"SomeField": "nothing"}),
        ];
        for ev in &events {
            let event = JsonEvent::borrow(ev);
            let mut a = batched.candidates(&event);
            let mut b = incremental.candidates(&event);
            a.sort_unstable();
            b.sort_unstable();
            assert_eq!(a, b, "verdicts diverge for event {ev}");
        }
    }

    /// `append_rule` is meant to be called with monotonic rule indices.
    /// Verify that calling it on a fresh index, then on additional rules,
    /// keeps `rule_count` consistent and the candidate sets growing
    /// monotonically.
    #[test]
    fn test_append_rule_grows_rule_count() {
        let yaml = r#"
title: A
logsource:
    product: windows
detection:
    selection:
        EventType: 'a'
    condition: selection
---
title: B
logsource:
    product: windows
detection:
    selection:
        EventType: 'b'
    condition: selection
"#;
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();
        let rules = engine.rules();

        let mut index = RuleIndex::empty();
        assert_eq!(index.rule_count(), 0);

        index.append_rule(0, &rules[0]);
        assert_eq!(index.rule_count(), 1);
        let ev = json!({"EventType": "a"});
        assert_eq!(index.candidates(&JsonEvent::borrow(&ev)), vec![0]);

        index.append_rule(1, &rules[1]);
        assert_eq!(index.rule_count(), 2);
        let ev = json!({"EventType": "b"});
        assert_eq!(index.candidates(&JsonEvent::borrow(&ev)), vec![1]);
    }

    #[test]
    fn test_unindexable_partitioned_by_product() {
        let (_, index) = build_index(
            r#"
title: Win
logsource:
    product: Windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Lin
logsource:
    product: linux
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Generic
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#,
        );

        assert_eq!(index.unindexable_count(), 3);
        // Product keys are lowercased, so the mixed-case "Windows" maps to
        // the "windows" bucket.
        assert_eq!(
            index
                .unindexable_by_product
                .get(&Some("windows".to_string()))
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(
            index
                .unindexable_by_product
                .get(&Some("linux".to_string()))
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(
            index.unindexable_by_product.get(&None).map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn test_candidates_with_logsource_prunes_and_falls_back() {
        let (_, index) = build_index(
            r#"
title: Win
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Lin
logsource:
    product: linux
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Generic
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#,
        );
        // Rule order: 0 = Win, 1 = Lin, 2 = Generic. All unindexable, so the
        // value index is empty and only the product buckets select candidates.
        let ev = json!({"CommandLine": "whoami"});
        let event = JsonEvent::borrow(&ev);

        // product windows: the None bucket plus the windows bucket.
        let mut c = index.candidates_with_logsource(&event, Some("windows"));
        c.sort_unstable();
        assert_eq!(c, vec![0, 2]);

        // product absent from every bucket: only the product-less None bucket.
        let mut c = index.candidates_with_logsource(&event, Some("macos"));
        c.sort_unstable();
        assert_eq!(c, vec![2]);

        // no event product: fall back to the full candidate set.
        let mut c = index.candidates_with_logsource(&event, None);
        c.sort_unstable();
        assert_eq!(c, vec![0, 1, 2]);
    }

    #[test]
    fn test_candidates_with_logsource_equivalent_to_postfilter() {
        use rsigma_parser::LogSource;

        let yaml = r#"
title: Win Exact
logsource:
    product: windows
detection:
    selection:
        EventID: '1'
    condition: selection
---
title: Lin Exact
logsource:
    product: linux
detection:
    selection:
        EventID: '1'
    condition: selection
---
title: Win Contains
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Lin Contains
logsource:
    product: linux
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Generic Contains
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#;
        let (engine, index) = build_index(yaml);
        let rules = engine.rules();

        // Local mirror of the engine's conflict-based predicate.
        fn compatible(rule: &LogSource, event: &LogSource) -> bool {
            fn conflicts(r: &Option<String>, e: &Option<String>) -> bool {
                matches!((r, e), (Some(r), Some(e)) if !r.eq_ignore_ascii_case(e))
            }
            !(conflicts(&rule.product, &event.product)
                || conflicts(&rule.service, &event.service)
                || conflicts(&rule.category, &event.category))
        }

        let cases: [(serde_json::Value, Option<&str>, Option<&str>); 5] = [
            (
                json!({"EventID": "1", "CommandLine": "whoami"}),
                Some("windows"),
                None,
            ),
            (
                json!({"EventID": "1", "CommandLine": "whoami"}),
                Some("linux"),
                None,
            ),
            (json!({"CommandLine": "whoami"}), Some("macos"), None),
            (
                json!({"EventID": "1", "CommandLine": "whoami"}),
                Some("windows"),
                Some("process_creation"),
            ),
            (json!({"CommandLine": "whoami"}), None, None),
        ];

        for (ev, product, category) in cases {
            let event = JsonEvent::borrow(&ev);
            let event_ls = LogSource {
                product: product.map(String::from),
                category: category.map(String::from),
                ..Default::default()
            };

            // The Phase 1 reference: every candidate, kept if compatible.
            let mut reference: Vec<usize> = index
                .candidates(&event)
                .into_iter()
                .filter(|&idx| compatible(&rules[idx].logsource, &event_ls))
                .collect();
            // The Phase 2 index path, with the same residual filter applied.
            let mut got: Vec<usize> = index
                .candidates_with_logsource(&event, product)
                .into_iter()
                .filter(|&idx| compatible(&rules[idx].logsource, &event_ls))
                .collect();
            reference.sort_unstable();
            got.sort_unstable();
            assert_eq!(reference, got, "diverge for {ev} product={product:?}");
        }
    }
}
