//! Cross-rule Aho-Corasick index over positive substring patterns.
//!
//! At rule load time, builds a single double-array Aho-Corasick automaton per
//! event field over every positive substring needle from every loaded rule.
//! At eval time, the engine scans each indexed field once with the per-field
//! automaton and produces a `Vec<bool>` (one entry per rule) that is `true`
//! iff at least one of the rule's positive substring patterns matched
//! somewhere on the event.
//!
//! When a rule is **AC-prunable**, the engine drops it from the candidate set
//! when its bit in the hit vector is `false`. A rule is AC-prunable when its
//! firing requires at least one positive substring match (see
//! [`rule_is_ac_prunable`]) and every one of its needles sits in an
//! automaton that was actually built, so dropping on "no hit" is provably
//! safe.
//!
//! # Why daachorse
//!
//! For very large pattern sets (>10K patterns total across all rules),
//! daachorse's compact double-array structure is ~3-5x faster and uses ~56%
//! less memory than the equivalent NFA/DFA built by `aho-corasick`. At this
//! scale, `aho-corasick`'s Teddy SIMD prefilter is disabled because Teddy
//! supports up to ~100 patterns, so the comparison narrows to double-array
//! AC vs full DFA AC.
//!
//! For smaller rule sets, the per-rule Phase 1 [`AhoCorasickSet`] matchers
//! are already optimal; this index is gated behind the `daachorse-index`
//! feature and turned on explicitly via [`crate::Engine::set_cross_rule_ac`].
//!
//! [`AhoCorasickSet`]: crate::matcher::CompiledMatcher::AhoCorasickSet

use std::collections::HashMap;

use daachorse::DoubleArrayAhoCorasick;
use rsigma_parser::ConditionExpr;

use crate::compiler::{CompiledDetection, CompiledRule};
use crate::event::{Event, EventValue};
use crate::matcher::CompiledMatcher;

/// Maximum number of patterns indexed per field. Beyond this cap the field
/// falls back to no cross-rule automaton (rules on that field are kept in
/// the candidate set unfiltered). Sized so that even pathologically large
/// IOC rule packs don't bloat the engine's memory footprint past tens of
/// megabytes per field.
pub(crate) const MAX_PATTERNS_PER_FIELD: usize = 100_000;

/// Per-field cross-rule automaton.
struct FieldAc {
    automaton: DoubleArrayAhoCorasick<u32>,
    /// `pattern_id → rule indices`. A pattern can be reused across multiple
    /// rules, so the inner vector is small but unbounded. Kept as `Vec<u32>`
    /// instead of a `HashSet` because iteration order doesn't matter and
    /// duplicates are deduped at insert time.
    pattern_to_rules: Vec<Vec<u32>>,
}

/// Cross-rule Aho-Corasick index. Built from a slice of compiled rules,
/// holds at most one automaton per indexed field. Fields without any
/// positive substring item across the whole rule set are absent from the
/// map, and so are fields whose automaton was not built.
pub(crate) struct CrossRuleAcIndex {
    per_field: HashMap<String, FieldAc>,
    rule_count: usize,
    /// Per-rule flag: `true` iff the rule may be dropped on "no AC hit".
    /// Computed by the same build that produced `per_field`, so a rule whose
    /// needles landed on a field without an automaton is never prunable.
    prunable: Vec<bool>,
    /// Fields that had needles but no automaton (over the pattern cap, or
    /// the automaton build failed).
    unindexed_fields: usize,
}

impl CrossRuleAcIndex {
    pub(crate) fn empty() -> Self {
        Self {
            per_field: HashMap::new(),
            rule_count: 0,
            prunable: Vec::new(),
            unindexed_fields: 0,
        }
    }

    /// Returns true when the index contains no per-field automaton. The
    /// engine uses this to skip the scan entirely on rule sets that don't
    /// benefit from the cross-rule index.
    pub(crate) fn is_empty(&self) -> bool {
        self.per_field.is_empty()
    }

    /// Build the index from the engine's compiled rules.
    ///
    /// Walks every rule, collects `(field, lowered_needle, rule_idx)`
    /// triples, deduplicates patterns per field, and builds one
    /// `DoubleArrayAhoCorasick` per field. Fields whose pattern count
    /// exceeds [`MAX_PATTERNS_PER_FIELD`] are dropped (no automaton built);
    /// rules referencing such fields are not pruned by the index but still
    /// evaluated normally.
    pub(crate) fn build(rules: &[CompiledRule]) -> Self {
        Self::build_with_cap(rules, MAX_PATTERNS_PER_FIELD)
    }

    fn build_with_cap(rules: &[CompiledRule], max_patterns_per_field: usize) -> Self {
        // (field, needle) → rule indices that own this pattern on that
        // field. The pattern strings are pre-lowered (Sigma is case-
        // insensitive by default; we lower up-front because daachorse has
        // no built-in CI matching).
        let mut per_field: HashMap<String, HashMap<String, Vec<u32>>> = HashMap::new();

        for (rule_idx, rule) in rules.iter().enumerate() {
            let rule_idx_u32 = u32::try_from(rule_idx).unwrap_or(u32::MAX);
            for detection in rule.detections.values() {
                collect_rule_needles(detection, rule_idx_u32, &mut per_field);
            }
        }

        // Rules with at least one needle on a field that ends up without an
        // automaton. Their hit bit can never be set for that needle, so they
        // must not be pruned.
        let mut uncovered = vec![false; rules.len()];
        let mut mark_uncovered = |rule_ids: &mut dyn Iterator<Item = &u32>| {
            for &rid in rule_ids {
                if let Some(slot) = uncovered.get_mut(rid as usize) {
                    *slot = true;
                }
            }
        };
        let mut skipped: Vec<String> = Vec::new();

        // Build one automaton per field with patterns in stable order. The
        // build order assigns pattern ids 0..n_patterns; we keep
        // `pattern_to_rules` aligned to that order.
        let mut built: HashMap<String, FieldAc> = HashMap::new();
        for (field, needle_to_rules) in per_field {
            if needle_to_rules.is_empty() {
                continue;
            }
            if needle_to_rules.len() > max_patterns_per_field {
                skipped.push(format!(
                    "'{field}' has {} patterns, over the cap of {max_patterns_per_field}",
                    needle_to_rules.len()
                ));
                mark_uncovered(&mut needle_to_rules.values().flatten());
                continue;
            }

            // Sort by pattern string for deterministic id assignment so
            // rebuilds produce identical state on identical inputs.
            let mut entries: Vec<(String, Vec<u32>)> = needle_to_rules.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));

            let mut patterns: Vec<String> = Vec::with_capacity(entries.len());
            let mut pattern_to_rules: Vec<Vec<u32>> = Vec::with_capacity(entries.len());
            for (pattern, mut rule_ids) in entries {
                rule_ids.sort_unstable();
                rule_ids.dedup();
                patterns.push(pattern);
                pattern_to_rules.push(rule_ids);
            }

            match DoubleArrayAhoCorasick::<u32>::new(&patterns) {
                Ok(automaton) => {
                    built.insert(
                        field,
                        FieldAc {
                            automaton,
                            pattern_to_rules,
                        },
                    );
                }
                Err(e) => {
                    skipped.push(format!(
                        "'{field}' failed to build ({} patterns): {e}",
                        patterns.len()
                    ));
                    mark_uncovered(&mut pattern_to_rules.iter().flatten());
                }
            }
        }

        if !skipped.is_empty() {
            skipped.sort();
            log::warn!(
                "cross-rule AC: {} field(s) left without an automaton; rules matching on them are always evaluated: {}",
                skipped.len(),
                skipped.join("; ")
            );
        }

        let prunable = rules
            .iter()
            .zip(&uncovered)
            .map(|(rule, &uncovered)| !uncovered && rule_is_ac_prunable(rule))
            .collect();

        Self {
            per_field: built,
            rule_count: rules.len(),
            prunable,
            unindexed_fields: skipped.len(),
        }
    }

    /// Whether the rule at `idx` may be dropped when none of its patterns
    /// hit the event.
    pub(crate) fn is_prunable(&self, idx: usize) -> bool {
        self.prunable.get(idx).copied().unwrap_or(false)
    }

    /// Number of fields that carried needles but got no automaton in the
    /// most recent build.
    pub(crate) fn unindexed_field_count(&self) -> usize {
        self.unindexed_fields
    }

    /// Number of fields with active automatons. Used for diagnostics and
    /// tests; not on the hot path.
    #[cfg(test)]
    pub(crate) fn field_count(&self) -> usize {
        self.per_field.len()
    }

    /// Mark every rule whose at least one positive substring pattern matches
    /// the event. `hits` must have length `self.rule_count`; entries are
    /// updated in place (set to `true` for matched rules).
    ///
    /// The caller is expected to start with `hits` either zeroed (for an
    /// AC-only filter) or pre-marked for non-AC-prunable rules (so the
    /// vector represents the union of "rule must be evaluated" reasons).
    pub(crate) fn mark_hits<E: Event>(&self, event: &E, hits: &mut [bool]) {
        debug_assert_eq!(hits.len(), self.rule_count);

        for (field, ac) in &self.per_field {
            if let Some(value) = event.get_field(field) {
                mark_value_hits(ac, &value, hits);
            }
        }
    }
}

/// Feed every string projection of `value` through `ac`.
///
/// This mirrors the matcher's own `match_str_value`: numbers and bools are
/// matched by their string form, and an array matches when any member
/// matches. The automaton must therefore see exactly the haystacks the
/// matcher would, or an AC-prunable rule gets dropped on a value the matcher
/// would have matched. Objects and nulls have no string projection, so they
/// contribute no hits, which is precise rather than merely conservative: the
/// matcher cannot fire on them either.
fn mark_value_hits(ac: &FieldAc, value: &EventValue, hits: &mut [bool]) {
    match value {
        EventValue::Str(s) => mark_str_hits(ac, s, hits),
        EventValue::Int(n) => mark_str_hits(ac, &n.to_string(), hits),
        EventValue::Float(f) => mark_str_hits(ac, &f.to_string(), hits),
        EventValue::Bool(b) => mark_str_hits(ac, if *b { "true" } else { "false" }, hits),
        EventValue::Array(members) => {
            for member in members {
                mark_value_hits(ac, member, hits);
            }
        }
        _ => {}
    }
}

fn mark_str_hits(ac: &FieldAc, value: &str, hits: &mut [bool]) {
    // Sigma matches case-insensitively by default; the index stores
    // pre-lowered needles, so the haystack must be lowered too.
    let lowered = crate::matcher::ascii_lowercase_cow(value);

    for m in ac.automaton.find_overlapping_iter(lowered.as_bytes()) {
        let pattern_id = m.value() as usize;
        if let Some(rule_ids) = ac.pattern_to_rules.get(pattern_id) {
            for &rid in rule_ids {
                let idx = rid as usize;
                if let Some(slot) = hits.get_mut(idx) {
                    *slot = true;
                }
            }
        }
    }
}

/// Collect `(field, lowered_needle) → rule_idx` triples from a detection
/// tree. `Not(...)` subtrees contribute nothing because their negation
/// inverts the match logic and the AC index can only prove pattern
/// presence, not absence.
fn collect_rule_needles(
    detection: &CompiledDetection,
    rule_idx: u32,
    out: &mut HashMap<String, HashMap<String, Vec<u32>>>,
) {
    match detection {
        CompiledDetection::AllOf(items) => {
            for item in items {
                if let Some(field) = &item.field {
                    extract_from_matcher(
                        &item.matcher,
                        field,
                        /*negated=*/ false,
                        rule_idx,
                        out,
                    );
                }
            }
        }
        CompiledDetection::AnyOf(subs) => {
            for sub in subs {
                collect_rule_needles(sub, rule_idx, out);
            }
        }
        CompiledDetection::And(subs) => {
            for sub in subs {
                collect_rule_needles(sub, rule_idx, out);
            }
        }
        // Array object-scope predicates are on member sub-fields, not
        // top-level fields, so they contribute no top-level needles.
        CompiledDetection::ArrayMatch { .. } => {}
        // Extended array body: member-scoped, contributes no top-level needles.
        CompiledDetection::Conditional { .. } => {}
        CompiledDetection::Keywords(_) => {
            // Field-less; the cross-rule index is per-field so keywords are
            // out of scope. Phase 1's per-rule Aho-Corasick still handles
            // keyword detections optimally.
        }
    }
}

fn extract_from_matcher(
    m: &CompiledMatcher,
    field: &str,
    negated: bool,
    rule_idx: u32,
    out: &mut HashMap<String, HashMap<String, Vec<u32>>>,
) {
    if negated {
        return;
    }
    match m {
        CompiledMatcher::Contains { value, .. }
        | CompiledMatcher::StartsWith { value, .. }
        | CompiledMatcher::EndsWith { value, .. } => {
            push_needle(out, field, value, rule_idx);
        }
        CompiledMatcher::AhoCorasickSet { needles, .. } => {
            for needle in needles {
                push_needle(out, field, needle, rule_idx);
            }
        }
        CompiledMatcher::AnyOf(children) | CompiledMatcher::AllOf(children) => {
            for child in children {
                extract_from_matcher(child, field, negated, rule_idx, out);
            }
        }
        CompiledMatcher::CaseInsensitiveGroup { children, .. } => {
            for child in children {
                extract_from_matcher(child, field, negated, rule_idx, out);
            }
        }
        CompiledMatcher::Not(inner) => {
            extract_from_matcher(inner, field, true, rule_idx, out);
        }
        // Exact, Regex, RegexSetMatch, Cidr, Numeric*, Exists, BoolEq,
        // FieldRef, Null, Expand, TimestampPart: not substring-prunable.
        // Exact is excluded because the rule index already pre-filters it
        // at the rule level.
        _ => {}
    }
}

fn push_needle(
    out: &mut HashMap<String, HashMap<String, Vec<u32>>>,
    field: &str,
    needle: &str,
    rule_idx: u32,
) {
    if needle.is_empty() {
        return;
    }
    // `mark_hits` scans a lowered haystack. Case-insensitive matchers already
    // store their value lowered, but `|cased` matchers keep the original, so
    // lower here or a cased needle could never be found and its rule would be
    // pruned on every event. Lowering only widens the hit set, and
    // `matcher_is_pure_positive_substring` restricts cased needles to ASCII so
    // the lowering stays a faithful per-character mapping.
    let lowered = crate::matcher::ascii_lowercase_cow(needle);
    out.entry(field.to_string())
        .or_default()
        .entry(lowered.into_owned())
        .or_default()
        .push(rule_idx);
}

/// Conservative analysis: `true` iff dropping the rule on "zero AC hits" is
/// provably correct.
///
/// A rule is AC-prunable when:
/// 1. It has at least one positive substring detection item somewhere.
/// 2. Every detection in the rule is built exclusively from positive
///    substring matchers (Contains/StartsWith/EndsWith/AhoCorasickSet,
///    optionally nested under AnyOf/AllOf/CaseInsensitiveGroup) whose
///    needles the index can witness (see [`needle_is_indexable`]). No Exact,
///    Regex, Numeric, FieldRef, Cidr, Expand, Not, etc.
/// 3. No condition expression contains `Not`, `not 1 of`, etc. (Negated
///    selectors invert match polarity, so "no substring hits" no longer
///    implies "rule cannot fire".)
///
/// Under these constraints, the rule fires iff some substring matches some
/// field, so a `false` AC verdict provably implies the rule cannot fire,
/// provided every field the rule's needles sit on got an automaton.
/// [`CrossRuleAcIndex::build`] checks that last part.
pub(crate) fn rule_is_ac_prunable(rule: &CompiledRule) -> bool {
    if rule.detections.is_empty() {
        return false;
    }

    let mut has_positive_substring = false;
    for detection in rule.detections.values() {
        let mut found = false;
        if !detection_is_pure_positive_substring(detection, &mut found) {
            return false;
        }
        has_positive_substring |= found;
    }
    if !has_positive_substring {
        return false;
    }

    rule.conditions.iter().all(condition_is_negation_free)
}

/// Returns `true` if every leaf in the detection is a positive substring
/// matcher. Sets `*found_positive_substring = true` if at least one
/// substring leaf was seen (to distinguish empty/keyword-only detections
/// from genuine substring detections).
fn detection_is_pure_positive_substring(
    detection: &CompiledDetection,
    found_positive_substring: &mut bool,
) -> bool {
    match detection {
        CompiledDetection::AllOf(items) => {
            if items.is_empty() {
                return false;
            }
            for item in items {
                if item.field.is_none() {
                    return false;
                }
                if item.exists.is_some() {
                    return false;
                }
                if !matcher_is_pure_positive_substring(&item.matcher, found_positive_substring) {
                    return false;
                }
            }
            true
        }
        CompiledDetection::AnyOf(subs) => {
            if subs.is_empty() {
                return false;
            }
            for sub in subs {
                if !detection_is_pure_positive_substring(sub, found_positive_substring) {
                    return false;
                }
            }
            true
        }
        // Keywords are field-less and the cross-rule index is per-field, so
        // we conservatively reject keyword detections from AC pruning.
        CompiledDetection::Keywords(_) => false,
        // Array object-scope matching is not a top-level positive substring
        // assertion, so rules using it are never eligible for cross-rule AC
        // pruning (they are always evaluated).
        CompiledDetection::ArrayMatch { .. }
        | CompiledDetection::And(_)
        | CompiledDetection::Conditional { .. } => false,
    }
}

fn matcher_is_pure_positive_substring(
    matcher: &CompiledMatcher,
    found_positive_substring: &mut bool,
) -> bool {
    match matcher {
        CompiledMatcher::Contains {
            value,
            case_insensitive,
        }
        | CompiledMatcher::StartsWith {
            value,
            case_insensitive,
        }
        | CompiledMatcher::EndsWith {
            value,
            case_insensitive,
        } => {
            if !needle_is_indexable(value, *case_insensitive) {
                return false;
            }
            *found_positive_substring = true;
            true
        }
        CompiledMatcher::AhoCorasickSet {
            needles,
            case_insensitive,
            ..
        } => {
            if !needles
                .iter()
                .all(|n| needle_is_indexable(n, *case_insensitive))
            {
                return false;
            }
            *found_positive_substring = true;
            true
        }
        CompiledMatcher::AnyOf(children) | CompiledMatcher::AllOf(children) => {
            !children.is_empty()
                && children
                    .iter()
                    .all(|c| matcher_is_pure_positive_substring(c, found_positive_substring))
        }
        CompiledMatcher::CaseInsensitiveGroup { children, .. } => {
            !children.is_empty()
                && children
                    .iter()
                    .all(|c| matcher_is_pure_positive_substring(c, found_positive_substring))
        }
        // Anything else (Exact, Regex, RegexSetMatch, Cidr, Numeric*,
        // FieldRef, Null, BoolEq, Exists, Expand, TimestampPart, Not)
        // breaks the AC-prunable invariant.
        _ => false,
    }
}

/// Whether the index can witness a needle faithfully enough to prune on.
///
/// An empty needle matches every string but is never inserted (an automaton
/// cannot report a zero-length match), so it disqualifies its rule.
///
/// Case-insensitive needles are stored already lowered by the same
/// `to_lowercase` the haystack goes through, so they are exact. A `|cased`
/// needle is lowered by [`push_needle`] instead, which is only a faithful
/// per-character mapping while the needle is ASCII: Rust lowers a Greek
/// capital sigma to a different character depending on its position in the
/// word, which can break a non-ASCII needle's contiguity in the lowered
/// haystack and lose a match. Non-ASCII cased needles therefore disqualify
/// their rule from pruning instead of being indexed unsoundly.
fn needle_is_indexable(needle: &str, case_insensitive: bool) -> bool {
    !needle.is_empty() && (case_insensitive || needle.is_ascii())
}

fn condition_is_negation_free(cond: &ConditionExpr) -> bool {
    match cond {
        // Sigma's `not 1 of selection_*` is parsed as `Not(Selector { ... })`,
        // so any `Not` node anywhere in the tree disqualifies the rule from
        // AC pruning.
        ConditionExpr::Not(_) => false,
        ConditionExpr::Identifier(_) => true,
        ConditionExpr::Selector { .. } => true,
        ConditionExpr::And(parts) | ConditionExpr::Or(parts) => {
            parts.iter().all(condition_is_negation_free)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;
    use crate::event::JsonEvent;
    use rsigma_parser::parse_sigma_yaml;
    use serde_json::json;

    fn engine_from(yaml: &str) -> Engine {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();
        engine
    }

    fn build_index(yaml: &str) -> (Engine, CrossRuleAcIndex) {
        let engine = engine_from(yaml);
        let index = CrossRuleAcIndex::build(engine.rules());
        (engine, index)
    }

    fn engine_with_ac(yaml: &str) -> Engine {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = Engine::new();
        engine.set_cross_rule_ac(true);
        engine.add_collection(&collection).unwrap();
        engine
    }

    /// A `|cased` needle is stored in its original case, but the automaton
    /// scans a lowered haystack. Indexing it verbatim made the needle
    /// unfindable and pruned the rule on every event.
    #[test]
    fn cased_substring_rule_still_matches_under_ac() {
        let yaml = r#"
title: Cased Substring
logsource:
    category: test
detection:
    selection:
        CommandLine|contains|cased: 'PowerShell'
    condition: selection
"#;
        let engine = engine_with_ac(yaml);
        let event_json = json!({"CommandLine": "PowerShell.exe -Command x"});
        let event = JsonEvent::borrow(&event_json);
        assert_eq!(engine.evaluate(&event).len(), 1);
    }

    /// A cased needle outside ASCII cannot be lowered faithfully, so its rule
    /// must not be prunable at all.
    #[test]
    fn non_ascii_cased_needle_is_not_prunable() {
        let yaml = r#"
title: Cased Unicode
logsource:
    category: test
detection:
    selection:
        User|contains|cased: 'Ärzte'
    condition: selection
"#;
        let engine = engine_from(yaml);
        assert!(!rule_is_ac_prunable(&engine.rules()[0]));
    }

    /// Arrays and numbers have string projections the matcher does match, so
    /// the automaton must see them too. Skipping them left the hit bit clear,
    /// which the engine reads as "drop this rule".
    #[test]
    fn non_string_field_values_still_match_under_ac() {
        let yaml = r#"
title: Array Field
logsource:
    category: test
detection:
    selection:
        Image|endswith: '\wmic.exe'
    condition: selection
---
title: Numeric Field
logsource:
    category: test
detection:
    selection:
        EventID|contains: '468'
    condition: selection
"#;
        let engine = engine_with_ac(yaml);

        let array_event = json!({"Image": [r"C:\a\wmic.exe", r"C:\b\cmd.exe"]});
        let event = JsonEvent::borrow(&array_event);
        assert_eq!(engine.evaluate(&event).len(), 1);

        let numeric_event = json!({"EventID": 4688});
        let event = JsonEvent::borrow(&numeric_event);
        assert_eq!(engine.evaluate(&event).len(), 1);

        let bool_event = json!({"Image": true});
        let event = JsonEvent::borrow(&bool_event);
        assert_eq!(engine.evaluate(&event).len(), 0);
    }

    #[test]
    fn empty_when_no_substring_patterns() {
        let yaml = r#"
title: Exact Only
logsource:
    product: windows
detection:
    selection:
        EventType: 'login'
    condition: selection
"#;
        let (_, index) = build_index(yaml);
        assert!(index.is_empty());
    }

    #[test]
    fn populates_per_field_automaton() {
        let yaml = r#"
title: Contains Heavy
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'whoami'
            - 'mimikatz'
            - 'powershell'
    condition: selection
"#;
        let (_, index) = build_index(yaml);
        assert_eq!(index.field_count(), 1);
    }

    #[test]
    fn marks_hits_for_matching_rule() {
        let yaml = r#"
title: Whoami Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Mimikatz Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
"#;
        let (engine, index) = build_index(yaml);
        let mut hits = vec![false; engine.rule_count()];
        let ev = json!({"CommandLine": "execute whoami /all"});
        index.mark_hits(&JsonEvent::borrow(&ev), &mut hits);
        assert!(hits[0], "first rule should hit on 'whoami'");
        assert!(!hits[1], "second rule should not hit");
    }

    #[test]
    fn marks_hits_case_insensitive() {
        let yaml = r#"
title: Whoami Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#;
        let (engine, index) = build_index(yaml);
        let mut hits = vec![false; engine.rule_count()];
        let ev = json!({"CommandLine": "execute WHOAMI /all"});
        index.mark_hits(&JsonEvent::borrow(&ev), &mut hits);
        assert!(hits[0], "haystack lowering must match upper-case input");
    }

    #[test]
    fn negated_substring_excluded_from_index() {
        let yaml = r#"
title: Negated
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains|not: 'whoami'
    condition: selection
"#;
        let (_, index) = build_index(yaml);
        assert!(index.is_empty());
    }

    #[test]
    fn ahocorasick_needles_indexed() {
        let yaml = r#"
title: AC Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'mimikatz'
            - 'powershell'
            - 'rundll32'
            - 'regsvr32'
            - 'certutil'
            - 'bitsadmin'
            - 'mshta'
            - 'wscript'
    condition: selection
"#;
        let (engine, index) = build_index(yaml);
        let mut hits = vec![false; engine.rule_count()];
        let ev = json!({"CommandLine": "rundll32.exe foo"});
        index.mark_hits(&JsonEvent::borrow(&ev), &mut hits);
        assert!(hits[0]);
    }

    #[test]
    fn shared_pattern_marks_multiple_rules() {
        let yaml = r#"
title: Rule A
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Rule B
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#;
        let (engine, index) = build_index(yaml);
        let mut hits = vec![false; engine.rule_count()];
        let ev = json!({"CommandLine": "whoami /all"});
        index.mark_hits(&JsonEvent::borrow(&ev), &mut hits);
        assert!(hits[0] && hits[1]);
    }

    #[test]
    fn ac_prunable_pure_substring_rule() {
        let yaml = r#"
title: Pure Contains
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#;
        let engine = engine_from(yaml);
        assert!(rule_is_ac_prunable(&engine.rules()[0]));
    }

    #[test]
    fn ac_prunable_rejects_mixed_exact_and_substring() {
        let yaml = r#"
title: Mixed
logsource:
    product: windows
detection:
    selection:
        EventType: 'process_create'
        CommandLine|contains: 'whoami'
    condition: selection
"#;
        let engine = engine_from(yaml);
        assert!(!rule_is_ac_prunable(&engine.rules()[0]));
    }

    #[test]
    fn ac_prunable_rejects_negation_in_condition() {
        let yaml = r#"
title: Negated Condition
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    other:
        CommandLine|contains: 'admin'
    condition: selection and not other
"#;
        let engine = engine_from(yaml);
        assert!(!rule_is_ac_prunable(&engine.rules()[0]));
    }

    #[test]
    fn ac_prunable_rejects_keywords() {
        let yaml = r#"
title: Keyword Only
logsource:
    product: windows
detection:
    keywords:
        - 'suspicious'
        - 'malware'
    condition: keywords
"#;
        let engine = engine_from(yaml);
        assert!(!rule_is_ac_prunable(&engine.rules()[0]));
    }

    #[test]
    fn ac_prunable_accepts_anyof_substring_values() {
        let yaml = r#"
title: AnyOf Substrings
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'whoami'
            - 'mimikatz'
            - 'powershell'
    condition: selection
"#;
        let engine = engine_from(yaml);
        assert!(rule_is_ac_prunable(&engine.rules()[0]));
    }

    /// A field over the pattern cap gets no automaton, so the hit bit of a
    /// rule matching on it can never be set. Such rules must not be prunable
    /// even while another field keeps the index non-empty.
    #[test]
    fn rules_on_a_field_without_an_automaton_are_not_prunable() {
        let yaml = r#"
title: Over Cap A
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'alpha'
    condition: selection
---
title: Over Cap B
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'bravo'
    condition: selection
---
title: Indexed
logsource:
    product: windows
detection:
    selection:
        Image|contains: 'charlie'
    condition: selection
---
title: Spans Both Fields
logsource:
    product: windows
detection:
    selection:
        - CommandLine|contains: 'delta'
        - Image|contains: 'echo'
    condition: selection
"#;
        let engine = engine_from(yaml);
        let index = CrossRuleAcIndex::build_with_cap(engine.rules(), 2);
        assert_eq!(index.field_count(), 1, "only Image fits under the cap");
        assert_eq!(index.unindexed_field_count(), 1);
        assert!(!index.is_prunable(0));
        assert!(!index.is_prunable(1));
        assert!(index.is_prunable(2));
        assert!(
            !index.is_prunable(3),
            "one needle on the unindexed field is enough to keep the rule"
        );

        // With room for every field, all four rules are prunable again.
        let index = CrossRuleAcIndex::build_with_cap(engine.rules(), MAX_PATTERNS_PER_FIELD);
        assert_eq!(index.unindexed_field_count(), 0);
        assert!((0..4).all(|idx| index.is_prunable(idx)));
    }

    /// An empty needle matches every value but is never inserted, so the
    /// automaton cannot witness it.
    #[test]
    fn empty_needle_is_not_prunable() {
        let yaml = r#"
title: Empty
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: ''
    condition: selection
---
title: Empty Among Others
logsource:
    product: windows
detection:
    selection:
        CommandLine|endswith:
            - ''
            - '.exe'
    condition: selection
"#;
        let engine = engine_from(yaml);
        assert!(!rule_is_ac_prunable(&engine.rules()[0]));
        assert!(!rule_is_ac_prunable(&engine.rules()[1]));
    }

    #[test]
    fn cap_drops_overflowing_field() {
        // Build a synthetic rule set with > MAX_PATTERNS_PER_FIELD distinct
        // patterns on the same field. The builder must skip the field
        // rather than panicking.
        let mut yaml = String::new();
        let n = MAX_PATTERNS_PER_FIELD + 5;
        for i in 0..n {
            yaml.push_str(&format!(
                "title: R{i}\n\
                 id: r-{i:08}\n\
                 logsource:\n\
                 \x20   product: windows\n\
                 detection:\n\
                 \x20   selection:\n\
                 \x20       CommandLine|contains: 'pat-{i:08}'\n\
                 \x20   condition: selection\n\
                 ---\n",
            ));
        }
        let engine = engine_from(&yaml);
        let index = CrossRuleAcIndex::build(engine.rules());
        // Field is dropped, so the index is empty for CommandLine.
        assert!(index.is_empty());
    }
}
