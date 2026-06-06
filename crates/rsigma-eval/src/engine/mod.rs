//! Rule evaluation engine with logsource routing.
//!
//! The `Engine` manages a set of compiled Sigma rules and evaluates events
//! against them. It supports optional logsource-based pre-filtering to
//! reduce the number of rules evaluated per event.

pub(crate) mod bloom_index;
#[cfg(feature = "daachorse-index")]
pub(crate) mod cross_rule_ac;
mod filters;
#[cfg(test)]
mod tests;

use rsigma_parser::{
    ConditionExpr, FilterRule, FilterRuleTarget, LogSource, SigmaCollection, SigmaRule,
};

use crate::compiler::{CompiledRule, compile_detection, compile_rule, evaluate_rule_with_bloom};
use crate::error::{EvalError, Result};
use crate::event::Event;
use crate::pipeline::{Pipeline, apply_pipelines};
use crate::result::{EvaluationResult, MatchDetailLevel};
use crate::rule_index::RuleIndex;

use bloom_index::{BloomCache, FieldBloomIndex};

use filters::{filter_logsource_contains, logsource_matches, rewrite_condition_identifiers};

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
/// use rsigma_eval::event::JsonEvent;
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
/// let event = JsonEvent::borrow(&event_val);
/// let matches = engine.evaluate(&event);
/// assert_eq!(matches.len(), 1);
/// assert_eq!(matches[0].header.rule_title, "Detect Whoami");
/// ```
pub struct Engine {
    rules: Vec<CompiledRule>,
    pipelines: Vec<Pipeline>,
    /// Global override: include the full event JSON in all match results.
    /// When `true`, overrides per-rule `rsigma.include_event` custom attributes.
    include_event: bool,
    /// Verbosity of the match detail recorded on detection results.
    /// `Off` by default, which preserves the historical `{ field, value }`
    /// wire shape. See [`Engine::set_match_detail`].
    match_detail: MatchDetailLevel,
    /// Monotonic counter used to namespace injected filter detections,
    /// preventing key collisions when multiple filters share detection names.
    filter_counter: usize,
    /// Inverted index mapping `(field, exact_value)` to candidate rule indices.
    /// Rebuilt after every rule mutation (add, filter).
    rule_index: RuleIndex,
    /// Per-field bloom filter over positive substring needles. Rebuilt
    /// alongside `rule_index`. Consulted only when `bloom_prefilter` is
    /// enabled.
    bloom_index: FieldBloomIndex,
    /// Toggle for bloom pre-filtering. Off by default: the per-event probe
    /// overhead exceeds the savings on rule sets where most events overlap
    /// with at least one needle's trigrams. Workloads with many substring
    /// rules and mostly-non-matching events (e.g. high-volume telemetry
    /// streams against an active threat-intel ruleset) opt in via
    /// [`Engine::set_bloom_prefilter`].
    bloom_prefilter: bool,
    /// Memory budget the bloom builder is allowed to consume across all
    /// per-field filters. `None` means use the crate default
    /// (`bloom_index::DEFAULT_MAX_TOTAL_BYTES`, 1 MB).
    bloom_max_bytes: Option<usize>,
    /// Cross-rule Aho-Corasick index for substring patterns, gated on the
    /// `daachorse-index` feature. Built only when [`cross_rule_ac_enabled`]
    /// is `true`; [`cross_rule_ac_prunable`] is the conservative per-rule
    /// flag computed at the same time so the `evaluate` hot path can drop
    /// rules safely.
    ///
    /// [`cross_rule_ac_enabled`]: Self::cross_rule_ac_enabled
    /// [`cross_rule_ac_prunable`]: Self::cross_rule_ac_prunable
    #[cfg(feature = "daachorse-index")]
    cross_rule_ac_index: cross_rule_ac::CrossRuleAcIndex,
    /// Toggle for the cross-rule AC pre-filter. Off by default; the index
    /// only pays off on rule sets > 5K rules with many shared substring
    /// patterns. See [`Engine::set_cross_rule_ac`].
    #[cfg(feature = "daachorse-index")]
    cross_rule_ac_enabled: bool,
    /// Per-rule conservative AC-prunability flag. `true` iff the rule's
    /// firing requires at least one positive substring match (no `Exact`,
    /// `Regex`, `Numeric`, `Not`, etc.), so dropping the rule on a
    /// "no AC hit" verdict is provably correct.
    #[cfg(feature = "daachorse-index")]
    cross_rule_ac_prunable: Vec<bool>,
}

impl Engine {
    /// Create a new empty engine.
    pub fn new() -> Self {
        Engine {
            rules: Vec::new(),
            pipelines: Vec::new(),
            include_event: false,
            match_detail: MatchDetailLevel::Off,
            filter_counter: 0,
            rule_index: RuleIndex::empty(),
            bloom_index: FieldBloomIndex::empty(),
            bloom_prefilter: false,
            bloom_max_bytes: None,
            #[cfg(feature = "daachorse-index")]
            cross_rule_ac_index: cross_rule_ac::CrossRuleAcIndex::empty(),
            #[cfg(feature = "daachorse-index")]
            cross_rule_ac_enabled: false,
            #[cfg(feature = "daachorse-index")]
            cross_rule_ac_prunable: Vec::new(),
        }
    }

    /// Create a new engine with a pipeline.
    pub fn new_with_pipeline(pipeline: Pipeline) -> Self {
        Engine {
            rules: Vec::new(),
            pipelines: vec![pipeline],
            include_event: false,
            match_detail: MatchDetailLevel::Off,
            filter_counter: 0,
            rule_index: RuleIndex::empty(),
            bloom_index: FieldBloomIndex::empty(),
            bloom_prefilter: false,
            bloom_max_bytes: None,
            #[cfg(feature = "daachorse-index")]
            cross_rule_ac_index: cross_rule_ac::CrossRuleAcIndex::empty(),
            #[cfg(feature = "daachorse-index")]
            cross_rule_ac_enabled: false,
            #[cfg(feature = "daachorse-index")]
            cross_rule_ac_prunable: Vec::new(),
        }
    }

    /// Enable or disable bloom-filter pre-filtering of positive substring
    /// detection items.
    ///
    /// When enabled, `evaluate*` short-circuits any positive substring
    /// matcher (`Contains` / `StartsWith` / `EndsWith` / `AhoCorasickSet`,
    /// alone or wrapped in `CaseInsensitiveGroup`) whose field cannot
    /// possibly contain a needle trigram.
    ///
    /// Disabled by default. The per-event probe (trigram extraction +
    /// double hashing) costs ~1 µs on a typical CommandLine field, which
    /// outweighs the savings on rule sets where most events overlap with
    /// at least one needle. Enable for workloads that pair many substring
    /// rules with mostly-non-matching events; benchmark with
    /// `eval_bloom_rejection` before flipping it on in production.
    pub fn set_bloom_prefilter(&mut self, enabled: bool) {
        self.bloom_prefilter = enabled;
    }

    /// Returns whether bloom pre-filtering is currently enabled.
    pub fn bloom_prefilter_enabled(&self) -> bool {
        self.bloom_prefilter
    }

    /// Set the memory budget for the per-field bloom index.
    ///
    /// Must be called **before** `add_collection` / `add_rule` for the new
    /// budget to take effect on the existing rule set; otherwise it is
    /// applied at the next index rebuild. The default budget is 1 MB,
    /// shared across all per-field filters. Lower the cap on memory-
    /// constrained deployments; raise it for large rule sets where the
    /// default starts evicting useful filters.
    pub fn set_bloom_max_bytes(&mut self, max_bytes: usize) {
        self.bloom_max_bytes = Some(max_bytes);
        if !self.rules.is_empty() {
            self.rebuild_index();
        }
    }

    /// Returns the configured bloom memory budget, if one has been set
    /// explicitly. `None` means the crate default (1 MB) is in use.
    pub fn bloom_max_bytes(&self) -> Option<usize> {
        self.bloom_max_bytes
    }

    /// Enable or disable the cross-rule Aho-Corasick pre-filter.
    ///
    /// When enabled, the engine builds a single per-field
    /// `DoubleArrayAhoCorasick` automaton over every positive substring
    /// needle from every rule and drops AC-prunable rules from the
    /// candidate set when none of their patterns hit the event.
    ///
    /// Off by default. Pays off on large rule sets (> ~5K rules) with many
    /// shared substring patterns (threat-intel feeds, IOC packs). For
    /// smaller rule sets the per-rule [`AhoCorasickSet`] matcher already
    /// handles the workload optimally; the cross-rule index only adds
    /// build-time and lookup overhead. Benchmark with `eval_cross_rule_ac`
    /// against representative rule sets before enabling in production.
    ///
    /// Available behind the `daachorse-index` Cargo feature.
    ///
    /// [`AhoCorasickSet`]: crate::matcher::CompiledMatcher::AhoCorasickSet
    #[cfg(feature = "daachorse-index")]
    pub fn set_cross_rule_ac(&mut self, enabled: bool) {
        self.cross_rule_ac_enabled = enabled;
        if enabled && !self.rules.is_empty() {
            self.rebuild_index();
        }
    }

    /// Returns whether the cross-rule AC pre-filter is currently enabled.
    /// Available behind the `daachorse-index` Cargo feature.
    #[cfg(feature = "daachorse-index")]
    pub fn cross_rule_ac_enabled(&self) -> bool {
        self.cross_rule_ac_enabled
    }

    /// Set global `include_event` — when `true`, all match results include
    /// the full event JSON regardless of per-rule custom attributes.
    pub fn set_include_event(&mut self, include: bool) {
        self.include_event = include;
    }

    /// Set the match-detail verbosity for detection results.
    ///
    /// `Off` (default) records each match as `{ field, value }`, identical to
    /// pre-enrichment releases. `Summary` adds the originating selection, the
    /// matcher kind, and case sensitivity, and reports keyword and absence
    /// matches that `Off` omits. `Full` additionally records the pattern that
    /// fired. The extra work runs only when a rule matches and only above
    /// `Off`, so the default hot path is unchanged.
    pub fn set_match_detail(&mut self, level: MatchDetailLevel) {
        self.match_detail = level;
    }

    /// Returns the configured match-detail verbosity.
    pub fn match_detail(&self) -> MatchDetailLevel {
        self.match_detail
    }

    /// Add a pipeline to the engine.
    ///
    /// Pipelines are applied to rules during `add_rule` / `add_collection`.
    /// Only affects rules added **after** this call.
    pub fn add_pipeline(&mut self, pipeline: Pipeline) {
        self.pipelines.push(pipeline);
        self.pipelines.sort_by_key(|p| p.priority);
    }

    /// Add a single parsed Sigma rule.
    ///
    /// If pipelines are set, the rule is cloned and transformed before
    /// compilation. The rule index folds the new rule incrementally; the
    /// bloom index also folds it incrementally and only triggers a full
    /// rebuild when its doubling watermark is reached, so this call is
    /// amortized O(1) per rule. With the `daachorse-index` feature
    /// enabled **and** the cross-rule AC index turned on at runtime, the
    /// call falls back to a full rebuild because the daachorse automaton
    /// has no incremental update path.
    pub fn add_rule(&mut self, rule: &SigmaRule) -> Result<()> {
        let compiled = self.compile_with_pipelines(rule)?;
        self.rules.push(compiled);
        self.index_append_last_rule();
        Ok(())
    }

    /// Add many parsed Sigma rules in a single batch.
    ///
    /// Each rule is compiled (with the engine's pipelines applied, if any)
    /// and pushed onto the rule set. Compilation errors are collected and
    /// returned as `(rule_index_in_input, error)` pairs without aborting the
    /// batch; rules that did compile remain loaded. The inverted index and
    /// per-field bloom filter are rebuilt **once** at the end of the batch.
    ///
    /// Prefer this over a loop of [`Engine::add_rule`] when loading large
    /// rule sets: the per-call rebuild is O(N) in the total rule count, so
    /// per-rule adds turn a 3K-rule corpus into O(N²) work.
    pub fn add_rules<'a, I>(&mut self, rules: I) -> Vec<(usize, EvalError)>
    where
        I: IntoIterator<Item = &'a SigmaRule>,
    {
        let mut errors = Vec::new();
        for (idx, rule) in rules.into_iter().enumerate() {
            match self.compile_with_pipelines(rule) {
                Ok(compiled) => self.rules.push(compiled),
                Err(e) => errors.push((idx, e)),
            }
        }
        self.rebuild_index();
        errors
    }

    /// Add all detection rules from a parsed collection, then apply filters.
    ///
    /// Filter rules modify referenced detection rules by appending exclusion
    /// conditions. Correlation rules are handled by `CorrelationEngine`.
    /// The inverted index is rebuilt once after all rules and filters are loaded.
    pub fn add_collection(&mut self, collection: &SigmaCollection) -> Result<()> {
        for rule in &collection.rules {
            let compiled = self.compile_with_pipelines(rule)?;
            self.rules.push(compiled);
        }
        for filter in &collection.filters {
            self.apply_filter_no_rebuild(filter)?;
        }
        self.rebuild_index();
        Ok(())
    }

    /// Compile a rule, applying any configured pipelines first. Shared by
    /// the single- and batched-add paths so they stay behaviourally
    /// identical.
    fn compile_with_pipelines(&self, rule: &SigmaRule) -> Result<CompiledRule> {
        if self.pipelines.is_empty() {
            compile_rule(rule)
        } else {
            let mut transformed = rule.clone();
            apply_pipelines(&self.pipelines, &mut transformed)?;
            compile_rule(&transformed)
        }
    }

    /// Add all detection rules from a collection, applying the given pipelines.
    ///
    /// This is a convenience method that temporarily sets pipelines, adds the
    /// collection, then clears them. The inverted index is rebuilt once after
    /// all rules and filters are loaded.
    pub fn add_collection_with_pipelines(
        &mut self,
        collection: &SigmaCollection,
        pipelines: &[Pipeline],
    ) -> Result<()> {
        let prev = std::mem::take(&mut self.pipelines);
        self.pipelines = pipelines.to_vec();
        self.pipelines.sort_by_key(|p| p.priority);
        let result = self.add_collection(collection);
        self.pipelines = prev;
        result
    }

    /// Apply a filter rule to all referenced detection rules and rebuild the index.
    pub fn apply_filter(&mut self, filter: &FilterRule) -> Result<()> {
        self.apply_filter_no_rebuild(filter)?;
        self.rebuild_index();
        Ok(())
    }

    /// Apply a filter rule without rebuilding the index.
    /// Used internally when multiple mutations are batched.
    fn apply_filter_no_rebuild(&mut self, filter: &FilterRule) -> Result<()> {
        // Compile filter detections
        let mut filter_detections = Vec::new();
        for (name, detection) in &filter.detection.named {
            let compiled = compile_detection(detection)?;
            filter_detections.push((name.clone(), compiled));
        }

        if filter_detections.is_empty() {
            return Ok(());
        }

        let fc = self.filter_counter;
        self.filter_counter += 1;

        // Rewrite the filter's own condition expression with namespaced identifiers
        // so that `selection` becomes `__filter_0_selection`, etc.
        let rewritten_cond = if let Some(cond_expr) = filter.detection.conditions.first() {
            rewrite_condition_identifiers(cond_expr, fc)
        } else {
            // No explicit condition: AND all detections (legacy fallback)
            if filter_detections.len() == 1 {
                ConditionExpr::Identifier(format!("__filter_{fc}_{}", filter_detections[0].0))
            } else {
                ConditionExpr::And(
                    filter_detections
                        .iter()
                        .map(|(name, _)| ConditionExpr::Identifier(format!("__filter_{fc}_{name}")))
                        .collect(),
                )
            }
        };

        // Find and modify referenced rules
        let mut matched_any = false;
        for rule in &mut self.rules {
            let rule_matches = match &filter.rules {
                FilterRuleTarget::Any => true,
                FilterRuleTarget::Specific(refs) => refs
                    .iter()
                    .any(|r| rule.id.as_deref() == Some(r.as_str()) || rule.title == *r),
            };

            // Also check logsource compatibility if the filter specifies one
            if rule_matches {
                if let Some(ref filter_ls) = filter.logsource
                    && !filter_logsource_contains(filter_ls, &rule.logsource)
                {
                    continue;
                }

                // Inject filter detections into the rule
                for (name, compiled) in &filter_detections {
                    rule.detections
                        .insert(format!("__filter_{fc}_{name}"), compiled.clone());
                }

                // Wrap each existing rule condition with the filter condition
                rule.conditions = rule
                    .conditions
                    .iter()
                    .map(|cond| ConditionExpr::And(vec![cond.clone(), rewritten_cond.clone()]))
                    .collect();
                matched_any = true;
            }
        }

        if let FilterRuleTarget::Specific(_) = &filter.rules
            && !matched_any
        {
            log::warn!(
                "filter '{}' references rules {:?} but none matched any loaded rule",
                filter.title,
                filter.rules
            );
        }

        Ok(())
    }

    /// Add a pre-compiled rule directly. The rule index folds the new
    /// rule incrementally; the bloom index also folds it incrementally
    /// and only triggers a full rebuild when its doubling watermark is
    /// reached, so this call is amortized O(1) per rule. With the
    /// cross-rule AC index enabled (`daachorse-index` feature, runtime
    /// toggle), this falls back to a full rebuild because daachorse has
    /// no incremental update path.
    pub fn add_compiled_rule(&mut self, rule: CompiledRule) {
        self.rules.push(rule);
        self.index_append_last_rule();
    }

    /// Add many pre-compiled rules in a single batch. The inverted index
    /// and bloom filter are rebuilt exactly once at the end, regardless of
    /// how many rules are appended.
    pub fn extend_compiled_rules<I>(&mut self, rules: I)
    where
        I: IntoIterator<Item = CompiledRule>,
    {
        self.rules.extend(rules);
        self.rebuild_index();
    }

    /// Rebuild every per-engine index from the current rule set.
    ///
    /// Used by batched rule loads (`add_rules`, `extend_compiled_rules`,
    /// `add_collection`) and by mutations that rewrite existing rules
    /// (`apply_filter`), where rebuilding once over the final shape is
    /// cheaper than maintaining incremental state across mutations. The
    /// single-rule paths use [`Engine::index_append_last_rule`] instead.
    fn rebuild_index(&mut self) {
        self.rule_index = RuleIndex::build(&self.rules);
        self.bloom_index = match self.bloom_max_bytes {
            Some(budget) => FieldBloomIndex::build_with_budget(&self.rules, budget),
            None => FieldBloomIndex::build(&self.rules),
        };
        #[cfg(feature = "daachorse-index")]
        {
            if self.cross_rule_ac_enabled {
                self.cross_rule_ac_index = cross_rule_ac::CrossRuleAcIndex::build(&self.rules);
                self.cross_rule_ac_prunable = self
                    .rules
                    .iter()
                    .map(cross_rule_ac::rule_is_ac_prunable)
                    .collect();
            } else {
                self.cross_rule_ac_index = cross_rule_ac::CrossRuleAcIndex::empty();
                self.cross_rule_ac_prunable.clear();
            }
        }
    }

    /// Fold the rule most recently pushed onto `self.rules` into the
    /// inverted and bloom indexes incrementally. Cost is bounded by the
    /// new rule's detection tree size, not by the total rule count.
    ///
    /// The bloom index periodically forces a full rebuild via its
    /// doubling watermark to re-enforce the memory budget and reset the
    /// FPR drift that incremental inserts accumulate. Cross-rule AC
    /// (daachorse) has no incremental story, so when it is enabled this
    /// call falls back to [`Engine::rebuild_index`].
    fn index_append_last_rule(&mut self) {
        #[cfg(feature = "daachorse-index")]
        {
            if self.cross_rule_ac_enabled {
                self.rebuild_index();
                return;
            }
        }

        let new_idx = self.rules.len() - 1;
        let rule = &self.rules[new_idx];
        self.rule_index.append_rule(new_idx, rule);
        self.bloom_index.append_rule(rule);

        if self.bloom_index.should_rebuild(self.rules.len()) {
            self.bloom_index = match self.bloom_max_bytes {
                Some(budget) => FieldBloomIndex::build_with_budget(&self.rules, budget),
                None => FieldBloomIndex::build(&self.rules),
            };
        }
    }

    /// Evaluate an event against candidate rules using the inverted index.
    pub fn evaluate<E: Event>(&self, event: &E) -> Vec<EvaluationResult> {
        if self.bloom_prefilter {
            self.evaluate_with_bloom_path(event)
        } else {
            self.evaluate_no_bloom_path(event)
        }
    }

    /// Build the cross-rule AC keep-mask for `event`, or `None` when the
    /// cross-rule index is disabled or empty (no filtering needed).
    ///
    /// `Some(mask)` answers "should this rule survive the cross-rule AC
    /// filter": `mask[idx] = true` means keep, `false` means drop.
    /// Non-AC-prunable rules are always kept.
    #[cfg(feature = "daachorse-index")]
    fn cross_rule_ac_keep_mask<E: Event>(&self, event: &E) -> Option<Vec<bool>> {
        if !self.cross_rule_ac_enabled || self.cross_rule_ac_index.is_empty() {
            return None;
        }
        let mut hits = vec![false; self.rules.len()];
        self.cross_rule_ac_index.mark_hits(event, &mut hits);
        // Compose: keep = !ac_prunable OR ac_hit. The prunable vector and
        // the rule slice are kept aligned by `rebuild_index`.
        for (idx, slot) in hits.iter_mut().enumerate() {
            if !self
                .cross_rule_ac_prunable
                .get(idx)
                .copied()
                .unwrap_or(false)
            {
                *slot = true;
            }
        }
        Some(hits)
    }

    #[cfg(not(feature = "daachorse-index"))]
    #[inline(always)]
    fn cross_rule_ac_keep_mask<E: Event>(&self, _event: &E) -> Option<Vec<bool>> {
        None
    }

    fn evaluate_no_bloom_path<E: Event>(&self, event: &E) -> Vec<EvaluationResult> {
        // The public `evaluate_rule` is not generic over `BloomLookup`, so
        // the no-bloom hot path lowers to straight-line code identical to
        // the pre-bloom engine.
        let keep = self.cross_rule_ac_keep_mask(event);
        let mut results = Vec::new();
        for idx in self.rule_index.candidates(event) {
            if let Some(ref mask) = keep
                && !mask[idx]
            {
                continue;
            }
            let rule = &self.rules[idx];
            if let Some(mut m) =
                evaluate_rule_with_bloom(rule, event, &bloom_index::NoBloom, self.match_detail)
            {
                if self.include_event
                    && let Some(d) = m.as_detection_mut()
                    && d.event.is_none()
                {
                    d.event = Some(event.to_json());
                }
                results.push(m);
            }
        }
        results
    }

    fn evaluate_with_bloom_path<E: Event>(&self, event: &E) -> Vec<EvaluationResult> {
        let bloom = BloomCache::new(&self.bloom_index, event);
        let keep = self.cross_rule_ac_keep_mask(event);
        let mut results = Vec::new();
        for idx in self.rule_index.candidates(event) {
            if let Some(ref mask) = keep
                && !mask[idx]
            {
                continue;
            }
            let rule = &self.rules[idx];
            if let Some(mut m) = evaluate_rule_with_bloom(rule, event, &bloom, self.match_detail) {
                if self.include_event
                    && let Some(d) = m.as_detection_mut()
                    && d.event.is_none()
                {
                    d.event = Some(event.to_json());
                }
                results.push(m);
            }
        }
        results
    }

    /// Evaluate an event against candidate rules matching the given logsource.
    ///
    /// Uses the inverted index for candidate pre-filtering, then applies the
    /// logsource constraint. Only rules whose logsource is compatible with
    /// `event_logsource` are evaluated.
    pub fn evaluate_with_logsource<E: Event>(
        &self,
        event: &E,
        event_logsource: &LogSource,
    ) -> Vec<EvaluationResult> {
        if self.bloom_prefilter {
            self.evaluate_with_logsource_with_bloom(event, event_logsource)
        } else {
            self.evaluate_with_logsource_no_bloom(event, event_logsource)
        }
    }

    fn evaluate_with_logsource_no_bloom<E: Event>(
        &self,
        event: &E,
        event_logsource: &LogSource,
    ) -> Vec<EvaluationResult> {
        let keep = self.cross_rule_ac_keep_mask(event);
        let mut results = Vec::new();
        for idx in self.rule_index.candidates(event) {
            if let Some(ref mask) = keep
                && !mask[idx]
            {
                continue;
            }
            let rule = &self.rules[idx];
            if logsource_matches(&rule.logsource, event_logsource)
                && let Some(mut m) =
                    evaluate_rule_with_bloom(rule, event, &bloom_index::NoBloom, self.match_detail)
            {
                if self.include_event
                    && let Some(d) = m.as_detection_mut()
                    && d.event.is_none()
                {
                    d.event = Some(event.to_json());
                }
                results.push(m);
            }
        }
        results
    }

    fn evaluate_with_logsource_with_bloom<E: Event>(
        &self,
        event: &E,
        event_logsource: &LogSource,
    ) -> Vec<EvaluationResult> {
        let bloom = BloomCache::new(&self.bloom_index, event);
        let keep = self.cross_rule_ac_keep_mask(event);
        let mut results = Vec::new();
        for idx in self.rule_index.candidates(event) {
            if let Some(ref mask) = keep
                && !mask[idx]
            {
                continue;
            }
            let rule = &self.rules[idx];
            if logsource_matches(&rule.logsource, event_logsource)
                && let Some(mut m) =
                    evaluate_rule_with_bloom(rule, event, &bloom, self.match_detail)
            {
                if self.include_event
                    && let Some(d) = m.as_detection_mut()
                    && d.event.is_none()
                {
                    d.event = Some(event.to_json());
                }
                results.push(m);
            }
        }
        results
    }

    /// Evaluate a batch of events, returning per-event match results.
    ///
    /// When the `parallel` feature is enabled, events are evaluated concurrently
    /// using rayon's work-stealing thread pool. Otherwise, falls back to
    /// sequential evaluation.
    pub fn evaluate_batch<E: Event + Sync>(&self, events: &[&E]) -> Vec<Vec<EvaluationResult>> {
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            events.par_iter().map(|e| self.evaluate(e)).collect()
        }
        #[cfg(not(feature = "parallel"))]
        {
            events.iter().map(|e| self.evaluate(e)).collect()
        }
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
