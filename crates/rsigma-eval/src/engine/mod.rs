//! Rule evaluation engine with logsource routing.
//!
//! The `Engine` manages a set of compiled Sigma rules and evaluates events
//! against them. It supports optional logsource-based pre-filtering to
//! reduce the number of rules evaluated per event.

mod filters;
#[cfg(test)]
mod tests;

use rsigma_parser::{
    ConditionExpr, FilterRule, FilterRuleTarget, LogSource, SigmaCollection, SigmaRule,
};

use crate::compiler::{CompiledRule, compile_detection, compile_rule, evaluate_rule};
use crate::error::Result;
use crate::event::Event;
use crate::pipeline::{Pipeline, apply_pipelines};
use crate::result::MatchResult;
use crate::rule_index::RuleIndex;

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
/// assert_eq!(matches[0].rule_title, "Detect Whoami");
/// ```
pub struct Engine {
    rules: Vec<CompiledRule>,
    pipelines: Vec<Pipeline>,
    /// Global override: include the full event JSON in all match results.
    /// When `true`, overrides per-rule `rsigma.include_event` custom attributes.
    include_event: bool,
    /// Monotonic counter used to namespace injected filter detections,
    /// preventing key collisions when multiple filters share detection names.
    filter_counter: usize,
    /// Inverted index mapping `(field, exact_value)` to candidate rule indices.
    /// Rebuilt after every rule mutation (add, filter).
    rule_index: RuleIndex,
}

impl Engine {
    /// Create a new empty engine.
    pub fn new() -> Self {
        Engine {
            rules: Vec::new(),
            pipelines: Vec::new(),
            include_event: false,
            filter_counter: 0,
            rule_index: RuleIndex::empty(),
        }
    }

    /// Create a new engine with a pipeline.
    pub fn new_with_pipeline(pipeline: Pipeline) -> Self {
        Engine {
            rules: Vec::new(),
            pipelines: vec![pipeline],
            include_event: false,
            filter_counter: 0,
            rule_index: RuleIndex::empty(),
        }
    }

    /// Set global `include_event` — when `true`, all match results include
    /// the full event JSON regardless of per-rule custom attributes.
    pub fn set_include_event(&mut self, include: bool) {
        self.include_event = include;
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
    /// If pipelines are set, the rule is cloned and transformed before compilation.
    /// The inverted index is rebuilt after adding the rule.
    pub fn add_rule(&mut self, rule: &SigmaRule) -> Result<()> {
        let compiled = if self.pipelines.is_empty() {
            compile_rule(rule)?
        } else {
            let mut transformed = rule.clone();
            apply_pipelines(&self.pipelines, &mut transformed)?;
            compile_rule(&transformed)?
        };
        self.rules.push(compiled);
        self.rebuild_index();
        Ok(())
    }

    /// Add all detection rules from a parsed collection, then apply filters.
    ///
    /// Filter rules modify referenced detection rules by appending exclusion
    /// conditions. Correlation rules are handled by `CorrelationEngine`.
    /// The inverted index is rebuilt once after all rules and filters are loaded.
    pub fn add_collection(&mut self, collection: &SigmaCollection) -> Result<()> {
        for rule in &collection.rules {
            let compiled = if self.pipelines.is_empty() {
                compile_rule(rule)?
            } else {
                let mut transformed = rule.clone();
                apply_pipelines(&self.pipelines, &mut transformed)?;
                compile_rule(&transformed)?
            };
            self.rules.push(compiled);
        }
        for filter in &collection.filters {
            self.apply_filter_no_rebuild(filter)?;
        }
        self.rebuild_index();
        Ok(())
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

    /// Add a pre-compiled rule directly and rebuild the index.
    pub fn add_compiled_rule(&mut self, rule: CompiledRule) {
        self.rules.push(rule);
        self.rebuild_index();
    }

    /// Rebuild the inverted index from the current rule set.
    fn rebuild_index(&mut self) {
        self.rule_index = RuleIndex::build(&self.rules);
    }

    /// Evaluate an event against candidate rules using the inverted index.
    pub fn evaluate<E: Event>(&self, event: &E) -> Vec<MatchResult> {
        let mut results = Vec::new();
        for idx in self.rule_index.candidates(event) {
            let rule = &self.rules[idx];
            if let Some(mut m) = evaluate_rule(rule, event) {
                if self.include_event && m.event.is_none() {
                    m.event = Some(event.to_json());
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
    ) -> Vec<MatchResult> {
        let mut results = Vec::new();
        for idx in self.rule_index.candidates(event) {
            let rule = &self.rules[idx];
            if logsource_matches(&rule.logsource, event_logsource)
                && let Some(mut m) = evaluate_rule(rule, event)
            {
                if self.include_event && m.event.is_none() {
                    m.event = Some(event.to_json());
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
    pub fn evaluate_batch<E: Event + Sync>(&self, events: &[&E]) -> Vec<Vec<MatchResult>> {
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
