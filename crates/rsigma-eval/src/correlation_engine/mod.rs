//! Stateful correlation engine with time-windowed aggregation.
//!
//! `CorrelationEngine` wraps the stateless `Engine` and adds support for
//! Sigma correlation rules: `event_count`, `value_count`, `temporal`,
//! `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`,
//! and `value_median`.
//!
//! # Architecture
//!
//! 1. Events are first evaluated against detection rules (stateless)
//! 2. Detection matches update correlation window state (stateful)
//! 3. When a correlation condition is met, a `CorrelationResult` is emitted
//! 4. Correlation results can chain into higher-level correlations

#[cfg(test)]
mod tests;
mod types;

pub use types::*;

use std::collections::HashMap;

use chrono::{DateTime, TimeZone, Utc};

use rsigma_parser::{CorrelationRule, CorrelationType, SigmaCollection, SigmaRule};

use crate::correlation::{
    CompiledCorrelation, EventBuffer, EventRefBuffer, GroupKey, WindowState, compile_correlation,
};
use crate::engine::Engine;
use crate::error::{EvalError, Result};
use crate::event::{Event, EventValue};
use crate::pipeline::{Pipeline, apply_pipelines, apply_pipelines_to_correlation};
use crate::result::MatchResult;

// =============================================================================
// Correlation Engine
// =============================================================================

/// Current snapshot schema version. Bump when the serialized format changes.
const SNAPSHOT_VERSION: u32 = 1;

/// Stateful correlation engine.
///
/// Wraps the stateless `Engine` for detection rules and adds time-windowed
/// correlation on top. Supports all 7 Sigma correlation types and chaining.
pub struct CorrelationEngine {
    /// Inner stateless detection engine.
    engine: Engine,
    /// Compiled correlation rules.
    correlations: Vec<CompiledCorrelation>,
    /// Maps rule ID/name -> indices into `correlations` that reference it.
    /// This allows quick lookup: "which correlations care about rule X?"
    rule_index: HashMap<String, Vec<usize>>,
    /// Maps detection rule index -> (rule_id, rule_name) for reverse lookup.
    /// Used to find which correlations a detection match triggers.
    rule_ids: Vec<(Option<String>, Option<String>)>,
    /// Per-(correlation_index, group_key) window state.
    state: HashMap<(usize, GroupKey), WindowState>,
    /// Last alert timestamp per (correlation_index, group_key) for suppression.
    last_alert: HashMap<(usize, GroupKey), i64>,
    /// Per-(correlation_index, group_key) compressed event buffer (`Full` mode).
    event_buffers: HashMap<(usize, GroupKey), EventBuffer>,
    /// Per-(correlation_index, group_key) event reference buffer (`Refs` mode).
    event_ref_buffers: HashMap<(usize, GroupKey), EventRefBuffer>,
    /// Set of detection rule IDs/names that are "correlation-only"
    /// (referenced by correlations where `generate == false`).
    /// Used to filter detection output when `config.emit_detections == false`.
    correlation_only_rules: std::collections::HashSet<String>,
    /// Configuration.
    config: CorrelationConfig,
    /// Processing pipelines applied to rules during add_rule.
    pipelines: Vec<Pipeline>,
}

impl CorrelationEngine {
    /// Create a new correlation engine with the given configuration.
    pub fn new(config: CorrelationConfig) -> Self {
        CorrelationEngine {
            engine: Engine::new(),
            correlations: Vec::new(),
            rule_index: HashMap::new(),
            rule_ids: Vec::new(),
            state: HashMap::new(),
            last_alert: HashMap::new(),
            event_buffers: HashMap::new(),
            event_ref_buffers: HashMap::new(),
            correlation_only_rules: std::collections::HashSet::new(),
            config,
            pipelines: Vec::new(),
        }
    }

    /// Add a pipeline to the engine.
    ///
    /// Pipelines are applied to rules during `add_rule` / `add_collection`.
    pub fn add_pipeline(&mut self, pipeline: Pipeline) {
        self.pipelines.push(pipeline);
        self.pipelines.sort_by_key(|p| p.priority);
    }

    /// Set global `include_event` on the inner detection engine.
    pub fn set_include_event(&mut self, include: bool) {
        self.engine.set_include_event(include);
    }

    /// Set the global correlation event mode.
    ///
    /// - `None`: no event storage (default)
    /// - `Full`: compressed event bodies
    /// - `Refs`: lightweight timestamp + ID references
    pub fn set_correlation_event_mode(&mut self, mode: CorrelationEventMode) {
        self.config.correlation_event_mode = mode;
    }

    /// Set the maximum number of events to store per correlation window group.
    /// Only meaningful when `correlation_event_mode` is not `None`.
    pub fn set_max_correlation_events(&mut self, max: usize) {
        self.config.max_correlation_events = max;
    }

    /// Add a single detection rule.
    ///
    /// If pipelines are set, the rule is cloned and transformed before compilation.
    /// The inner engine receives the already-transformed rule directly (not through
    /// its own pipeline, to avoid double transformation).
    pub fn add_rule(&mut self, rule: &SigmaRule) -> Result<()> {
        if self.pipelines.is_empty() {
            self.apply_custom_attributes(&rule.custom_attributes);
            self.rule_ids.push((rule.id.clone(), rule.name.clone()));
            self.engine.add_rule(rule)?;
        } else {
            let mut transformed = rule.clone();
            apply_pipelines(&self.pipelines, &mut transformed)?;
            self.apply_custom_attributes(&transformed.custom_attributes);
            self.rule_ids
                .push((transformed.id.clone(), transformed.name.clone()));
            // Use compile_rule + add_compiled_rule to bypass inner engine's pipelines
            let compiled = crate::compiler::compile_rule(&transformed)?;
            self.engine.add_compiled_rule(compiled);
        }
        Ok(())
    }

    /// Read `rsigma.*` custom attributes from a rule and apply them to the
    /// engine configuration.  This allows pipelines to influence engine
    /// behaviour via `SetCustomAttribute` transformations — the same pattern
    /// used by pySigma backends (e.g. pySigma-backend-loki).
    ///
    /// Supported attributes:
    /// - `rsigma.timestamp_field` — prepends a field name to the timestamp
    ///   extraction priority list so the correlation engine can find the
    ///   event timestamp in non-standard field names.
    /// - `rsigma.suppress` — sets the default suppression window (e.g. `5m`).
    ///   Only applied when the CLI did not already set `--suppress`.
    /// - `rsigma.action` — sets the default post-fire action (`alert`/`reset`).
    ///   Only applied when the CLI did not already set `--action`.
    fn apply_custom_attributes(
        &mut self,
        attrs: &std::collections::HashMap<String, serde_yaml::Value>,
    ) {
        // rsigma.timestamp_field — prepend to priority list, skip duplicates
        if let Some(field) = attrs.get("rsigma.timestamp_field").and_then(|v| v.as_str())
            && !self.config.timestamp_fields.iter().any(|f| f == field)
        {
            self.config.timestamp_fields.insert(0, field.to_string());
        }

        // rsigma.suppress — only when CLI didn't already set one
        if let Some(val) = attrs.get("rsigma.suppress").and_then(|v| v.as_str())
            && self.config.suppress.is_none()
            && let Ok(ts) = rsigma_parser::Timespan::parse(val)
        {
            self.config.suppress = Some(ts.seconds);
        }

        // rsigma.action — only when CLI left it at the default (Alert)
        if let Some(val) = attrs.get("rsigma.action").and_then(|v| v.as_str())
            && self.config.action_on_match == CorrelationAction::Alert
            && let Ok(a) = val.parse::<CorrelationAction>()
        {
            self.config.action_on_match = a;
        }
    }

    /// Add a single correlation rule.
    pub fn add_correlation(&mut self, corr: &CorrelationRule) -> Result<()> {
        let owned;
        let effective = if self.pipelines.is_empty() {
            corr
        } else {
            owned = {
                let mut c = corr.clone();
                apply_pipelines_to_correlation(&self.pipelines, &mut c)?;
                c
            };
            &owned
        };

        // Apply engine-level custom attributes from the (possibly transformed)
        // correlation rule (e.g. rsigma.timestamp_field).
        self.apply_custom_attributes(&effective.custom_attributes);

        let compiled = compile_correlation(effective)?;
        let idx = self.correlations.len();

        // Index by each referenced rule ID/name
        for rule_ref in &compiled.rule_refs {
            self.rule_index
                .entry(rule_ref.clone())
                .or_default()
                .push(idx);
        }

        // Track correlation-only rules (generate == false is the default)
        if !compiled.generate {
            for rule_ref in &compiled.rule_refs {
                self.correlation_only_rules.insert(rule_ref.clone());
            }
        }

        self.correlations.push(compiled);
        Ok(())
    }

    /// Add all rules and correlations from a parsed collection.
    ///
    /// Detection rules are added first (so they're available for correlation
    /// references), then correlation rules.
    pub fn add_collection(&mut self, collection: &SigmaCollection) -> Result<()> {
        for rule in &collection.rules {
            self.add_rule(rule)?;
        }
        // Apply filter rules to the inner engine's detection rules
        for filter in &collection.filters {
            self.engine.apply_filter(filter)?;
        }
        for corr in &collection.correlations {
            self.add_correlation(corr)?;
        }
        self.validate_rule_refs()?;
        self.detect_correlation_cycles()?;
        Ok(())
    }

    /// Validate that every correlation's `rule_refs` resolve to at least one
    /// known detection rule (by ID or name) or another correlation (by ID or name).
    fn validate_rule_refs(&self) -> Result<()> {
        let mut known: std::collections::HashSet<&str> = std::collections::HashSet::new();

        for (id, name) in &self.rule_ids {
            if let Some(id) = id {
                known.insert(id.as_str());
            }
            if let Some(name) = name {
                known.insert(name.as_str());
            }
        }
        for corr in &self.correlations {
            if let Some(ref id) = corr.id {
                known.insert(id.as_str());
            }
            if let Some(ref name) = corr.name {
                known.insert(name.as_str());
            }
        }

        for corr in &self.correlations {
            for rule_ref in &corr.rule_refs {
                if !known.contains(rule_ref.as_str()) {
                    return Err(EvalError::UnknownRuleRef(rule_ref.clone()));
                }
            }
        }
        Ok(())
    }

    /// Detect cycles in the correlation reference graph.
    ///
    /// Builds a directed graph where each correlation (identified by its id/name)
    /// has edges to the correlations it references via `rule_refs`. Uses DFS with
    /// a "gray/black" coloring scheme to detect back-edges (cycles).
    ///
    /// Returns `Err(EvalError::CorrelationCycle)` if a cycle is found.
    fn detect_correlation_cycles(&self) -> Result<()> {
        // Build a set of all correlation identifiers (id and/or name)
        let mut corr_identifiers: HashMap<&str, usize> = HashMap::new();
        for (idx, corr) in self.correlations.iter().enumerate() {
            if let Some(ref id) = corr.id {
                corr_identifiers.insert(id.as_str(), idx);
            }
            if let Some(ref name) = corr.name {
                corr_identifiers.insert(name.as_str(), idx);
            }
        }

        // Build adjacency list: corr index → set of corr indices it references
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); self.correlations.len()];
        for (idx, corr) in self.correlations.iter().enumerate() {
            for rule_ref in &corr.rule_refs {
                if let Some(&target_idx) = corr_identifiers.get(rule_ref.as_str()) {
                    adj[idx].push(target_idx);
                }
            }
        }

        // DFS cycle detection with three states: white (unvisited), gray (in stack), black (done)
        let mut state = vec![0u8; self.correlations.len()]; // 0=white, 1=gray, 2=black
        let mut path: Vec<usize> = Vec::new();

        for start in 0..self.correlations.len() {
            if state[start] == 0
                && let Some(cycle) = Self::dfs_find_cycle(start, &adj, &mut state, &mut path)
            {
                let names: Vec<String> = cycle
                    .iter()
                    .map(|&i| {
                        self.correlations[i]
                            .id
                            .as_deref()
                            .or(self.correlations[i].name.as_deref())
                            .unwrap_or(&self.correlations[i].title)
                            .to_string()
                    })
                    .collect();
                return Err(crate::error::EvalError::CorrelationCycle(
                    names.join(" -> "),
                ));
            }
        }
        Ok(())
    }

    /// DFS helper that returns the cycle path if a back-edge is found.
    fn dfs_find_cycle(
        node: usize,
        adj: &[Vec<usize>],
        state: &mut [u8],
        path: &mut Vec<usize>,
    ) -> Option<Vec<usize>> {
        state[node] = 1; // gray
        path.push(node);

        for &next in &adj[node] {
            if state[next] == 1 {
                // Back-edge found — extract cycle from path
                if let Some(pos) = path.iter().position(|&n| n == next) {
                    let mut cycle = path[pos..].to_vec();
                    cycle.push(next); // close the cycle
                    return Some(cycle);
                }
            }
            if state[next] == 0
                && let Some(cycle) = Self::dfs_find_cycle(next, adj, state, path)
            {
                return Some(cycle);
            }
        }

        path.pop();
        state[node] = 2; // black
        None
    }

    /// Process an event, extracting the timestamp from configured event fields.
    ///
    /// When no timestamp field is found, the `timestamp_fallback` policy applies:
    /// - `WallClock`: use `Utc::now()` (good for real-time streaming)
    /// - `Skip`: return detections only, skip correlation state updates
    pub fn process_event(&mut self, event: &impl Event) -> ProcessResult {
        let all_detections = self.engine.evaluate(event);

        let ts = match self.extract_event_timestamp(event) {
            Some(ts) => ts,
            None => match self.config.timestamp_fallback {
                TimestampFallback::WallClock => Utc::now().timestamp(),
                TimestampFallback::Skip => {
                    // Still run detection (stateless), but skip correlation
                    let detections = self.filter_detections(all_detections);
                    return ProcessResult {
                        detections,
                        correlations: Vec::new(),
                    };
                }
            },
        };
        self.process_with_detections(event, all_detections, ts)
    }

    /// Process an event with an explicit Unix epoch timestamp (seconds).
    ///
    /// The timestamp is clamped to `[0, i64::MAX / 2]` to prevent overflow
    /// when adding timespan durations internally.
    pub fn process_event_at(&mut self, event: &impl Event, timestamp_secs: i64) -> ProcessResult {
        let all_detections = self.engine.evaluate(event);
        self.process_with_detections(event, all_detections, timestamp_secs)
    }

    /// Process an event with pre-computed detection results.
    ///
    /// Enables external parallelism: callers can run detection (via
    /// [`evaluate`](Self::evaluate)) in parallel, then feed results here
    /// sequentially for stateful correlation.
    pub fn process_with_detections(
        &mut self,
        event: &impl Event,
        all_detections: Vec<MatchResult>,
        timestamp_secs: i64,
    ) -> ProcessResult {
        let timestamp_secs = timestamp_secs.clamp(0, i64::MAX / 2);

        // Memory management — evict before adding new state to enforce limit
        if self.state.len() >= self.config.max_state_entries {
            self.evict_all(timestamp_secs);
        }

        // Feed detection matches into correlations
        let mut correlations = Vec::new();
        self.feed_detections(event, &all_detections, timestamp_secs, &mut correlations);

        // Chain — correlation results may trigger higher-level correlations
        self.chain_correlations(&correlations, timestamp_secs);

        // Filter detections by generate flag
        let detections = self.filter_detections(all_detections);

        ProcessResult {
            detections,
            correlations,
        }
    }

    /// Run stateless detection only (no correlation), delegating to the inner engine.
    ///
    /// Takes `&self` so it can be called concurrently from multiple threads
    /// (e.g. via `rayon::par_iter`) while the mutable correlation phase runs
    /// sequentially afterwards.
    pub fn evaluate(&self, event: &impl Event) -> Vec<MatchResult> {
        self.engine.evaluate(event)
    }

    /// Process a batch of events: parallel detection, then sequential correlation.
    ///
    /// When the `parallel` feature is enabled, the stateless detection phase runs
    /// concurrently via rayon. Timestamp extraction also runs in the parallel
    /// phase (it borrows `&self.config` immutably). After `collect()` releases the
    /// immutable borrows, each event's pre-computed detections are fed into the
    /// stateful correlation engine sequentially.
    pub fn process_batch<E: Event + Sync>(&mut self, events: &[&E]) -> Vec<ProcessResult> {
        // Borrow split: take immutable refs to fields needed for the parallel phase.
        // These are released by collect() before the sequential &mut self phase.
        let engine = &self.engine;
        let ts_fields = &self.config.timestamp_fields;

        let batch_results: Vec<(Vec<MatchResult>, Option<i64>)> = {
            #[cfg(feature = "parallel")]
            {
                use rayon::prelude::*;
                events
                    .par_iter()
                    .map(|e| {
                        let detections = engine.evaluate(e);
                        let ts = extract_event_ts(e, ts_fields);
                        (detections, ts)
                    })
                    .collect()
            }
            #[cfg(not(feature = "parallel"))]
            {
                events
                    .iter()
                    .map(|e| {
                        let detections = engine.evaluate(e);
                        let ts = extract_event_ts(e, ts_fields);
                        (detections, ts)
                    })
                    .collect()
            }
        };

        // Sequential correlation phase
        let mut results = Vec::with_capacity(events.len());
        for ((detections, ts_opt), event) in batch_results.into_iter().zip(events) {
            match ts_opt {
                Some(ts) => {
                    results.push(self.process_with_detections(event, detections, ts));
                }
                None => match self.config.timestamp_fallback {
                    TimestampFallback::WallClock => {
                        let ts = Utc::now().timestamp();
                        results.push(self.process_with_detections(event, detections, ts));
                    }
                    TimestampFallback::Skip => {
                        // Still return detection results, but skip correlation
                        let detections = self.filter_detections(detections);
                        results.push(ProcessResult {
                            detections,
                            correlations: Vec::new(),
                        });
                    }
                },
            }
        }
        results
    }

    /// Filter detections by the `generate` flag / `emit_detections` config.
    ///
    /// If `emit_detections` is false and some rules are correlation-only,
    /// their detection output is suppressed.
    fn filter_detections(&self, all_detections: Vec<MatchResult>) -> Vec<MatchResult> {
        if !self.config.emit_detections && !self.correlation_only_rules.is_empty() {
            all_detections
                .into_iter()
                .filter(|m| {
                    let id_match = m
                        .rule_id
                        .as_ref()
                        .is_some_and(|id| self.correlation_only_rules.contains(id));
                    !id_match
                })
                .collect()
        } else {
            all_detections
        }
    }

    /// Feed detection matches into correlation window states.
    fn feed_detections(
        &mut self,
        event: &impl Event,
        detections: &[MatchResult],
        ts: i64,
        out: &mut Vec<CorrelationResult>,
    ) {
        // Collect all (corr_idx, rule_id, rule_name) tuples upfront to avoid
        // borrow conflicts between self.rule_ids and self.update_correlation.
        let mut work: Vec<(usize, Option<String>, Option<String>)> = Vec::new();

        for det in detections {
            // Use the MatchResult's rule_id to find the original rule's ID/name.
            // We also look up by rule_id in our rule_ids table for the name.
            let (rule_id, rule_name) = self.find_rule_identity(det);

            // Collect correlation indices that reference this rule
            let mut corr_indices = Vec::new();
            if let Some(ref id) = rule_id
                && let Some(indices) = self.rule_index.get(id)
            {
                corr_indices.extend(indices);
            }
            if let Some(ref name) = rule_name
                && let Some(indices) = self.rule_index.get(name)
            {
                corr_indices.extend(indices);
            }

            corr_indices.sort_unstable();
            corr_indices.dedup();

            for &corr_idx in &corr_indices {
                work.push((corr_idx, rule_id.clone(), rule_name.clone()));
            }
        }

        for (corr_idx, rule_id, rule_name) in work {
            self.update_correlation(corr_idx, event, ts, &rule_id, &rule_name, out);
        }
    }

    /// Find the (id, name) for a detection match by searching our rule_ids table.
    fn find_rule_identity(&self, det: &MatchResult) -> (Option<String>, Option<String>) {
        // First, try to find by matching rule_id in our table
        if let Some(ref match_id) = det.rule_id {
            for (id, name) in &self.rule_ids {
                if id.as_deref() == Some(match_id.as_str()) {
                    return (id.clone(), name.clone());
                }
            }
        }
        // Fall back to using just the MatchResult's rule_id
        (det.rule_id.clone(), None)
    }

    /// Resolve the event mode for a given correlation.
    fn resolve_event_mode(&self, corr_idx: usize) -> CorrelationEventMode {
        let corr = &self.correlations[corr_idx];
        corr.event_mode
            .unwrap_or(self.config.correlation_event_mode)
    }

    /// Resolve the max events cap for a given correlation.
    fn resolve_max_events(&self, corr_idx: usize) -> usize {
        let corr = &self.correlations[corr_idx];
        corr.max_events
            .unwrap_or(self.config.max_correlation_events)
    }

    /// Update a single correlation's state and check its condition.
    fn update_correlation(
        &mut self,
        corr_idx: usize,
        event: &impl Event,
        ts: i64,
        rule_id: &Option<String>,
        rule_name: &Option<String>,
        out: &mut Vec<CorrelationResult>,
    ) {
        // Borrow the correlation by reference — no cloning needed.  Rust allows
        // simultaneous &self.correlations and &mut self.state / &mut self.last_alert
        // because they are disjoint struct fields.
        let corr = &self.correlations[corr_idx];
        let corr_type = corr.correlation_type;
        let timespan = corr.timespan_secs;
        let level = corr.level;
        let suppress_secs = corr.suppress_secs.or(self.config.suppress);
        let action = corr.action.unwrap_or(self.config.action_on_match);
        let event_mode = self.resolve_event_mode(corr_idx);
        let max_events = self.resolve_max_events(corr_idx);

        // Determine the rule_ref strings for alias resolution and temporal tracking.
        let mut ref_strs: Vec<&str> = Vec::new();
        if let Some(id) = rule_id.as_deref() {
            ref_strs.push(id);
        }
        if let Some(name) = rule_name.as_deref() {
            ref_strs.push(name);
        }
        let rule_ref = rule_id.as_deref().or(rule_name.as_deref()).unwrap_or("");

        // Extract group key
        let group_key = GroupKey::extract(event, &corr.group_by, &ref_strs);

        // Get or create window state
        let state_key = (corr_idx, group_key.clone());
        let state = self
            .state
            .entry(state_key.clone())
            .or_insert_with(|| WindowState::new_for(corr_type));

        // Evict expired entries
        let cutoff = ts - timespan as i64;
        state.evict(cutoff);

        // Push the new event into the state
        match corr_type {
            CorrelationType::EventCount => {
                state.push_event_count(ts);
            }
            CorrelationType::ValueCount => {
                if let Some(ref fields) = corr.condition.field
                    && let Some(field_name) = fields.first()
                    && let Some(val) = event.get_field(field_name)
                    && let Some(s) = value_to_string_for_count(&val)
                {
                    state.push_value_count(ts, s);
                }
            }
            CorrelationType::Temporal | CorrelationType::TemporalOrdered => {
                state.push_temporal(ts, rule_ref);
            }
            CorrelationType::ValueSum
            | CorrelationType::ValueAvg
            | CorrelationType::ValuePercentile
            | CorrelationType::ValueMedian => {
                if let Some(ref fields) = corr.condition.field
                    && let Some(field_name) = fields.first()
                    && let Some(val) = event.get_field(field_name)
                    && let Some(n) = value_to_f64_ev(&val)
                {
                    state.push_numeric(ts, n);
                }
            }
        }

        // Push event into buffer based on event mode
        match event_mode {
            CorrelationEventMode::Full => {
                let buf = self
                    .event_buffers
                    .entry(state_key.clone())
                    .or_insert_with(|| EventBuffer::new(max_events));
                buf.evict(cutoff);
                let json = event.to_json();
                buf.push(ts, &json);
            }
            CorrelationEventMode::Refs => {
                let buf = self
                    .event_ref_buffers
                    .entry(state_key.clone())
                    .or_insert_with(|| EventRefBuffer::new(max_events));
                buf.evict(cutoff);
                let json = event.to_json();
                buf.push(ts, &json);
            }
            CorrelationEventMode::None => {}
        }

        // Check condition — after this, `state` is no longer used (NLL drops the borrow).
        let fired = state.check_condition(
            &corr.condition,
            corr_type,
            &corr.rule_refs,
            corr.extended_expr.as_ref(),
        );

        if let Some(agg_value) = fired {
            let alert_key = (corr_idx, group_key.clone());

            // Suppression check: skip if we've already alerted within the suppress window
            let suppressed = if let Some(suppress) = suppress_secs {
                if let Some(&last_ts) = self.last_alert.get(&alert_key) {
                    (ts - last_ts) < suppress as i64
                } else {
                    false
                }
            } else {
                false
            };

            if !suppressed {
                // Retrieve stored events / refs based on mode
                let (events, event_refs) = match event_mode {
                    CorrelationEventMode::Full => {
                        let stored = self
                            .event_buffers
                            .get(&alert_key)
                            .map(|buf| buf.decompress_all())
                            .unwrap_or_default();
                        (Some(stored), None)
                    }
                    CorrelationEventMode::Refs => {
                        let stored = self
                            .event_ref_buffers
                            .get(&alert_key)
                            .map(|buf| buf.refs())
                            .unwrap_or_default();
                        (None, Some(stored))
                    }
                    CorrelationEventMode::None => (None, None),
                };

                // Only clone title/id/tags when we actually produce output
                let corr = &self.correlations[corr_idx];
                let result = CorrelationResult {
                    rule_title: corr.title.clone(),
                    rule_id: corr.id.clone(),
                    level,
                    tags: corr.tags.clone(),
                    correlation_type: corr_type,
                    group_key: group_key.to_pairs(&corr.group_by),
                    aggregated_value: agg_value,
                    timespan_secs: timespan,
                    events,
                    event_refs,
                    custom_attributes: corr.custom_attributes.clone(),
                };
                out.push(result);

                // Record alert time for suppression
                self.last_alert.insert(alert_key.clone(), ts);

                // Action on match
                if action == CorrelationAction::Reset {
                    if let Some(state) = self.state.get_mut(&alert_key) {
                        state.clear();
                    }
                    if let Some(buf) = self.event_buffers.get_mut(&alert_key) {
                        buf.clear();
                    }
                    if let Some(buf) = self.event_ref_buffers.get_mut(&alert_key) {
                        buf.clear();
                    }
                }
            }
        }
    }

    /// Propagate correlation results to higher-level correlations (chaining).
    ///
    /// When a correlation fires, any correlation that references it (by ID or name)
    /// is updated. Limits chain depth to 10 to prevent infinite loops.
    fn chain_correlations(&mut self, fired: &[CorrelationResult], ts: i64) {
        const MAX_CHAIN_DEPTH: usize = 10;
        let mut pending: Vec<CorrelationResult> = fired.to_vec();
        let mut depth = 0;

        while !pending.is_empty() && depth < MAX_CHAIN_DEPTH {
            depth += 1;

            // Collect work items: (corr_idx, group_key_pairs, fired_ref)
            #[allow(clippy::type_complexity)]
            let mut work: Vec<(usize, Vec<(String, String)>, String)> = Vec::new();
            for result in &pending {
                if let Some(ref id) = result.rule_id
                    && let Some(indices) = self.rule_index.get(id)
                {
                    let fired_ref = result
                        .rule_id
                        .as_deref()
                        .unwrap_or(&result.rule_title)
                        .to_string();
                    for &corr_idx in indices {
                        work.push((corr_idx, result.group_key.clone(), fired_ref.clone()));
                    }
                }
            }

            let mut next_pending = Vec::new();
            for (corr_idx, group_key_pairs, fired_ref) in work {
                let corr = &self.correlations[corr_idx];
                let corr_type = corr.correlation_type;
                let timespan = corr.timespan_secs;
                let level = corr.level;

                let group_key = GroupKey::from_pairs(&group_key_pairs, &corr.group_by);
                let state_key = (corr_idx, group_key.clone());
                let state = self
                    .state
                    .entry(state_key)
                    .or_insert_with(|| WindowState::new_for(corr_type));

                let cutoff = ts - timespan as i64;
                state.evict(cutoff);

                match corr_type {
                    CorrelationType::EventCount => {
                        state.push_event_count(ts);
                    }
                    CorrelationType::Temporal | CorrelationType::TemporalOrdered => {
                        state.push_temporal(ts, &fired_ref);
                    }
                    _ => {
                        state.push_event_count(ts);
                    }
                }

                let fired = state.check_condition(
                    &corr.condition,
                    corr_type,
                    &corr.rule_refs,
                    corr.extended_expr.as_ref(),
                );

                if let Some(agg_value) = fired {
                    let corr = &self.correlations[corr_idx];
                    next_pending.push(CorrelationResult {
                        rule_title: corr.title.clone(),
                        rule_id: corr.id.clone(),
                        level,
                        tags: corr.tags.clone(),
                        correlation_type: corr_type,
                        group_key: group_key.to_pairs(&corr.group_by),
                        aggregated_value: agg_value,
                        timespan_secs: timespan,
                        // Chained correlations don't include events (they aggregate
                        // over correlation results, not raw events)
                        events: None,
                        event_refs: None,
                        custom_attributes: corr.custom_attributes.clone(),
                    });
                }
            }

            pending = next_pending;
        }

        if !pending.is_empty() {
            log::warn!(
                "Correlation chain depth limit reached ({MAX_CHAIN_DEPTH}); \
                 {} pending result(s) were not propagated further. \
                 This may indicate a cycle in correlation references.",
                pending.len()
            );
        }
    }

    // =========================================================================
    // Timestamp extraction
    // =========================================================================

    /// Extract a Unix epoch timestamp (seconds) from an event.
    ///
    /// Tries each configured timestamp field in order. Supports:
    /// - Numeric values (epoch seconds, or epoch millis if > 1e12)
    /// - ISO 8601 strings (e.g., "2024-07-10T12:30:00Z")
    ///
    /// Returns `None` if no field yields a valid timestamp.
    fn extract_event_timestamp(&self, event: &impl Event) -> Option<i64> {
        for field_name in &self.config.timestamp_fields {
            if let Some(val) = event.get_field(field_name)
                && let Some(ts) = parse_timestamp_value(&val)
            {
                return Some(ts);
            }
        }
        None
    }

    // =========================================================================
    // State management
    // =========================================================================

    /// Manually evict all expired state entries.
    pub fn evict_expired(&mut self, now_secs: i64) {
        self.evict_all(now_secs);
    }

    /// Evict expired entries and remove empty states.
    fn evict_all(&mut self, now_secs: i64) {
        // Phase 1: Time-based eviction — remove entries outside their correlation window
        let timespans: Vec<u64> = self.correlations.iter().map(|c| c.timespan_secs).collect();

        self.state.retain(|&(corr_idx, _), state| {
            if corr_idx < timespans.len() {
                let cutoff = now_secs - timespans[corr_idx] as i64;
                state.evict(cutoff);
            }
            !state.is_empty()
        });

        // Evict event buffers in sync with window state
        self.event_buffers.retain(|&(corr_idx, _), buf| {
            if corr_idx < timespans.len() {
                let cutoff = now_secs - timespans[corr_idx] as i64;
                buf.evict(cutoff);
            }
            !buf.is_empty()
        });
        self.event_ref_buffers.retain(|&(corr_idx, _), buf| {
            if corr_idx < timespans.len() {
                let cutoff = now_secs - timespans[corr_idx] as i64;
                buf.evict(cutoff);
            }
            !buf.is_empty()
        });

        // Phase 2: Hard cap — if still over limit after time-based eviction (e.g.
        // high-cardinality traffic with long windows), drop the stalest entries
        // until we're at 90% capacity to avoid evicting on every single event.
        if self.state.len() >= self.config.max_state_entries {
            let target = self.config.max_state_entries * 9 / 10;
            let excess = self.state.len() - target;

            // Collect keys with their latest timestamp, sort by oldest first
            let mut by_staleness: Vec<_> = self
                .state
                .iter()
                .map(|(k, v)| (k.clone(), v.latest_timestamp().unwrap_or(i64::MIN)))
                .collect();
            by_staleness.sort_unstable_by_key(|&(_, ts)| ts);

            // Drop the oldest entries (and their associated event buffers)
            for (key, _) in by_staleness.into_iter().take(excess) {
                self.state.remove(&key);
                self.last_alert.remove(&key);
                self.event_buffers.remove(&key);
                self.event_ref_buffers.remove(&key);
            }
        }

        // Phase 3: Evict stale last_alert entries — remove if the suppress window
        // has passed or if the corresponding window state no longer exists.
        self.last_alert.retain(|key, &mut alert_ts| {
            let suppress = if key.0 < self.correlations.len() {
                self.correlations[key.0]
                    .suppress_secs
                    .or(self.config.suppress)
                    .unwrap_or(0)
            } else {
                0
            };
            (now_secs - alert_ts) < suppress as i64
        });
    }

    /// Number of active state entries (for monitoring).
    pub fn state_count(&self) -> usize {
        self.state.len()
    }

    /// Number of detection rules loaded.
    pub fn detection_rule_count(&self) -> usize {
        self.engine.rule_count()
    }

    /// Number of correlation rules loaded.
    pub fn correlation_rule_count(&self) -> usize {
        self.correlations.len()
    }

    /// Number of active event buffers (for monitoring).
    pub fn event_buffer_count(&self) -> usize {
        self.event_buffers.len()
    }

    /// Total compressed bytes across all event buffers (for monitoring).
    pub fn event_buffer_bytes(&self) -> usize {
        self.event_buffers
            .values()
            .map(|b| b.compressed_bytes())
            .sum()
    }

    /// Number of active event ref buffers — `Refs` mode (for monitoring).
    pub fn event_ref_buffer_count(&self) -> usize {
        self.event_ref_buffers.len()
    }

    /// Access the inner stateless engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Export all mutable correlation state as a serializable snapshot.
    ///
    /// The snapshot uses stable correlation identifiers (id > name > title)
    /// instead of internal indices, so it survives rule reloads as long as
    /// the correlation rules keep the same identifiers.
    pub fn export_state(&self) -> CorrelationSnapshot {
        let mut windows: HashMap<String, Vec<(GroupKey, WindowState)>> = HashMap::new();
        for ((idx, gk), ws) in &self.state {
            let corr_id = self.correlation_stable_id(*idx);
            windows
                .entry(corr_id)
                .or_default()
                .push((gk.clone(), ws.clone()));
        }

        let mut last_alert: HashMap<String, Vec<(GroupKey, i64)>> = HashMap::new();
        for ((idx, gk), ts) in &self.last_alert {
            let corr_id = self.correlation_stable_id(*idx);
            last_alert
                .entry(corr_id)
                .or_default()
                .push((gk.clone(), *ts));
        }

        let mut event_buffers: HashMap<String, Vec<(GroupKey, EventBuffer)>> = HashMap::new();
        for ((idx, gk), buf) in &self.event_buffers {
            let corr_id = self.correlation_stable_id(*idx);
            event_buffers
                .entry(corr_id)
                .or_default()
                .push((gk.clone(), buf.clone()));
        }

        let mut event_ref_buffers: HashMap<String, Vec<(GroupKey, EventRefBuffer)>> =
            HashMap::new();
        for ((idx, gk), buf) in &self.event_ref_buffers {
            let corr_id = self.correlation_stable_id(*idx);
            event_ref_buffers
                .entry(corr_id)
                .or_default()
                .push((gk.clone(), buf.clone()));
        }

        CorrelationSnapshot {
            version: SNAPSHOT_VERSION,
            windows,
            last_alert,
            event_buffers,
            event_ref_buffers,
        }
    }

    /// Import previously exported state, mapping stable identifiers back to
    /// current correlation indices. Entries whose identifiers no longer match
    /// any loaded correlation are silently dropped.
    ///
    /// Returns `false` (and imports nothing) if the snapshot version is
    /// incompatible with the current schema.
    pub fn import_state(&mut self, snapshot: CorrelationSnapshot) -> bool {
        if snapshot.version != SNAPSHOT_VERSION {
            return false;
        }
        let id_to_idx = self.build_id_to_index_map();

        for (corr_id, groups) in snapshot.windows {
            if let Some(&idx) = id_to_idx.get(&corr_id) {
                for (gk, ws) in groups {
                    self.state.insert((idx, gk), ws);
                }
            }
        }

        for (corr_id, groups) in snapshot.last_alert {
            if let Some(&idx) = id_to_idx.get(&corr_id) {
                for (gk, ts) in groups {
                    self.last_alert.insert((idx, gk), ts);
                }
            }
        }

        for (corr_id, groups) in snapshot.event_buffers {
            if let Some(&idx) = id_to_idx.get(&corr_id) {
                for (gk, buf) in groups {
                    self.event_buffers.insert((idx, gk), buf);
                }
            }
        }

        for (corr_id, groups) in snapshot.event_ref_buffers {
            if let Some(&idx) = id_to_idx.get(&corr_id) {
                for (gk, buf) in groups {
                    self.event_ref_buffers.insert((idx, gk), buf);
                }
            }
        }

        true
    }

    /// Stable identifier for a correlation rule: prefers id, then name, then title.
    fn correlation_stable_id(&self, idx: usize) -> String {
        let corr = &self.correlations[idx];
        corr.id
            .clone()
            .or_else(|| corr.name.clone())
            .unwrap_or_else(|| corr.title.clone())
    }

    /// Build a reverse map from stable id → current correlation index.
    fn build_id_to_index_map(&self) -> HashMap<String, usize> {
        self.correlations
            .iter()
            .enumerate()
            .map(|(idx, _)| (self.correlation_stable_id(idx), idx))
            .collect()
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new(CorrelationConfig::default())
    }
}

// =============================================================================
// Timestamp parsing helpers
// =============================================================================

/// Extract a timestamp from an event using the given field names.
///
/// Standalone version of `CorrelationEngine::extract_event_timestamp` for use
/// in contexts where borrowing `&self` is not possible (e.g. rayon closures).
fn extract_event_ts(event: &impl Event, timestamp_fields: &[String]) -> Option<i64> {
    for field_name in timestamp_fields {
        if let Some(val) = event.get_field(field_name)
            && let Some(ts) = parse_timestamp_value(&val)
        {
            return Some(ts);
        }
    }
    None
}

/// Parse an [`EventValue`] as a Unix epoch timestamp in seconds.
fn parse_timestamp_value(val: &EventValue) -> Option<i64> {
    match val {
        EventValue::Int(i) => Some(normalize_epoch(*i)),
        EventValue::Float(f) => Some(normalize_epoch(*f as i64)),
        EventValue::Str(s) => parse_timestamp_string(s),
        _ => None,
    }
}

/// Normalize an epoch value: if it looks like milliseconds (> year 33658),
/// convert to seconds.
fn normalize_epoch(v: i64) -> i64 {
    if v > 1_000_000_000_000 { v / 1000 } else { v }
}

/// Parse a timestamp string. Tries ISO 8601 with timezone, then without.
fn parse_timestamp_string(s: &str) -> Option<i64> {
    // Try RFC 3339 / ISO 8601 with timezone
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp());
    }

    // Try ISO 8601 without timezone (assume UTC)
    // Common formats: "2024-07-10T12:30:00", "2024-07-10 12:30:00"
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(Utc.from_utc_datetime(&naive).timestamp());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(Utc.from_utc_datetime(&naive).timestamp());
    }

    // Try with fractional seconds
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(Utc.from_utc_datetime(&naive).timestamp());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
        return Some(Utc.from_utc_datetime(&naive).timestamp());
    }

    None
}

/// Convert an [`EventValue`] to a string for value_count purposes.
fn value_to_string_for_count(v: &EventValue) -> Option<String> {
    match v {
        EventValue::Str(s) => Some(s.to_string()),
        EventValue::Int(n) => Some(n.to_string()),
        EventValue::Float(f) => Some(f.to_string()),
        EventValue::Bool(b) => Some(b.to_string()),
        EventValue::Null => Some("null".to_string()),
        _ => None,
    }
}

/// Convert an [`EventValue`] to f64 for numeric aggregation.
fn value_to_f64_ev(v: &EventValue) -> Option<f64> {
    v.as_f64()
}
