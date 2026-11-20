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

mod introspect;
#[cfg(test)]
mod tests;
mod types;

pub use introspect::{CorrelationInfo, CorrelationStateSnapshot, GroupKeyPart, GroupStateInfo};
pub use types::*;

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::Utc;

use rsigma_parser::{CorrelationRule, CorrelationType, SigmaCollection, SigmaRule, WindowMode};

use crate::correlation::{
    CompiledCorrelation, EventBuffer, EventRefBuffer, GroupKey, WindowDecision, WindowState,
    apply_window_open, compile_correlation,
};
use crate::engine::{Engine, IdentifiedEvaluation};
use crate::error::{EvalError, Result};
use crate::event::{Event, EventValue};
use crate::logsource::{ExtractLogSource, LogSourceExtractor};
use crate::pipeline::{Pipeline, apply_pipelines, apply_pipelines_to_correlation};
use crate::result::{CorrelationBody, EvaluationResult, ResultBody, RuleHeader};
use crate::rule_metadata::{RuleBundleMetadata, RuleMetadataLookup};
use crate::tenant::TenantId;
use crate::timestamp::{epoch_seconds_from_float, epoch_seconds_from_int, parse_timestamp_str};

type RuleIdentity = (Option<String>, Option<String>);

// =============================================================================
// Correlation Engine
// =============================================================================

/// Current snapshot schema version. Bump when the serialized format changes.
pub(crate) const SNAPSHOT_VERSION: u32 = 2;

/// Parent hops evaluated after a first-level correlation fire in one event.
/// The first-level result is produced by `feed_detections`; each loop
/// iteration here walks one parent. A chain longer than this is updated
/// and emitted through this many hops, then leftover parents are dropped
/// with a `WARN`.
const MAX_CHAIN_DEPTH: usize = 10;

/// Timespan above which a correlation without a per-group entry cap is
/// warned about at load: a busy group's window retains `timespan` x event
/// rate entries, which `max_state_entries` does not see.
const LONG_WINDOW_WARN_SECS: u64 = 3600;

/// Stateful correlation engine.
///
/// Wraps the stateless `Engine` for detection rules and adds time-windowed
/// correlation on top. Supports all 7 Sigma correlation types and chaining.
///
/// Generic over the inner engine's logsource extractor `L`, which defaults to
/// [`LogSourceExtractor`] (see [`Engine`]).
pub struct CorrelationEngine<L = LogSourceExtractor> {
    /// Inner stateless detection engine.
    engine: Engine<L>,
    /// Compiled correlation rules.
    correlations: Vec<CompiledCorrelation>,
    /// Maps rule ID/name -> indices into `correlations` that reference it.
    /// This allows quick lookup: "which correlations care about rule X?"
    rule_index: HashMap<String, Vec<usize>>,
    /// Maps detection rule index -> (rule_id, rule_name, rule_title) for reverse lookup.
    /// Used to find which correlations a detection match triggers.
    rule_ids: Vec<(Option<String>, Option<String>, String)>,
    /// Per-(tenant, correlation_index, group_key) window state.
    state: HashMap<StateKey, WindowState>,
    /// Last alert timestamp per (tenant, correlation_index, group_key) for suppression.
    last_alert: HashMap<StateKey, i64>,
    /// Per-(tenant, correlation_index, group_key) compressed event buffer (`Full` mode).
    event_buffers: HashMap<StateKey, EventBuffer>,
    /// Per-(tenant, correlation_index, group_key) event reference buffer (`Refs` mode).
    event_ref_buffers: HashMap<StateKey, EventRefBuffer>,
    /// Set of rule IDs/names (detections or correlations) that are
    /// "correlation-only" (referenced by correlations where `generate == false`).
    /// Used to filter their output when `config.emit_detections == false`.
    correlation_only_rules: std::collections::HashSet<String>,
    /// Rules referenced by at least one correlation with `generate: true`.
    /// Such a reference wins over correlation-only references.
    generated_rules: std::collections::HashSet<String>,
    /// Configuration.
    config: CorrelationConfig,
    /// Processing pipelines applied to rules during add_rule.
    pipelines: Vec<Pipeline>,
    /// Events skipped by `require_tenant` because they carried no tenant.
    untenanted_skipped: u64,
    /// Live state keys per tenant, kept in step with `state` while a
    /// per-tenant cap is set, so quota checks and eviction touch only that
    /// tenant's entries. Empty when there is no per-tenant cap.
    tenant_keys: HashMap<Option<TenantId>, HashSet<StateKey>>,
    /// Entries evicted because a tenant hit its quota.
    tenant_quota_evictions: u64,
}

impl CorrelationEngine {
    /// Create a new correlation engine with the given configuration.
    pub fn new(config: CorrelationConfig) -> Self {
        Self::with_engine(config, Engine::new())
    }
}

impl<L> CorrelationEngine<L> {
    /// Create a new correlation engine whose inner detection engine prunes
    /// with `extractor`, a custom [`ExtractLogSource`] implementation.
    pub fn with_logsource_extractor(config: CorrelationConfig, extractor: L) -> Self {
        Self::with_engine(config, Engine::with_logsource_extractor(extractor))
    }

    fn with_engine(config: CorrelationConfig, engine: Engine<L>) -> Self {
        CorrelationEngine {
            engine,
            correlations: Vec::new(),
            rule_index: HashMap::new(),
            rule_ids: Vec::new(),
            state: HashMap::new(),
            last_alert: HashMap::new(),
            event_buffers: HashMap::new(),
            event_ref_buffers: HashMap::new(),
            correlation_only_rules: std::collections::HashSet::new(),
            generated_rules: std::collections::HashSet::new(),
            config,
            pipelines: Vec::new(),
            untenanted_skipped: 0,
            tenant_keys: HashMap::new(),
            tenant_quota_evictions: 0,
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

    /// Forward to [`crate::Engine::set_match_detail`] on the inner detection
    /// engine. Correlation detections inherit the level set here.
    pub fn set_match_detail(&mut self, level: crate::result::MatchDetailLevel) {
        self.engine.set_match_detail(level);
    }

    /// Forward to [`crate::Engine::set_bloom_prefilter`] on the inner
    /// detection engine. Off by default; the optimization helps only on
    /// substring-heavy rule sets paired with mostly-non-matching events.
    pub fn set_bloom_prefilter(&mut self, enabled: bool) {
        self.engine.set_bloom_prefilter(enabled);
    }

    /// Forward to [`crate::Engine::set_logsource_extractor`] on the inner
    /// detection engine. Correlation inherits logsource pruning, since
    /// `process_event` evaluates through this engine.
    pub fn set_logsource_extractor(&mut self, extractor: Option<L>) {
        self.engine.set_logsource_extractor(extractor);
    }

    /// Total rule candidates pruned by logsource on the inner engine.
    pub fn logsource_pruned_total(&self) -> u64 {
        self.engine.logsource_pruned_total()
    }

    /// Total evaluate calls with no extractable event logsource (fail-open).
    pub fn logsource_absent_total(&self) -> u64 {
        self.engine.logsource_absent_total()
    }

    /// Forward to [`crate::Engine::set_bloom_max_bytes`] on the inner
    /// detection engine.
    pub fn set_bloom_max_bytes(&mut self, max_bytes: usize) {
        self.engine.set_bloom_max_bytes(max_bytes);
    }

    /// Forward to [`crate::Engine::set_cross_rule_ac`] on the inner
    /// detection engine. Off by default. Available behind the
    /// `daachorse-index` Cargo feature.
    #[cfg(feature = "daachorse-index")]
    pub fn set_cross_rule_ac(&mut self, enabled: bool) {
        self.engine.set_cross_rule_ac(enabled);
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
            self.rule_ids
                .push((rule.id.clone(), rule.name.clone(), rule.title.clone()));
            self.engine.add_rule(rule)?;
        } else {
            let mut transformed = rule.clone();
            apply_pipelines(&self.pipelines, &mut transformed)?;
            self.apply_custom_attributes(&transformed.custom_attributes);
            self.rule_ids.push((
                transformed.id.clone(),
                transformed.name.clone(),
                transformed.title.clone(),
            ));
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
        attrs: &std::collections::HashMap<String, yaml_serde::Value>,
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
        if self.has_unbounded_long_window(&compiled) {
            log::warn!(
                "Correlation '{}' has a {}s timespan and no per-group entry cap; \
                 a busy group retains timespan x event rate entries. \
                 Set max_group_entries (--max-group-entries) or the rsigma.max_group_entries attribute to bound it.",
                compiled.id.as_deref().unwrap_or(&compiled.title),
                compiled.timespan_secs
            );
        }
        let idx = self.correlations.len();

        // Index by each referenced rule ID/name
        for rule_ref in &compiled.rule_refs {
            self.rule_index
                .entry(rule_ref.clone())
                .or_default()
                .push(idx);
        }

        // A rule is standalone when any referencing correlation requests it,
        // regardless of the order in which correlations are loaded.
        for rule_ref in &compiled.rule_refs {
            if compiled.generate {
                self.generated_rules.insert(rule_ref.clone());
                self.correlation_only_rules.remove(rule_ref);
            } else if !self.generated_rules.contains(rule_ref) {
                self.correlation_only_rules.insert(rule_ref.clone());
            }
        }

        self.correlations.push(compiled);
        Ok(())
    }

    /// Whether `corr` keeps a window longer than [`LONG_WINDOW_WARN_SECS`]
    /// with no per-group entry cap from the rule or the engine config.
    fn has_unbounded_long_window(&self, corr: &CompiledCorrelation) -> bool {
        corr.timespan_secs > LONG_WINDOW_WARN_SECS
            && corr
                .max_group_entries
                .or(self.config.max_group_entries)
                .is_none()
    }

    /// Add all rules and correlations from a parsed collection.
    ///
    /// Detection rules are added first (so they're available for correlation
    /// references), then correlation rules. Detection rules are compiled
    /// sequentially and then pushed to the inner engine in a single batch,
    /// so the inverted index and bloom filter are rebuilt exactly once for
    /// the whole collection. Without this batching, large rule sets
    /// (multi-thousand rules) hit an O(N²) rebuild cost on load.
    pub fn add_collection(&mut self, collection: &SigmaCollection) -> Result<()> {
        let mut compiled_batch = Vec::with_capacity(collection.rules.len());
        if self.pipelines.is_empty() {
            for rule in &collection.rules {
                self.apply_custom_attributes(&rule.custom_attributes);
                self.rule_ids
                    .push((rule.id.clone(), rule.name.clone(), rule.title.clone()));
                compiled_batch.push(crate::compiler::compile_rule(rule)?);
            }
        } else {
            for rule in &collection.rules {
                let mut transformed = rule.clone();
                apply_pipelines(&self.pipelines, &mut transformed)?;
                self.apply_custom_attributes(&transformed.custom_attributes);
                self.rule_ids.push((
                    transformed.id.clone(),
                    transformed.name.clone(),
                    transformed.title.clone(),
                ));
                // Bypass the inner engine's pipelines (would double-transform)
                compiled_batch.push(crate::compiler::compile_rule(&transformed)?);
            }
        }
        self.engine.extend_compiled_rules(compiled_batch);
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

        for (id, name, _) in &self.rule_ids {
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
    pub fn process_event<E: Event>(&mut self, event: &E) -> ProcessResult
    where
        L: ExtractLogSource<E>,
    {
        self.process_event_for_tenant(event, None)
    }

    /// Process an event as `tenant`, extracting the timestamp from configured
    /// event fields.
    ///
    /// The tenant keys every window this event touches; correlation results
    /// carry it. `None` is the untenanted bucket used when tenancy is off.
    pub fn process_event_for_tenant<E: Event>(
        &mut self,
        event: &E,
        tenant: Option<&TenantId>,
    ) -> ProcessResult
    where
        L: ExtractLogSource<E>,
    {
        let detections = self.engine.evaluate_identified(event);
        self.correlate_identified_detections_for_tenant(event, detections, tenant)
    }

    /// Run the correlation layer over externally-produced detections.
    ///
    /// Like [`process_event`](Self::process_event) but the detections are
    /// supplied by the caller instead of computed by this engine's inner
    /// detection engine. This lets a multi-engine router run detection in a
    /// per-schema engine and still feed every detection into one shared
    /// correlation store. Timestamp extraction and the `timestamp_fallback`
    /// policy match `process_event`. Rule identity is recovered as in
    /// [`process_with_detections`](Self::process_with_detections).
    pub fn correlate_detections(
        &mut self,
        event: &impl Event,
        all_detections: Vec<EvaluationResult>,
    ) -> ProcessResult {
        self.correlate_detections_for_tenant(event, all_detections, None)
    }

    /// Like [`correlate_detections`](Self::correlate_detections) but as
    /// `tenant`.
    pub fn correlate_detections_for_tenant(
        &mut self,
        event: &impl Event,
        all_detections: Vec<EvaluationResult>,
        tenant: Option<&TenantId>,
    ) -> ProcessResult {
        let identities = all_detections
            .iter()
            .map(|detection| self.find_rule_identity(detection))
            .collect();
        self.correlate_with_identities(event, all_detections, identities, tenant)
    }

    /// Run the correlation layer over detections identified by this engine's
    /// rule table, keying every window by `tenant`.
    pub(crate) fn correlate_identified_detections_for_tenant(
        &mut self,
        event: &impl Event,
        detections: Vec<IdentifiedEvaluation>,
        tenant: Option<&TenantId>,
    ) -> ProcessResult {
        let (all_detections, identities) = split_identified(detections);
        self.correlate_with_identities(event, all_detections, identities, tenant)
    }

    fn correlate_with_identities(
        &mut self,
        event: &impl Event,
        all_detections: Vec<EvaluationResult>,
        identities: Vec<RuleIdentity>,
        tenant: Option<&TenantId>,
    ) -> ProcessResult {
        let ts = match self.extract_event_timestamp(event) {
            Some(ts) => ts,
            None => match self.config.timestamp_fallback {
                TimestampFallback::WallClock => Utc::now().timestamp(),
                TimestampFallback::Skip => {
                    // Still surface detections, but skip correlation state.
                    return self.filter_detections(all_detections, identities);
                }
            },
        };
        self.process_with_detection_identities(event, all_detections, identities, ts, tenant)
    }

    /// Process an event with an explicit Unix epoch timestamp (seconds).
    ///
    /// The timestamp is clamped to `[0, i64::MAX / 2]` to prevent overflow
    /// when adding timespan durations internally.
    pub fn process_event_at<E: Event>(&mut self, event: &E, timestamp_secs: i64) -> ProcessResult
    where
        L: ExtractLogSource<E>,
    {
        self.process_event_at_for_tenant(event, timestamp_secs, None)
    }

    /// Like [`process_event_at`](Self::process_event_at) but as `tenant`.
    pub fn process_event_at_for_tenant<E: Event>(
        &mut self,
        event: &E,
        timestamp_secs: i64,
        tenant: Option<&TenantId>,
    ) -> ProcessResult
    where
        L: ExtractLogSource<E>,
    {
        let detections = self.engine.evaluate_identified(event);
        let (all_detections, identities) = split_identified(detections);
        self.process_with_detection_identities(
            event,
            all_detections,
            identities,
            timestamp_secs,
            tenant,
        )
    }

    /// Process an event with pre-computed detection results.
    ///
    /// Enables external parallelism: callers can run detection (via
    /// [`evaluate`](Self::evaluate)) in parallel, then feed results here
    /// sequentially for stateful correlation.
    ///
    /// A result carries its rule's `id` but not its `name`, so a detection
    /// from a rule without an `id` is matched to its rule by title and feeds
    /// no correlation when several such rules share that title.
    /// [`process_event_at`](Self::process_event_at) and
    /// [`process_batch`](Self::process_batch) keep the compiled identity.
    pub fn process_with_detections(
        &mut self,
        event: &impl Event,
        all_detections: Vec<EvaluationResult>,
        timestamp_secs: i64,
    ) -> ProcessResult {
        self.process_with_detections_for_tenant(event, all_detections, timestamp_secs, None)
    }

    /// Like [`process_with_detections`](Self::process_with_detections) but as
    /// `tenant`.
    pub fn process_with_detections_for_tenant(
        &mut self,
        event: &impl Event,
        all_detections: Vec<EvaluationResult>,
        timestamp_secs: i64,
        tenant: Option<&TenantId>,
    ) -> ProcessResult {
        let identities = all_detections
            .iter()
            .map(|detection| self.find_rule_identity(detection))
            .collect();
        self.process_with_detection_identities(
            event,
            all_detections,
            identities,
            timestamp_secs,
            tenant,
        )
    }

    fn process_with_detection_identities(
        &mut self,
        event: &impl Event,
        all_detections: Vec<EvaluationResult>,
        identities: Vec<RuleIdentity>,
        timestamp_secs: i64,
        tenant: Option<&TenantId>,
    ) -> ProcessResult {
        let timestamp_secs = timestamp_secs.clamp(0, i64::MAX / 2);

        // A shared `None` bucket is never allowed when tenancy is required:
        // skip the event's correlation update and count it.
        if self.config.require_tenant && tenant.is_none() {
            self.untenanted_skipped += 1;
            return self.filter_detections(all_detections, identities);
        }

        // Memory management — evict before adding new state to enforce limit
        if self.state.len() >= self.config.max_state_entries {
            self.evict_all(timestamp_secs);
        }

        // Feed detection matches into correlations
        let mut correlations: Vec<EvaluationResult> = Vec::new();
        let mut fired_indices = Vec::new();
        self.feed_detections(
            event,
            &identities,
            timestamp_secs,
            tenant,
            &mut correlations,
            &mut fired_indices,
        );

        // Chain — parent firings go into a separate vec so we do not
        // alias `correlations` as both the input slice and the output.
        let mut chained = Vec::new();
        let mut chained_indices = Vec::new();
        self.chain_correlations(
            &correlations,
            &fired_indices,
            timestamp_secs,
            &mut chained,
            &mut chained_indices,
        );
        correlations.extend(chained);
        fired_indices.extend(chained_indices);

        // Filter detections and correlations by the generate flag of the
        // correlations that reference them.
        let mut out = self.filter_detections(all_detections, identities);
        out.extend(
            correlations
                .into_iter()
                .zip(fired_indices)
                .filter(|(_, idx)| {
                    let corr = &self.correlations[*idx];
                    let identities = corr.id.as_deref().into_iter().chain(corr.name.as_deref());
                    !self.is_correlation_only(identities)
                })
                .map(|(result, _)| result),
        );
        out
    }

    /// Number of events skipped by `require_tenant` because they carried no
    /// tenant.
    pub fn untenanted_skipped(&self) -> u64 {
        self.untenanted_skipped
    }

    /// Events skipped by `require_tenant` since the previous call, draining the
    /// counter.
    pub fn take_untenanted_skipped(&mut self) -> u64 {
        std::mem::take(&mut self.untenanted_skipped)
    }

    /// Set the per-tenant state cap. `None` leaves only the global cap.
    pub fn set_max_state_entries_per_tenant(&mut self, max: Option<usize>) {
        self.config.max_state_entries_per_tenant = max;
        self.tenant_keys.clear();
        if max.is_some() {
            for key in self.state.keys() {
                self.tenant_keys
                    .entry(key.tenant.clone())
                    .or_default()
                    .insert(key.clone());
            }
        }
    }

    /// Entries evicted because a tenant hit its quota since the previous call,
    /// draining the counter.
    pub fn take_tenant_quota_evictions(&mut self) -> u64 {
        std::mem::take(&mut self.tenant_quota_evictions)
    }

    /// Run stateless detection only (no correlation), delegating to the inner engine.
    ///
    /// Returns one [`EvaluationResult`] per matched detection. Takes `&self`
    /// so it can be called concurrently from multiple threads (e.g. via
    /// `rayon::par_iter`) while the mutable correlation phase runs
    /// sequentially afterwards.
    pub fn evaluate<E: Event>(&self, event: &E) -> Vec<EvaluationResult>
    where
        L: ExtractLogSource<E>,
    {
        self.engine.evaluate(event)
    }

    /// Process a batch of events: parallel detection, then sequential correlation.
    ///
    /// When the `parallel` feature is enabled, the stateless detection phase runs
    /// concurrently via rayon. Timestamp extraction also runs in the parallel
    /// phase (it borrows `&self.config` immutably). After `collect()` releases the
    /// immutable borrows, each event's pre-computed detections are fed into the
    /// stateful correlation engine sequentially.
    pub fn process_batch<E: Event + Sync>(&mut self, events: &[&E]) -> Vec<ProcessResult>
    where
        L: ExtractLogSource<E> + Sync,
    {
        self.process_batch_for_tenants(events, &[])
    }

    /// Process a batch of events, each as the tenant at its position in
    /// `tenants`.
    ///
    /// `tenants` is either empty (every event is untenanted) or exactly as
    /// long as `events`. Any other length is a caller bug: in debug builds it
    /// trips a `debug_assert!`, and in release builds it logs and returns one
    /// empty result per event.
    pub fn process_batch_for_tenants<E: Event + Sync>(
        &mut self,
        events: &[&E],
        tenants: &[Option<TenantId>],
    ) -> Vec<ProcessResult>
    where
        L: ExtractLogSource<E> + Sync,
    {
        if !tenants.is_empty() && tenants.len() != events.len() {
            debug_assert!(
                false,
                "tenants must be empty or parallel to events: {} tenants for {} events",
                tenants.len(),
                events.len()
            );
            log::error!(
                "tenant slice length mismatch: {} tenants for {} events; returning empty results",
                tenants.len(),
                events.len()
            );
            return vec![ProcessResult::new(); events.len()];
        }

        // Borrow split: take immutable refs to fields needed for the parallel phase.
        // These are released by collect() before the sequential &mut self phase.
        let engine = &self.engine;
        let ts_fields = &self.config.timestamp_fields;

        let batch_results: Vec<(Vec<IdentifiedEvaluation>, Option<i64>)> = {
            #[cfg(feature = "parallel")]
            {
                use rayon::prelude::*;
                events
                    .par_iter()
                    .map(|e| {
                        let detections = engine.evaluate_identified(e);
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
                        let detections = engine.evaluate_identified(e);
                        let ts = extract_event_ts(e, ts_fields);
                        (detections, ts)
                    })
                    .collect()
            }
        };

        // Sequential correlation phase
        let mut results = Vec::with_capacity(events.len());
        for (index, ((identified, ts_opt), event)) in
            batch_results.into_iter().zip(events).enumerate()
        {
            let tenant = crate::tenant::tenant_at(tenants, index);
            let (detections, identities) = split_identified(identified);
            let ts = match ts_opt {
                Some(ts) => ts,
                None => match self.config.timestamp_fallback {
                    TimestampFallback::WallClock => Utc::now().timestamp(),
                    TimestampFallback::Skip => {
                        // Still return detection results, but skip correlation
                        results.push(self.filter_detections(detections, identities));
                        continue;
                    }
                },
            };
            results.push(
                self.process_with_detection_identities(event, detections, identities, ts, tenant),
            );
        }
        results
    }

    /// Filter detections by the `generate` flag / `emit_detections` config.
    ///
    /// If `emit_detections` is false and some rules are correlation-only,
    /// their detection output is suppressed.
    fn filter_detections(
        &self,
        all_detections: Vec<EvaluationResult>,
        identities: Vec<RuleIdentity>,
    ) -> Vec<EvaluationResult> {
        if !self.config.emit_detections && !self.correlation_only_rules.is_empty() {
            all_detections
                .into_iter()
                .zip(identities)
                .filter_map(|(detection, (id, name))| {
                    let identities = id.as_deref().into_iter().chain(name.as_deref());
                    (!self.is_correlation_only(identities)).then_some(detection)
                })
                .collect()
        } else {
            all_detections
        }
    }

    /// Whether output for a rule (detection or correlation) with these
    /// identities is suppressed: only correlations without `generate: true`
    /// reference it, and `emit_detections` is off.
    fn is_correlation_only<'a>(
        &self,
        mut identities: impl Iterator<Item = &'a str> + Clone,
    ) -> bool {
        !self.config.emit_detections
            && identities
                .clone()
                .any(|identity| self.correlation_only_rules.contains(identity))
            && !identities.any(|identity| self.generated_rules.contains(identity))
    }

    /// Feed detection matches into correlation window states.
    fn feed_detections(
        &mut self,
        event: &impl Event,
        identities: &[RuleIdentity],
        ts: i64,
        tenant: Option<&TenantId>,
        out: &mut Vec<EvaluationResult>,
        fired_indices: &mut Vec<usize>,
    ) {
        // Collect all (corr_idx, rule_id, rule_name) tuples upfront to avoid
        // borrow conflicts between self.rule_ids and self.update_correlation.
        let mut work: Vec<(usize, Option<String>, Option<String>)> = Vec::new();

        for (rule_id, rule_name) in identities {
            // Collect correlation indices that reference this rule
            let mut corr_indices = Vec::new();
            if let Some(id) = rule_id
                && let Some(indices) = self.rule_index.get(id)
            {
                corr_indices.extend(indices);
            }
            if let Some(name) = rule_name
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
            let before = out.len();
            self.update_correlation(corr_idx, event, ts, tenant, &rule_id, &rule_name, out);
            if out.len() > before {
                fired_indices.push(corr_idx);
            }
        }
    }

    /// Find the (id, name) for a detection match by searching our rule_ids table.
    fn find_rule_identity(&self, det: &EvaluationResult) -> RuleIdentity {
        // Prefer the stable ID carried by the result.
        if let Some(ref match_id) = det.header.rule_id {
            for (id, name, _) in &self.rule_ids {
                if id.as_deref() == Some(match_id.as_str()) {
                    return (id.clone(), name.clone());
                }
            }
        }

        // `process_with_detections` accepts the public EvaluationResult shape,
        // which does not carry a rule name. Recover name-only rule identity
        // from the title retained alongside the compiled rule.
        let mut title_matches = self
            .rule_ids
            .iter()
            .filter(|(_, _, title)| title == &det.header.rule_title);
        if let Some((id, name, _)) = title_matches.next()
            && title_matches.next().is_none()
        {
            return (id.clone(), name.clone());
        }

        (det.header.rule_id.clone(), None)
    }

    /// Update a single correlation's state and check its condition.
    #[allow(clippy::too_many_arguments)]
    fn update_correlation(
        &mut self,
        corr_idx: usize,
        event: &impl Event,
        ts: i64,
        tenant: Option<&TenantId>,
        rule_id: &Option<String>,
        rule_name: &Option<String>,
        out: &mut Vec<EvaluationResult>,
    ) {
        // Copy the scalars and resolve the group key while borrowing the
        // correlation immutably. The borrow ends before the state entry so the
        // tenant quota can evict from `self.state`.
        let (
            corr_type,
            timespan,
            window_mode,
            gap_secs,
            level,
            suppress_secs,
            action,
            event_mode,
            max_events,
            max_group_entries,
            rule_ref,
            group_key,
        ) = {
            let corr = &self.correlations[corr_idx];
            let corr_type = corr.correlation_type;
            let timespan = corr.timespan_secs;
            let window_mode = corr.window_mode;
            let gap_secs = corr.gap_secs;
            let level = corr.level;
            let suppress_secs = corr.suppress_secs.or(self.config.suppress);
            let action = corr.action.unwrap_or(self.config.action_on_match);
            let event_mode = corr
                .event_mode
                .unwrap_or(self.config.correlation_event_mode);
            let max_events = corr
                .max_events
                .unwrap_or(self.config.max_correlation_events);
            let max_group_entries = corr.max_group_entries.or(self.config.max_group_entries);

            // Determine the rule_ref strings for alias resolution and temporal tracking.
            let mut ref_strs: Vec<&str> = Vec::new();
            if let Some(id) = rule_id.as_deref() {
                ref_strs.push(id);
            }
            if let Some(name) = rule_name.as_deref() {
                ref_strs.push(name);
            }
            let rule_ref = ref_strs
                .iter()
                .copied()
                .find(|identity| corr.rule_refs.iter().any(|rule_ref| rule_ref == identity))
                .unwrap_or("")
                .to_string();

            // An event without every group-by value cannot be assigned to a
            // correlation group.
            let Some(group_key) = GroupKey::extract(event, &corr.group_by, &ref_strs) else {
                return;
            };

            (
                corr_type,
                timespan,
                window_mode,
                gap_secs,
                level,
                suppress_secs,
                action,
                event_mode,
                max_events,
                max_group_entries,
                rule_ref,
                group_key,
            )
        };

        // Get or create window state
        let state_key = StateKey {
            tenant: tenant.cloned(),
            corr_idx,
            group_key: group_key.clone(),
        };
        let is_new = !self.state.contains_key(&state_key);
        if is_new
            && let Some(cap) = self.config.max_state_entries_per_tenant
            && self.tenant_len(&state_key.tenant) >= cap
        {
            self.evict_tenant(tenant, ts);
        }
        if is_new {
            self.note_tenant_insert(&state_key);
        }
        let state = self
            .state
            .entry(state_key.clone())
            .or_insert_with(|| WindowState::new_for(corr_type));

        // Re-borrow the correlation: `self.state` and `self.correlations` are
        // disjoint fields, so the mutable state borrow and this read coexist.
        let corr = &self.correlations[corr_idx];

        // Apply the window's pre-insert maintenance (sliding evict, tumbling
        // bucket reset/late-event discard, or session gap/cap reset). On
        // `Reset` the event buffers below are cleared in sync; on `Discard`
        // (a late arrival in an earlier tumbling bucket) the event is dropped
        // without touching the state or buffers.
        let cutoff = ts - timespan as i64;
        let decision = apply_window_open(state, ts, timespan, window_mode, gap_secs);
        if decision == WindowDecision::Discard {
            return;
        }
        let reset = decision == WindowDecision::Reset;

        // Push the new event into the state
        match corr_type {
            CorrelationType::EventCount => {
                state.push_event_count(ts);
            }
            CorrelationType::ValueCount => {
                if let Some(ref fields) = corr.condition.field
                    && let Some(key) = composite_value_count_key(event, fields)
                {
                    state.push_value_count(ts, key);
                }
            }
            CorrelationType::Temporal | CorrelationType::TemporalOrdered => {
                state.push_temporal(ts, &rule_ref);
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

        // Enforce the per-group entry cap. Session windows keep their oldest
        // entry as the span anchor so truncation cannot silently extend the
        // `timespan` cap.
        if let Some(cap) = max_group_entries {
            state.truncate_oldest(cap, window_mode == WindowMode::Session);
        }

        // Push event into buffer based on event mode. Keep the buffer's retained
        // events aligned with the window state: sliding evicts by the trailing
        // cutoff, while tumbling/session clear the buffer when the window reset.
        match event_mode {
            CorrelationEventMode::Full => {
                let buf = self
                    .event_buffers
                    .entry(state_key.clone())
                    .or_insert_with(|| EventBuffer::new(max_events));
                if window_mode == rsigma_parser::WindowMode::Sliding {
                    buf.evict(cutoff);
                } else if reset {
                    buf.clear();
                }
                let json = event.to_json();
                buf.push(ts, &json);
            }
            CorrelationEventMode::Refs => {
                let buf = self
                    .event_ref_buffers
                    .entry(state_key.clone())
                    .or_insert_with(|| EventRefBuffer::new(max_events));
                if window_mode == rsigma_parser::WindowMode::Sliding {
                    buf.evict(cutoff);
                } else if reset {
                    buf.clear();
                }
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
            let alert_key = state_key.clone();

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
                let result = EvaluationResult {
                    header: RuleHeader {
                        rule_title: corr.title.clone(),
                        rule_id: corr.id.clone(),
                        tenant_id: tenant.cloned(),
                        level,
                        tags: corr.tags.clone(),
                        custom_attributes: corr.custom_attributes.clone(),
                        enrichments: None,
                        ruleset: None,
                    },
                    body: ResultBody::Correlation(CorrelationBody {
                        correlation_type: corr_type,
                        group_key: group_key.to_pairs(&corr.group_by),
                        aggregated_value: agg_value,
                        timespan_secs: timespan,
                        events,
                        event_refs,
                    }),
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

    /// IDs and names a fired correlation can be referenced by.
    ///
    /// Parents index `rule_refs` as written in YAML (id or name). The
    /// emitted result only carries `rule_id`, so name-based parents need
    /// this extra key or they never see the child.
    fn chain_lookup_keys(&self, corr_idx: usize) -> Vec<String> {
        let corr = &self.correlations[corr_idx];
        let mut keys = Vec::with_capacity(2);
        keys.extend(corr.id.iter().cloned());
        if corr.name.as_ref() != corr.id.as_ref() {
            keys.extend(corr.name.iter().cloned());
        }
        keys
    }

    /// Propagate correlation results to higher-level correlations (chaining).
    ///
    /// When a correlation fires, any correlation that references it (by ID or name)
    /// is updated. Newly fired parents are appended to `out`, with their
    /// correlation indices in `out_indices`, and become the next `pending`
    /// set. Limits chain depth to 10 to prevent infinite loops.
    fn chain_correlations(
        &mut self,
        fired: &[EvaluationResult],
        fired_indices: &[usize],
        ts: i64,
        out: &mut Vec<EvaluationResult>,
        out_indices: &mut Vec<usize>,
    ) {
        debug_assert_eq!(fired.len(), fired_indices.len());
        // Chaining only needs which correlation fired and for which group, so
        // `pending` carries that instead of cloning results and their events.
        // Only correlation results chain. Detections never reach here.
        #[allow(clippy::type_complexity)]
        let mut pending: Vec<(usize, Vec<(String, String)>, Option<TenantId>)> = fired_indices
            .iter()
            .zip(fired)
            .filter_map(|(&idx, result)| {
                Some((
                    idx,
                    result.as_correlation()?.group_key.clone(),
                    result.header.tenant_id.clone(),
                ))
            })
            .collect();
        let mut depth = 0;

        while !pending.is_empty() && depth < MAX_CHAIN_DEPTH {
            depth += 1;

            // Collect work items: (corr_idx, group_key_pairs, fired_ref, tenant)
            #[allow(clippy::type_complexity)]
            let mut work: Vec<(
                usize,
                Vec<(String, String)>,
                String,
                Option<TenantId>,
            )> = Vec::new();
            let mut seen = std::collections::HashSet::<(usize, String, Option<TenantId>)>::new();
            for (source_idx, group_key, tenant) in &pending {
                for key in self.chain_lookup_keys(*source_idx) {
                    if let Some(indices) = self.rule_index.get(&key) {
                        for &corr_idx in indices {
                            if seen.insert((corr_idx, key.clone(), tenant.clone())) {
                                work.push((
                                    corr_idx,
                                    group_key.clone(),
                                    key.clone(),
                                    tenant.clone(),
                                ));
                            }
                        }
                    }
                }
            }

            let mut next_pending = Vec::new();
            for (corr_idx, group_key_pairs, fired_ref, tenant) in work {
                let (
                    corr_type,
                    timespan,
                    window_mode,
                    gap_secs,
                    level,
                    suppress_secs,
                    action,
                    max_group_entries,
                    group_key,
                ) = {
                    let corr = &self.correlations[corr_idx];
                    let Some(group_key) = GroupKey::from_pairs(&group_key_pairs, &corr.group_by)
                    else {
                        continue;
                    };
                    (
                        corr.correlation_type,
                        corr.timespan_secs,
                        corr.window_mode,
                        corr.gap_secs,
                        corr.level,
                        corr.suppress_secs.or(self.config.suppress),
                        corr.action.unwrap_or(self.config.action_on_match),
                        corr.max_group_entries.or(self.config.max_group_entries),
                        group_key,
                    )
                };
                let state_key = StateKey {
                    tenant: tenant.clone(),
                    corr_idx,
                    group_key: group_key.clone(),
                };
                let is_new = !self.state.contains_key(&state_key);
                if is_new
                    && let Some(cap) = self.config.max_state_entries_per_tenant
                    && self.tenant_len(&state_key.tenant) >= cap
                {
                    self.evict_tenant(tenant.as_ref(), ts);
                }
                if is_new {
                    self.note_tenant_insert(&state_key);
                }
                let state = self
                    .state
                    .entry(state_key.clone())
                    .or_insert_with(|| WindowState::new_for(corr_type));

                // Late arrivals in an earlier tumbling bucket are discarded;
                // chained correlations keep no event buffers, so `Reset` needs
                // no extra bookkeeping here.
                if apply_window_open(state, ts, timespan, window_mode, gap_secs)
                    == WindowDecision::Discard
                {
                    continue;
                }

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

                // Same per-group cap as the direct path; session windows
                // keep the span anchor.
                if let Some(cap) = max_group_entries {
                    state.truncate_oldest(cap, window_mode == WindowMode::Session);
                }

                // `self.state` and `self.correlations` are disjoint fields, so
                // the mutable state borrow and this read coexist.
                let corr = &self.correlations[corr_idx];
                let fired = state.check_condition(
                    &corr.condition,
                    corr_type,
                    &corr.rule_refs,
                    corr.extended_expr.as_ref(),
                );

                if let Some(agg_value) = fired {
                    let alert_key = state_key;
                    let suppressed = if let Some(suppress) = suppress_secs {
                        self.last_alert
                            .get(&alert_key)
                            .is_some_and(|&last_ts| (ts - last_ts) < suppress as i64)
                    } else {
                        false
                    };
                    if suppressed {
                        continue;
                    }

                    let corr = &self.correlations[corr_idx];
                    let fired_group_key = group_key.to_pairs(&corr.group_by);
                    let result = EvaluationResult {
                        header: RuleHeader {
                            rule_title: corr.title.clone(),
                            rule_id: corr.id.clone(),
                            tenant_id: tenant.clone(),
                            level,
                            tags: corr.tags.clone(),
                            custom_attributes: corr.custom_attributes.clone(),
                            enrichments: None,
                            ruleset: None,
                        },
                        body: ResultBody::Correlation(CorrelationBody {
                            correlation_type: corr_type,
                            group_key: fired_group_key.clone(),
                            aggregated_value: agg_value,
                            timespan_secs: timespan,
                            // Chained correlations don't include events
                            // (they aggregate over correlation results, not
                            // raw events)
                            events: None,
                            event_refs: None,
                        }),
                    };
                    next_pending.push((corr_idx, fired_group_key, tenant.clone()));
                    out.push(result);
                    out_indices.push(corr_idx);
                    self.last_alert.insert(alert_key.clone(), ts);

                    if action == CorrelationAction::Reset
                        && let Some(state) = self.state.get_mut(&alert_key)
                    {
                        state.clear();
                    }
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
    /// Returns `None` if no field yields a valid timestamp; a value before
    /// 1970 or past the representable range does not count as one.
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

    /// Index a new state key under its tenant while a per-tenant cap is set.
    fn note_tenant_insert(&mut self, key: &StateKey) {
        if self.config.max_state_entries_per_tenant.is_some() {
            self.tenant_keys
                .entry(key.tenant.clone())
                .or_default()
                .insert(key.clone());
        }
    }

    /// Drop a removed state key from its tenant's index.
    fn note_tenant_removal(&mut self, key: &StateKey) {
        if let Some(keys) = self.tenant_keys.get_mut(&key.tenant) {
            keys.remove(key);
            if keys.is_empty() {
                self.tenant_keys.remove(&key.tenant);
            }
        }
    }

    /// Live state entries of `tenant`, tracked while a per-tenant cap is set.
    fn tenant_len(&self, tenant: &Option<TenantId>) -> usize {
        self.tenant_keys.get(tenant).map_or(0, HashSet::len)
    }

    /// Remove one state entry and every sidecar keyed by it.
    fn remove_state_entry(&mut self, key: &StateKey) -> bool {
        let existed = self.state.remove(key).is_some();
        if existed {
            self.note_tenant_removal(key);
        }
        self.last_alert.remove(key);
        self.event_buffers.remove(key);
        self.event_ref_buffers.remove(key);
        existed
    }

    /// Evict one tenant's expired entries, then its stalest entries down to 90%
    /// of the configured per-tenant cap. Returns how many entries were removed.
    fn evict_tenant(&mut self, tenant: Option<&TenantId>, now_secs: i64) -> usize {
        let Some(cap) = self.config.max_state_entries_per_tenant else {
            return 0;
        };
        let tenant_key = tenant.cloned();
        let keys: Vec<StateKey> = self
            .tenant_keys
            .get(&tenant_key)
            .map(|keys| keys.iter().cloned().collect())
            .unwrap_or_default();

        // Expired phase: drop the tenant's emptied windows. `last_alert` stays,
        // so a group evicted here is still suppressed until `evict_all` ages
        // the alert out.
        let mut evicted = 0;
        for key in &keys {
            let Some(state) = self.state.get_mut(key) else {
                continue;
            };
            if let Some(correlation) = self.correlations.get(key.corr_idx) {
                let timespan = correlation.timespan_secs as i64;
                match correlation.window_mode {
                    WindowMode::Sliding => {
                        state.evict(now_secs - timespan);
                    }
                    mode @ (WindowMode::Tumbling | WindowMode::Session) => {
                        let staleness = if mode == WindowMode::Session {
                            correlation.gap_secs.map_or(timespan, |gap| gap as i64)
                        } else {
                            timespan
                        };
                        if state
                            .latest_timestamp()
                            .is_some_and(|last| now_secs - last > staleness)
                        {
                            state.clear();
                        }
                    }
                }
            }
            if state.is_empty() {
                self.state.remove(key);
                self.note_tenant_removal(key);
                self.event_buffers.remove(key);
                self.event_ref_buffers.remove(key);
                evicted += 1;
            }
        }

        // Stalest phase: at the cap, drop the tenant's stalest windows down to
        // 90% of it, and at least one.
        let count = self.tenant_len(&tenant_key);
        if count >= cap {
            let target = cap * 9 / 10;
            let excess = count.saturating_sub(target);
            let mut by_staleness: Vec<_> = self
                .tenant_keys
                .get(&tenant_key)
                .into_iter()
                .flatten()
                .filter_map(|key| {
                    self.state
                        .get(key)
                        .map(|state| (key, state.latest_timestamp().unwrap_or(i64::MIN)))
                })
                .collect();
            if excess < by_staleness.len() {
                by_staleness.select_nth_unstable_by_key(excess, |&(_, ts)| ts);
            }
            let stalest: Vec<_> = by_staleness
                .iter()
                .take(excess)
                .map(|&(key, _)| key.clone())
                .collect();
            for key in stalest {
                if self.remove_state_entry(&key) {
                    evicted += 1;
                }
            }
        }

        self.tenant_quota_evictions += evicted as u64;
        evicted
    }

    /// Evict expired entries and remove empty states.
    fn evict_all(&mut self, now_secs: i64) {
        // Phase 1: Time-based eviction — remove entries outside their correlation
        // window. Eviction is window-mode aware:
        //
        // - Sliding: trim entries older than the trailing cutoff, as always.
        // - Tumbling/session: never trim from the front — that would forget the
        //   bucket/session start and silently weaken the `timespan` cap (the
        //   window would drift toward sliding semantics). Instead, drop the
        //   whole group once it is stale (no event within its bucket span /
        //   session gap), which is exactly the point at which the next arrival
        //   would reset it anyway.
        let specs: Vec<(u64, WindowMode, Option<u64>)> = self
            .correlations
            .iter()
            .map(|c| (c.timespan_secs, c.window_mode, c.gap_secs))
            .collect();

        let mut removed_keys = Vec::new();
        self.state.retain(|key, state| {
            if let Some(&(timespan, mode, gap)) = specs.get(key.corr_idx) {
                match mode {
                    WindowMode::Sliding => {
                        state.evict(now_secs - timespan as i64);
                    }
                    WindowMode::Tumbling | WindowMode::Session => {
                        let staleness = if mode == WindowMode::Session {
                            gap.unwrap_or(timespan)
                        } else {
                            timespan
                        } as i64;
                        if state
                            .latest_timestamp()
                            .is_some_and(|last| now_secs - last > staleness)
                        {
                            state.clear();
                        }
                    }
                }
            }
            if state.is_empty() {
                removed_keys.push(key.clone());
                false
            } else {
                true
            }
        });
        for key in removed_keys {
            self.note_tenant_removal(&key);
        }

        // Evict event buffers in sync with window state: sliding buffers trim by
        // the trailing cutoff, tumbling/session buffers live and die with their
        // window state (dropped above when the group went stale).
        let state = &self.state;
        self.event_buffers.retain(|key, buf| {
            if let Some(&(timespan, mode, _)) = specs.get(key.corr_idx) {
                match mode {
                    WindowMode::Sliding => buf.evict(now_secs - timespan as i64),
                    WindowMode::Tumbling | WindowMode::Session => {
                        if !state.contains_key(key) {
                            return false;
                        }
                    }
                }
            }
            !buf.is_empty()
        });
        self.event_ref_buffers.retain(|key, buf| {
            if let Some(&(timespan, mode, _)) = specs.get(key.corr_idx) {
                match mode {
                    WindowMode::Sliding => buf.evict(now_secs - timespan as i64),
                    WindowMode::Tumbling | WindowMode::Session => {
                        if !state.contains_key(key) {
                            return false;
                        }
                    }
                }
            }
            !buf.is_empty()
        });

        // Phase 2: Hard cap — if still over limit after time-based eviction (e.g.
        // high-cardinality traffic with long windows), drop the stalest entries
        // until we're at 90% capacity to avoid evicting on every single event.
        if self.state.len() >= self.config.max_state_entries {
            let target = self.config.max_state_entries * 9 / 10;
            let excess = self.state.len() - target;

            log::warn!(
                "Correlation state hard cap reached ({} entries, max {}); \
                 evicting {} stalest entries to {} (90% capacity). \
                 This indicates high-cardinality traffic; consider raising \
                 max_state_entries or shortening correlation windows.",
                self.state.len(),
                self.config.max_state_entries,
                excess,
                target,
            );

            // Partition by latest timestamp so the `excess` stalest entries
            // come first, and clone only their keys.
            let mut by_staleness: Vec<_> = self
                .state
                .iter()
                .map(|(k, v)| (k, v.latest_timestamp().unwrap_or(i64::MIN)))
                .collect();
            if excess < by_staleness.len() {
                by_staleness.select_nth_unstable_by_key(excess, |&(_, ts)| ts);
            }
            let stalest: Vec<_> = by_staleness
                .iter()
                .take(excess)
                .map(|&(k, _)| k.clone())
                .collect();

            // Drop the stalest entries (and their associated event buffers)
            for key in stalest {
                self.remove_state_entry(&key);
            }
        }

        // Phase 3: Evict stale last_alert entries — remove if the suppress window
        // has passed or if the corresponding window state no longer exists.
        self.last_alert.retain(|key, &mut alert_ts| {
            let suppress = if key.corr_idx < self.correlations.len() {
                self.correlations[key.corr_idx]
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
    pub fn engine(&self) -> &Engine<L> {
        &self.engine
    }

    /// Resolve a rule key (an id, or a title for a rule without one) to the
    /// documentation of every loaded rule that carries it, across both the
    /// detection rules and the correlations.
    pub fn rule_metadata(&self, key: &str) -> RuleMetadataLookup {
        let mut variants = Vec::new();
        self.collect_rule_metadata(key, &mut variants);
        RuleMetadataLookup::from_variants(variants)
    }

    pub(crate) fn collect_rule_metadata(&self, key: &str, out: &mut Vec<RuleBundleMetadata>) {
        self.engine.collect_rule_metadata(key, out);
        crate::rule_metadata::matching_correlations(&self.correlations, key, out);
    }

    /// Export all mutable correlation state as a serializable snapshot.
    ///
    /// The snapshot uses stable correlation identifiers (id > name > title)
    /// instead of internal indices, so it survives rule reloads as long as
    /// the correlation rules keep the same identifiers. State is nested per
    /// tenant; with tenancy off it is one `tenant: None` entry.
    pub fn export_state(&self) -> CorrelationSnapshot {
        let mut by_tenant: BTreeMap<Option<TenantId>, TenantStateSnapshot> = BTreeMap::new();

        for (key, ws) in &self.state {
            let corr_id = self.correlation_stable_id(key.corr_idx);
            by_tenant
                .entry(key.tenant.clone())
                .or_insert_with(|| TenantStateSnapshot::empty(key.tenant.clone()))
                .windows
                .entry(corr_id)
                .or_default()
                .push((key.group_key.clone(), ws.clone()));
        }

        for (key, ts) in &self.last_alert {
            let corr_id = self.correlation_stable_id(key.corr_idx);
            by_tenant
                .entry(key.tenant.clone())
                .or_insert_with(|| TenantStateSnapshot::empty(key.tenant.clone()))
                .last_alert
                .entry(corr_id)
                .or_default()
                .push((key.group_key.clone(), *ts));
        }

        for (key, buf) in &self.event_buffers {
            let corr_id = self.correlation_stable_id(key.corr_idx);
            by_tenant
                .entry(key.tenant.clone())
                .or_insert_with(|| TenantStateSnapshot::empty(key.tenant.clone()))
                .event_buffers
                .entry(corr_id)
                .or_default()
                .push((key.group_key.clone(), buf.clone()));
        }

        for (key, buf) in &self.event_ref_buffers {
            let corr_id = self.correlation_stable_id(key.corr_idx);
            by_tenant
                .entry(key.tenant.clone())
                .or_insert_with(|| TenantStateSnapshot::empty(key.tenant.clone()))
                .event_ref_buffers
                .entry(corr_id)
                .or_default()
                .push((key.group_key.clone(), buf.clone()));
        }

        CorrelationSnapshot {
            version: SNAPSHOT_VERSION,
            windows: HashMap::new(),
            last_alert: HashMap::new(),
            event_buffers: HashMap::new(),
            event_ref_buffers: HashMap::new(),
            tenants: by_tenant.into_values().collect(),
            rulesets: BTreeMap::new(),
        }
    }

    /// Import previously exported state, mapping stable identifiers back to
    /// current correlation indices. Entries whose identifiers no longer match
    /// any loaded correlation are silently dropped.
    ///
    /// A snapshot exported by a fan-out over exactly one ruleset imports that
    /// ruleset's state.
    ///
    /// Returns `false` (and imports nothing) if the snapshot version is
    /// incompatible with the current schema, or if the snapshot holds state
    /// for several rulesets.
    pub fn import_state(&mut self, snapshot: CorrelationSnapshot) -> bool {
        self.import_state_detailed(snapshot).is_some()
    }

    /// Like [`import_state`](Self::import_state), returning the counts of
    /// restored and discarded entries.
    ///
    /// Accepts versions 1 and 2. Attribution follows
    /// [`CorrelationConfig::require_tenant`]: with it set, untenanted entries
    /// are discarded; without it, tenanted entries are discarded. Returns
    /// `None` for an unknown version or a multi-ruleset snapshot that does not
    /// fit this engine.
    pub fn import_state_detailed(
        &mut self,
        mut snapshot: CorrelationSnapshot,
    ) -> Option<ImportStats> {
        if !matches!(snapshot.version, 1 | 2) {
            return None;
        }
        if !snapshot.rulesets.is_empty() {
            if snapshot.has_collection_state() || snapshot.rulesets.len() != 1 {
                return None;
            }
            let (_, inner) = std::mem::take(&mut snapshot.rulesets).pop_first()?;
            return self.import_state_detailed(inner);
        }
        let id_to_idx = self.build_id_to_index_map();
        let require_tenant = self.config.require_tenant;
        let mut stats = ImportStats::default();

        let mut tenant_states = std::mem::take(&mut snapshot.tenants);
        // The version 1 top-level maps are the untenanted bucket.
        tenant_states.push(TenantStateSnapshot {
            tenant: None,
            windows: snapshot.windows,
            last_alert: snapshot.last_alert,
            event_buffers: snapshot.event_buffers,
            event_ref_buffers: snapshot.event_ref_buffers,
        });

        for tenant_state in tenant_states {
            let entries = tenant_state.window_entries();
            let tenant = tenant_state.tenant;
            let keep = if require_tenant {
                tenant.is_some()
            } else {
                tenant.is_none()
            };
            if !keep {
                if tenant.is_none() {
                    stats.discarded_untenanted += entries;
                } else {
                    stats.discarded_tenanted += entries;
                }
                continue;
            }

            for (corr_id, groups) in tenant_state.windows {
                if let Some(&idx) = id_to_idx.get(&corr_id) {
                    for (gk, ws) in groups {
                        let key = StateKey {
                            tenant: tenant.clone(),
                            corr_idx: idx,
                            group_key: gk,
                        };
                        if self.state.insert(key.clone(), ws).is_none() {
                            self.note_tenant_insert(&key);
                        }
                        stats.restored += 1;
                    }
                }
            }

            for (corr_id, groups) in tenant_state.last_alert {
                if let Some(&idx) = id_to_idx.get(&corr_id) {
                    for (gk, ts) in groups {
                        self.last_alert.insert(
                            StateKey {
                                tenant: tenant.clone(),
                                corr_idx: idx,
                                group_key: gk,
                            },
                            ts,
                        );
                    }
                }
            }

            for (corr_id, groups) in tenant_state.event_buffers {
                if let Some(&idx) = id_to_idx.get(&corr_id) {
                    for (gk, buf) in groups {
                        self.event_buffers.insert(
                            StateKey {
                                tenant: tenant.clone(),
                                corr_idx: idx,
                                group_key: gk,
                            },
                            buf,
                        );
                    }
                }
            }

            for (corr_id, groups) in tenant_state.event_ref_buffers {
                if let Some(&idx) = id_to_idx.get(&corr_id) {
                    for (gk, buf) in groups {
                        self.event_ref_buffers.insert(
                            StateKey {
                                tenant: tenant.clone(),
                                corr_idx: idx,
                                group_key: gk,
                            },
                            buf,
                        );
                    }
                }
            }
        }

        Some(stats)
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

fn split_identified(
    identified: Vec<IdentifiedEvaluation>,
) -> (Vec<EvaluationResult>, Vec<RuleIdentity>) {
    identified
        .into_iter()
        .map(|identified| {
            (
                identified.result,
                (identified.rule_id, identified.rule_name),
            )
        })
        .unzip()
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
///
/// Values before 1970, non-finite floats, and dates past the representable
/// range are `None`, so the next timestamp field or the fallback applies.
fn parse_timestamp_value(val: &EventValue) -> Option<i64> {
    match val {
        EventValue::Int(i) => epoch_seconds_from_int(*i),
        EventValue::Float(f) => epoch_seconds_from_float(*f),
        EventValue::Str(s) => parse_timestamp_str(s)
            .map(|dt| dt.timestamp())
            .filter(|ts| *ts >= 0),
        _ => None,
    }
}

/// Render a value for a `value_count` distinct key. Unlike a group key, a
/// null counts as the distinct value `null`.
fn value_to_string_for_count(v: &EventValue) -> Option<String> {
    match v {
        EventValue::Null => Some("null".to_string()),
        v => v.as_str().map(Cow::into_owned),
    }
}

/// Build a composite distinct-key for `value_count` over one or more fields.
///
/// Each field's value is rendered with [`value_to_string_for_count`] and the
/// rendered parts are joined with `\u{1f}` (the ASCII Unit Separator), which
/// is unlikely to occur in normal log data. If any field is missing or has a
/// type that does not produce a stable string representation, the event is
/// excluded from the distinct count (return `None`), matching the historical
/// single-field behavior.
fn composite_value_count_key(event: &impl Event, fields: &[String]) -> Option<String> {
    // Common case: exactly one field. Avoid the separator overhead.
    if let [field_name] = fields {
        let val = event.get_field(field_name)?;
        return value_to_string_for_count(&val);
    }

    let mut parts = Vec::with_capacity(fields.len());
    for field_name in fields {
        let val = event.get_field(field_name)?;
        let rendered = value_to_string_for_count(&val)?;
        parts.push(rendered);
    }
    Some(parts.join("\u{1f}"))
}

/// Convert an [`EventValue`] to f64 for numeric aggregation.
fn value_to_f64_ev(v: &EventValue) -> Option<f64> {
    v.as_f64()
}
