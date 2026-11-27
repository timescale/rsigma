//! Multi-engine schema router: classify each event, route it to the detection
//! engine built for its schema's pipeline-set, and feed every detection into
//! one shared correlation store.
//!
//! # Design
//!
//! - One [`Engine`] per deduplicated pipeline-set (index-aligned with
//!   [`RoutingPlan::pipeline_sets`]). The schema's pipeline is applied to the
//!   detection rules in its engine, exactly as a single-pipeline run would.
//! - One shared [`CorrelationEngine`] (present only when the rule set has
//!   correlation rules), built Sigma-native (no pipeline). Detections from any
//!   per-schema engine feed into it via
//!   [`CorrelationEngine::correlate_detections`].
//! - Cross-schema correlation grouping works because the group-by extraction is
//!   schema-aware: each set carries a `Sigma -> event field` map (derived from
//!   its pipelines' field-name mappings), and the event is wrapped in a
//!   [`MappedEvent`] before correlation so the Sigma-native group-by names
//!   resolve to the schema's field names. The window store stays shared, keyed
//!   by the logical correlation plus the extracted group values.
//!
//! This subsumes the single-schema case (one pipeline-set is the degenerate
//! configuration), so there is no separate code path for "routing off".

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use rsigma_parser::{LogSource, SigmaCollection, SigmaRule};

use crate::correlation_engine::{
    CorrelationConfig, CorrelationEngine, CorrelationSnapshot, CorrelationStateSnapshot,
    ProcessResult,
};
use crate::engine::{Engine, IdentifiedEvaluation};
use crate::error::Result;
use crate::event::{Event, MappedEvent};
use crate::logsource::{ExtractLogSource, LogSourceExtractor};
use crate::pipeline::Pipeline;
use crate::pipeline::transformations::Transformation;
use crate::result::MatchDetailLevel;
use crate::rule_metadata::RuleMetadataLookup;
use crate::schema::{OnUnknown, RouteDecision, RoutingPlan, SchemaClassifier};
use crate::tenant::{TenantId, tenant_at};

/// Per-schema logsource pruning summary: how many rules a schema's events
/// evaluate versus how many are pruned by its implied logsource. A static view
/// (independent of any specific event's field values) for operator visibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaPruning {
    /// The recognized schema name.
    pub schema: String,
    /// Rules evaluated for this schema (logsource-compatible).
    pub eligible: usize,
    /// Rules pruned for this schema (logsource-conflicting).
    pub pruned: usize,
}

/// What the router did with an event, for reporting and `on_unknown` handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOutcome {
    /// Evaluated against a bound or known schema's set.
    Evaluated,
    /// Evaluated against the default set because the schema was unrecognized
    /// (`on_unknown: warn` or `passthrough`).
    EvaluatedUnknown,
    /// Dropped without evaluating (`on_unknown: drop`).
    Dropped,
    /// Dropped and flagged as an error (`on_unknown: error`).
    Errored,
}

/// The result of routing one event.
pub struct RouteResult {
    /// Evaluation results (empty when dropped or errored).
    pub results: ProcessResult,
    /// The classified schema name, or `None` when unrecognized.
    pub schema: Option<String>,
    /// What the router did.
    pub outcome: RouteOutcome,
}

/// Collect a combined `Sigma -> [event field]` map from a pipeline-set's
/// field-name mappings, used for schema-aware correlation group-by extraction.
fn collect_field_map(pipelines: &[Pipeline]) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for pipeline in pipelines {
        for item in &pipeline.transformations {
            if let Transformation::FieldNameMapping { mapping } = &item.transformation {
                for (from, to) in mapping {
                    map.entry(from.clone())
                        .or_default()
                        .extend(to.iter().cloned());
                }
            }
        }
    }
    map
}

/// Outcome of the stateless phase for one event in [`SchemaRouter::process_batch`].
enum Routed1 {
    /// Dropped or errored (`on_unknown`): no results.
    Skip,
    /// Evaluate detections against the shared correlation store under set `set`.
    Eval {
        set: usize,
        detections: Vec<IdentifiedEvaluation>,
    },
}

/// Keep a detection rule when partitioning a per-schema engine: rules with no
/// product apply to every platform; a product-tagged rule is kept only when its
/// product is among the set's allowed products (lowercased).
fn rule_product_kept(rule: &SigmaRule, products: &std::collections::HashSet<String>) -> bool {
    match &rule.logsource.product {
        None => true,
        Some(p) => products.contains(&p.to_ascii_lowercase()),
    }
}

/// Whether a pipeline rewrites a rule's product via `change_logsource`, which
/// makes pre-pipeline product partitioning unsafe (a rule could be re-producted
/// at compile time). Such a set keeps its full ruleset.
fn pipeline_changes_product(pipeline: &Pipeline) -> bool {
    pipeline.transformations.iter().any(|item| {
        matches!(
            &item.transformation,
            Transformation::ChangeLogsource {
                product: Some(_),
                ..
            }
        )
    })
}

/// Resolve an event's logsource for conflict-based pruning: the extractor's
/// value (explicit event fields, then static/format defaults) wins, and the
/// recognized schema's implied logsource fills any dimension left unset. This
/// is what lets a `product`-less event still prune cross-product rules once its
/// schema is known (for example a `sysmon`-classified event implies
/// `product: windows`).
fn resolve_event_logsource<E: Event, L: ExtractLogSource<E>>(
    extractor: &L,
    implied: Option<&LogSource>,
    event: &E,
) -> LogSource {
    let mut ls = extractor.extract(event);
    if let Some(implied) = implied {
        if ls.product.is_none() {
            ls.product = implied.product.clone();
        }
        if ls.service.is_none() {
            ls.service = implied.service.clone();
        }
        if ls.category.is_none() {
            ls.category = implied.category.clone();
        }
        for (key, value) in &implied.custom {
            ls.custom
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
    }
    ls
}

/// An event's schema and the logsource it implies for pruning.
struct Classified<'a> {
    schema: Option<String>,
    /// The schema's implied logsource, or `None` when the classification is
    /// ambiguous.
    implied: Option<&'a LogSource>,
    /// The winning signature tied at its specificity with a different-name
    /// signature that implies a different logsource, so the name tie-break
    /// cannot tell which platform the event came from.
    ambiguous: bool,
}

/// Classify an event and look up the logsource its schema implies.
///
/// Ties are only checked when `check_ties` is set, because only logsource
/// pruning and partition fallbacks act on them. An ambiguous classification
/// implies no logsource (fail open), so only the event's own fields can
/// prune rules.
fn classify_for_routing<'a, E: Event>(
    classifier: &SchemaClassifier,
    plan: &'a RoutingPlan,
    event: &E,
    check_ties: bool,
) -> Classified<'a> {
    if !check_ties {
        let schema = classifier.classify(event).map(|m| m.name);
        let implied = schema.as_deref().and_then(|s| plan.schema_logsource(s));
        return Classified {
            schema,
            implied,
            ambiguous: false,
        };
    }
    let Some((winner, mut ties)) = classifier.winner_and_ties(event) else {
        return Classified {
            schema: None,
            implied: None,
            ambiguous: false,
        };
    };
    let implied = plan.schema_logsource(&winner.name);
    let ambiguous = ties.any(|tie| plan.schema_logsource(&tie.name) != implied);
    Classified {
        schema: Some(winner.name.clone()),
        implied: if ambiguous { None } else { implied },
        ambiguous,
    }
}

/// The rules per-schema partitioning left out of one pipeline-set's engine,
/// for events that may still need them.
///
/// With the full rule set, an event is checked against every rule its
/// resolved logsource does not rule out. A partitioned set only holds the
/// rules for its schemas' products, so an event whose resolved product falls
/// outside them (an explicit `product` field that contradicts the schema, or
/// no product at all because the classification is ambiguous) is also
/// evaluated against the removed rules. Without logsource routing only an
/// ambiguous event needs them. The removed rules' engine is compiled on the
/// first event that needs it, so a deployment that never sees such an event
/// pays only for one shared copy of the parsed rules.
struct PartitionFallback {
    /// The whole parsed collection, shared by every set's fallback.
    collection: Arc<SigmaCollection>,
    /// Lowercased products the set's own engine keeps.
    kept_products: HashSet<String>,
    pipelines: Vec<Pipeline>,
    /// Settings for the engine when it is compiled; kept in step with the
    /// router's per-schema engines by the router's setters.
    settings: EngineSettings,
    engine: OnceLock<Engine>,
}

/// Per-engine settings the router applies to every per-schema engine.
#[derive(Debug, Clone, Copy)]
struct EngineSettings {
    include_event: bool,
    match_detail: MatchDetailLevel,
    bloom_prefilter: bool,
    bloom_max_bytes: Option<usize>,
    #[cfg(feature = "daachorse-index")]
    cross_rule_ac: bool,
}

impl EngineSettings {
    fn apply(&self, engine: &mut Engine) {
        engine.set_include_event(self.include_event);
        engine.set_match_detail(self.match_detail);
        if let Some(budget) = self.bloom_max_bytes {
            engine.set_bloom_max_bytes(budget);
        }
        engine.set_bloom_prefilter(self.bloom_prefilter);
        #[cfg(feature = "daachorse-index")]
        engine.set_cross_rule_ac(self.cross_rule_ac);
    }
}

impl PartitionFallback {
    /// Whether the set's own engine holds every rule an event with resolved
    /// product `product` can match.
    fn covers(&self, product: Option<&str>) -> bool {
        product.is_some_and(|p| self.kept_products.contains(&p.to_ascii_lowercase()))
    }

    fn engine(&self) -> &Engine {
        self.engine.get_or_init(|| {
            let mut engine = Engine::new();
            self.settings.apply(&mut engine);
            for pipeline in &self.pipelines {
                engine.add_pipeline(pipeline.clone());
            }
            let removed: Vec<&SigmaRule> = self
                .collection
                .rules
                .iter()
                .filter(|r| !rule_product_kept(r, &self.kept_products))
                .collect();
            for (idx, error) in engine.add_rules(removed.iter().copied()) {
                log::warn!(
                    "schema routing: rule '{}' left out by partitioning failed to compile: {error}",
                    removed[idx].title
                );
            }
            for filter in &self.collection.filters {
                if let Err(error) = engine.apply_filter(filter) {
                    log::warn!(
                        "schema routing: filter '{}' failed to apply to the rules left out by partitioning: {error}",
                        filter.title
                    );
                }
            }
            engine
        })
    }
}

/// Shared, read-only routing state for one event.
struct RouteCtx<'a, L> {
    classifier: &'a SchemaClassifier,
    plan: &'a RoutingPlan,
    engines: &'a [Engine],
    fallbacks: &'a [Option<PartitionFallback>],
    extractor: Option<&'a L>,
    ambiguous: &'a AtomicU64,
}

impl<L> RouteCtx<'_, L> {
    fn check_ties(&self) -> bool {
        self.extractor.is_some() || self.fallbacks.iter().any(Option::is_some)
    }

    /// Classify `event`, counting an ambiguous classification when it changes
    /// what logsource pruning does.
    fn classify<E: Event>(&self, event: &E) -> Classified<'_> {
        let classified = classify_for_routing(self.classifier, self.plan, event, self.check_ties());
        if classified.ambiguous && self.extractor.is_some() {
            self.ambiguous.fetch_add(1, Ordering::Relaxed);
        }
        classified
    }

    /// Evaluate `event` on set `set`, adding the partition fallback's rules
    /// when the set's own engine may lack a rule the event can match.
    fn evaluate<E: Event>(
        &self,
        set: usize,
        classified: &Classified<'_>,
        event: &E,
    ) -> Vec<IdentifiedEvaluation>
    where
        L: ExtractLogSource<E>,
    {
        let fallback = self.fallbacks.get(set).and_then(Option::as_ref);
        match self.extractor {
            Some(ex) => {
                let ls = resolve_event_logsource(ex, classified.implied, event);
                let mut detections = self.engines[set].evaluate_pruned_identified(event, &ls);
                if let Some(fallback) = fallback
                    && !fallback.covers(ls.product.as_deref())
                {
                    detections.extend(fallback.engine().evaluate_pruned_identified(event, &ls));
                }
                detections
            }
            None => {
                let mut detections = self.engines[set].evaluate_identified(event);
                if classified.ambiguous
                    && let Some(fallback) = fallback
                {
                    detections.extend(fallback.engine().evaluate_identified(event));
                }
                detections
            }
        }
    }
}

/// Stateless detection for one event: classify, decide, evaluate. Borrows only
/// shared state so it can run in parallel across a batch. When a logsource
/// extractor is configured, the event's logsource is resolved (explicit fields
/// plus the schema's implied logsource) and fed into conflict-based pruning.
fn detect_one<E: Event, L: ExtractLogSource<E>>(ctx: &RouteCtx<'_, L>, event: &E) -> Routed1 {
    let classified = ctx.classify(event);
    match ctx.plan.decide(classified.schema.as_deref()) {
        RouteDecision::Drop | RouteDecision::Error => Routed1::Skip,
        RouteDecision::Evaluate { set, .. } => Routed1::Eval {
            set,
            detections: ctx.evaluate(set, &classified, event),
        },
    }
}

/// A multi-engine router over a classifier, a [`RoutingPlan`], one detection
/// engine per pipeline-set, and one shared correlation store.
///
/// Generic over the logsource extractor `L`, which defaults to
/// [`LogSourceExtractor`]. Build with [`SchemaRouter::build`] for the default,
/// or [`SchemaRouter::build_with_logsource_extractor`] for a custom
/// [`ExtractLogSource`] implementation.
pub struct SchemaRouter<L = LogSourceExtractor> {
    classifier: SchemaClassifier,
    plan: RoutingPlan,
    /// One detection engine per pipeline-set (index = set index).
    engines: Vec<Engine>,
    /// `Sigma -> event field` map per pipeline-set, for correlation group-by.
    field_maps: Vec<HashMap<String, Vec<String>>>,
    /// Shared correlation store; `None` when there are no correlation rules.
    correlation: Option<CorrelationEngine>,
    /// Event-logsource extractor for conflict-based pruning; `None` disables
    /// pruning. Resolution happens per event in the router (extractor value
    /// plus the schema's implied logsource), so it is not set on the engines.
    logsource_extractor: Option<L>,
    /// Events whose schema implied no logsource because the classification
    /// tied between schemas implying different ones. Surfaced via
    /// [`SchemaRouter::logsource_ambiguous_total`].
    logsource_ambiguous: AtomicU64,
    /// Per pipeline-set (index = set index): the rules partitioning removed,
    /// for events whose resolved product the set does not cover. `None` for
    /// unpartitioned sets, and without logsource routing also for sets whose
    /// schemas cannot win a tie against a schema implying another logsource.
    fallbacks: Vec<Option<PartitionFallback>>,
}

impl SchemaRouter {
    /// Build a router. `pipeline_sets` must be index-aligned with
    /// `plan.pipeline_sets()` (one resolved pipeline list per set).
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        collection: &SigmaCollection,
        classifier: SchemaClassifier,
        plan: RoutingPlan,
        pipeline_sets: Vec<Vec<Pipeline>>,
        corr_config: CorrelationConfig,
        include_event: bool,
        match_detail: MatchDetailLevel,
        logsource_extractor: Option<LogSourceExtractor>,
        partition_rules: bool,
    ) -> Result<Self> {
        Self::build_inner(
            collection,
            classifier,
            plan,
            pipeline_sets,
            corr_config,
            include_event,
            match_detail,
            logsource_extractor,
            partition_rules,
        )
    }
}

impl<L> SchemaRouter<L> {
    /// Build a router that prunes with `extractor`, a custom
    /// [`ExtractLogSource`] implementation. Arguments are otherwise as in
    /// [`SchemaRouter::build`]. The recognized schema's implied logsource
    /// still fills any dimension the extractor leaves unset.
    #[allow(clippy::too_many_arguments)]
    pub fn build_with_logsource_extractor(
        collection: &SigmaCollection,
        classifier: SchemaClassifier,
        plan: RoutingPlan,
        pipeline_sets: Vec<Vec<Pipeline>>,
        corr_config: CorrelationConfig,
        include_event: bool,
        match_detail: MatchDetailLevel,
        extractor: L,
        partition_rules: bool,
    ) -> Result<Self> {
        Self::build_inner(
            collection,
            classifier,
            plan,
            pipeline_sets,
            corr_config,
            include_event,
            match_detail,
            Some(extractor),
            partition_rules,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_inner(
        collection: &SigmaCollection,
        classifier: SchemaClassifier,
        plan: RoutingPlan,
        pipeline_sets: Vec<Vec<Pipeline>>,
        corr_config: CorrelationConfig,
        include_event: bool,
        match_detail: MatchDetailLevel,
        logsource_extractor: Option<L>,
        partition_rules: bool,
    ) -> Result<Self> {
        // Optional, gated per-schema rule partitioning: each engine bound only
        // to platform-locked schemas compiles just the rules whose product can
        // apply, cutting the N-copies memory cost. Off by default and disabled
        // for any set whose pipelines rewrite product.
        let partition = if partition_rules {
            plan.set_product_partition()
        } else {
            vec![None; pipeline_sets.len()]
        };

        // Sets an ambiguous event can land on: a schema routed there can win
        // a tie against a schema that implies a different logsource.
        let routes = plan.routes();
        let can_win_ambiguous_tie = |set_idx: usize| {
            routes
                .iter()
                .filter(|(set, _)| *set == set_idx)
                .any(|(_, schema)| {
                    let implied = plan.schema_logsource(schema);
                    classifier
                        .tie_peers(schema)
                        .any(|peer| plan.schema_logsource(peer) != implied)
                })
        };

        let mut shared_collection: Option<Arc<SigmaCollection>> = None;
        let mut engines = Vec::with_capacity(pipeline_sets.len());
        let mut field_maps = Vec::with_capacity(pipeline_sets.len());
        let mut fallbacks = Vec::with_capacity(pipeline_sets.len());
        for (idx, set) in pipeline_sets.iter().enumerate() {
            let mut engine = Engine::new();
            engine.set_include_event(include_event);
            engine.set_match_detail(match_detail);
            for p in set {
                engine.add_pipeline(p.clone());
            }
            // Partition only when the set has an allowed-product set and no
            // pipeline rewrites product; otherwise compile the full ruleset.
            let partitioned = partition
                .get(idx)
                .and_then(|o| o.as_ref())
                .filter(|_| !set.iter().any(pipeline_changes_product));
            let mut fallback = None;
            match partitioned {
                Some(products) => {
                    let mut filtered = collection.clone();
                    filtered.rules.retain(|r| rule_product_kept(r, products));
                    engine.add_collection(&filtered)?;
                    let removes_rules = filtered.rules.len() < collection.rules.len();
                    if removes_rules
                        && (logsource_extractor.is_some() || can_win_ambiguous_tie(idx))
                    {
                        let shared =
                            shared_collection.get_or_insert_with(|| Arc::new(collection.clone()));
                        fallback = Some(PartitionFallback {
                            collection: Arc::clone(shared),
                            kept_products: products.clone(),
                            pipelines: set.clone(),
                            settings: EngineSettings {
                                include_event,
                                match_detail,
                                bloom_prefilter: false,
                                bloom_max_bytes: None,
                                #[cfg(feature = "daachorse-index")]
                                cross_rule_ac: false,
                            },
                            engine: OnceLock::new(),
                        });
                    }
                }
                None => engine.add_collection(collection)?,
            }
            engines.push(engine);
            fallbacks.push(fallback);
            field_maps.push(collect_field_map(set));
        }

        // The shared correlation store is Sigma-native (no pipeline): group-by
        // names stay logical and are mapped per schema at feed time. Its inner
        // detection engine is unused (routed detection runs in `engines`).
        let correlation = if collection.correlations.is_empty() {
            None
        } else {
            let mut ce = CorrelationEngine::new(corr_config);
            ce.set_include_event(include_event);
            ce.set_match_detail(match_detail);
            ce.add_collection(collection)?;
            Some(ce)
        };

        Ok(SchemaRouter {
            classifier,
            plan,
            engines,
            field_maps,
            correlation,
            logsource_extractor,
            logsource_ambiguous: AtomicU64::new(0),
            fallbacks,
        })
    }

    fn route_ctx(&self) -> RouteCtx<'_, L> {
        RouteCtx {
            classifier: &self.classifier,
            plan: &self.plan,
            engines: &self.engines,
            fallbacks: &self.fallbacks,
            extractor: self.logsource_extractor.as_ref(),
            ambiguous: &self.logsource_ambiguous,
        }
    }

    /// Set global `include_event` on every per-schema engine and the shared
    /// correlation store. Takes effect for the next event evaluated.
    pub fn set_include_event(&mut self, include: bool) {
        for engine in &mut self.engines {
            engine.set_include_event(include);
        }
        self.update_fallbacks(|settings| settings.include_event = include);
        if let Some(correlation) = &mut self.correlation {
            correlation.set_include_event(include);
        }
    }

    /// Enable or disable bloom pre-filtering on every per-schema engine (see
    /// [`Engine::set_bloom_prefilter`]). Off by default.
    pub fn set_bloom_prefilter(&mut self, enabled: bool) {
        for engine in &mut self.engines {
            engine.set_bloom_prefilter(enabled);
        }
        self.update_fallbacks(|settings| settings.bloom_prefilter = enabled);
    }

    /// Set the bloom memory budget of every per-schema engine (see
    /// [`Engine::set_bloom_max_bytes`]).
    pub fn set_bloom_max_bytes(&mut self, max_bytes: usize) {
        for engine in &mut self.engines {
            engine.set_bloom_max_bytes(max_bytes);
        }
        self.update_fallbacks(|settings| settings.bloom_max_bytes = Some(max_bytes));
    }

    /// Enable or disable the cross-rule Aho-Corasick pre-filter on every
    /// per-schema engine (see [`Engine::set_cross_rule_ac`]). Off by default.
    /// Available behind the `daachorse-index` Cargo feature.
    #[cfg(feature = "daachorse-index")]
    pub fn set_cross_rule_ac(&mut self, enabled: bool) {
        for engine in &mut self.engines {
            engine.set_cross_rule_ac(enabled);
        }
        self.update_fallbacks(|settings| settings.cross_rule_ac = enabled);
    }

    /// Fields the cross-rule AC index left without an automaton, summed over
    /// every per-schema engine (see [`Engine::cross_rule_ac_unindexed_fields`]).
    /// Available behind the `daachorse-index` Cargo feature.
    #[cfg(feature = "daachorse-index")]
    pub fn cross_rule_ac_unindexed_fields(&self) -> usize {
        let fallbacks = self
            .fallbacks
            .iter()
            .flatten()
            .filter_map(|f| f.engine.get());
        self.engines
            .iter()
            .chain(fallbacks)
            .map(Engine::cross_rule_ac_unindexed_fields)
            .sum()
    }

    /// Change the settings partition fallbacks compile with, and apply them
    /// to any fallback engine already compiled.
    fn update_fallbacks(&mut self, change: impl Fn(&mut EngineSettings)) {
        for fallback in self.fallbacks.iter_mut().flatten() {
            change(&mut fallback.settings);
            if let Some(engine) = fallback.engine.get_mut() {
                fallback.settings.apply(engine);
            }
        }
    }

    /// The unknown-handling policy this router enforces.
    pub fn on_unknown(&self) -> OnUnknown {
        self.plan.on_unknown()
    }

    /// Whether this router has a correlation store.
    pub fn has_correlations(&self) -> bool {
        self.correlation.is_some()
    }

    /// Number of detection rules (same across every per-schema engine, unless
    /// per-schema rule partitioning is enabled; see [`engine_rule_counts`]).
    ///
    /// [`engine_rule_counts`]: SchemaRouter::engine_rule_counts
    pub fn detection_rule_count(&self) -> usize {
        self.engines.first().map(|e| e.rule_count()).unwrap_or(0)
    }

    /// Per-pipeline-set detection rule counts, in set order. Equal across sets
    /// unless per-schema rule partitioning is enabled, in which case
    /// platform-locked sets carry fewer rules than the default set.
    pub fn engine_rule_counts(&self) -> Vec<usize> {
        self.engines.iter().map(Engine::rule_count).collect()
    }

    /// Total rule candidates pruned by logsource across every per-schema
    /// engine (each event routes to exactly one engine).
    pub fn logsource_pruned_total(&self) -> u64 {
        let fallbacks = self
            .fallbacks
            .iter()
            .flatten()
            .filter_map(|f| f.engine.get());
        self.engines
            .iter()
            .chain(fallbacks)
            .map(Engine::logsource_pruned_total)
            .sum()
    }

    /// Total evaluate calls with no extractable event logsource (fail-open)
    /// across every per-schema engine.
    pub fn logsource_absent_total(&self) -> u64 {
        self.engines
            .iter()
            .map(Engine::logsource_absent_total)
            .sum()
    }

    /// Total events evaluated without their schema's implied logsource
    /// because the winning signature tied, at the same specificity, with a
    /// different-name signature implying a different logsource. Those events
    /// are pruned only by their own logsource fields, so every rule their
    /// fields do not rule out is evaluated. Zero unless logsource routing is
    /// enabled (an extractor is set).
    pub fn logsource_ambiguous_total(&self) -> u64 {
        self.logsource_ambiguous.load(Ordering::Relaxed)
    }

    /// Static per-schema pruning summary: for each schema with an implied
    /// logsource, how many rules its events evaluate versus prune. Empty when
    /// logsource routing is disabled (no extractor). Sorted by descending
    /// pruned count, then schema name.
    pub fn schema_pruning_summary(&self) -> Vec<SchemaPruning> {
        if self.logsource_extractor.is_none() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for schema in self.plan.schemas_with_logsource() {
            let Some(implied) = self.plan.schema_logsource(&schema) else {
                continue;
            };
            let set = match self.plan.decide(Some(&schema)) {
                RouteDecision::Evaluate { set, .. } => set,
                RouteDecision::Drop | RouteDecision::Error => 0,
            };
            let (eligible, pruned) = self.engines[set].logsource_eligibility(implied);
            out.push(SchemaPruning {
                schema,
                eligible,
                pruned,
            });
        }
        out.sort_by(|a, b| {
            b.pruned
                .cmp(&a.pruned)
                .then_with(|| a.schema.cmp(&b.schema))
        });
        out
    }

    /// Number of correlation rules in the shared store (0 when none).
    pub fn correlation_rule_count(&self) -> usize {
        self.correlation
            .as_ref()
            .map(|c| c.correlation_rule_count())
            .unwrap_or(0)
    }

    /// Number of live correlation window-state entries (0 when none).
    pub fn state_count(&self) -> usize {
        self.correlation
            .as_ref()
            .map(|c| c.state_count())
            .unwrap_or(0)
    }

    /// Resolve a rule key (an id, or a title for a rule without one) to the
    /// documentation of every loaded rule that carries it.
    ///
    /// A rule set is compiled once per pipeline-set, so the same rule usually
    /// yields one candidate per schema. Candidates whose post-pipeline metadata
    /// is identical collapse to a single answer; a rule whose pipelines rewrite
    /// its documentation differently per schema stays
    /// [`Ambiguous`](RuleMetadataLookup::Ambiguous).
    pub fn rule_metadata(&self, key: &str) -> RuleMetadataLookup {
        let mut variants = Vec::new();
        for engine in &self.engines {
            engine.collect_rule_metadata(key, &mut variants);
        }
        if let Some(correlation) = &self.correlation {
            correlation.collect_rule_metadata(key, &mut variants);
        }
        RuleMetadataLookup::from_variants(variants)
    }

    /// Introspect the shared correlation store, if any (id/group filtered).
    pub fn correlation_introspect(
        &self,
        id: Option<&str>,
        group: Option<&str>,
    ) -> Option<CorrelationStateSnapshot> {
        self.correlation
            .as_ref()
            .map(|c| c.introspect_filtered(id, group))
    }

    /// Like [`correlation_introspect`](Self::correlation_introspect), keeping
    /// only groups owned by `tenant` when it is set.
    pub fn correlation_introspect_for_tenant(
        &self,
        id: Option<&str>,
        group: Option<&str>,
        tenant: Option<&crate::tenant::TenantId>,
    ) -> Option<CorrelationStateSnapshot> {
        self.correlation
            .as_ref()
            .map(|c| c.introspect_for_tenant(id, group, tenant))
    }

    /// Export the shared correlation state, if any, for hot-reload carry-over.
    pub fn export_state(&self) -> Option<CorrelationSnapshot> {
        self.correlation.as_ref().map(|c| c.export_state())
    }

    /// Entries evicted because a tenant hit its correlation quota since the
    /// previous call, draining the counter.
    pub fn take_tenant_quota_evictions(&mut self) -> u64 {
        self.correlation
            .as_mut()
            .map_or(0, |c| c.take_tenant_quota_evictions())
    }

    /// Events skipped by `require_tenant` since the previous call, draining the
    /// counter.
    pub fn take_untenanted_skipped(&mut self) -> u64 {
        self.correlation
            .as_mut()
            .map_or(0, |c| c.take_untenanted_skipped())
    }

    /// Import previously exported correlation state into the shared store.
    /// No-op (returns `true`) when there is no correlation store.
    pub fn import_state(&mut self, snapshot: CorrelationSnapshot) -> bool {
        self.import_state_detailed(snapshot).is_some()
    }

    /// Like [`import_state`](Self::import_state), returning the restored and
    /// discarded entry counts. No correlation store restores nothing.
    pub fn import_state_detailed(
        &mut self,
        snapshot: CorrelationSnapshot,
    ) -> Option<crate::ImportStats> {
        match &mut self.correlation {
            Some(c) => c.import_state_detailed(snapshot),
            None => Some(crate::ImportStats::default()),
        }
    }

    /// Stateless classify + detection for a batch. Safe to call under a shared
    /// borrow when there is no correlation store; see [`Self::process_batch`].
    pub fn detect_batch<E: Event + Sync>(&self, events: &[&E]) -> Vec<ProcessResult>
    where
        L: ExtractLogSource<E> + Sync,
    {
        let ctx = self.route_ctx();
        let phase1: Vec<Routed1> = crate::parallel::map_ordered(events, |e| detect_one(&ctx, *e));
        phase1
            .into_iter()
            .map(|routed| match routed {
                Routed1::Skip => Vec::new(),
                Routed1::Eval { detections, .. } => detections
                    .into_iter()
                    .map(|identified| identified.result)
                    .collect(),
            })
            .collect()
    }

    /// Route a batch of events: parallel classify + detection, then sequential
    /// correlation into the shared store. Mirrors
    /// `CorrelationEngine::process_batch`: the stateless phase runs concurrently
    /// (under the `parallel` feature) and the stateful correlation phase runs
    /// in order. Drop/error outcomes yield empty results for that event.
    ///
    /// When there is no correlation store this is equivalent to [`Self::detect_batch`]
    /// and only needs a shared borrow of the router.
    pub fn process_batch<E: Event + Sync>(&mut self, events: &[&E]) -> Vec<ProcessResult>
    where
        L: ExtractLogSource<E> + Sync,
    {
        self.process_batch_for_tenants(events, &[])
    }

    /// Route a batch of events with a parallel tenant slice, feeding each
    /// detection into the shared correlation store under its tenant.
    ///
    /// `tenants` is empty (untenanted) or exactly parallel to `events`.
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
        if self.correlation.is_none() {
            return self.detect_batch(events);
        }

        // Stateless phase: classify + route + detect. Borrows only `&self`
        // fields, so it parallelizes; correlation state is untouched here.
        let ctx = self.route_ctx();
        let phase1: Vec<Routed1> = crate::parallel::map_ordered(events, |e| detect_one(&ctx, *e));

        // Stateful phase: feed detections into the shared correlation store in
        // event order. Disjoint field borrows let the field maps and the
        // correlation store be held at once.
        let field_maps = &self.field_maps;
        let correlation = self.correlation.as_mut().expect("checked above");
        phase1
            .into_iter()
            .zip(events)
            .enumerate()
            .map(|(index, (routed, event))| match routed {
                Routed1::Skip => Vec::new(),
                Routed1::Eval { set, detections } => {
                    let mapped = MappedEvent::new(*event, &field_maps[set]);
                    correlation.correlate_identified_detections_for_tenant(
                        &mapped,
                        detections,
                        tenant_at(tenants, index),
                    )
                }
            })
            .collect()
    }

    /// Classify and route one event.
    pub fn route<E: Event>(&mut self, event: &E) -> RouteResult
    where
        L: ExtractLogSource<E>,
    {
        self.route_for_tenant(event, None)
    }

    /// Classify and route one event as `tenant`.
    pub fn route_for_tenant<E: Event>(
        &mut self,
        event: &E,
        tenant: Option<&TenantId>,
    ) -> RouteResult
    where
        L: ExtractLogSource<E>,
    {
        let ctx = self.route_ctx();
        let classified = ctx.classify(event);
        let decision = self.plan.decide(classified.schema.as_deref());
        let detections = match decision {
            RouteDecision::Evaluate { set, .. } => ctx.evaluate(set, &classified, event),
            RouteDecision::Drop | RouteDecision::Error => Vec::new(),
        };
        let schema = classified.schema;
        match decision {
            RouteDecision::Drop => RouteResult {
                results: Vec::new(),
                schema,
                outcome: RouteOutcome::Dropped,
            },
            RouteDecision::Error => RouteResult {
                results: Vec::new(),
                schema,
                outcome: RouteOutcome::Errored,
            },
            RouteDecision::Evaluate { set, unknown } => {
                let results = match &mut self.correlation {
                    Some(ce) => {
                        let mapped = MappedEvent::new(event, &self.field_maps[set]);
                        ce.correlate_identified_detections_for_tenant(&mapped, detections, tenant)
                    }
                    None => detections
                        .into_iter()
                        .map(|identified| identified.result)
                        .collect(),
                };
                RouteResult {
                    results,
                    schema,
                    outcome: if unknown {
                        RouteOutcome::EvaluatedUnknown
                    } else {
                        RouteOutcome::Evaluated
                    },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JsonEvent;
    use crate::pipeline::parse_pipeline;
    use crate::schema::RoutingConfig;
    use rsigma_parser::parse_sigma_yaml;
    use serde_json::json;

    const RULES: &str = r#"
title: Whoami
id: rule-whoami
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
"#;

    const ECS_PIPELINE: &str = r#"
name: ecs_test
priority: 20
transformations:
  - id: map
    type: field_name_mapping
    mapping:
      CommandLine: process.command_line
      User: user.name
"#;

    fn plan(bindings: &[(&str, &[&str])]) -> RoutingPlan {
        let config = RoutingConfig {
            on_unknown: OnUnknown::Warn,
            default_pipelines: vec![],
            aliases: std::collections::HashMap::new(),
            bindings: bindings
                .iter()
                .map(|(s, ps)| crate::schema::SchemaBinding {
                    schema: (*s).to_string(),
                    pipelines: ps.iter().map(|p| (*p).to_string()).collect(),
                    logsource: None,
                })
                .collect(),
        };
        RoutingPlan::from_config(&config)
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "tenants must be empty or parallel to events")]
    fn a_detection_only_router_checks_the_tenant_slice_length() {
        let collection = parse_sigma_yaml(RULES).unwrap();
        let mut router = SchemaRouter::build(
            &collection,
            SchemaClassifier::builtin(),
            plan(&[]),
            vec![vec![]],
            CorrelationConfig::default(),
            false,
            MatchDetailLevel::Off,
            None,
            false,
        )
        .unwrap();
        let value = json!({"CommandLine": "whoami"});
        let event = JsonEvent::borrow(&value);
        router.process_batch_for_tenants(&[&event], &[None, None]);
    }

    #[test]
    fn routes_ecs_event_to_ecs_engine() {
        let collection = parse_sigma_yaml(RULES).unwrap();
        // set 0 = default (no pipeline, Sigma-native fields), set 1 = ECS.
        let ecs = parse_pipeline(ECS_PIPELINE).unwrap();
        let plan = plan(&[("ecs", &["ecs_test"])]);
        let mut router = SchemaRouter::build(
            &collection,
            SchemaClassifier::builtin(),
            plan,
            vec![vec![], vec![ecs]],
            CorrelationConfig::default(),
            false,
            MatchDetailLevel::Off,
            None,
            false,
        )
        .unwrap();

        // ECS event: fields are renamed; only the ECS engine matches it.
        let ecs_event = json!({"ecs.version": "8.0.0", "process.command_line": "cmd /c whoami"});
        let r = router.route(&JsonEvent::borrow(&ecs_event));
        assert_eq!(r.schema.as_deref(), Some("ecs"));
        assert_eq!(r.outcome, RouteOutcome::Evaluated);
        assert_eq!(r.results.len(), 1, "ECS event matches via the ECS engine");

        // A Sigma-native event with the same command is unrecognized here
        // (no ecs.version, no sysmon markers) -> generic_json -> default set,
        // which has no pipeline, so the rule's CommandLine matches it.
        let native = json!({"CommandLine": "cmd /c whoami"});
        let r = router.route(&JsonEvent::borrow(&native));
        assert_eq!(r.schema.as_deref(), Some("generic_json"));
        assert_eq!(r.results.len(), 1);
    }

    #[test]
    fn cross_schema_correlation_groups_the_same_entity() {
        // A detection rule plus an event_count correlation grouped by User.
        // The same user appears once as an ECS event (user.name) and once as a
        // Sigma-native event (User); they must land in the same window and fire.
        let rules = r#"
title: Whoami
id: rule-whoami
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
---
title: Repeated whoami by user
correlation:
    type: event_count
    rules:
        - rule-whoami
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 2
level: high
"#;
        let collection = parse_sigma_yaml(rules).unwrap();
        let ecs = parse_pipeline(ECS_PIPELINE).unwrap();
        // set 0 = default (Sigma-native), set 1 = ECS. ecs schema -> set 1;
        // everything else (incl. the generic event) -> default set 0.
        let plan = plan(&[("ecs", &["ecs_test"])]);

        let config = CorrelationConfig {
            timestamp_fallback: crate::correlation_engine::TimestampFallback::WallClock,
            ..Default::default()
        };

        let mut router = SchemaRouter::build(
            &collection,
            SchemaClassifier::builtin(),
            plan,
            vec![vec![], vec![ecs]],
            config,
            false,
            MatchDetailLevel::Off,
            None,
            false,
        )
        .unwrap();

        // First occurrence: ECS event for user alice.
        let ecs_event = json!({
            "ecs.version": "8.0.0",
            "process.command_line": "cmd /c whoami",
            "user.name": "alice"
        });
        let r1 = router.route(&JsonEvent::borrow(&ecs_event));
        assert_eq!(r1.schema.as_deref(), Some("ecs"));
        assert!(
            !r1.results.iter().any(|r| r.is_correlation()),
            "first event must not fire the count>=2 correlation yet"
        );

        // Second occurrence: Sigma-native event for the SAME user alice.
        let native_event = json!({"CommandLine": "cmd /c whoami", "User": "alice"});
        let r2 = router.route(&JsonEvent::borrow(&native_event));
        assert!(
            r2.results.iter().any(|r| r.is_correlation()),
            "the two events share group User=alice across schemas and must correlate"
        );
    }

    #[test]
    fn drop_policy_skips_unknown_events() {
        let collection = parse_sigma_yaml(RULES).unwrap();
        let config = RoutingConfig {
            on_unknown: OnUnknown::Drop,
            default_pipelines: vec![],
            aliases: std::collections::HashMap::new(),
            // Bind generic_json away so a plain event is truly unknown.
            bindings: vec![],
        };
        let plan = RoutingPlan::from_config(&config);
        let mut router = SchemaRouter::build(
            &collection,
            // Classifier with no generic_json: only ECS recognized, everything
            // else is unknown.
            SchemaClassifier::new(vec![]),
            plan,
            vec![vec![]],
            CorrelationConfig::default(),
            false,
            MatchDetailLevel::Off,
            None,
            false,
        )
        .unwrap();

        let native = json!({"CommandLine": "cmd /c whoami"});
        let r = router.route(&JsonEvent::borrow(&native));
        assert_eq!(r.schema, None);
        assert_eq!(r.outcome, RouteOutcome::Dropped);
        assert!(r.results.is_empty());
    }

    #[test]
    fn schema_derived_logsource_prunes_cross_product_rules() {
        // A Windows rule and a Linux rule that both match the same CommandLine.
        let rules = r#"
title: Win whoami
id: win-whoami
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
---
title: Linux whoami
id: linux-whoami
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
"#;
        let collection = parse_sigma_yaml(rules).unwrap();
        // A flat Sysmon event with no explicit `product` field. It classifies
        // as `sysmon`, whose built-in implied logsource is product: windows.
        let event = json!({
            "EventID": 1,
            "ProcessGuid": "{abc}",
            "Image": "C:/Windows/System32/cmd.exe",
            "CommandLine": "cmd /c whoami"
        });

        // Without an extractor, no pruning: both rules fire.
        let mut plain = SchemaRouter::build(
            &collection,
            SchemaClassifier::builtin(),
            plan(&[]),
            vec![vec![]],
            CorrelationConfig::default(),
            false,
            MatchDetailLevel::Off,
            None,
            false,
        )
        .unwrap();
        let r = plain.route(&JsonEvent::borrow(&event));
        assert_eq!(r.schema.as_deref(), Some("sysmon"));
        assert_eq!(r.results.len(), 2, "no pruning without an extractor");

        // With an extractor, the schema-derived product (windows) prunes the
        // Linux rule while keeping the Windows rule, even though the event
        // carries no explicit product field.
        let mut pruned = SchemaRouter::build(
            &collection,
            SchemaClassifier::builtin(),
            plan(&[]),
            vec![vec![]],
            CorrelationConfig::default(),
            false,
            MatchDetailLevel::Off,
            Some(LogSourceExtractor::new()),
            false,
        )
        .unwrap();
        let r = pruned.route(&JsonEvent::borrow(&event));
        assert_eq!(r.schema.as_deref(), Some("sysmon"));
        assert_eq!(
            r.results.len(),
            1,
            "schema-derived product prunes the Linux rule"
        );
        assert_eq!(pruned.logsource_pruned_total(), 1);

        // The static per-schema summary reflects the same eligibility: for the
        // sysmon schema (product: windows) the Linux rule is pruned and the
        // Windows rule stays eligible. Cross-platform schemas are absent, and
        // the summary is empty without an extractor.
        let summary = pruned.schema_pruning_summary();
        let sysmon = summary
            .iter()
            .find(|s| s.schema == "sysmon")
            .expect("sysmon in summary");
        assert_eq!(sysmon.eligible, 1);
        assert_eq!(sysmon.pruned, 1);
        assert!(!summary.iter().any(|s| s.schema == "ecs"));
        assert!(plain.schema_pruning_summary().is_empty());
    }

    #[test]
    fn partition_rules_compiles_only_applicable_rules_per_set() {
        // Windows, Linux, and a product-less rule that all match `whoami`.
        let rules = r#"
title: Win whoami
id: win-whoami
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
---
title: Linux whoami
id: linux-whoami
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
---
title: Any whoami
id: any-whoami
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: high
"#;
        let collection = parse_sigma_yaml(rules).unwrap();
        // Bind sysmon (implied product: windows) to a non-default pipeline-set
        // (a no-op field mapping so the set differs from the default set).
        let passthrough = parse_pipeline(
            "name: passthrough\npriority: 10\ntransformations:\n  - id: noop\n    type: field_name_mapping\n    mapping:\n      __unused_a: __unused_b\n",
        )
        .unwrap();
        let plan = plan(&[("sysmon", &["passthrough"])]);

        let router = SchemaRouter::build(
            &collection,
            SchemaClassifier::builtin(),
            plan,
            vec![vec![], vec![passthrough]],
            CorrelationConfig::default(),
            false,
            MatchDetailLevel::Off,
            None,
            true, // partition rules
        )
        .unwrap();

        // Default set keeps all 3; the sysmon set drops the Linux rule and
        // keeps the Windows and product-less rules.
        assert_eq!(router.engine_rule_counts(), vec![3, 2]);
    }

    /// Only a partitioned set whose schema can win a tie against a schema
    /// with another logsource keeps the removed rules, and their engine is
    /// compiled on the first ambiguous event rather than at build time.
    #[test]
    fn partition_fallback_is_kept_only_where_a_tie_can_land_and_built_lazily() {
        let rules = r#"
title: Win whoami
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
---
title: Linux whoami
logsource:
    product: linux
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"#;
        let config = r#"
schemas:
  - name: vendor_a
    specificity: 70
    match:
      - field_present: vendor_marker
  - name: vendor_b
    specificity: 70
    match:
      - field_present: vendor_marker
routing:
  bindings:
    - schema: vendor_a
      pipelines: [noop_a]
      logsource:
        product: windows
    - schema: vendor_b
      pipelines: [noop_b]
      logsource:
        product: linux
    - schema: sysmon
      pipelines: [noop_c]
"#;
        let (signatures, routing) = crate::schema::parse_schema_config(config).unwrap();
        let plan = RoutingPlan::from_config(&routing.unwrap());
        let pipeline_sets: Vec<Vec<Pipeline>> = plan
            .pipeline_sets()
            .iter()
            .map(|names| {
                names
                    .iter()
                    .map(|n| {
                        parse_pipeline(&format!(
                            "name: {n}\npriority: 10\ntransformations:\n  - id: noop\n    type: field_name_mapping\n    mapping:\n      __unused_{n}: __unused_b\n"
                        ))
                        .unwrap()
                    })
                    .collect()
            })
            .collect();
        let set_of = |schema: &str| match plan.decide(Some(schema)) {
            RouteDecision::Evaluate { set, .. } => set,
            other => panic!("unexpected {other:?}"),
        };
        let (a, b, sysmon) = (set_of("vendor_a"), set_of("vendor_b"), set_of("sysmon"));
        let build = |extractor: Option<LogSourceExtractor>| {
            SchemaRouter::build(
                &parse_sigma_yaml(rules).unwrap(),
                SchemaClassifier::with_user_signatures(signatures.clone()),
                plan.clone(),
                pipeline_sets.clone(),
                CorrelationConfig::default(),
                false,
                MatchDetailLevel::Off,
                extractor,
                true,
            )
            .unwrap()
        };

        // Without logsource routing only an ambiguous event needs the removed
        // rules. vendor_a wins its tie against vendor_b, which implies linux;
        // vendor_b never wins it, and sysmon has no tie peer that sorts after
        // it.
        let router = build(None);
        assert!(router.fallbacks[a].is_some());
        assert!(router.fallbacks[b].is_none());
        assert!(router.fallbacks[sysmon].is_none());
        assert!(
            router.fallbacks[0].is_none(),
            "the default set is never partitioned"
        );

        // With it, an explicit product field can contradict any schema, so
        // every set that removed rules keeps them.
        let mut router = build(Some(LogSourceExtractor::new()));
        assert!(router.fallbacks[a].is_some());
        assert!(router.fallbacks[b].is_some());
        assert!(router.fallbacks[sysmon].is_some());
        assert!(router.fallbacks[0].is_none());
        assert!(
            Arc::ptr_eq(
                &router.fallbacks[a].as_ref().unwrap().collection,
                &router.fallbacks[b].as_ref().unwrap().collection
            ),
            "fallbacks share one copy of the parsed rules"
        );

        let fallback = router.fallbacks[a].as_ref().unwrap();
        assert!(
            fallback.engine.get().is_none(),
            "compiled on first use only"
        );

        router.set_include_event(true);
        let value = json!({"vendor_marker": true, "CommandLine": "whoami"});
        let r = router.route(&JsonEvent::borrow(&value));
        assert_eq!(r.results.len(), 2);
        assert!(
            r.results
                .iter()
                .all(|m| m.as_detection().is_some_and(|d| d.event.is_some())),
            "the fallback engine inherits include_event"
        );
        let fallback = router.fallbacks[a].as_ref().unwrap();
        assert_eq!(fallback.engine.get().map(Engine::rule_count), Some(1));
    }

    #[test]
    fn partition_rules_off_keeps_full_ruleset() {
        let rules = r#"
title: Win whoami
id: win-whoami
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
---
title: Linux whoami
id: linux-whoami
logsource:
    product: linux
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
"#;
        let collection = parse_sigma_yaml(rules).unwrap();
        let passthrough = parse_pipeline(
            "name: passthrough\npriority: 10\ntransformations:\n  - id: noop\n    type: field_name_mapping\n    mapping:\n      __unused_a: __unused_b\n",
        )
        .unwrap();
        let plan = plan(&[("sysmon", &["passthrough"])]);
        let router = SchemaRouter::build(
            &collection,
            SchemaClassifier::builtin(),
            plan,
            vec![vec![], vec![passthrough]],
            CorrelationConfig::default(),
            false,
            MatchDetailLevel::Off,
            None,
            false, // partitioning off
        )
        .unwrap();
        assert_eq!(router.engine_rule_counts(), vec![2, 2]);
    }
}
