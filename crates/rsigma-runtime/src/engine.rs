use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use rsigma_eval::event::Event;
use rsigma_eval::pipeline::sources::DynamicSource;
use rsigma_eval::{
    CorrelationConfig, CorrelationEngine, CorrelationSnapshot, CorrelationStateSnapshot, Engine,
    LogSourceExtractor, MatchDetailLevel, Pipeline, ProcessResult, RoutingPlan, RuleFieldSet,
    RuleMetadataLookup, RulesetEngines, RulesetStats, RulesetUnit, SchemaClassifier, SchemaPruning,
    SchemaRouter, TenantId, UnitEngine, parse_pipeline_file,
};
use rsigma_parser::SigmaCollection;
use rsigma_parser::ruleset::{ResolveOptions, resolve_ruleset};

use crate::ruleset::{RuleSource, RulesetBinding, load_pipelines as load_ruleset_pipelines};
use crate::sources::{self, SourceResolver, TemplateExpander};

/// How `load_rules` obtains dynamic source values.
///
/// A full reload fetches every source. A rebuild triggered by a source
/// change reads the cache and fetches only sources that have no cached value,
/// so the rebuild does not poll every source again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SourceFetch {
    /// Fetch every source.
    #[default]
    Fresh,
    /// Use cached values, fetching only cache misses.
    CacheFirst,
}

/// Wraps a CorrelationEngine (or a plain Engine) and provides the interface
/// the runtime needs: process events, reload rules, and query state.
pub struct RuntimeEngine {
    engine: EngineVariant,
    pipelines: Vec<Pipeline>,
    pipeline_paths: Vec<PathBuf>,
    rules_path: std::path::PathBuf,
    corr_config: CorrelationConfig,
    include_event: bool,
    source_resolver: Option<Arc<dyn SourceResolver>>,
    /// How the next `load_rules` resolves dynamic sources. Full reloads use
    /// [`SourceFetch::Fresh`]. A cache-first rebuild sets
    /// [`SourceFetch::CacheFirst`] for that load only.
    source_fetch: SourceFetch,
    /// External dynamic source declarations (loaded via `--source`). Pipelines
    /// reference these with `${source.<id>}`; the declarations themselves no
    /// longer live inside pipeline files. Resolved and expanded into the
    /// pipelines on every `load_rules()`.
    external_sources: Vec<DynamicSource>,
    allow_remote_include: bool,
    /// Refuse to load a rule set in which any document failed to parse.
    strict_rules: bool,
    /// Parse errors in the rule set loaded by the last successful
    /// `load_rules()`.
    parse_errors: usize,
    /// Opt-in bloom-filter pre-filtering of positive substring matchers.
    /// Forwarded to the inner detection engine on every rule reload.
    bloom_prefilter: bool,
    /// Optional override for the bloom memory budget in bytes. `None`
    /// means use the eval crate default.
    bloom_max_bytes: Option<usize>,
    /// Match-detail verbosity forwarded to the inner detection engine on
    /// every rule reload. `Off` by default (historical wire shape).
    match_detail: MatchDetailLevel,
    /// Opt-in cross-rule Aho-Corasick pre-filter. Forwarded to the inner
    /// detection engine on every rule reload. Available behind the
    /// `daachorse-index` Cargo feature.
    #[cfg(feature = "daachorse-index")]
    cross_rule_ac: bool,
    /// Post-pipeline rule field set, refreshed at the end of every
    /// `load_rules()`. Wrapped in `ArcSwap` so readers (e.g. the daemon's
    /// `/api/v1/fields/*` endpoints) can snapshot a stable view without
    /// blocking the hot path during a reload.
    rule_field_set: Arc<ArcSwap<RuleFieldSet>>,
    /// Optional schema-routing spec. When set, `load_rules` builds a
    /// [`SchemaRouter`] (one detection engine per pipeline-set plus a shared
    /// correlation store) instead of a single engine, and rebuilds it on
    /// hot-reload from the same spec.
    routing: Option<RoutingSpec>,
    /// Opt-in conflict-based logsource extractor. Forwarded to the inner
    /// detection engine(s) on every rule reload and carried across hot-reload.
    logsource_extractor: Option<LogSourceExtractor>,
    /// Where the engine loads rules from: one path or named rulesets.
    rule_source: RuleSource,
    /// Classifier for `when` schema bindings in ruleset mode.
    ruleset_classifier: Option<Arc<SchemaClassifier>>,
}

/// Everything needed to (re)build a [`SchemaRouter`] on rule load. Pipeline
/// sets are pre-resolved by the caller (builtin names + files), index-aligned
/// with `plan.pipeline_sets()`.
#[derive(Clone)]
pub struct RoutingSpec {
    pub classifier: SchemaClassifier,
    pub plan: RoutingPlan,
    pub pipeline_sets: Vec<Vec<Pipeline>>,
    /// Opt-in, gated per-schema rule partitioning: compile each platform-locked
    /// per-schema engine with only the rules whose product can apply.
    pub partition_rules: bool,
}

enum EngineVariant {
    DetectionOnly(Box<Engine>),
    WithCorrelations(Box<CorrelationEngine>),
    Routed(Box<SchemaRouter>),
    Rulesets(Box<RulesetEngines>),
}

/// Summary statistics about the loaded engine state.
#[derive(Debug, Clone, Copy)]
pub struct EngineStats {
    pub detection_rules: usize,
    pub correlation_rules: usize,
    pub state_entries: usize,
    /// Rule documents that failed to parse and were left out of the
    /// loaded rule set.
    pub parse_errors: usize,
}

impl RuntimeEngine {
    pub fn new(
        rules_path: std::path::PathBuf,
        pipelines: Vec<Pipeline>,
        corr_config: CorrelationConfig,
        include_event: bool,
    ) -> Self {
        RuntimeEngine {
            engine: EngineVariant::DetectionOnly(Box::new(Engine::new())),
            pipelines,
            pipeline_paths: Vec::new(),
            rules_path: rules_path.clone(),
            corr_config,
            include_event,
            source_resolver: None,
            source_fetch: SourceFetch::Fresh,
            external_sources: Vec::new(),
            allow_remote_include: false,
            strict_rules: false,
            parse_errors: 0,
            bloom_prefilter: false,
            bloom_max_bytes: None,
            match_detail: MatchDetailLevel::Off,
            #[cfg(feature = "daachorse-index")]
            cross_rule_ac: false,
            rule_field_set: Arc::new(ArcSwap::from_pointee(RuleFieldSet::default())),
            routing: None,
            logsource_extractor: None,
            rule_source: RuleSource::Path(rules_path.clone()),
            ruleset_classifier: None,
        }
    }

    /// Build an engine that loads several named rulesets.
    pub fn with_rulesets(
        bindings: Vec<RulesetBinding>,
        corr_config: CorrelationConfig,
        include_event: bool,
    ) -> Self {
        let mut engine = Self::new(PathBuf::new(), Vec::new(), corr_config, include_event);
        engine.rule_source = RuleSource::Rulesets(bindings);
        engine
    }

    /// Where this engine loads its rules from.
    pub fn rule_source(&self) -> &RuleSource {
        &self.rule_source
    }

    /// Set the schema classifier used by `when` bindings in ruleset mode.
    pub fn set_ruleset_classifier(&mut self, classifier: Option<Arc<SchemaClassifier>>) {
        self.ruleset_classifier = classifier;
    }

    /// The schema classifier used by `when` bindings, if one is configured.
    pub fn ruleset_classifier(&self) -> Option<Arc<SchemaClassifier>> {
        self.ruleset_classifier.clone()
    }

    /// Events refused by each ruleset's `when` binding since the previous
    /// call, draining the counters.
    pub fn take_ruleset_skipped(&self) -> Vec<(Arc<str>, u64)> {
        match &self.engine {
            EngineVariant::Rulesets(engines) => engines.take_skipped(),
            _ => Vec::new(),
        }
    }

    /// Per-ruleset loaded rule counts and schema bindings.
    pub fn ruleset_stats(&self) -> Vec<RulesetStats> {
        match &self.engine {
            EngineVariant::Rulesets(engines) => engines.ruleset_stats(),
            _ => Vec::new(),
        }
    }

    /// Enable schema routing. The next `load_rules()` builds a
    /// [`SchemaRouter`] from this spec instead of a single engine. Pass `None`
    /// to disable. Set before `load_rules()`; hot-reload carries it forward.
    pub fn set_routing(&mut self, spec: Option<RoutingSpec>) {
        self.routing = spec;
    }

    /// Whether schema routing is configured.
    pub fn has_routing(&self) -> bool {
        self.routing.is_some()
    }

    /// Return the routing spec, if any. Used by hot-reload to carry the
    /// configuration across a `RuntimeEngine` swap.
    pub fn routing(&self) -> Option<RoutingSpec> {
        self.routing.clone()
    }

    /// Set the opt-in logsource extractor. The next `load_rules()` forwards it
    /// to the inner detection engine(s); hot-reload carries it forward. Pass
    /// `None` to disable. Set before `load_rules()`.
    pub fn set_logsource_extractor(&mut self, extractor: Option<LogSourceExtractor>) {
        self.logsource_extractor = extractor;
    }

    /// Return the logsource extractor, if any. Used by hot-reload to carry the
    /// configuration across a `RuntimeEngine` swap.
    pub fn logsource_extractor(&self) -> Option<LogSourceExtractor> {
        self.logsource_extractor.clone()
    }

    /// Total rule candidates pruned by logsource across the active engine
    /// variant since the last load. Zero when no extractor is configured.
    pub fn logsource_pruned_total(&self) -> u64 {
        match &self.engine {
            EngineVariant::DetectionOnly(engine) => engine.logsource_pruned_total(),
            EngineVariant::WithCorrelations(engine) => engine.logsource_pruned_total(),
            EngineVariant::Routed(router) => router.logsource_pruned_total(),
            EngineVariant::Rulesets(engines) => engines.logsource_pruned_total(),
        }
    }

    /// Total evaluate calls with no extractable event logsource (fail-open)
    /// across the active engine variant.
    pub fn logsource_absent_total(&self) -> u64 {
        match &self.engine {
            EngineVariant::DetectionOnly(engine) => engine.logsource_absent_total(),
            EngineVariant::WithCorrelations(engine) => engine.logsource_absent_total(),
            EngineVariant::Routed(router) => router.logsource_absent_total(),
            EngineVariant::Rulesets(engines) => engines.logsource_absent_total(),
        }
    }

    /// Static per-schema logsource pruning summary. Non-empty only for the
    /// routed variant with logsource routing enabled.
    pub fn schema_pruning_summary(&self) -> Vec<SchemaPruning> {
        match &self.engine {
            EngineVariant::Routed(router) => router.schema_pruning_summary(),
            EngineVariant::Rulesets(engines) => engines.schema_pruning_summary(),
            EngineVariant::DetectionOnly(_) | EngineVariant::WithCorrelations(_) => Vec::new(),
        }
    }

    /// Return an immutable snapshot of the post-pipeline rule field set.
    ///
    /// Cheap to call: returns a refcounted handle that stays valid even if
    /// `load_rules()` runs concurrently. The daemon's field-observability
    /// endpoints use this to compute the intersection between observed
    /// event keys and rule-referenced fields without coordinating with the
    /// engine lock.
    pub fn rule_field_set(&self) -> Arc<RuleFieldSet> {
        self.rule_field_set.load_full()
    }

    /// Enable or disable bloom-filter pre-filtering on the inner detection
    /// engine. Off by default. Applies on the next `load_rules()`; pre-load
    /// callers should set this before calling `load_rules()`.
    pub fn set_bloom_prefilter(&mut self, enabled: bool) {
        self.bloom_prefilter = enabled;
    }

    /// Return the current bloom pre-filter setting. Used by hot-reload to
    /// carry tuning across a `RuntimeEngine` swap so a daemon-startup
    /// `set_bloom_prefilter(true)` does not silently revert on the first
    /// reload.
    pub fn bloom_prefilter(&self) -> bool {
        self.bloom_prefilter
    }

    /// Override the bloom memory budget on the inner detection engine.
    /// Applies on the next `load_rules()`.
    pub fn set_bloom_max_bytes(&mut self, max_bytes: usize) {
        self.bloom_max_bytes = Some(max_bytes);
    }

    /// Return the configured bloom memory budget, if one was set.
    pub fn bloom_max_bytes(&self) -> Option<usize> {
        self.bloom_max_bytes
    }

    /// Set the match-detail verbosity on the inner detection engine.
    /// `Off` by default. Applies on the next `load_rules()`; pre-load
    /// callers should set this before calling `load_rules()`.
    pub fn set_match_detail(&mut self, level: MatchDetailLevel) {
        self.match_detail = level;
    }

    /// Require a tenant on every event before correlation updates.
    ///
    /// Applies on the next `load_rules()`; pre-load callers should set this
    /// before calling `load_rules()`.
    pub fn set_require_tenant(&mut self, require: bool) {
        self.corr_config.require_tenant = require;
    }

    /// Whether correlation skips untenanted events.
    pub fn require_tenant(&self) -> bool {
        self.corr_config.require_tenant
    }

    /// Set the per-tenant correlation state cap. Applies on the next
    /// `load_rules()`; pre-load callers should set this before calling it.
    pub fn set_max_state_entries_per_tenant(&mut self, max: Option<usize>) {
        self.corr_config.max_state_entries_per_tenant = max;
    }

    /// Entries evicted because a tenant hit its correlation quota since the
    /// previous call, summed across engine variants.
    pub fn take_tenant_quota_evictions(&mut self) -> u64 {
        match &mut self.engine {
            EngineVariant::DetectionOnly(_) => 0,
            EngineVariant::WithCorrelations(engine) => engine.take_tenant_quota_evictions(),
            EngineVariant::Routed(router) => router.take_tenant_quota_evictions(),
            EngineVariant::Rulesets(engines) => engines.take_tenant_quota_evictions(),
        }
    }

    /// Events skipped by `require_tenant` since the previous call, summed across
    /// engine variants.
    pub fn take_untenanted_skipped(&mut self) -> u64 {
        match &mut self.engine {
            EngineVariant::DetectionOnly(_) => 0,
            EngineVariant::WithCorrelations(engine) => engine.take_untenanted_skipped(),
            EngineVariant::Routed(router) => router.take_untenanted_skipped(),
            EngineVariant::Rulesets(engines) => engines.take_untenanted_skipped(),
        }
    }

    /// Return the current match-detail verbosity. Used by hot-reload to
    /// carry the setting across a `RuntimeEngine` swap.
    pub fn match_detail(&self) -> MatchDetailLevel {
        self.match_detail
    }

    /// Enable or disable the cross-rule Aho-Corasick pre-filter on the
    /// inner detection engine. Off by default; the optimization helps only
    /// on substring-heavy rule sets > ~5K rules. Applies on the next
    /// `load_rules()`.
    ///
    /// Available behind the `daachorse-index` Cargo feature.
    #[cfg(feature = "daachorse-index")]
    pub fn set_cross_rule_ac(&mut self, enabled: bool) {
        self.cross_rule_ac = enabled;
    }

    /// Return the current cross-rule Aho-Corasick setting.
    #[cfg(feature = "daachorse-index")]
    pub fn cross_rule_ac(&self) -> bool {
        self.cross_rule_ac
    }

    /// Set a source resolver for dynamic pipeline sources.
    ///
    /// When set, `load_rules()` resolves dynamic sources and expands
    /// `${source.*}` templates before compiling rules.
    pub fn set_source_resolver(&mut self, resolver: Arc<dyn SourceResolver>) {
        self.source_resolver = Some(resolver);
    }

    /// Get the source resolver, if one is configured.
    pub fn source_resolver(&self) -> Option<&Arc<dyn SourceResolver>> {
        self.source_resolver.as_ref()
    }

    /// Choose how the next `load_rules` resolves dynamic sources.
    pub fn set_source_fetch(&mut self, fetch: SourceFetch) {
        self.source_fetch = fetch;
    }

    /// How the next `load_rules` resolves dynamic sources.
    pub fn source_fetch(&self) -> SourceFetch {
        self.source_fetch
    }

    /// Set the external dynamic source declarations (loaded via `--source`).
    /// The next `load_rules()` resolves them and expands `${source.*}`
    /// references in the pipelines; hot-reload carries them forward.
    pub fn set_external_sources(&mut self, sources: Vec<DynamicSource>) {
        self.external_sources = sources;
    }

    /// The external dynamic source declarations. Used by hot-reload to carry
    /// the configuration across a `RuntimeEngine` swap.
    pub fn external_sources(&self) -> &[DynamicSource] {
        &self.external_sources
    }

    /// Allow `include` directives to reference HTTP/NATS sources.
    pub fn set_allow_remote_include(&mut self, allow: bool) {
        self.allow_remote_include = allow;
    }

    /// Whether remote includes are allowed.
    pub fn allow_remote_include(&self) -> bool {
        self.allow_remote_include
    }

    /// Make `load_rules()` fail when any rule document fails to parse,
    /// instead of loading the documents that did parse. Off by default.
    /// Applies on the next `load_rules()`; hot-reload carries it forward.
    pub fn set_strict_rules(&mut self, strict: bool) {
        self.strict_rules = strict;
    }

    /// Whether strict rule loading is enabled.
    pub fn strict_rules(&self) -> bool {
        self.strict_rules
    }

    /// Set the pipeline file paths used for hot-reload.
    ///
    /// When paths are set, `load_rules()` re-reads pipeline YAML from disk
    /// before rebuilding the engine. This enables pipeline hot-reload
    /// alongside rule hot-reload.
    pub fn set_pipeline_paths(&mut self, paths: Vec<PathBuf>) {
        self.pipeline_paths = paths;
    }

    /// Return the pipeline file paths (used by the daemon to set up watchers).
    pub fn pipeline_paths(&self) -> &[PathBuf] {
        &self.pipeline_paths
    }

    /// Resolve dynamic sources in all pipelines and expand templates.
    ///
    /// This is the async entry point for source resolution. Call this before
    /// `load_rules()` when you have an async context available, or let
    /// `load_rules()` handle it synchronously via `tokio::runtime::Handle`,
    /// which needs a multi-threaded runtime and returns an error on a
    /// current-thread one.
    pub async fn resolve_dynamic_pipelines(&mut self) -> Result<(), String> {
        let Some(resolver) = &self.source_resolver else {
            return Ok(());
        };

        let pipelines = std::mem::take(&mut self.pipelines);
        let external = self.external_sources.clone();
        let fetch = self.source_fetch;
        let resolved = resolve_pipelines_async(
            resolver,
            &pipelines,
            &external,
            self.allow_remote_include,
            fetch,
        )
        .await;
        match resolved {
            Ok(p) => {
                self.pipelines = p;
                Ok(())
            }
            Err(e) => {
                self.pipelines = pipelines;
                Err(e)
            }
        }
    }

    /// Load (or reload) rules from the configured path.
    ///
    /// On reload, correlation state is exported before replacing the engine
    /// and re-imported after, so in-flight windows and suppression state
    /// survive rule changes (entries for removed correlations are dropped).
    ///
    /// If pipeline paths are set (via [`set_pipeline_paths`](Self::set_pipeline_paths)),
    /// pipelines are re-read from disk before rebuilding the engine. If any
    /// pipeline file fails to parse, the entire reload is aborted and the
    /// old engine remains active.
    ///
    /// Rule documents that fail to parse are logged and left out, unless
    /// every rule failed to parse or [`set_strict_rules`](Self::set_strict_rules)
    /// is on; then the load fails and the old engine remains active.
    ///
    /// Dynamic pipeline sources are resolved if a source resolver is configured.
    pub fn load_rules(&mut self) -> Result<EngineStats, String> {
        let load_span = tracing::info_span!("load_rules", rules_path = %self.rules_path.display());
        let _enter = load_span.enter();
        let load_start = std::time::Instant::now();

        if let RuleSource::Rulesets(bindings) = &self.rule_source {
            return self.load_rulesets(&bindings.clone());
        }

        if !self.pipeline_paths.is_empty() {
            self.pipelines = reload_pipelines(&self.pipeline_paths)?;
        }

        if let Some(resolved) = self.resolve_pipeline_sources(&self.pipelines)? {
            self.pipelines = resolved;
        }

        let previous_state = self.export_state();
        let collection = load_collection(&self.rules_path)?;
        check_parse_errors(&collection, self.strict_rules)?;
        let parse_errors = collection.error_count();

        let variant = self.build_variant(
            &collection,
            &self.pipelines,
            self.routing.clone(),
            previous_state.as_ref(),
        )?;
        let stats = variant_stats(&variant, parse_errors);
        self.engine = variant;
        self.parse_errors = parse_errors;
        self.refresh_rule_field_set(&collection);
        tracing::debug!(
            detection_rules = stats.detection_rules,
            correlation_rules = stats.correlation_rules,
            duration_ms = load_start.elapsed().as_millis() as u64,
            "Rule load complete",
        );
        Ok(stats)
    }

    fn load_rulesets(&mut self, bindings: &[RulesetBinding]) -> Result<EngineStats, String> {
        let previous = self.export_state();
        let mut units = Vec::new();
        let mut parse_errors = 0usize;

        for binding in bindings {
            let resolved =
                resolve_ruleset(&binding.name, &binding.spec, &ResolveOptions::default())
                    .map_err(|error| format!("ruleset '{}': {error}", binding.name))?;
            let collection = resolved.collection;
            check_parse_errors(&collection, self.strict_rules)
                .map_err(|error| format!("ruleset '{}': {error}", binding.name))?;
            parse_errors += collection.error_count();
            let mut pipelines = load_ruleset_pipelines(binding)?;
            if let Some(resolved) = self
                .resolve_pipeline_sources(&pipelines)
                .map_err(|error| format!("ruleset '{}': {error}", binding.name))?
            {
                pipelines = resolved;
            }
            let previous_state = previous
                .as_ref()
                .and_then(|snapshot| snapshot.rulesets.get(&binding.name));
            let routing = if bindings.len() == 1 {
                self.routing.clone()
            } else {
                None
            };
            let variant = self.build_variant(&collection, &pipelines, routing, previous_state)?;
            let field_set = RuleFieldSet::collect(&collection, &pipelines, true);
            units.push(RulesetUnit {
                name: Arc::from(binding.name.as_str()),
                when_schemas: binding.when_schemas.clone(),
                tenants: binding.tenants.clone(),
                engine: into_unit(variant),
                field_set,
            });
        }

        let engines = RulesetEngines::new(units, self.ruleset_classifier.clone())
            .map_err(|error| error.to_string())?;
        let field_set = engines.rule_field_set();
        let stats = EngineStats {
            detection_rules: engines.detection_rule_count(),
            correlation_rules: engines.correlation_rule_count(),
            state_entries: engines.state_entries(),
            parse_errors,
        };
        self.rule_field_set.store(Arc::new(field_set));
        self.engine = EngineVariant::Rulesets(Box::new(engines));
        self.parse_errors = parse_errors;
        Ok(stats)
    }

    /// Resolve dynamic `${source.*}` sources in `pipelines`.
    ///
    /// Returns `None` when no resolver is configured or no pipeline is
    /// dynamic. Both error cases fail closed: rules compiled with unresolved
    /// templates differ from what the operator wrote, and on a hot-reload the
    /// previous engine keeps serving traffic when this returns an error.
    fn resolve_pipeline_sources(
        &self,
        pipelines: &[Pipeline],
    ) -> Result<Option<Vec<Pipeline>>, String> {
        let Some(resolver) = self.source_resolver.clone() else {
            return Ok(None);
        };
        if !pipelines.iter().any(|p| p.is_dynamic()) {
            return Ok(None);
        }
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            "Dynamic pipelines require a tokio runtime; refusing to load rules with \
             unresolved sources"
                .to_string()
        })?;
        let allow_remote = self.allow_remote_include;
        let external = self.external_sources.clone();
        let fetch = self.source_fetch;
        let resolved = block_on_from_sync(&handle, async {
            resolve_pipelines_async(&resolver, pipelines, &external, allow_remote, fetch).await
        })?;
        resolved
            .map(Some)
            .map_err(|e| format!("Dynamic source resolution failed: {e}"))
    }

    /// Build one engine variant from a parsed collection. Shared by the
    /// path-based loader and the named-ruleset loader.
    fn build_variant(
        &self,
        collection: &SigmaCollection,
        pipelines: &[Pipeline],
        routing: Option<RoutingSpec>,
        previous_state: Option<&CorrelationSnapshot>,
    ) -> Result<EngineVariant, String> {
        if let Some(mut spec) = routing {
            // Resolve dynamic `${source.*}` sources in the routed pipeline-sets,
            // with the same fail-closed policy as the single-engine path above.
            if let Some(resolver) = self.source_resolver.clone() {
                let needs_resolve = spec
                    .pipeline_sets
                    .iter()
                    .any(|set| set.iter().any(|p| p.is_dynamic()));
                if needs_resolve {
                    let handle = tokio::runtime::Handle::try_current().map_err(|_| {
                        "Dynamic pipelines require a tokio runtime; refusing to load rules with \
                         unresolved sources"
                            .to_string()
                    })?;
                    let allow_remote = self.allow_remote_include;
                    let external = self.external_sources.clone();
                    let fetch = self.source_fetch;
                    let mut resolved_sets = Vec::with_capacity(spec.pipeline_sets.len());
                    for set in spec.pipeline_sets {
                        let resolved = block_on_from_sync(&handle, async {
                            resolve_pipelines_async(&resolver, &set, &external, allow_remote, fetch)
                                .await
                        })?;
                        match resolved {
                            Ok(p) => resolved_sets.push(p),
                            Err(e) => {
                                return Err(format!(
                                    "Dynamic source resolution failed (schema routing): {e}"
                                ));
                            }
                        }
                    }
                    spec.pipeline_sets = resolved_sets;
                }
            }

            let partition_rules = spec.partition_rules;
            let mut router = SchemaRouter::build(
                collection,
                spec.classifier,
                spec.plan,
                spec.pipeline_sets,
                self.corr_config.clone(),
                self.include_event,
                self.match_detail,
                self.logsource_extractor.clone(),
                partition_rules,
            )
            .map_err(|e| format!("Error building schema router: {e}"))?;

            if let Some(snapshot) = previous_state {
                router.import_state(snapshot.clone());
            }
            return Ok(EngineVariant::Routed(Box::new(router)));
        }

        if !collection.correlations.is_empty() {
            let mut engine = CorrelationEngine::new(self.corr_config.clone());
            engine.set_include_event(self.include_event);
            engine.set_match_detail(self.match_detail);
            if let Some(budget) = self.bloom_max_bytes {
                engine.set_bloom_max_bytes(budget);
            }
            engine.set_bloom_prefilter(self.bloom_prefilter);
            #[cfg(feature = "daachorse-index")]
            engine.set_cross_rule_ac(self.cross_rule_ac);
            engine.set_logsource_extractor(self.logsource_extractor.clone());
            for p in pipelines {
                engine.add_pipeline(p.clone());
            }
            engine
                .add_collection(collection)
                .map_err(|e| format!("Error compiling rules: {e}"))?;

            if let Some(snapshot) = previous_state {
                engine.import_state(snapshot.clone());
            }
            return Ok(EngineVariant::WithCorrelations(Box::new(engine)));
        }

        let mut engine = Engine::new();
        engine.set_include_event(self.include_event);
        engine.set_match_detail(self.match_detail);
        if let Some(budget) = self.bloom_max_bytes {
            engine.set_bloom_max_bytes(budget);
        }
        engine.set_bloom_prefilter(self.bloom_prefilter);
        #[cfg(feature = "daachorse-index")]
        engine.set_cross_rule_ac(self.cross_rule_ac);
        engine.set_logsource_extractor(self.logsource_extractor.clone());
        for p in pipelines {
            engine.add_pipeline(p.clone());
        }
        engine
            .add_collection(collection)
            .map_err(|e| format!("Error compiling rules: {e}"))?;
        Ok(EngineVariant::DetectionOnly(Box::new(engine)))
    }

    /// Recompute the post-pipeline rule field set and publish it. Called at
    /// the end of every successful `load_rules()` branch.
    fn refresh_rule_field_set(&self, collection: &SigmaCollection) {
        let field_set = RuleFieldSet::collect(collection, &self.pipelines, true);
        self.rule_field_set.store(Arc::new(field_set));
    }

    /// Whether detection for this engine is stateless across batches.
    ///
    /// When true, multiple batches may evaluate concurrently under a shared
    /// borrow. Correlation engines require exclusive ordered access.
    pub fn allows_concurrent_detection(&self) -> bool {
        match &self.engine {
            EngineVariant::DetectionOnly(_) => true,
            EngineVariant::WithCorrelations(_) => false,
            EngineVariant::Routed(router) => !router.has_correlations(),
            EngineVariant::Rulesets(engines) => engines.allows_concurrent_detection(),
        }
    }

    /// Stateless detection for engines that allow concurrent batches.
    ///
    /// Returns `None` when correlation state requires [`Self::process_batch`].
    pub fn process_batch_shared<E: Event + Sync>(
        &self,
        events: &[&E],
    ) -> Option<Vec<ProcessResult>> {
        self.process_batch_shared_for_tenants(events, &[])
    }

    /// Like [`process_batch_shared`](Self::process_batch_shared) with a
    /// parallel tenant slice.
    pub fn process_batch_shared_for_tenants<E: Event + Sync>(
        &self,
        events: &[&E],
        tenants: &[Option<TenantId>],
    ) -> Option<Vec<ProcessResult>> {
        match &self.engine {
            EngineVariant::DetectionOnly(engine) => Some(engine.evaluate_batch(events)),
            EngineVariant::Routed(router) if !router.has_correlations() => {
                Some(router.detect_batch(events))
            }
            EngineVariant::WithCorrelations(_) | EngineVariant::Routed(_) => None,
            EngineVariant::Rulesets(engines) => engines.detect_batch_for_tenants(events, tenants),
        }
    }

    /// Process a batch of events using parallel detection + sequential correlation.
    ///
    /// Delegates to `Engine::evaluate_batch` or `CorrelationEngine::process_batch`
    /// depending on whether correlation rules are loaded.
    pub fn process_batch<E: Event + Sync>(&mut self, events: &[&E]) -> Vec<ProcessResult> {
        self.process_batch_for_tenants(events, &[])
    }

    /// Like [`process_batch`](Self::process_batch) with a parallel tenant slice.
    pub fn process_batch_for_tenants<E: Event + Sync>(
        &mut self,
        events: &[&E],
        tenants: &[Option<TenantId>],
    ) -> Vec<ProcessResult> {
        match &mut self.engine {
            EngineVariant::DetectionOnly(engine) => engine.evaluate_batch(events),
            EngineVariant::WithCorrelations(engine) => {
                engine.process_batch_for_tenants(events, tenants)
            }
            EngineVariant::Routed(router) => router.process_batch_for_tenants(events, tenants),
            EngineVariant::Rulesets(engines) => engines.process_batch_for_tenants(events, tenants),
        }
    }

    /// Return summary statistics about the current engine state.
    pub fn stats(&self) -> EngineStats {
        match &self.engine {
            EngineVariant::DetectionOnly(engine) => EngineStats {
                detection_rules: engine.rule_count(),
                correlation_rules: 0,
                state_entries: 0,
                parse_errors: self.parse_errors,
            },
            EngineVariant::WithCorrelations(engine) => EngineStats {
                detection_rules: engine.detection_rule_count(),
                correlation_rules: engine.correlation_rule_count(),
                state_entries: engine.state_count(),
                parse_errors: self.parse_errors,
            },
            EngineVariant::Routed(router) => EngineStats {
                detection_rules: router.detection_rule_count(),
                correlation_rules: router.correlation_rule_count(),
                state_entries: router.state_count(),
                parse_errors: self.parse_errors,
            },
            EngineVariant::Rulesets(engines) => EngineStats {
                detection_rules: engines.detection_rule_count(),
                correlation_rules: engines.correlation_rule_count(),
                state_entries: engines.state_entries(),
                parse_errors: self.parse_errors,
            },
        }
    }

    /// Resolve a rule key (an id, or a title for a rule without one) to the
    /// documentation of every loaded rule that carries it.
    ///
    /// Aggregated output such as an incident's `rule_counts` records only the
    /// key, so this is how a consumer recovers what the rule was for.
    pub fn rule_metadata(&self, key: &str) -> RuleMetadataLookup {
        match &self.engine {
            EngineVariant::DetectionOnly(engine) => engine.rule_metadata(key),
            EngineVariant::WithCorrelations(engine) => engine.rule_metadata(key),
            EngineVariant::Routed(router) => router.rule_metadata(key),
            EngineVariant::Rulesets(engines) => engines.rule_metadata(key),
        }
    }

    /// Return the path from which rules are loaded.
    pub fn rules_path(&self) -> &Path {
        &self.rules_path
    }

    /// Return the configured processing pipelines.
    pub fn pipelines(&self) -> &[Pipeline] {
        &self.pipelines
    }

    /// Return the correlation configuration.
    pub fn corr_config(&self) -> &CorrelationConfig {
        &self.corr_config
    }

    /// Whether detection results include the matched event.
    pub fn include_event(&self) -> bool {
        self.include_event
    }

    /// Set whether detection results include the matched event, on the
    /// loaded engine and on every engine a later `load_rules()` builds.
    ///
    /// Rules that set `rsigma.include_event: "true"` keep their event either
    /// way.
    pub fn set_include_event(&mut self, include: bool) {
        self.include_event = include;
        match &mut self.engine {
            EngineVariant::DetectionOnly(engine) => engine.set_include_event(include),
            EngineVariant::WithCorrelations(engine) => engine.set_include_event(include),
            EngineVariant::Routed(router) => router.set_include_event(include),
            EngineVariant::Rulesets(engines) => engines.set_include_event(include),
        }
    }

    /// Export correlation state as a serializable snapshot.
    /// Returns `None` if the engine is detection-only (no correlation state to persist).
    pub fn export_state(&self) -> Option<CorrelationSnapshot> {
        match &self.engine {
            EngineVariant::DetectionOnly(_) => None,
            EngineVariant::WithCorrelations(engine) => Some(engine.export_state()),
            EngineVariant::Routed(router) => router.export_state(),
            EngineVariant::Rulesets(engines) => Some(engines.export_state()),
        }
    }

    /// Read-only introspection of the correlation window state, filtered by
    /// correlation id and/or group-key substring. `None` for a detection-only
    /// engine or a routed engine with no correlation rules.
    pub fn introspect_correlations(
        &self,
        id: Option<&str>,
        group: Option<&str>,
    ) -> Option<CorrelationStateSnapshot> {
        self.introspect_correlations_for_tenant(id, group, None)
    }

    /// Like [`introspect_correlations`](Self::introspect_correlations), keeping
    /// only groups owned by `tenant` when it is set.
    pub fn introspect_correlations_for_tenant(
        &self,
        id: Option<&str>,
        group: Option<&str>,
        tenant: Option<&rsigma_eval::TenantId>,
    ) -> Option<CorrelationStateSnapshot> {
        match &self.engine {
            EngineVariant::DetectionOnly(_) => None,
            EngineVariant::WithCorrelations(engine) => {
                Some(engine.introspect_for_tenant(id, group, tenant))
            }
            EngineVariant::Routed(router) => {
                router.correlation_introspect_for_tenant(id, group, tenant)
            }
            EngineVariant::Rulesets(engines) => {
                let mut snapshot = CorrelationStateSnapshot {
                    correlations: Vec::new(),
                    groups: Vec::new(),
                };
                for (ruleset, mut part) in engines.introspect_filtered_for_tenant(id, group, tenant)
                {
                    for row in &mut part.correlations {
                        row.ruleset = Some(ruleset.clone());
                    }
                    for row in &mut part.groups {
                        row.ruleset = Some(ruleset.clone());
                    }
                    snapshot.correlations.extend(part.correlations);
                    snapshot.groups.extend(part.groups);
                }
                Some(snapshot)
            }
        }
    }

    /// Import previously exported correlation state.
    /// Returns `true` if the import succeeded, `false` if the snapshot version
    /// is incompatible. No-op (returns `true`) if the engine is detection-only.
    pub fn import_state(&mut self, snapshot: &CorrelationSnapshot) -> bool {
        self.import_state_detailed(snapshot).is_some()
    }

    /// Like [`import_state`](Self::import_state), returning the restored and
    /// discarded entry counts.
    pub fn import_state_detailed(
        &mut self,
        snapshot: &CorrelationSnapshot,
    ) -> Option<rsigma_eval::ImportStats> {
        match &mut self.engine {
            EngineVariant::WithCorrelations(engine) => {
                engine.import_state_detailed(snapshot.clone())
            }
            EngineVariant::Routed(router) => router.import_state_detailed(snapshot.clone()),
            EngineVariant::DetectionOnly(_) => Some(rsigma_eval::ImportStats::default()),
            EngineVariant::Rulesets(engines) => engines.import_state_detailed(snapshot),
        }
    }
}

fn into_unit(variant: EngineVariant) -> UnitEngine {
    match variant {
        EngineVariant::DetectionOnly(engine) => UnitEngine::Detection(engine),
        EngineVariant::WithCorrelations(engine) => UnitEngine::Correlation(engine),
        EngineVariant::Routed(router) => UnitEngine::Routed(router),
        EngineVariant::Rulesets(_) => unreachable!("rulesets do not nest"),
    }
}

fn variant_stats(variant: &EngineVariant, parse_errors: usize) -> EngineStats {
    match variant {
        EngineVariant::DetectionOnly(engine) => EngineStats {
            detection_rules: engine.rule_count(),
            correlation_rules: 0,
            state_entries: 0,
            parse_errors,
        },
        EngineVariant::WithCorrelations(engine) => EngineStats {
            detection_rules: engine.detection_rule_count(),
            correlation_rules: engine.correlation_rule_count(),
            state_entries: engine.state_count(),
            parse_errors,
        },
        EngineVariant::Routed(router) => EngineStats {
            detection_rules: router.detection_rule_count(),
            correlation_rules: router.correlation_rule_count(),
            state_entries: router.state_count(),
            parse_errors,
        },
        EngineVariant::Rulesets(engines) => EngineStats {
            detection_rules: engines.detection_rule_count(),
            correlation_rules: engines.correlation_rule_count(),
            state_entries: engines.state_entries(),
            parse_errors,
        },
    }
}

fn load_collection(path: &Path) -> Result<SigmaCollection, String> {
    let collection = if path.is_dir() {
        rsigma_parser::parse_sigma_directory(path)
            .map_err(|e| format!("Error loading rules from {}: {e}", path.display()))?
    } else {
        rsigma_parser::parse_sigma_file(path)
            .map_err(|e| format!("Error loading rule {}: {e}", path.display()))?
    };

    if collection.has_errors() {
        tracing::warn!(
            count = collection.error_count(),
            "Parse errors while loading rules"
        );
        for (i, err) in collection.errors().take(3).enumerate() {
            tracing::warn!(index = i + 1, error = %err, "Rule parse error detail");
        }
    }
    if collection.warning_count() > 0 {
        tracing::warn!(
            count = collection.warning_count(),
            "Parse warnings while loading rules"
        );
        for (i, warning) in collection.warnings().take(3).enumerate() {
            tracing::warn!(index = i + 1, warning = %warning, "Rule parse warning detail");
        }
    }

    Ok(collection)
}

fn check_parse_errors(collection: &SigmaCollection, strict: bool) -> Result<(), String> {
    let no_rules = collection.rules.is_empty() && collection.correlations.is_empty();
    let errors = collection.error_count();
    let Some(first) = collection.errors().next() else {
        if no_rules {
            tracing::warn!("No detection or correlation rules found");
        }
        return Ok(());
    };
    if strict {
        return Err(format!(
            "{errors} rule parse error(s) with strict rule loading enabled; first: {first}"
        ));
    }
    if no_rules {
        return Err(format!(
            "No rules loaded: every rule failed to parse ({errors} parse error(s)); first: {first}"
        ));
    }
    Ok(())
}

/// Re-read and parse all pipeline files from disk, sorted by priority.
///
/// Pipeline files that still declare an inline `sources:` block are rejected
/// by [`parse_pipeline_file`] with a hint pointing at `rsigma rule
/// migrate-sources`, so a stale deprecated pipeline surfaces as a hard reload
/// error rather than silently loading.
fn reload_pipelines(paths: &[PathBuf]) -> Result<Vec<Pipeline>, String> {
    let mut pipelines = Vec::with_capacity(paths.len());
    for path in paths {
        let pipeline = parse_pipeline_file(path)
            .map_err(|e| format!("Error reloading pipeline {}: {e}", path.display()))?;
        pipelines.push(pipeline);
    }
    pipelines.sort_by_key(|p| p.priority);
    Ok(pipelines)
}

/// Resolve dynamic sources in pipelines asynchronously.
///
/// Source declarations come from external `--source` files (`external`);
/// pipelines only carry `${source.*}` references. The external sources are
/// resolved once into a shared data map, then every dynamic pipeline has its
/// references and `include` directives expanded against it.
async fn resolve_pipelines_async(
    resolver: &Arc<dyn SourceResolver>,
    pipelines: &[Pipeline],
    external: &[DynamicSource],
    allow_remote_include: bool,
    fetch: SourceFetch,
) -> Result<Vec<Pipeline>, String> {
    if !pipelines.iter().any(|p| p.is_dynamic()) {
        return Ok(pipelines.to_vec());
    }

    let resolved = match fetch {
        SourceFetch::Fresh => sources::resolve_all(resolver.as_ref(), external).await,
        SourceFetch::CacheFirst => {
            sources::resolve_all_cache_first(resolver.as_ref(), external).await
        }
    };
    let resolved_data = resolved.map_err(|e| format!("Failed to resolve dynamic sources: {e}"))?;

    let mut resolved_pipelines = Vec::with_capacity(pipelines.len());
    for pipeline in pipelines {
        if pipeline.is_dynamic() {
            let mut expanded = TemplateExpander::expand(pipeline, &resolved_data);
            sources::include::expand_includes(
                &mut expanded,
                &resolved_data,
                external,
                allow_remote_include,
            )?;
            resolved_pipelines.push(expanded);
        } else {
            resolved_pipelines.push(pipeline.clone());
        }
    }
    Ok(resolved_pipelines)
}

/// Wait for `fut` from synchronous code running inside a Tokio runtime.
///
/// Only a multi-threaded runtime can do this: `block_in_place` panics on a
/// current-thread runtime, and blocking its only thread would also stall the
/// connection tasks the future may be waiting on. There the caller gets an
/// error instead, and the rules are not loaded with unresolved sources.
fn block_on_from_sync<F: Future>(
    handle: &tokio::runtime::Handle,
    fut: F,
) -> Result<F::Output, String> {
    if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
        return Err(
            "Resolving dynamic pipeline sources from load_rules needs a multi-threaded tokio \
             runtime; refusing to load rules with unresolved sources"
                .to_string(),
        );
    }
    Ok(tokio::task::block_in_place(|| handle.block_on(fut)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::pipeline::sources::{
        DataFormat, DynamicSource, ErrorPolicy, RefreshPolicy, SourceType,
    };

    const RULE_YAML: &str = r#"
title: TestRule
id: 11111111-1111-1111-1111-111111111111
status: experimental
logsource:
    product: test
detection:
    selection:
        EventID: 1
    condition: selection
"#;

    /// A dynamic pipeline that references an external source but declares
    /// none inline (the only form allowed since v0.19.0).
    const DYNAMIC_PIPELINE: &str = r#"
name: dynamic_pipeline
priority: 10
vars:
  feed: "${source.feed}"
transformations:
  - type: value_placeholders
"#;

    #[test]
    fn inline_sources_in_pipeline_file_fail_to_load() {
        // A pipeline file that still declares an inline `sources:` block is
        // rejected outright (the migration path is `rsigma rule
        // migrate-sources`), so a stale pipeline surfaces as a load error
        // rather than silently loading.
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("rule.yml");
        std::fs::write(&rule_path, RULE_YAML).unwrap();

        let pipeline_path = dir.path().join("pipeline.yml");
        std::fs::write(
            &pipeline_path,
            r#"
name: legacy_pipeline_with_inline_sources
priority: 50
sources:
  - id: threat_feed
    type: file
    path: /tmp/does-not-matter.json
    format: json
transformations:
  - type: value_placeholders
"#,
        )
        .unwrap();

        let mut engine =
            RuntimeEngine::new(rule_path, Vec::new(), CorrelationConfig::default(), false);
        engine.set_pipeline_paths(vec![pipeline_path]);
        let err = engine
            .load_rules()
            .expect_err("inline sources must be rejected");
        assert!(
            err.contains("migrate-sources"),
            "error should point at the migration tool; got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn load_rules_fails_closed_when_dynamic_source_resolution_fails() {
        // A dynamic pipeline whose external source cannot resolve must surface
        // the error so callers (LogProcessor::reload_rules in particular) can
        // keep the previous engine active, rather than silently loading rules
        // with unexpanded `${source.*}` placeholders.
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("rule.yml");
        std::fs::write(&rule_path, RULE_YAML).unwrap();

        let pipeline_path = dir.path().join("pipeline.yml");
        std::fs::write(&pipeline_path, DYNAMIC_PIPELINE).unwrap();
        let pipeline = parse_pipeline_file(&pipeline_path).unwrap();
        assert!(
            pipeline.is_dynamic(),
            "fixture should produce a dynamic pipeline"
        );

        // The external source points at a path that does not exist; the
        // resolver returns a SourceError on first read.
        let missing = dir.path().join("missing.json");
        let external = vec![DynamicSource {
            id: "feed".to_string(),
            source_type: SourceType::File {
                path: missing,
                format: DataFormat::Json,
                extract: None,
                stix: None,
            },
            refresh: RefreshPolicy::Once,
            timeout: None,
            on_error: ErrorPolicy::Fail,
            required: true,
            default: None,
        }];

        let mut engine = RuntimeEngine::new(
            rule_path,
            vec![pipeline],
            CorrelationConfig::default(),
            false,
        );
        engine.set_source_resolver(Arc::new(sources::DefaultSourceResolver::new()));
        engine.set_external_sources(external);

        let err = engine
            .load_rules()
            .expect_err("missing source must cause load_rules to fail closed");
        assert!(
            err.contains("Dynamic source resolution failed"),
            "error should explain the fail-closed path; got: {err}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn load_rules_refuses_dynamic_sources_on_a_current_thread_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("rule.yml");
        std::fs::write(&rule_path, RULE_YAML).unwrap();
        let pipeline_path = dir.path().join("pipeline.yml");
        std::fs::write(&pipeline_path, DYNAMIC_PIPELINE).unwrap();
        let source_path = dir.path().join("feed.json");
        std::fs::write(&source_path, "[]").unwrap();
        let pipeline = parse_pipeline_file(&pipeline_path).unwrap();

        let mut engine = RuntimeEngine::new(
            rule_path,
            vec![pipeline],
            CorrelationConfig::default(),
            false,
        );
        engine.set_source_resolver(Arc::new(sources::DefaultSourceResolver::new()));
        engine.set_external_sources(vec![DynamicSource {
            id: "feed".to_string(),
            source_type: SourceType::File {
                path: source_path,
                format: DataFormat::Json,
                extract: None,
                stix: None,
            },
            refresh: RefreshPolicy::Once,
            timeout: None,
            on_error: ErrorPolicy::Fail,
            required: true,
            default: None,
        }]);

        let err = engine
            .load_rules()
            .expect_err("a current-thread runtime cannot resolve sources from load_rules");
        assert!(err.contains("multi-threaded"), "got: {err}");
        assert_eq!(
            engine.pipelines.len(),
            1,
            "the unresolved pipelines are kept for a retry"
        );
    }

    struct CountingResolver {
        fetches: std::sync::atomic::AtomicUsize,
        cached: std::sync::Mutex<Option<serde_json::Value>>,
    }

    #[async_trait::async_trait]
    impl SourceResolver for CountingResolver {
        async fn resolve(
            &self,
            source: &DynamicSource,
        ) -> Result<crate::sources::ResolvedValue, crate::sources::SourceError> {
            self.fetches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let Some(data) = self.cached.lock().unwrap().clone() else {
                return Err(crate::sources::SourceError {
                    source_id: source.id.clone(),
                    kind: crate::sources::SourceErrorKind::Fetch("no value".into()),
                });
            };
            Ok(crate::sources::ResolvedValue {
                data,
                resolved_at: std::time::Instant::now(),
                from_cache: false,
            })
        }

        fn cached(&self, _source_id: &str) -> Option<serde_json::Value> {
            self.cached.lock().unwrap().clone()
        }
    }

    fn cached_feed_source() -> DynamicSource {
        DynamicSource {
            id: "feed".to_string(),
            source_type: SourceType::File {
                path: std::path::PathBuf::from("/unused"),
                format: DataFormat::Json,
                extract: None,
                stix: None,
            },
            refresh: RefreshPolicy::Once,
            timeout: None,
            on_error: ErrorPolicy::Fail,
            required: true,
            default: None,
        }
    }

    fn ruleset_binding(
        name: &str,
        root: &Path,
        pipelines: Vec<crate::ruleset::PipelineRef>,
    ) -> RulesetBinding {
        RulesetBinding {
            name: name.to_string(),
            spec: rsigma_parser::ruleset::RulesetSpec {
                sources: vec![root.join("rules")],
                ..Default::default()
            },
            pipelines,
            when_schemas: Vec::new(),
            tenants: Vec::new(),
        }
    }

    #[test]
    fn rulesets_load_and_stamp_results_in_order() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["a", "b"] {
            let root = dir.path().join(name);
            std::fs::create_dir_all(root.join("rules")).unwrap();
            std::fs::write(root.join("rules/rule.yml"), RULE_YAML).unwrap();
        }
        let bindings = vec![
            ruleset_binding("a", &dir.path().join("a"), Vec::new()),
            ruleset_binding("b", &dir.path().join("b"), Vec::new()),
        ];
        let mut engine =
            RuntimeEngine::with_rulesets(bindings, CorrelationConfig::default(), false);
        engine.load_rules().unwrap();
        let value = serde_json::json!({"EventID": 1});
        let event = rsigma_eval::JsonEvent::borrow(&value);
        let results = engine.process_batch(&[&event]);
        assert_eq!(results[0].len(), 2);
        assert_eq!(results[0][0].header.ruleset.as_deref(), Some("a"));
        assert_eq!(results[0][1].header.ruleset.as_deref(), Some("b"));
    }

    #[test]
    fn a_broken_ruleset_on_reload_keeps_the_old_engine() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("a");
        std::fs::create_dir_all(root.join("rules")).unwrap();
        std::fs::write(root.join("rules/rule.yml"), RULE_YAML).unwrap();
        let mut engine = RuntimeEngine::with_rulesets(
            vec![ruleset_binding("a", &root, Vec::new())],
            CorrelationConfig::default(),
            false,
        );
        engine.load_rules().unwrap();
        std::fs::remove_dir_all(root.join("rules")).unwrap();
        assert!(engine.load_rules().is_err());
        let value = serde_json::json!({"EventID": 1});
        let event = rsigma_eval::JsonEvent::borrow(&value);
        assert_eq!(engine.process_batch(&[&event])[0].len(), 1);
    }

    fn single_ruleset_engine(root: &Path) -> RuntimeEngine {
        RuntimeEngine::with_rulesets(
            vec![ruleset_binding("a", root, Vec::new())],
            CorrelationConfig::default(),
            false,
        )
    }

    #[test]
    fn a_ruleset_whose_rules_all_fail_to_parse_keeps_the_old_engine() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("a");
        std::fs::create_dir_all(root.join("rules")).unwrap();
        std::fs::write(root.join("rules/rule.yml"), RULE_YAML).unwrap();
        let mut engine = single_ruleset_engine(&root);
        engine.load_rules().unwrap();

        std::fs::write(root.join("rules/rule.yml"), "title: [unclosed\n").unwrap();
        let err = engine.load_rules().unwrap_err();
        assert!(
            err.contains("ruleset 'a'") && err.contains("every rule failed to parse"),
            "got: {err}"
        );
        let value = serde_json::json!({"EventID": 1});
        let event = rsigma_eval::JsonEvent::borrow(&value);
        assert_eq!(engine.process_batch(&[&event])[0].len(), 1);
    }

    #[test]
    fn strict_rules_reject_a_ruleset_with_a_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("a");
        std::fs::create_dir_all(root.join("rules")).unwrap();
        std::fs::write(root.join("rules/rule.yml"), RULE_YAML).unwrap();
        std::fs::write(root.join("rules/broken.yml"), "title: [unclosed\n").unwrap();
        let mut engine = single_ruleset_engine(&root);

        engine.set_strict_rules(true);
        let err = engine.load_rules().unwrap_err();
        assert!(
            err.contains("ruleset 'a'") && err.contains("strict rule loading"),
            "got: {err}"
        );

        engine.set_strict_rules(false);
        let stats = engine.load_rules().unwrap();
        assert_eq!(stats.detection_rules, 1);
        assert_eq!(stats.parse_errors, 1);
    }

    fn feed_source(path: PathBuf) -> Vec<DynamicSource> {
        vec![DynamicSource {
            id: "feed".to_string(),
            source_type: SourceType::File {
                path,
                format: DataFormat::Json,
                extract: None,
                stix: None,
            },
            refresh: RefreshPolicy::Once,
            timeout: None,
            on_error: ErrorPolicy::Fail,
            required: true,
            default: None,
        }]
    }

    fn engine_with_feed(resolver: Arc<CountingResolver>) -> RuntimeEngine {
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("rule.yml");
        std::fs::write(&rule_path, RULE_YAML).unwrap();
        let pipeline_path = dir.path().join("pipeline.yml");
        std::fs::write(&pipeline_path, DYNAMIC_PIPELINE).unwrap();
        let pipeline = parse_pipeline_file(&pipeline_path).unwrap();
        let mut engine = RuntimeEngine::new(
            rule_path,
            vec![pipeline],
            CorrelationConfig::default(),
            false,
        );
        engine.set_source_resolver(resolver);
        engine.set_external_sources(vec![cached_feed_source()]);
        std::mem::forget(dir);
        engine
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cache_first_skips_a_hit_and_fetches_a_miss() {
        let resolver = Arc::new(CountingResolver {
            fetches: std::sync::atomic::AtomicUsize::new(0),
            cached: std::sync::Mutex::new(Some(serde_json::json!(["198.51.100.7"]))),
        });
        let mut hit = engine_with_feed(Arc::clone(&resolver));
        hit.set_source_fetch(SourceFetch::CacheFirst);
        hit.load_rules().expect("a cached value needs no fetch");
        assert_eq!(
            resolver.fetches.load(std::sync::atomic::Ordering::SeqCst),
            0
        );

        *resolver.cached.lock().unwrap() = None;
        resolver
            .fetches
            .store(0, std::sync::atomic::Ordering::SeqCst);
        let mut miss = engine_with_feed(resolver);
        miss.set_source_fetch(SourceFetch::CacheFirst);
        let err = miss
            .load_rules()
            .expect_err("a cache miss fetches, and this resolver has nothing");
        assert!(err.contains("no value"), "got: {err}");
        assert_eq!(miss.source_resolver().unwrap().cached("feed"), None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ruleset_pipelines_resolve_dynamic_sources() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("a");
        std::fs::create_dir_all(root.join("rules")).unwrap();
        std::fs::write(
            root.join("rules/rule.yml"),
            "title: Feed\nid: feed\nlogsource:\n    category: test\ndetection:\n    selection:\n        Image|expand: '%feed%'\n    condition: selection\n",
        )
        .unwrap();
        let pipeline_path = dir.path().join("pipeline.yml");
        std::fs::write(&pipeline_path, DYNAMIC_PIPELINE).unwrap();
        let feed = dir.path().join("feed.json");
        let mut engine = RuntimeEngine::with_rulesets(
            vec![ruleset_binding(
                "a",
                &root,
                vec![crate::ruleset::PipelineRef::File(pipeline_path)],
            )],
            CorrelationConfig::default(),
            false,
        );
        engine.set_source_resolver(Arc::new(sources::DefaultSourceResolver::new()));
        engine.set_external_sources(feed_source(feed.clone()));

        let err = engine.load_rules().unwrap_err();
        assert!(
            err.contains("ruleset 'a'") && err.contains("Dynamic source resolution failed"),
            "a missing source must fail closed; got: {err}"
        );

        std::fs::write(&feed, r#"["whoami"]"#).unwrap();
        engine.load_rules().unwrap();
        let value = serde_json::json!({"Image": "whoami"});
        let event = rsigma_eval::JsonEvent::borrow(&value);
        assert_eq!(engine.process_batch(&[&event])[0].len(), 1);
    }

    #[test]
    fn file_pipelines_are_reparsed_on_reload_and_builtins_survive() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("a");
        std::fs::create_dir_all(root.join("rules")).unwrap();
        std::fs::write(
            root.join("rules/rule.yml"),
            "title: Windows rule\nid: windows-rule\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    selection:\n        EventID: 1\n    condition: selection\n",
        )
        .unwrap();
        let pipeline_path = root.join("pipeline.yml");
        std::fs::write(
            &pipeline_path,
            "name: rename\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      EventID: process.path\n",
        )
        .unwrap();
        let sysmon = rsigma_eval::resolve_builtin_pipeline("sysmon")
            .unwrap()
            .unwrap();
        let binding = ruleset_binding(
            "a",
            &root,
            vec![
                crate::ruleset::PipelineRef::Builtin(sysmon),
                crate::ruleset::PipelineRef::File(pipeline_path.clone()),
            ],
        );
        let mut engine =
            RuntimeEngine::with_rulesets(vec![binding], CorrelationConfig::default(), false);
        engine.load_rules().unwrap();
        let first = serde_json::json!({"EventID": 1, "process.path": 1});
        assert_eq!(
            engine.process_batch(&[&rsigma_eval::JsonEvent::borrow(&first)])[0].len(),
            1
        );

        std::fs::write(
            &pipeline_path,
            "name: rename\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      EventID: process.id\n",
        )
        .unwrap();
        engine.load_rules().unwrap();

        let value = serde_json::json!({"EventID": 1, "process.id": 1});
        let event = rsigma_eval::JsonEvent::borrow(&value);
        assert_eq!(engine.process_batch(&[&event])[0].len(), 1);

        let without_event_id = serde_json::json!({"process.id": 1});
        assert_eq!(
            engine.process_batch(&[&rsigma_eval::JsonEvent::borrow(&without_event_id)])[0].len(),
            0,
            "the builtin sysmon pipeline must survive the reload"
        );
    }

    #[test]
    fn correlation_state_survives_reload_per_ruleset() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("a");
        std::fs::create_dir_all(root.join("rules")).unwrap();
        std::fs::write(
            root.join("rules/rule.yml"),
            r#"title: Whoami
id: whoami
logsource:
    product: test
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Burst
id: burst
correlation:
    type: event_count
    rules: [whoami]
    group-by: [EventID]
    timespan: 5m
    condition:
        gte: 2
"#,
        )
        .unwrap();
        let mut engine = RuntimeEngine::with_rulesets(
            vec![ruleset_binding("a", &root, Vec::new())],
            CorrelationConfig::default(),
            false,
        );
        engine.load_rules().unwrap();
        let first = serde_json::json!({"EventID": 1, "timestamp": "2026-01-01T00:00:00Z"});
        engine.process_batch(&[&rsigma_eval::JsonEvent::borrow(&first)]);
        engine.load_rules().unwrap();
        let second = serde_json::json!({"EventID": 1, "timestamp": "2026-01-01T00:00:30Z"});
        let results = engine.process_batch(&[&rsigma_eval::JsonEvent::borrow(&second)]);
        assert!(
            results[0].iter().any(|result| result.is_correlation()),
            "correlation state did not survive the reload"
        );
    }

    #[test]
    fn mixing_detection_and_correlation_rulesets_disables_concurrent_detection() {
        let dir = tempfile::tempdir().unwrap();
        let detection_root = dir.path().join("detection");
        std::fs::create_dir_all(detection_root.join("rules")).unwrap();
        std::fs::write(detection_root.join("rules/rule.yml"), RULE_YAML).unwrap();
        let correlation_root = dir.path().join("correlation");
        std::fs::create_dir_all(correlation_root.join("rules")).unwrap();
        std::fs::write(
            correlation_root.join("rules/rule.yml"),
            r#"title: Whoami
id: whoami
logsource:
    product: test
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Burst
id: burst
correlation:
    type: event_count
    rules: [whoami]
    group-by: [EventID]
    timespan: 5m
    condition:
        gte: 2
"#,
        )
        .unwrap();
        let mut engine = RuntimeEngine::with_rulesets(
            vec![
                ruleset_binding("detection", &detection_root, Vec::new()),
                ruleset_binding("correlation", &correlation_root, Vec::new()),
            ],
            CorrelationConfig::default(),
            false,
        );
        engine.load_rules().unwrap();
        assert!(!engine.allows_concurrent_detection());
    }

    /// One rule that leaves event retention to the engine, and one that asks
    /// for its event.
    const RETENTION_RULES_YAML: &str = r#"
title: Plain
id: plain
logsource:
    product: test
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Keeps
id: keeps
logsource:
    product: test
detection:
    selection:
        EventID: 1
    condition: selection
custom_attributes:
    rsigma.include_event: "true"
"#;

    const RETENTION_CORRELATION_YAML: &str = r#"
---
title: Counted
id: counted
logsource:
    product: test
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Burst
id: burst
correlation:
    type: event_count
    rules: [counted]
    group-by: [EventID]
    timespan: 5m
    condition:
        gte: 100
"#;

    /// Rule id to whether its detection carried the event, for one event.
    fn retained_events(engine: &mut RuntimeEngine) -> Vec<(String, bool)> {
        let value = serde_json::json!({"EventID": 1});
        let event = rsigma_eval::JsonEvent::borrow(&value);
        let mut out: Vec<(String, bool)> = engine.process_batch(&[&event])[0]
            .iter()
            .filter_map(|r| {
                let body = r.as_detection()?;
                Some((r.header.rule_id.clone()?, body.event.is_some()))
            })
            .collect();
        out.sort();
        out
    }

    fn assert_toggle(mut engine: RuntimeEngine) {
        engine.load_rules().unwrap();
        let only_keeps = vec![("keeps".to_string(), true), ("plain".to_string(), false)];
        let both = vec![("keeps".to_string(), true), ("plain".to_string(), true)];
        assert_eq!(retained_events(&mut engine), only_keeps);

        engine.set_include_event(true);
        assert!(engine.include_event());
        assert_eq!(retained_events(&mut engine), both);

        engine.load_rules().unwrap();
        assert_eq!(
            retained_events(&mut engine),
            both,
            "a rule reload keeps the toggled value"
        );

        engine.set_include_event(false);
        assert!(!engine.include_event());
        assert_eq!(retained_events(&mut engine), only_keeps);
    }

    fn write_rules(dir: &Path, yaml: &str) -> PathBuf {
        let rules = dir.join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(rules.join("rules.yml"), yaml).unwrap();
        rules
    }

    #[test]
    fn include_event_toggles_on_a_detection_only_engine() {
        let dir = tempfile::tempdir().unwrap();
        let rules = write_rules(dir.path(), RETENTION_RULES_YAML);
        let engine = RuntimeEngine::new(rules, Vec::new(), CorrelationConfig::default(), false);
        assert_toggle(engine);
    }

    #[test]
    fn include_event_toggles_on_a_correlation_engine() {
        let dir = tempfile::tempdir().unwrap();
        let rules = write_rules(
            dir.path(),
            &format!("{RETENTION_RULES_YAML}{RETENTION_CORRELATION_YAML}"),
        );
        let mut engine = RuntimeEngine::new(rules, Vec::new(), CorrelationConfig::default(), false);
        engine.load_rules().unwrap();
        assert!(matches!(engine.engine, EngineVariant::WithCorrelations(_)));
        assert_toggle(engine);
    }

    #[test]
    fn include_event_toggles_on_a_routed_engine() {
        let dir = tempfile::tempdir().unwrap();
        let rules = write_rules(
            dir.path(),
            &format!("{RETENTION_RULES_YAML}{RETENTION_CORRELATION_YAML}"),
        );
        let mut engine = RuntimeEngine::new(rules, Vec::new(), CorrelationConfig::default(), false);
        engine.set_routing(Some(default_routing_spec()));
        engine.load_rules().unwrap();
        assert!(matches!(engine.engine, EngineVariant::Routed(_)));
        assert_toggle(engine);
    }

    fn default_routing_spec() -> RoutingSpec {
        RoutingSpec {
            classifier: SchemaClassifier::builtin(),
            plan: RoutingPlan::from_config(&rsigma_eval::RoutingConfig::default()),
            pipeline_sets: vec![Vec::new()],
            partition_rules: false,
        }
    }

    #[test]
    fn include_event_toggles_on_ruleset_engines() {
        let dir = tempfile::tempdir().unwrap();
        let detection_root = dir.path().join("detection");
        write_rules(&detection_root, RETENTION_RULES_YAML);
        let correlation_root = dir.path().join("correlation");
        write_rules(
            &correlation_root,
            &format!("{RETENTION_RULES_YAML}{RETENTION_CORRELATION_YAML}"),
        );

        let engine = RuntimeEngine::with_rulesets(
            vec![ruleset_binding("detection", &detection_root, Vec::new())],
            CorrelationConfig::default(),
            false,
        );
        assert_toggle(engine);

        let engine = RuntimeEngine::with_rulesets(
            vec![ruleset_binding(
                "correlation",
                &correlation_root,
                Vec::new(),
            )],
            CorrelationConfig::default(),
            false,
        );
        assert_toggle(engine);

        let mut engine = RuntimeEngine::with_rulesets(
            vec![ruleset_binding(
                "correlation",
                &correlation_root,
                Vec::new(),
            )],
            CorrelationConfig::default(),
            false,
        );
        engine.set_routing(Some(default_routing_spec()));
        engine.load_rules().unwrap();
        match &engine.engine {
            EngineVariant::Rulesets(engines) => {
                assert!(matches!(engines.units()[0].engine, UnitEngine::Routed(_)))
            }
            _ => panic!("expected ruleset engines"),
        }
        assert_toggle(engine);
    }
}
