use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use rsigma_eval::event::Event;
use rsigma_eval::pipeline::sources::DynamicSource;
use rsigma_eval::{
    CorrelationConfig, CorrelationEngine, CorrelationSnapshot, CorrelationStateSnapshot, Engine,
    LogSourceExtractor, MatchDetailLevel, Pipeline, ProcessResult, RoutingPlan, RuleFieldSet,
    SchemaClassifier, SchemaPruning, SchemaRouter, parse_pipeline_file,
};
use rsigma_parser::SigmaCollection;

use crate::sources::{self, SourceResolver, TemplateExpander};

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
    /// External dynamic source declarations (loaded via `--source`). Pipelines
    /// reference these with `${source.<id>}`; the declarations themselves no
    /// longer live inside pipeline files. Resolved and expanded into the
    /// pipelines on every `load_rules()`.
    external_sources: Vec<DynamicSource>,
    allow_remote_include: bool,
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
}

/// Summary statistics about the loaded engine state.
#[derive(Debug, Clone, Copy)]
pub struct EngineStats {
    pub detection_rules: usize,
    pub correlation_rules: usize,
    pub state_entries: usize,
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
            rules_path,
            corr_config,
            include_event,
            source_resolver: None,
            external_sources: Vec::new(),
            allow_remote_include: false,
            bloom_prefilter: false,
            bloom_max_bytes: None,
            match_detail: MatchDetailLevel::Off,
            #[cfg(feature = "daachorse-index")]
            cross_rule_ac: false,
            rule_field_set: Arc::new(ArcSwap::from_pointee(RuleFieldSet::default())),
            routing: None,
            logsource_extractor: None,
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
        }
    }

    /// Total evaluate calls with no extractable event logsource (fail-open)
    /// across the active engine variant.
    pub fn logsource_absent_total(&self) -> u64 {
        match &self.engine {
            EngineVariant::DetectionOnly(engine) => engine.logsource_absent_total(),
            EngineVariant::WithCorrelations(engine) => engine.logsource_absent_total(),
            EngineVariant::Routed(router) => router.logsource_absent_total(),
        }
    }

    /// Static per-schema logsource pruning summary. Non-empty only for the
    /// routed variant with logsource routing enabled.
    pub fn schema_pruning_summary(&self) -> Vec<SchemaPruning> {
        match &self.engine {
            EngineVariant::Routed(router) => router.schema_pruning_summary(),
            _ => Vec::new(),
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
    /// `load_rules()` handle it synchronously via `tokio::runtime::Handle`.
    pub async fn resolve_dynamic_pipelines(&mut self) -> Result<(), String> {
        let Some(resolver) = &self.source_resolver else {
            return Ok(());
        };

        let pipelines = std::mem::take(&mut self.pipelines);
        let external = self.external_sources.clone();
        let resolved =
            resolve_pipelines_async(resolver, &pipelines, &external, self.allow_remote_include)
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
    /// Dynamic pipeline sources are resolved if a source resolver is configured.
    pub fn load_rules(&mut self) -> Result<EngineStats, String> {
        let load_span = tracing::info_span!("load_rules", rules_path = %self.rules_path.display());
        let _enter = load_span.enter();
        let load_start = std::time::Instant::now();

        if !self.pipeline_paths.is_empty() {
            self.pipelines = reload_pipelines(&self.pipeline_paths)?;
        }

        // Resolve dynamic sources if a resolver is set.
        //
        // Both error cases must fail closed. Loading rules with unresolved
        // `${source.*}` templates produces rules whose semantics differ
        // from what the operator wrote; on a hot-reload, the previous
        // engine is still serving traffic, so returning an error here
        // keeps it active rather than silently replacing it with a broken
        // one.
        if self.source_resolver.is_some() && self.pipelines.iter().any(|p| p.is_dynamic()) {
            let handle = tokio::runtime::Handle::try_current().map_err(|_| {
                "Dynamic pipelines require a tokio runtime; refusing to load rules with \
                 unresolved sources"
                    .to_string()
            })?;
            let pipelines = std::mem::take(&mut self.pipelines);
            let resolver = self.source_resolver.clone().unwrap();
            let allow_remote = self.allow_remote_include;
            let external = self.external_sources.clone();
            let resolved = tokio::task::block_in_place(|| {
                handle.block_on(async {
                    resolve_pipelines_async(&resolver, &pipelines, &external, allow_remote).await
                })
            });
            match resolved {
                Ok(p) => self.pipelines = p,
                Err(e) => {
                    // Restore the captured pipelines so a higher-level
                    // retry can re-run the same load against the same
                    // inputs.
                    self.pipelines = pipelines;
                    return Err(format!("Dynamic source resolution failed: {e}"));
                }
            }
        }

        let previous_state = self.export_state();
        let collection = load_collection(&self.rules_path)?;
        let has_correlations = !collection.correlations.is_empty();

        if let Some(mut spec) = self.routing.clone() {
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
                    let mut resolved_sets = Vec::with_capacity(spec.pipeline_sets.len());
                    for set in spec.pipeline_sets {
                        let resolved = tokio::task::block_in_place(|| {
                            handle.block_on(async {
                                resolve_pipelines_async(&resolver, &set, &external, allow_remote)
                                    .await
                            })
                        });
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
                &collection,
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
                router.import_state(snapshot);
            }

            let stats = EngineStats {
                detection_rules: router.detection_rule_count(),
                correlation_rules: router.correlation_rule_count(),
                state_entries: router.state_count(),
            };
            self.engine = EngineVariant::Routed(Box::new(router));
            self.refresh_rule_field_set(&collection);
            tracing::debug!(
                detection_rules = stats.detection_rules,
                correlation_rules = stats.correlation_rules,
                duration_ms = load_start.elapsed().as_millis() as u64,
                "Rule load complete (schema routing)",
            );
            return Ok(stats);
        }

        if has_correlations {
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
            for p in &self.pipelines {
                engine.add_pipeline(p.clone());
            }
            engine
                .add_collection(&collection)
                .map_err(|e| format!("Error compiling rules: {e}"))?;

            if let Some(snapshot) = previous_state {
                engine.import_state(snapshot);
            }

            let stats = EngineStats {
                detection_rules: engine.detection_rule_count(),
                correlation_rules: engine.correlation_rule_count(),
                state_entries: engine.state_count(),
            };
            self.engine = EngineVariant::WithCorrelations(Box::new(engine));
            self.refresh_rule_field_set(&collection);
            tracing::debug!(
                detection_rules = stats.detection_rules,
                correlation_rules = stats.correlation_rules,
                duration_ms = load_start.elapsed().as_millis() as u64,
                "Rule load complete",
            );
            Ok(stats)
        } else {
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
            for p in &self.pipelines {
                engine.add_pipeline(p.clone());
            }
            engine
                .add_collection(&collection)
                .map_err(|e| format!("Error compiling rules: {e}"))?;

            let stats = EngineStats {
                detection_rules: engine.rule_count(),
                correlation_rules: 0,
                state_entries: 0,
            };
            self.engine = EngineVariant::DetectionOnly(Box::new(engine));
            self.refresh_rule_field_set(&collection);
            tracing::debug!(
                detection_rules = stats.detection_rules,
                correlation_rules = stats.correlation_rules,
                duration_ms = load_start.elapsed().as_millis() as u64,
                "Rule load complete",
            );
            Ok(stats)
        }
    }

    /// Recompute the post-pipeline rule field set and publish it. Called at
    /// the end of every successful `load_rules()` branch.
    fn refresh_rule_field_set(&self, collection: &SigmaCollection) {
        let field_set = RuleFieldSet::collect(collection, &self.pipelines, true);
        self.rule_field_set.store(Arc::new(field_set));
    }

    /// Process a batch of events using parallel detection + sequential correlation.
    ///
    /// Delegates to `Engine::evaluate_batch` or `CorrelationEngine::process_batch`
    /// depending on whether correlation rules are loaded.
    pub fn process_batch<E: Event + Sync>(&mut self, events: &[&E]) -> Vec<ProcessResult> {
        match &mut self.engine {
            EngineVariant::DetectionOnly(engine) => engine.evaluate_batch(events),
            EngineVariant::WithCorrelations(engine) => engine.process_batch(events),
            EngineVariant::Routed(router) => router.process_batch(events),
        }
    }

    /// Return summary statistics about the current engine state.
    pub fn stats(&self) -> EngineStats {
        match &self.engine {
            EngineVariant::DetectionOnly(engine) => EngineStats {
                detection_rules: engine.rule_count(),
                correlation_rules: 0,
                state_entries: 0,
            },
            EngineVariant::WithCorrelations(engine) => EngineStats {
                detection_rules: engine.detection_rule_count(),
                correlation_rules: engine.correlation_rule_count(),
                state_entries: engine.state_count(),
            },
            EngineVariant::Routed(router) => EngineStats {
                detection_rules: router.detection_rule_count(),
                correlation_rules: router.correlation_rule_count(),
                state_entries: router.state_count(),
            },
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

    /// Export correlation state as a serializable snapshot.
    /// Returns `None` if the engine is detection-only (no correlation state to persist).
    pub fn export_state(&self) -> Option<CorrelationSnapshot> {
        match &self.engine {
            EngineVariant::DetectionOnly(_) => None,
            EngineVariant::WithCorrelations(engine) => Some(engine.export_state()),
            EngineVariant::Routed(router) => router.export_state(),
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
        match &self.engine {
            EngineVariant::DetectionOnly(_) => None,
            EngineVariant::WithCorrelations(engine) => Some(engine.introspect_filtered(id, group)),
            EngineVariant::Routed(router) => router.correlation_introspect(id, group),
        }
    }

    /// Import previously exported correlation state.
    /// Returns `true` if the import succeeded, `false` if the snapshot version
    /// is incompatible. No-op (returns `true`) if the engine is detection-only.
    pub fn import_state(&mut self, snapshot: &CorrelationSnapshot) -> bool {
        match &mut self.engine {
            EngineVariant::WithCorrelations(engine) => engine.import_state(snapshot.clone()),
            EngineVariant::Routed(router) => router.import_state(snapshot.clone()),
            EngineVariant::DetectionOnly(_) => true,
        }
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

    if !collection.errors.is_empty() {
        tracing::warn!(
            count = collection.errors.len(),
            "Parse errors while loading rules"
        );
        for (i, err) in collection.errors.iter().take(3).enumerate() {
            tracing::warn!(index = i + 1, error = %err, "Rule parse error detail");
        }
    }

    Ok(collection)
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
) -> Result<Vec<Pipeline>, String> {
    if !pipelines.iter().any(|p| p.is_dynamic()) {
        return Ok(pipelines.to_vec());
    }

    let resolved_data = sources::resolve_all(resolver.as_ref(), external)
        .await
        .map_err(|e| format!("Failed to resolve dynamic sources: {e}"))?;

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
    /// none inline (the only form allowed since v1.0).
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
}
