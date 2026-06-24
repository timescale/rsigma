use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use rsigma_eval::event::Event;
use rsigma_eval::{
    CorrelationConfig, CorrelationEngine, CorrelationSnapshot, Engine, MatchDetailLevel, Pipeline,
    ProcessResult, RoutingPlan, RuleFieldSet, SchemaClassifier, SchemaRouter, parse_pipeline_file,
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
}

/// Everything needed to (re)build a [`SchemaRouter`] on rule load. Pipeline
/// sets are pre-resolved by the caller (builtin names + files), index-aligned
/// with `plan.pipeline_sets()`.
#[derive(Clone)]
pub struct RoutingSpec {
    pub classifier: SchemaClassifier,
    pub plan: RoutingPlan,
    pub pipeline_sets: Vec<Vec<Pipeline>>,
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
            allow_remote_include: false,
            bloom_prefilter: false,
            bloom_max_bytes: None,
            match_detail: MatchDetailLevel::Off,
            #[cfg(feature = "daachorse-index")]
            cross_rule_ac: false,
            rule_field_set: Arc::new(ArcSwap::from_pointee(RuleFieldSet::default())),
            routing: None,
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

        let mut resolved_pipelines = Vec::with_capacity(self.pipelines.len());
        for pipeline in &self.pipelines {
            if pipeline.is_dynamic() {
                match sources::resolve_all(resolver.as_ref(), &pipeline.sources).await {
                    Ok(resolved_data) => {
                        let mut expanded = TemplateExpander::expand(pipeline, &resolved_data);
                        // Expand include directives
                        sources::include::expand_includes(
                            &mut expanded,
                            &resolved_data,
                            self.allow_remote_include,
                        )?;
                        resolved_pipelines.push(expanded);
                    }
                    Err(e) => {
                        return Err(format!(
                            "Failed to resolve dynamic pipeline '{}': {e}",
                            pipeline.name
                        ));
                    }
                }
            } else {
                resolved_pipelines.push(pipeline.clone());
            }
        }
        self.pipelines = resolved_pipelines;
        Ok(())
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
            let resolved = tokio::task::block_in_place(|| {
                handle.block_on(async {
                    resolve_pipelines_async(&resolver, &pipelines, allow_remote).await
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
                    let mut resolved_sets = Vec::with_capacity(spec.pipeline_sets.len());
                    for set in spec.pipeline_sets {
                        let resolved = tokio::task::block_in_place(|| {
                            handle.block_on(async {
                                resolve_pipelines_async(&resolver, &set, allow_remote).await
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

            let mut router = SchemaRouter::build(
                &collection,
                spec.classifier,
                spec.plan,
                spec.pipeline_sets,
                self.corr_config.clone(),
                self.include_event,
                self.match_detail,
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
/// Every pipeline file that still declares an inline `sources:` block
/// triggers the [`warn_pipeline_inline_sources`](crate::warn_pipeline_inline_sources)
/// deprecation notice. The helper deduplicates by canonical path across the
/// whole process, so the warning surfaces on the first daemon hot-reload that
/// observes a deprecated pipeline and is silent on subsequent reloads of the
/// same file (every SIGHUP, file-watcher event, or `POST /api/v1/reload`
/// thereafter is a noop for the dedup set).
fn reload_pipelines(paths: &[PathBuf]) -> Result<Vec<Pipeline>, String> {
    let mut pipelines = Vec::with_capacity(paths.len());
    for path in paths {
        let pipeline = parse_pipeline_file(path)
            .map_err(|e| format!("Error reloading pipeline {}: {e}", path.display()))?;
        if !pipeline.sources.is_empty() {
            crate::warn_pipeline_inline_sources(path, &pipeline.name);
        }
        pipelines.push(pipeline);
    }
    pipelines.sort_by_key(|p| p.priority);
    Ok(pipelines)
}

/// Resolve dynamic sources in pipelines asynchronously.
async fn resolve_pipelines_async(
    resolver: &Arc<dyn SourceResolver>,
    pipelines: &[Pipeline],
    allow_remote_include: bool,
) -> Result<Vec<Pipeline>, String> {
    let mut resolved_pipelines = Vec::with_capacity(pipelines.len());
    for pipeline in pipelines {
        if pipeline.is_dynamic() {
            let resolved_data = sources::resolve_all(resolver.as_ref(), &pipeline.sources)
                .await
                .map_err(|e| {
                    format!(
                        "Failed to resolve dynamic pipeline '{}': {e}",
                        pipeline.name
                    )
                })?;
            let mut expanded = TemplateExpander::expand(pipeline, &resolved_data);
            sources::include::expand_includes(&mut expanded, &resolved_data, allow_remote_include)?;
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
    use crate::pipeline_deprecation::reset_inline_sources_dedup_for_tests;

    // The pipeline-embedded `sources:` dedup set is process-wide, so tests
    // that read it must serialize against every other test that touches it,
    // including the unit tests in `pipeline_deprecation`. They share one lock
    // (`DEDUP_TEST_LOCK`) so cargo's parallel test threads don't race on the
    // global set. `serial_guard` recovers a poisoned lock so a failing test
    // does not cascade into the others.
    fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::pipeline_deprecation::DEDUP_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

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

    const PIPELINE_WITH_SOURCES: &str = r#"
name: legacy_pipeline_with_inline_sources
priority: 50
sources:
  - id: threat_feed
    type: file
    path: /tmp/does-not-matter.json
    format: json
transformations:
  - type: value_placeholders
"#;

    const PIPELINE_NO_SOURCES: &str = r#"
name: simple_pipeline
priority: 10
transformations:
  - id: rename
    type: field_name_mapping
    mapping:
      EventID: event.id
"#;

    fn dedup_set_contains(path: &Path) -> bool {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        crate::pipeline_deprecation::tests_only_snapshot().contains(&canonical)
    }

    #[test]
    fn load_rules_surfaces_inline_sources_deprecation_through_runtime() {
        let _guard = serial_guard();
        reset_inline_sources_dedup_for_tests();

        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("rule.yml");
        std::fs::write(&rule_path, RULE_YAML).unwrap();

        let pipeline_path = dir.path().join("pipeline.yml");
        std::fs::write(&pipeline_path, PIPELINE_WITH_SOURCES).unwrap();
        let pipeline = parse_pipeline_file(&pipeline_path).unwrap();

        let mut engine = RuntimeEngine::new(
            rule_path,
            vec![pipeline],
            CorrelationConfig::default(),
            false,
        );
        engine.set_pipeline_paths(vec![pipeline_path.clone()]);
        engine.load_rules().unwrap();

        assert!(
            dedup_set_contains(&pipeline_path),
            "RuntimeEngine::load_rules should route inline sources through \
             warn_pipeline_inline_sources so the daemon hot-reload path \
             covers the deprecation; the canonical pipeline path was not \
             recorded in the dedup set."
        );
    }

    #[test]
    fn load_rules_does_not_warn_when_pipeline_has_no_inline_sources() {
        let _guard = serial_guard();
        reset_inline_sources_dedup_for_tests();

        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("rule.yml");
        std::fs::write(&rule_path, RULE_YAML).unwrap();

        let pipeline_path = dir.path().join("clean.yml");
        std::fs::write(&pipeline_path, PIPELINE_NO_SOURCES).unwrap();
        let pipeline = parse_pipeline_file(&pipeline_path).unwrap();

        let mut engine = RuntimeEngine::new(
            rule_path,
            vec![pipeline],
            CorrelationConfig::default(),
            false,
        );
        engine.set_pipeline_paths(vec![pipeline_path.clone()]);
        engine.load_rules().unwrap();

        assert!(
            !dedup_set_contains(&pipeline_path),
            "a pipeline without inline sources must not register in the \
             deprecation dedup set."
        );
    }

    #[test]
    fn hot_reload_dedups_inline_sources_warning_for_same_pipeline_path() {
        let _guard = serial_guard();
        reset_inline_sources_dedup_for_tests();

        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("rule.yml");
        std::fs::write(&rule_path, RULE_YAML).unwrap();

        let pipeline_path = dir.path().join("pipeline.yml");
        std::fs::write(&pipeline_path, PIPELINE_WITH_SOURCES).unwrap();
        let pipeline = parse_pipeline_file(&pipeline_path).unwrap();

        let mut engine = RuntimeEngine::new(
            rule_path,
            vec![pipeline],
            CorrelationConfig::default(),
            false,
        );
        engine.set_pipeline_paths(vec![pipeline_path.clone()]);

        // Initial daemon startup loads the pipeline once.
        engine.load_rules().unwrap();
        assert!(dedup_set_contains(&pipeline_path));

        // A hot-reload (SIGHUP, file-watcher event, POST /api/v1/reload)
        // re-enters reload_pipelines; the dedup set must already contain
        // the canonical path so the warning does not re-fire. The proof is
        // that the set state is unchanged after the second reload.
        let canonical = pipeline_path.canonicalize().unwrap();
        let before = crate::pipeline_deprecation::tests_only_snapshot();
        engine.load_rules().unwrap();
        let after = crate::pipeline_deprecation::tests_only_snapshot();

        assert_eq!(
            before, after,
            "second load_rules should not change the dedup set",
        );
        assert!(after.contains(&canonical));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn load_rules_fails_closed_when_dynamic_source_resolution_fails() {
        // A dynamic pipeline whose source cannot resolve must surface the
        // error so callers (LogProcessor::reload_rules in particular) can
        // keep the previous engine active. The historical behavior logged
        // a warning and loaded rules with unexpanded `${source.*}`
        // placeholders, which silently produced detection rules with
        // different semantics from what the operator wrote.
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("rule.yml");
        std::fs::write(&rule_path, RULE_YAML).unwrap();

        // Pipeline declares a file dynamic source pointing at a path that
        // does not exist; the resolver returns SourceError on first read.
        let missing = dir.path().join("missing.json");
        let pipeline_yaml = format!(
            r#"
name: dynamic_missing
priority: 10
sources:
  - id: feed
    type: file
    path: {}
    format: json
    on_error: fail
transformations:
  - type: value_placeholders
"#,
            missing.display(),
        );
        let pipeline_path = dir.path().join("pipeline.yml");
        std::fs::write(&pipeline_path, pipeline_yaml).unwrap();
        let pipeline = parse_pipeline_file(&pipeline_path).unwrap();
        assert!(
            pipeline.is_dynamic(),
            "fixture should produce a dynamic pipeline"
        );

        let mut engine = RuntimeEngine::new(
            rule_path,
            vec![pipeline],
            CorrelationConfig::default(),
            false,
        );
        engine.set_source_resolver(Arc::new(sources::DefaultSourceResolver::new()));

        let err = engine
            .load_rules()
            .expect_err("missing source must cause load_rules to fail closed");
        assert!(
            err.contains("Dynamic source resolution failed"),
            "error should explain the fail-closed path; got: {err}"
        );
    }
}
