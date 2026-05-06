use std::path::{Path, PathBuf};
use std::sync::Arc;

use rsigma_eval::event::Event;
use rsigma_eval::{
    CorrelationConfig, CorrelationEngine, CorrelationSnapshot, Engine, Pipeline, ProcessResult,
    parse_pipeline_file,
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
}

enum EngineVariant {
    DetectionOnly(Engine),
    WithCorrelations(Box<CorrelationEngine>),
}

/// Summary statistics about the loaded engine state.
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
            engine: EngineVariant::DetectionOnly(Engine::new()),
            pipelines,
            pipeline_paths: Vec::new(),
            rules_path,
            corr_config,
            include_event,
            source_resolver: None,
            allow_remote_include: false,
        }
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
        if !self.pipeline_paths.is_empty() {
            self.pipelines = reload_pipelines(&self.pipeline_paths)?;
        }

        // Resolve dynamic sources if a resolver is set
        if self.source_resolver.is_some() && self.pipelines.iter().any(|p| p.is_dynamic()) {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
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
                        self.pipelines = pipelines;
                        tracing::warn!(error = %e, "Dynamic source resolution failed, using unresolved pipelines");
                    }
                }
            } else {
                tracing::warn!("No tokio runtime available for dynamic source resolution");
            }
        }

        let previous_state = self.export_state();
        let collection = load_collection(&self.rules_path)?;
        let has_correlations = !collection.correlations.is_empty();

        if has_correlations {
            let mut engine = CorrelationEngine::new(self.corr_config.clone());
            engine.set_include_event(self.include_event);
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
            Ok(stats)
        } else {
            let mut engine = Engine::new();
            engine.set_include_event(self.include_event);
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
            self.engine = EngineVariant::DetectionOnly(engine);
            Ok(stats)
        }
    }

    /// Process a batch of events using parallel detection + sequential correlation.
    ///
    /// Delegates to `Engine::evaluate_batch` or `CorrelationEngine::process_batch`
    /// depending on whether correlation rules are loaded.
    pub fn process_batch<E: Event + Sync>(&mut self, events: &[&E]) -> Vec<ProcessResult> {
        match &mut self.engine {
            EngineVariant::DetectionOnly(engine) => {
                let batch_detections = engine.evaluate_batch(events);
                batch_detections
                    .into_iter()
                    .map(|detections| ProcessResult {
                        detections,
                        correlations: vec![],
                    })
                    .collect()
            }
            EngineVariant::WithCorrelations(engine) => engine.process_batch(events),
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
        }
    }

    /// Import previously exported correlation state.
    /// Returns `true` if the import succeeded, `false` if the snapshot version
    /// is incompatible. No-op (returns `true`) if the engine is detection-only.
    pub fn import_state(&mut self, snapshot: &CorrelationSnapshot) -> bool {
        if let EngineVariant::WithCorrelations(engine) = &mut self.engine {
            engine.import_state(snapshot.clone())
        } else {
            true
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
    }

    Ok(collection)
}

/// Re-read and parse all pipeline files from disk, sorted by priority.
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
