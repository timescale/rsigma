use std::path::{Path, PathBuf};

use rsigma_eval::event::Event;
use rsigma_eval::{
    CorrelationConfig, CorrelationEngine, CorrelationSnapshot, Engine, Pipeline, ProcessResult,
    parse_pipeline_file,
};
use rsigma_parser::SigmaCollection;

/// Wraps a CorrelationEngine (or a plain Engine) and provides the interface
/// the runtime needs: process events, reload rules, and query state.
pub struct RuntimeEngine {
    engine: EngineVariant,
    pipelines: Vec<Pipeline>,
    pipeline_paths: Vec<PathBuf>,
    rules_path: std::path::PathBuf,
    corr_config: CorrelationConfig,
    include_event: bool,
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
        }
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
    pub fn load_rules(&mut self) -> Result<EngineStats, String> {
        if !self.pipeline_paths.is_empty() {
            self.pipelines = reload_pipelines(&self.pipeline_paths)?;
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
