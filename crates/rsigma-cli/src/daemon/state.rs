use std::path::Path;

use rsigma_eval::{
    CorrelationConfig, CorrelationEngine, CorrelationSnapshot, Engine, Event, Pipeline,
    ProcessResult,
};
use rsigma_parser::SigmaCollection;

/// Wraps a CorrelationEngine (or a plain Engine) and provides the interface
/// the daemon needs: process events, reload rules, and query state.
pub struct DaemonEngine {
    engine: EngineVariant,
    pipelines: Vec<Pipeline>,
    rules_path: std::path::PathBuf,
    corr_config: CorrelationConfig,
    include_event: bool,
}

enum EngineVariant {
    DetectionOnly(Engine),
    WithCorrelations(Box<CorrelationEngine>),
}

pub struct EngineStats {
    pub detection_rules: usize,
    pub correlation_rules: usize,
    pub state_entries: usize,
}

impl DaemonEngine {
    pub fn new(
        rules_path: std::path::PathBuf,
        pipelines: Vec<Pipeline>,
        corr_config: CorrelationConfig,
        include_event: bool,
    ) -> Self {
        DaemonEngine {
            engine: EngineVariant::DetectionOnly(Engine::new()),
            pipelines,
            rules_path,
            corr_config,
            include_event,
        }
    }

    /// Load (or reload) rules from the configured path.
    ///
    /// On reload, correlation state is exported before replacing the engine
    /// and re-imported after, so in-flight windows and suppression state
    /// survive rule changes (entries for removed correlations are dropped).
    pub fn load_rules(&mut self) -> Result<EngineStats, String> {
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
    pub fn process_batch(&mut self, events: &[&Event]) -> Vec<ProcessResult> {
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

    pub fn rules_path(&self) -> &Path {
        &self.rules_path
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
