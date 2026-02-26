use std::path::Path;

use rsigma_eval::{CorrelationConfig, CorrelationEngine, Engine, Event, Pipeline, ProcessResult};
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
    /// Returns Ok(()) on success, or an error string.
    pub fn load_rules(&mut self) -> Result<EngineStats, String> {
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

            let stats = EngineStats {
                detection_rules: engine.detection_rule_count(),
                correlation_rules: engine.correlation_rule_count(),
                state_entries: 0,
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

    pub fn process_event(&mut self, event: &Event) -> ProcessResult {
        match &mut self.engine {
            EngineVariant::DetectionOnly(engine) => {
                let detections = engine.evaluate(event);
                ProcessResult {
                    detections,
                    correlations: vec![],
                }
            }
            EngineVariant::WithCorrelations(engine) => engine.process_event(event),
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
