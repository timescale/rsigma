//! Rule sources for the runtime: one path or several named rulesets.

use std::path::{Path, PathBuf};

use rsigma_eval::{Pipeline, parse_pipeline_file};
use rsigma_parser::ruleset::RulesetSpec;

/// How a ruleset supplies its pipelines.
#[derive(Debug, Clone)]
pub enum PipelineRef {
    /// A builtin pipeline resolved at startup.
    Builtin(Pipeline),
    /// A pipeline file re-parsed on every reload.
    File(PathBuf),
}

/// One named ruleset binding for the runtime.
#[derive(Debug, Clone)]
pub struct RulesetBinding {
    /// Ruleset name.
    pub name: String,
    /// Ruleset specification.
    pub spec: RulesetSpec,
    /// Pipelines for this ruleset.
    pub pipelines: Vec<PipelineRef>,
    /// Schema names that admit an event to this ruleset.
    pub when_schemas: Vec<String>,
}

/// Where the runtime loads its rules from.
#[derive(Debug, Clone)]
pub enum RuleSource {
    /// A single file or directory path.
    Path(PathBuf),
    /// Several named rulesets.
    Rulesets(Vec<RulesetBinding>),
}

/// Paths the hot-reload watcher should watch, with their recursive flag.
pub fn watch_paths(source: &RuleSource) -> Vec<(PathBuf, bool)> {
    let mut paths = Vec::new();
    match source {
        RuleSource::Path(path) => {
            if path.is_dir() {
                paths.push((path.clone(), true));
            } else {
                paths.push((
                    path.parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| path.clone()),
                    false,
                ));
            }
        }
        RuleSource::Rulesets(bindings) => {
            for binding in bindings {
                for source_path in &binding.spec.sources {
                    if source_path.is_dir() {
                        paths.push((source_path.clone(), true));
                    } else {
                        paths.push((
                            source_path
                                .parent()
                                .map(Path::to_path_buf)
                                .unwrap_or_else(|| source_path.clone()),
                            false,
                        ));
                    }
                }
                for overlay in &binding.spec.overlays {
                    if let Some(file) = &overlay.file {
                        paths.push((
                            file.parent()
                                .map(Path::to_path_buf)
                                .unwrap_or_else(|| file.clone()),
                            false,
                        ));
                    }
                    if let Some(dir) = &overlay.dir {
                        paths.push((dir.clone(), true));
                    }
                }
                for pipeline in &binding.pipelines {
                    if let PipelineRef::File(path) = pipeline {
                        paths.push((
                            path.parent()
                                .map(Path::to_path_buf)
                                .unwrap_or_else(|| path.clone()),
                            false,
                        ));
                    }
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

/// Re-parse every file pipeline in a binding, keeping builtins.
pub fn load_pipelines(binding: &RulesetBinding) -> Result<Vec<Pipeline>, String> {
    let mut pipelines = Vec::new();
    for pipeline in &binding.pipelines {
        match pipeline {
            PipelineRef::Builtin(pipeline) => pipelines.push(pipeline.clone()),
            PipelineRef::File(path) => pipelines.push(
                parse_pipeline_file(path)
                    .map_err(|e| format!("pipeline '{}': {e}", path.display()))?,
            ),
        }
    }
    pipelines.sort_by_key(|pipeline| pipeline.priority);
    Ok(pipelines)
}
