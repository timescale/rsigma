//! Rule sources for the runtime: one path or several named rulesets.

use std::path::{Path, PathBuf};

use rsigma_eval::{Pipeline, TenantId, parse_pipeline_file};
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
    /// Tenant ids admitted to this ruleset. Empty means every tenant.
    pub tenants: Vec<TenantId>,
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
///
/// `pipeline_paths` are the pipeline files loaded alongside the source; a
/// ruleset's own pipeline files come from its binding. A file is watched
/// through its parent directory, so editors that replace the file on save
/// still trigger a reload.
pub fn watch_paths(source: &RuleSource, pipeline_paths: &[PathBuf]) -> Vec<(PathBuf, bool)> {
    let mut paths = Vec::new();
    match source {
        RuleSource::Path(path) => paths.push(watch_entry(path)),
        RuleSource::Rulesets(bindings) => {
            for binding in bindings {
                for source_path in &binding.spec.sources {
                    paths.push(watch_entry(source_path));
                }
                for overlay in &binding.spec.overlays {
                    if let Some(file) = &overlay.file {
                        paths.push((parent_dir(file), false));
                    }
                    if let Some(dir) = &overlay.dir {
                        paths.push((dir.clone(), true));
                    }
                }
                for pipeline in &binding.pipelines {
                    if let PipelineRef::File(path) = pipeline {
                        paths.push((parent_dir(path), false));
                    }
                }
            }
        }
    }
    for path in pipeline_paths {
        paths.push((parent_dir(path), false));
    }
    paths.sort();
    paths.dedup();
    paths
}

/// A directory is watched recursively; a file through its parent directory.
fn watch_entry(path: &Path) -> (PathBuf, bool) {
    if path.is_dir() {
        (path.to_path_buf(), true)
    } else {
        (parent_dir(path), false)
    }
}

/// The directory holding `path`, with `.` for a bare file name.
fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => PathBuf::from("."),
        Some(parent) => parent.to_path_buf(),
        None => path.to_path_buf(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::ruleset::OverlayEntry;

    #[test]
    fn path_mode_watches_the_rules_and_pipeline_files() {
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("rules");
        std::fs::create_dir(&rules).unwrap();
        let pipeline = dir.path().join("pipes").join("p.yml");
        let watched = watch_paths(&RuleSource::Path(rules.clone()), &[pipeline]);
        assert_eq!(
            watched,
            vec![(dir.path().join("pipes"), false), (rules, true)]
        );
    }

    #[test]
    fn bare_file_names_are_watched_through_the_working_directory() {
        let watched = watch_paths(
            &RuleSource::Path(PathBuf::from("rule.yml")),
            &[PathBuf::from("pipe.yml")],
        );
        assert_eq!(watched, vec![(PathBuf::from("."), false)]);
    }

    #[test]
    fn ruleset_mode_watches_sources_overlays_and_pipelines() {
        let dir = tempfile::tempdir().unwrap();
        let rules = dir.path().join("rules");
        std::fs::create_dir(&rules).unwrap();
        let ruleset = RulesetSpec {
            sources: vec![rules.clone(), PathBuf::from("single.yml")],
            overlays: vec![
                OverlayEntry {
                    file: Some(dir.path().join("overlays").join("level.yml")),
                    ..Default::default()
                },
                OverlayEntry {
                    dir: Some(dir.path().join("more")),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let binding = RulesetBinding {
            name: "a".to_string(),
            spec: ruleset,
            pipelines: vec![PipelineRef::File(dir.path().join("pipes").join("p.yml"))],
            when_schemas: Vec::new(),
            tenants: Vec::new(),
        };
        let watched = watch_paths(&RuleSource::Rulesets(vec![binding]), &[]);
        let mut expected = vec![
            (PathBuf::from("."), false),
            (rules, true),
            (dir.path().join("overlays"), false),
            (dir.path().join("more"), true),
            (dir.path().join("pipes"), false),
        ];
        expected.sort();
        assert_eq!(watched, expected);
    }
}
