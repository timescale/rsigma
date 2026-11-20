//! Daemon-wide source registry that merges external (`--source`) and
//! pipeline-declared dynamic sources with collision-error semantics.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;

use rsigma_eval::pipeline::sources::DynamicSource;

/// Origin of a source declaration for diagnostics and API responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceOrigin {
    /// Declared in a standalone sources file loaded via `--source`.
    External(PathBuf),
    /// Declared inline in a pipeline file's `sources:` block.
    Pipeline(String),
}

impl fmt::Display for SourceOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::External(path) => write!(f, "external:{}", path.display()),
            Self::Pipeline(name) => write!(f, "pipeline:{name}"),
        }
    }
}

/// A single entry in the registry: the source plus its declaration origin.
#[derive(Debug, Clone)]
pub struct RegistryEntry {
    pub source: DynamicSource,
    pub origin: SourceOrigin,
}

/// Daemon-scoped registry of all dynamic sources across both external
/// `--source` files and pipeline-embedded `sources:` blocks.
///
/// Construction enforces collision-error semantics: a source ID declared
/// in two different sites (or twice in external files) is a hard startup
/// error with the offending file paths quoted in the message.
#[derive(Debug, Clone)]
pub struct DaemonSourceRegistry {
    entries: Vec<RegistryEntry>,
    ids: HashSet<String>,
}

/// Error returned when two source declarations use the same ID.
#[derive(Debug, Clone)]
pub struct SourceCollisionError {
    pub source_id: String,
    pub first: SourceOrigin,
    pub second: SourceOrigin,
}

impl fmt::Display for SourceCollisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source ID '{}' declared in both {} and {}",
            self.source_id, self.first, self.second
        )
    }
}

impl std::error::Error for SourceCollisionError {}

impl DaemonSourceRegistry {
    /// Build a registry from external sources and pipeline-declared sources.
    ///
    /// Returns `Err` if any source ID appears more than once across all
    /// declaration sites.
    pub fn new(
        external: Vec<(DynamicSource, PathBuf)>,
        pipeline_sources: Vec<(DynamicSource, String)>,
    ) -> Result<Self, SourceCollisionError> {
        let mut seen: HashMap<String, SourceOrigin> = HashMap::new();
        let mut entries = Vec::with_capacity(external.len() + pipeline_sources.len());

        for (source, path) in external {
            let origin = SourceOrigin::External(path);
            if let Some(prev) = seen.get(&source.id) {
                return Err(SourceCollisionError {
                    source_id: source.id.clone(),
                    first: prev.clone(),
                    second: origin,
                });
            }
            seen.insert(source.id.clone(), origin.clone());
            entries.push(RegistryEntry { source, origin });
        }

        for (source, pipeline_name) in pipeline_sources {
            let origin = SourceOrigin::Pipeline(pipeline_name);
            if let Some(prev) = seen.get(&source.id) {
                return Err(SourceCollisionError {
                    source_id: source.id.clone(),
                    first: prev.clone(),
                    second: origin,
                });
            }
            seen.insert(source.id.clone(), origin.clone());
            entries.push(RegistryEntry { source, origin });
        }

        let ids = seen.into_keys().collect();
        Ok(Self { entries, ids })
    }

    /// Build a registry from only external sources (no pipeline sources).
    pub fn from_external(
        external: Vec<(DynamicSource, PathBuf)>,
    ) -> Result<Self, SourceCollisionError> {
        Self::new(external, Vec::new())
    }

    /// Build an empty registry (no sources at all).
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
            ids: HashSet::new(),
        }
    }

    /// All sources in the registry.
    pub fn sources(&self) -> Vec<&DynamicSource> {
        self.entries.iter().map(|e| &e.source).collect()
    }

    /// All owned sources in the registry.
    pub fn into_sources(self) -> Vec<DynamicSource> {
        self.entries.into_iter().map(|e| e.source).collect()
    }

    /// All entries (source + origin) in the registry.
    pub fn entries(&self) -> &[RegistryEntry] {
        &self.entries
    }

    /// The set of all declared source IDs.
    pub fn ids(&self) -> &HashSet<String> {
        &self.ids
    }

    /// Whether the registry has any sources.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of sources in the registry.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Look up a source by ID.
    pub fn get(&self, id: &str) -> Option<&RegistryEntry> {
        self.entries.iter().find(|e| e.source.id == id)
    }
}

/// Load external sources from `--source` paths. Each path is either a
/// single YAML file or a directory of `*.yml`/`*.yaml` files.
pub fn load_external_sources(
    paths: &[PathBuf],
) -> Result<Vec<(DynamicSource, PathBuf)>, rsigma_eval::EvalError> {
    let mut result = Vec::new();
    for path in paths {
        if path.is_dir() {
            let sources = rsigma_eval::parse_sources_dir(path)?;
            for source in sources {
                result.push((source, path.clone()));
            }
        } else {
            let sources = rsigma_eval::parse_sources_file(path)?;
            for source in sources {
                result.push((source, path.clone()));
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::pipeline::sources::{
        DataFormat, DynamicSource, ErrorPolicy, RefreshPolicy, SourceType,
    };

    fn file_source(id: &str) -> DynamicSource {
        DynamicSource {
            id: id.to_string(),
            source_type: SourceType::File {
                path: PathBuf::from("/tmp/test.json"),
                format: DataFormat::Json,
                extract: None,
                stix: None,
            },
            refresh: RefreshPolicy::Once,
            timeout: None,
            on_error: ErrorPolicy::UseCached,
            required: true,
            default: None,
        }
    }

    #[test]
    fn no_collision_different_ids() {
        let external = vec![
            (file_source("a"), PathBuf::from("sources.yml")),
            (file_source("b"), PathBuf::from("sources.yml")),
        ];
        let pipeline = vec![(file_source("c"), "my_pipeline".to_string())];
        let registry = DaemonSourceRegistry::new(external, pipeline).unwrap();
        assert_eq!(registry.len(), 3);
        assert!(registry.ids().contains("a"));
        assert!(registry.ids().contains("b"));
        assert!(registry.ids().contains("c"));
    }

    #[test]
    fn collision_within_external() {
        let external = vec![
            (file_source("dup"), PathBuf::from("a.yml")),
            (file_source("dup"), PathBuf::from("b.yml")),
        ];
        let err = DaemonSourceRegistry::new(external, Vec::new()).unwrap_err();
        assert_eq!(err.source_id, "dup");
        assert!(err.to_string().contains("a.yml"));
        assert!(err.to_string().contains("b.yml"));
    }

    #[test]
    fn collision_external_vs_pipeline() {
        let external = vec![(file_source("shared"), PathBuf::from("ext.yml"))];
        let pipeline = vec![(file_source("shared"), "pipe1".to_string())];
        let err = DaemonSourceRegistry::new(external, pipeline).unwrap_err();
        assert_eq!(err.source_id, "shared");
    }

    #[test]
    fn empty_registry() {
        let registry = DaemonSourceRegistry::empty();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }
}
