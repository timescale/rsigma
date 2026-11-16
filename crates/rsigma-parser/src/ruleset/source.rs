//! Loading ruleset sources with per-document provenance.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ast::{CorrelationRule, FilterRule, FilterRuleTarget, LogSource, SigmaRule};
use crate::diagnostic::CollectionDiagnostic;

use super::error::RulesetError;
use super::spec::RulesetSpec;

/// Options that constrain a resolution.
#[derive(Debug, Clone, Default)]
pub struct ResolveOptions {
    /// Reject any source or overlay path outside this root. Pipelines are not
    /// resolved here, so callers confine pipeline paths themselves.
    pub confine_to: Option<PathBuf>,
}

/// A rule document together with where it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    /// The parsed document.
    pub doc: CandidateDoc,
    /// Where the document was read from.
    pub origin: RuleOrigin,
}

/// A parsed document from a ruleset source.
#[derive(Debug, Clone, PartialEq)]
pub enum CandidateDoc {
    /// A detection rule.
    Detection(SigmaRule),
    /// A correlation rule.
    Correlation(CorrelationRule),
    /// A filter rule.
    Filter(FilterRule),
}

/// Where a candidate came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleOrigin {
    /// Index of the source in the spec.
    pub source: usize,
    /// The source root: a directory, or the parent of a file source.
    pub root: PathBuf,
    /// Path relative to the root, with `/` separators.
    pub file: PathBuf,
    /// Position among documents of its kind in that file.
    pub ordinal: usize,
}

/// A file read while resolving a ruleset, with the bytes used to hash it.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceFile {
    /// Index of the source in the spec; always 0 for overlay files.
    pub source: usize,
    /// The path as read.
    pub path: PathBuf,
    /// Path relative to the source root (the working directory for overlay
    /// files), with `/` separators.
    pub relative: PathBuf,
    /// The file's bytes as read, hashed into the lockfile digest.
    pub sha256_input: Vec<u8>,
}

/// Everything read from a spec's sources.
#[derive(Debug, Clone, Default)]
pub struct LoadedSources {
    /// Every parsed document, in source and file order.
    pub candidates: Vec<Candidate>,
    /// Every file read.
    pub files: Vec<SourceFile>,
    /// Parse diagnostics, with file paths.
    pub diagnostics: Vec<CollectionDiagnostic>,
}

/// The kind of a Sigma document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentKind {
    /// A detection rule.
    Detection,
    /// A correlation rule.
    Correlation,
    /// A filter rule.
    Filter,
}

impl DocumentKind {
    /// The lowercase name used in selectors and reports.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Detection => "detection",
            Self::Correlation => "correlation",
            Self::Filter => "filter",
        }
    }
}

impl Candidate {
    /// The document kind.
    pub fn kind(&self) -> DocumentKind {
        match self.doc {
            CandidateDoc::Detection(_) => DocumentKind::Detection,
            CandidateDoc::Correlation(_) => DocumentKind::Correlation,
            CandidateDoc::Filter(_) => DocumentKind::Filter,
        }
    }

    /// The document `id`.
    pub fn id(&self) -> Option<&str> {
        match &self.doc {
            CandidateDoc::Detection(rule) => rule.id.as_deref(),
            CandidateDoc::Correlation(rule) => rule.id.as_deref(),
            CandidateDoc::Filter(rule) => rule.id.as_deref(),
        }
    }

    /// The document `name`.
    pub fn name(&self) -> Option<&str> {
        match &self.doc {
            CandidateDoc::Detection(rule) => rule.name.as_deref(),
            CandidateDoc::Correlation(rule) => rule.name.as_deref(),
            CandidateDoc::Filter(rule) => rule.name.as_deref(),
        }
    }

    /// The document title.
    pub fn title(&self) -> &str {
        match &self.doc {
            CandidateDoc::Detection(rule) => &rule.title,
            CandidateDoc::Correlation(rule) => &rule.title,
            CandidateDoc::Filter(rule) => &rule.title,
        }
    }

    /// The document logsource; correlations have none of their own.
    pub fn logsource(&self) -> Option<&LogSource> {
        match &self.doc {
            CandidateDoc::Detection(rule) => Some(&rule.logsource),
            CandidateDoc::Correlation(_) => None,
            CandidateDoc::Filter(rule) => rule.logsource.as_ref(),
        }
    }

    /// The document tags.
    pub fn tags(&self) -> &[String] {
        match &self.doc {
            CandidateDoc::Detection(rule) => &rule.tags,
            CandidateDoc::Correlation(rule) => &rule.tags,
            CandidateDoc::Filter(rule) => &rule.tags,
        }
    }

    /// The document level.
    pub fn level(&self) -> Option<crate::ast::Level> {
        match &self.doc {
            CandidateDoc::Detection(rule) => rule.level,
            CandidateDoc::Correlation(rule) => rule.level,
            CandidateDoc::Filter(rule) => rule.level,
        }
    }

    /// The document status.
    pub fn status(&self) -> Option<crate::ast::Status> {
        match &self.doc {
            CandidateDoc::Detection(rule) => rule.status,
            CandidateDoc::Correlation(rule) => rule.status,
            CandidateDoc::Filter(rule) => rule.status,
        }
    }

    /// Rules a correlation references, by id or name.
    pub fn referenced_rules(&self) -> &[String] {
        match &self.doc {
            CandidateDoc::Correlation(rule) => &rule.rules,
            _ => &[],
        }
    }

    /// Rules a filter targets, if it is not `Any`.
    pub fn filter_targets(&self) -> Option<&[String]> {
        match &self.doc {
            CandidateDoc::Filter(rule) => match &rule.rules {
                FilterRuleTarget::Any => None,
                FilterRuleTarget::Specific(targets) => Some(targets),
            },
            _ => None,
        }
    }
}

/// Load every source declared by `spec` in declaration order, parsing each
/// file separately so every document keeps its origin.
pub fn load_sources(
    spec: &RulesetSpec,
    opts: &ResolveOptions,
) -> Result<LoadedSources, RulesetError> {
    let mut loaded = LoadedSources::default();

    for (source_index, source) in spec.sources.iter().enumerate() {
        if !source.exists() {
            return Err(RulesetError::MissingSource {
                ruleset: None,
                path: source.clone(),
            });
        }
        let root = if source.is_dir() {
            source.clone()
        } else {
            source
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
        };

        let mut paths = Vec::new();
        if source.is_dir() {
            // Per source, so overlapping sources each see their full tree and
            // the uniqueness check reports the overlap.
            let mut visited = HashSet::new();
            crate::walk::collect_yaml_files(&root, &root, None, &mut paths, &mut visited).map_err(
                |e| RulesetError::Io {
                    ruleset: None,
                    path: root.clone(),
                    source: std::io::Error::other(e.to_string()),
                },
            )?;
        } else {
            paths.push(source.clone());
        }

        for path in paths {
            let canonical = path.canonicalize().map_err(|e| RulesetError::Io {
                ruleset: None,
                path: path.clone(),
                source: e,
            })?;
            confine(&canonical, opts)?;

            let bytes = std::fs::read(&path).map_err(|e| RulesetError::Io {
                ruleset: None,
                path: path.clone(),
                source: e,
            })?;
            let text = String::from_utf8_lossy(&bytes);
            let relative = relative_to(&path, &root);
            let mut collection = match crate::parse_sigma_yaml(&text) {
                Ok(collection) => collection,
                Err(e) => {
                    loaded
                        .diagnostics
                        .push(CollectionDiagnostic::file(&path, &e));
                    continue;
                }
            };
            for diagnostic in &mut collection.diagnostics {
                diagnostic.path = Some(path.clone());
            }
            loaded.diagnostics.extend(collection.diagnostics);

            loaded.files.push(SourceFile {
                source: source_index,
                path: path.clone(),
                relative: relative.clone(),
                sha256_input: bytes,
            });

            for (ordinal, rule) in collection.rules.into_iter().enumerate() {
                loaded.candidates.push(Candidate {
                    doc: CandidateDoc::Detection(rule),
                    origin: RuleOrigin {
                        source: source_index,
                        root: root.clone(),
                        file: relative.clone(),
                        ordinal,
                    },
                });
            }
            for (ordinal, rule) in collection.correlations.into_iter().enumerate() {
                loaded.candidates.push(Candidate {
                    doc: CandidateDoc::Correlation(rule),
                    origin: RuleOrigin {
                        source: source_index,
                        root: root.clone(),
                        file: relative.clone(),
                        ordinal,
                    },
                });
            }
            for (ordinal, rule) in collection.filters.into_iter().enumerate() {
                loaded.candidates.push(Candidate {
                    doc: CandidateDoc::Filter(rule),
                    origin: RuleOrigin {
                        source: source_index,
                        root: root.clone(),
                        file: relative.clone(),
                        ordinal,
                    },
                });
            }
        }
    }

    Ok(loaded)
}

/// Reject a canonical path outside the confinement root.
pub(crate) fn confine(path: &Path, opts: &ResolveOptions) -> Result<(), RulesetError> {
    let Some(root) = &opts.confine_to else {
        return Ok(());
    };
    let root = root.canonicalize().map_err(|e| RulesetError::Io {
        ruleset: None,
        path: root.clone(),
        source: e,
    })?;
    if path.starts_with(&root) {
        Ok(())
    } else {
        Err(RulesetError::Confinement {
            ruleset: None,
            path: path.to_path_buf(),
        })
    }
}

/// Render `path` relative to `root` with `/` separators.
pub(crate) fn relative_to(path: &Path, root: &Path) -> PathBuf {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let mut out = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir => out.push(".."),
            Component::RootDir | Component::Prefix(_) => {}
        }
    }
    let text = out
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    PathBuf::from(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    fn rule(id: &str, title: &str) -> String {
        format!(
            "title: {title}\nid: {id}\nlogsource:\n    product: linux\ndetection:\n    selection:\n        Field: value\n    condition: selection\n"
        )
    }

    #[test]
    fn walks_nested_directories_in_sorted_order() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(&root.join("rules/b.yml"), &rule("b", "B"));
        write(&root.join("rules/a/z.yml"), &rule("z", "Z"));
        write(&root.join("rules/a/a.yml"), &rule("a", "A"));
        write(&root.join("rules/.hidden/c.yml"), &rule("c", "C"));

        let spec = RulesetSpec {
            sources: vec![root.join("rules")],
            ..Default::default()
        };
        let loaded = load_sources(&spec, &ResolveOptions::default()).unwrap();
        let files: Vec<String> = loaded
            .files
            .iter()
            .map(|f| f.relative.to_string_lossy().into_owned())
            .collect();
        assert_eq!(files, ["a/a.yml", "a/z.yml", "b.yml"], "{files:?}");
        assert_eq!(loaded.candidates.len(), 3);
        assert_eq!(loaded.candidates[0].origin.ordinal, 0);
        assert_eq!(loaded.candidates[1].origin.ordinal, 0);
        assert_eq!(loaded.candidates[2].origin.ordinal, 0);
    }

    #[test]
    fn overlapping_sources_load_the_same_files_in_either_order() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(&root.join("rules/windows/w.yml"), &rule("w", "W"));
        write(&root.join("rules/l.yml"), &rule("l", "L"));
        for sources in [
            vec![root.join("rules"), root.join("rules/windows")],
            vec![root.join("rules/windows"), root.join("rules")],
        ] {
            let spec = RulesetSpec {
                sources,
                ..Default::default()
            };
            let loaded = load_sources(&spec, &ResolveOptions::default()).unwrap();
            let per_source: Vec<usize> = (0..2)
                .map(|index| {
                    loaded
                        .candidates
                        .iter()
                        .filter(|c| c.origin.source == index)
                        .count()
                })
                .collect();
            let windows_first = spec.sources[0].ends_with("windows");
            let expected = if windows_first { [1, 2] } else { [2, 1] };
            assert_eq!(per_source, expected, "{:?}", spec.sources);
        }
    }

    #[test]
    fn reads_a_file_source_with_any_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rule.txt");
        write(&path, &rule("x", "X"));
        let spec = RulesetSpec {
            sources: vec![path.clone()],
            ..Default::default()
        };
        let loaded = load_sources(&spec, &ResolveOptions::default()).unwrap();
        assert_eq!(loaded.candidates.len(), 1);
        assert_eq!(loaded.candidates[0].origin.file, PathBuf::from("rule.txt"));
        assert_eq!(loaded.candidates[0].origin.root, dir.path());
    }

    #[test]
    fn symlink_loop_terminates() {
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("rules");
            write(&root.join("a.yml"), &rule("a", "A"));
            std::os::unix::fs::symlink(&root, root.join("loop")).unwrap();
            let spec = RulesetSpec {
                sources: vec![root],
                ..Default::default()
            };
            let loaded = load_sources(&spec, &ResolveOptions::default()).unwrap();
            assert_eq!(loaded.candidates.len(), 1);
        }
    }

    #[test]
    fn missing_source_errors() {
        let spec = RulesetSpec {
            sources: vec![PathBuf::from("/definitely/not/here")],
            ..Default::default()
        };
        let error = load_sources(&spec, &ResolveOptions::default()).unwrap_err();
        assert!(
            matches!(error, RulesetError::MissingSource { .. }),
            "{error}"
        );
    }

    #[test]
    fn multi_document_files_get_per_kind_ordinals() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yml");
        write(
            &path,
            &format!(
                "{}\n---\n{}\n---\ntitle: Filter\nlogsource:\n    product: linux\nfilter:\n    rules: any\n    selection:\n        Field: value\n    condition: selection\n",
                rule("a", "A"),
                rule("b", "B")
            ),
        );
        let spec = RulesetSpec {
            sources: vec![path],
            ..Default::default()
        };
        let loaded = load_sources(&spec, &ResolveOptions::default()).unwrap();
        assert_eq!(loaded.candidates.len(), 3);
        assert_eq!(loaded.candidates[0].origin.ordinal, 0);
        assert_eq!(loaded.candidates[1].origin.ordinal, 1);
        assert_eq!(loaded.candidates[2].origin.ordinal, 0);
        assert_eq!(loaded.candidates[2].kind(), DocumentKind::Filter);
    }

    #[test]
    fn parse_diagnostics_keep_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.yml");
        write(&path, "title: Broken\nlogsource: {}\ndetection: {}\n");
        let spec = RulesetSpec {
            sources: vec![path.clone()],
            ..Default::default()
        };
        let loaded = load_sources(&spec, &ResolveOptions::default()).unwrap();
        assert!(!loaded.diagnostics.is_empty());
        assert_eq!(loaded.diagnostics[0].path.as_deref(), Some(path.as_path()));
    }

    #[test]
    fn confinement_rejects_outside_and_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let inside = dir.path().join("inside");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        write(&outside.join("r.yml"), &rule("x", "X"));

        let opts = ResolveOptions {
            confine_to: Some(inside.clone()),
        };
        let spec = RulesetSpec {
            sources: vec![outside.clone()],
            ..Default::default()
        };
        let error = load_sources(&spec, &opts).unwrap_err();
        assert!(matches!(error, RulesetError::Confinement { .. }), "{error}");

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, inside.join("link")).unwrap();
            let spec = RulesetSpec {
                sources: vec![inside.join("link")],
                ..Default::default()
            };
            let error = load_sources(&spec, &opts).unwrap_err();
            assert!(matches!(error, RulesetError::Confinement { .. }), "{error}");
        }
    }
}
