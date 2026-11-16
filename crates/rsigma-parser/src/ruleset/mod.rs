//! Named rulesets: curated, overlaid rule collections resolved in memory.
//!
//! A ruleset is declared under `rulesets:` in `rsigma.yaml` and names its
//! sources, include and exclude selectors, dependency policy, overlays, and
//! pipelines. [`resolve_ruleset`] validates the spec, loads every source with
//! per-document provenance, and returns a [`SigmaCollection`] ready for
//! evaluation or emission.
//!
//! ```rust
//! use rsigma_parser::ruleset::{resolve_ruleset, ResolveOptions, RulesetSpec};
//!
//! let dir = tempfile::tempdir().unwrap();
//! std::fs::write(
//!     dir.path().join("rule.yml"),
//!     "title: Whoami\nlogsource:\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains: whoami\n    condition: selection\n",
//! )
//! .unwrap();
//!
//! let spec: RulesetSpec = yaml_serde::from_str(&format!(
//!     "sources:\n    - {}\n",
//!     dir.path().display()
//! ))
//! .unwrap();
//! let resolved = resolve_ruleset("local", &spec, &ResolveOptions::default()).unwrap();
//! assert_eq!(resolved.collection.rules.len(), 1);
//! ```
//!
//! [`SigmaCollection`]: crate::ast::SigmaCollection

mod closure;
mod error;
mod overlay;
mod select;
mod source;
mod spec;

pub use error::RulesetError;
pub use overlay::{
    AppliedOverlay, FsOverlayLoader, InlineOnlyOverlayLoader, OverlayLoader, OverlayOrigin,
};
pub use select::Decision;
pub use source::{
    Candidate, CandidateDoc, DocumentKind, LoadedSources, ResolveOptions, RuleOrigin, SourceFile,
    load_sources,
};
pub use spec::{
    DependencyPolicy, LogsourceSelector, OverlayEntry, OverlayPatch, RuleSelector, RulesetSpec,
    StaleOverlayPolicy, validate_ruleset_name, validate_spec,
};

use crate::ast::SigmaCollection;

/// Resolve a ruleset from its spec, loading sources from disk.
pub fn resolve_ruleset(
    name: &str,
    spec: &RulesetSpec,
    opts: &ResolveOptions,
) -> Result<ResolvedRuleset, RulesetError> {
    let problems = validate_spec(name, spec);
    if !problems.is_empty() {
        return Err(RulesetError::InvalidSpec(problems));
    }
    let loader = FsOverlayLoader::new(opts.confine_to.clone());
    let loaded = load_sources(spec, opts).map_err(|e| e.named(name))?;
    resolve_validated(name, spec, loaded, &loader)
}

/// A resolved ruleset: the kept collection plus per-document decisions.
#[derive(Debug, Clone)]
pub struct ResolvedRuleset {
    /// The ruleset name.
    pub name: String,
    /// The kept documents, with overlays applied.
    pub collection: SigmaCollection,
    /// One entry per candidate, kept or not, in candidate order.
    pub entries: Vec<RuleEntry>,
    /// Source files read.
    pub files: Vec<SourceFile>,
    /// Overlay files read.
    pub overlay_files: Vec<SourceFile>,
    /// Dropped correlations and skipped stale overlays.
    pub warnings: Vec<String>,
}

/// Why one candidate is in or out of the resolved collection.
#[derive(Debug, Clone)]
pub struct RuleEntry {
    /// The document kind.
    pub kind: DocumentKind,
    /// The document `id`.
    pub id: Option<String>,
    /// The document `name`.
    pub name: Option<String>,
    /// The document title.
    pub title: String,
    /// Where the document was read from.
    pub origin: RuleOrigin,
    /// Whether and why the document is kept.
    pub decision: Decision,
    /// Overlays applied to the document, in order.
    pub overlays: Vec<AppliedOverlay>,
}

/// Resolve already-loaded sources into a collection, applying metadata
/// overlays through `loader`. The spec is validated first, as in
/// [`resolve_ruleset`].
///
/// ```rust
/// use std::path::PathBuf;
///
/// use rsigma_parser::parse_sigma_yaml;
/// use rsigma_parser::ruleset::{
///     Candidate, CandidateDoc, InlineOnlyOverlayLoader, LoadedSources, RuleOrigin, RulesetSpec,
///     resolve_loaded,
/// };
///
/// let yaml = r#"
/// title: Whoami
/// id: 11111111-2222-3333-4444-555555555555
/// logsource:
///     product: windows
/// detection:
///     selection:
///         CommandLine|contains: whoami
///     condition: selection
/// "#;
/// let rule = parse_sigma_yaml(yaml).unwrap().rules.remove(0);
/// let loaded = LoadedSources {
///     candidates: vec![Candidate {
///         doc: CandidateDoc::Detection(rule),
///         origin: RuleOrigin {
///             source: 0,
///             root: PathBuf::from("."),
///             file: PathBuf::from("rule.yml"),
///             ordinal: 0,
///         },
///     }],
///     ..Default::default()
/// };
/// let spec = RulesetSpec {
///     sources: vec![PathBuf::from(".")],
///     ..Default::default()
/// };
/// let resolved = resolve_loaded("example", &spec, loaded, &InlineOnlyOverlayLoader).unwrap();
/// assert_eq!(resolved.collection.rules.len(), 1);
/// ```
pub fn resolve_loaded(
    name: &str,
    spec: &RulesetSpec,
    loaded: LoadedSources,
    loader: &dyn OverlayLoader,
) -> Result<ResolvedRuleset, RulesetError> {
    let problems = validate_spec(name, spec);
    if !problems.is_empty() {
        return Err(RulesetError::InvalidSpec(problems));
    }
    resolve_validated(name, spec, loaded, loader)
}

fn resolve_validated(
    name: &str,
    spec: &RulesetSpec,
    loaded: LoadedSources,
    loader: &dyn OverlayLoader,
) -> Result<ResolvedRuleset, RulesetError> {
    let closure = closure::close(name, spec, &loaded.candidates)?;
    let mut candidates = loaded.candidates;
    let expanded = overlay::expand_overlays(name, spec, loader)?;
    let (applied, overlay_warnings) =
        overlay::apply_overlays(name, spec, &mut candidates, &closure.decisions, expanded)?;

    let entries: Vec<RuleEntry> = candidates
        .iter()
        .zip(&closure.decisions)
        .enumerate()
        .map(|(index, (candidate, decision))| RuleEntry {
            kind: candidate.kind(),
            id: candidate.id().map(str::to_string),
            name: candidate.name().map(str::to_string),
            title: candidate.title().to_string(),
            origin: candidate.origin.clone(),
            decision: decision.clone(),
            overlays: applied[index].clone(),
        })
        .collect();

    let mut collection = SigmaCollection::new();
    collection.diagnostics = loaded.diagnostics;
    for (candidate, decision) in candidates.into_iter().zip(closure.decisions) {
        if !closure::is_kept(&decision) {
            continue;
        }
        match candidate.doc {
            CandidateDoc::Detection(rule) => collection.rules.push(rule),
            CandidateDoc::Correlation(rule) => collection.correlations.push(rule),
            CandidateDoc::Filter(rule) => collection.filters.push(rule),
        }
    }
    let mut warnings = closure.warnings;
    warnings.extend(overlay_warnings);
    Ok(ResolvedRuleset {
        name: name.to_string(),
        collection,
        entries,
        files: loaded.files,
        overlay_files: loader.files(),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::SigmaRule;

    fn rule(id: &str) -> SigmaRule {
        crate::parse_sigma_yaml(&format!(
            "title: Rule {id}\nid: {id}\nlogsource:\n    product: linux\ndetection:\n    selection:\n        Field: value\n    condition: selection\n"
        ))
        .unwrap()
        .rules
        .remove(0)
    }

    #[test]
    fn resolve_loaded_keeps_every_candidate() {
        let loaded = LoadedSources {
            candidates: vec![Candidate {
                doc: CandidateDoc::Detection(rule("a")),
                origin: RuleOrigin {
                    source: 0,
                    root: std::path::PathBuf::from("."),
                    file: std::path::PathBuf::from("a.yml"),
                    ordinal: 0,
                },
            }],
            ..Default::default()
        };
        let spec = RulesetSpec {
            sources: vec![std::path::PathBuf::from(".")],
            ..Default::default()
        };
        let resolved = resolve_loaded("test", &spec, loaded, &InlineOnlyOverlayLoader).unwrap();
        assert_eq!(resolved.collection.rules.len(), 1);
        assert_eq!(resolved.name, "test");
    }
}
