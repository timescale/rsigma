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

mod error;
mod select;
mod source;
mod spec;

pub use error::RulesetError;
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
    let loaded = load_sources(spec, opts).map_err(|e| e.named(name))?;
    resolve_loaded(name, spec, loaded)
}

/// A resolved ruleset: the kept collection plus per-document decisions.
#[derive(Debug, Clone)]
pub struct ResolvedRuleset {
    pub name: String,
    pub collection: SigmaCollection,
    pub files: Vec<SourceFile>,
    pub overlay_files: Vec<SourceFile>,
    pub warnings: Vec<String>,
}

/// Resolve already-loaded sources into a collection. This is pure: it performs
/// no I/O beyond overlay files, which are loaded by the overlay phase.
pub fn resolve_loaded(
    name: &str,
    spec: &RulesetSpec,
    loaded: LoadedSources,
) -> Result<ResolvedRuleset, RulesetError> {
    let decisions = select::decide(&loaded.candidates, spec)?;
    let mut collection = SigmaCollection::new();
    collection.diagnostics = loaded.diagnostics;
    for (candidate, decision) in loaded.candidates.into_iter().zip(decisions) {
        let keep = match decision {
            Decision::Included { .. } | Decision::PulledIn { .. } | Decision::FilterKept => true,
            // Filters are retained until dependency closure decides whether
            // their targets survived.
            Decision::NotSelected if candidate.kind() == DocumentKind::Filter => true,
            _ => false,
        };
        if !keep {
            continue;
        }
        match candidate.doc {
            CandidateDoc::Detection(rule) => collection.rules.push(rule),
            CandidateDoc::Correlation(rule) => collection.correlations.push(rule),
            CandidateDoc::Filter(rule) => collection.filters.push(rule),
        }
    }
    Ok(ResolvedRuleset {
        name: name.to_string(),
        collection,
        files: loaded.files,
        overlay_files: Vec::new(),
        warnings: Vec::new(),
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
        let resolved = resolve_loaded("test", &spec, loaded).unwrap();
        assert_eq!(resolved.collection.rules.len(), 1);
        assert_eq!(resolved.name, "test");
    }
}
