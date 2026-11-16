//! Metadata selection of ruleset candidates.

use std::collections::{HashMap, HashSet};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use crate::ast::{Level, Status};

use super::error::RulesetError;
use super::source::{Candidate, CandidateDoc, DocumentKind};
use super::spec::RuleSelector;

/// A compiled selector. Globs are built once; exact keys are stored in sets.
pub(crate) struct CompiledSelector {
    ids: HashSet<String>,
    names: HashSet<String>,
    titles: Option<GlobSet>,
    tags: Option<GlobSet>,
    levels: HashSet<Level>,
    statuses: HashSet<Status>,
    kinds: HashSet<DocumentKind>,
    paths: Option<GlobSet>,
    logsource: Option<CompiledLogsource>,
}

struct CompiledLogsource {
    product: HashSet<String>,
    category: HashSet<String>,
    service: HashSet<String>,
}

/// Candidate indices keyed by id and name, used for correlation references and
/// logsource matching.
pub(crate) struct RefIndex {
    by_id: HashMap<String, Vec<usize>>,
    by_name: HashMap<String, Vec<usize>>,
    by_title: HashMap<String, Vec<usize>>,
}

impl RefIndex {
    pub(crate) fn build(candidates: &[Candidate]) -> Self {
        let mut by_id: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_title: HashMap<String, Vec<usize>> = HashMap::new();
        for (index, candidate) in candidates.iter().enumerate() {
            if let Some(id) = candidate.id() {
                by_id.entry(id.to_string()).or_default().push(index);
            }
            if let Some(name) = candidate.name() {
                by_name.entry(name.to_string()).or_default().push(index);
            }
            by_title
                .entry(candidate.title().to_string())
                .or_default()
                .push(index);
        }
        Self {
            by_id,
            by_name,
            by_title,
        }
    }

    /// Resolve a correlation reference by exact id or name.
    pub(crate) fn resolve(&self, key: &str) -> Vec<usize> {
        let mut found = self.by_id.get(key).cloned().unwrap_or_default();
        if let Some(by_name) = self.by_name.get(key) {
            found.extend(by_name);
        }
        found.sort_unstable();
        found.dedup();
        found
    }

    /// Resolve a filter target by id, name, or (deprecated) title.
    pub(crate) fn resolve_filter_target(&self, key: &str) -> Vec<usize> {
        let mut found = self.resolve(key);
        if let Some(by_title) = self.by_title.get(key) {
            found.extend(by_title);
        }
        found.sort_unstable();
        found.dedup();
        found
    }
}

/// Why a candidate was kept or dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// Admitted by the include selector at this index, or by an empty include
    /// list.
    Included {
        /// The matching include selector, or `None` for an empty include list.
        selector: Option<usize>,
    },
    /// Rejected by the exclude selector at this index.
    Excluded {
        /// The matching exclude selector.
        selector: usize,
    },
    /// Matched no include selector.
    NotSelected,
    /// Pulled in as a dependency of the correlation with this id, name, or
    /// title.
    PulledIn {
        /// The correlation that referenced it.
        by: String,
    },
    /// A correlation dropped for an unresolved reference, and why.
    Dropped {
        /// The unresolved reference and why it did not resolve.
        reason: String,
    },
    /// A filter kept because it targets any rule or a kept detection.
    FilterKept,
    /// A filter whose targets are all gone.
    FilterOrphaned,
}

impl Decision {
    /// The snake_case label used in reports.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Included { .. } => "included",
            Self::Excluded { .. } => "excluded",
            Self::NotSelected => "not_selected",
            Self::PulledIn { .. } => "pulled_in",
            Self::Dropped { .. } => "dropped",
            Self::FilterKept => "filter_kept",
            Self::FilterOrphaned => "filter_orphaned",
        }
    }
}

pub(crate) fn compile_selector(selector: &RuleSelector) -> Result<CompiledSelector, RulesetError> {
    let mut levels = HashSet::new();
    for value in &selector.level {
        levels.insert(
            value
                .parse::<Level>()
                .map_err(|_| RulesetError::Selector(format!("unknown level '{value}'")))?,
        );
    }
    let mut statuses = HashSet::new();
    for value in &selector.status {
        statuses.insert(
            value
                .parse::<Status>()
                .map_err(|_| RulesetError::Selector(format!("unknown status '{value}'")))?,
        );
    }
    let mut kinds = HashSet::new();
    for value in &selector.kind {
        kinds.insert(match value.as_str() {
            "detection" => DocumentKind::Detection,
            "correlation" => DocumentKind::Correlation,
            "filter" => DocumentKind::Filter,
            other => {
                return Err(RulesetError::Selector(format!("unknown kind '{other}'")));
            }
        });
    }

    let titles = build_glob_set(&selector.title, true, false)?;
    let tags = build_glob_set(&selector.tags, true, false)?;
    let paths = build_glob_set(&selector.path, false, true)?;
    let logsource = selector
        .logsource
        .as_ref()
        .map(|logsource| CompiledLogsource {
            product: logsource
                .product
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            category: logsource
                .category
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            service: logsource
                .service
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
        });

    Ok(CompiledSelector {
        ids: selector.id.iter().map(|s| s.to_ascii_lowercase()).collect(),
        names: selector.name.iter().cloned().collect(),
        titles,
        tags,
        levels,
        statuses,
        kinds,
        paths,
        logsource,
    })
}

fn build_glob_set(
    patterns: &[String],
    case_insensitive: bool,
    literal_separator: bool,
) -> Result<Option<GlobSet>, RulesetError> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = GlobBuilder::new(pattern)
            .case_insensitive(case_insensitive)
            .literal_separator(literal_separator)
            .build()
            .map_err(|e| RulesetError::Selector(format!("invalid glob '{pattern}': {e}")))?;
        builder.add(glob);
    }
    builder
        .build()
        .map(Some)
        .map_err(|e| RulesetError::Selector(format!("invalid glob set: {e}")))
}

impl CompiledSelector {
    /// True when every key that is set matches the candidate.
    pub(crate) fn matches(
        &self,
        candidate_index: usize,
        candidates: &[Candidate],
        refs: &RefIndex,
    ) -> bool {
        let candidate = &candidates[candidate_index];
        if !self.ids.is_empty() {
            match candidate.id() {
                Some(id) if self.ids.contains(&id.to_ascii_lowercase()) => {}
                _ => return false,
            }
        }
        if !self.names.is_empty() {
            match candidate.name() {
                Some(name) if self.names.contains(name) => {}
                _ => return false,
            }
        }
        if let Some(titles) = &self.titles
            && !titles.is_match(candidate.title())
        {
            return false;
        }
        if let Some(tags) = &self.tags
            && !candidate.tags().iter().any(|tag| tags.is_match(tag))
        {
            return false;
        }
        if !self.levels.is_empty() {
            match candidate.level() {
                Some(level) if self.levels.contains(&level) => {}
                _ => return false,
            }
        }
        if !self.statuses.is_empty() {
            match candidate.status() {
                Some(status) if self.statuses.contains(&status) => {}
                _ => return false,
            }
        }
        if !self.kinds.is_empty() && !self.kinds.contains(&candidate.kind()) {
            return false;
        }
        if let Some(paths) = &self.paths
            && !paths.is_match(&candidate.origin.file)
        {
            return false;
        }
        if let Some(logsource) = &self.logsource
            && !logsource_matches(candidate_index, candidates, refs, logsource)
        {
            return false;
        }
        true
    }
}

/// Whether a candidate's logsource matches; a correlation matches when any
/// document reachable through its references does. Walks with an explicit
/// stack, since a crafted ruleset can chain thousands of correlations.
fn logsource_matches(
    index: usize,
    candidates: &[Candidate],
    refs: &RefIndex,
    selector: &CompiledLogsource,
) -> bool {
    let mut visited = HashSet::new();
    let mut stack = vec![index];
    while let Some(index) = stack.pop() {
        if !visited.insert(index) {
            continue;
        }
        let matched = match &candidates[index].doc {
            CandidateDoc::Detection(rule) => logsource_fields_match(&rule.logsource, selector),
            CandidateDoc::Filter(rule) => rule
                .logsource
                .as_ref()
                .is_some_and(|logsource| logsource_fields_match(logsource, selector)),
            CandidateDoc::Correlation(rule) => {
                for reference in &rule.rules {
                    stack.extend(refs.resolve(reference));
                }
                false
            }
        };
        if matched {
            return true;
        }
    }
    false
}

fn logsource_fields_match(logsource: &crate::ast::LogSource, selector: &CompiledLogsource) -> bool {
    let matches = |set: &HashSet<String>, value: &Option<String>| {
        set.is_empty()
            || value
                .as_ref()
                .is_some_and(|v| set.contains(&v.to_ascii_lowercase()))
    };
    matches(&selector.product, &logsource.product)
        && matches(&selector.category, &logsource.category)
        && matches(&selector.service, &logsource.service)
}

/// Decide every detection and correlation candidate. Filters are marked
/// `Excluded` when an exclude selector matches and `NotSelected` otherwise;
/// dependency closure decides their fate.
pub(crate) fn decide(
    candidates: &[Candidate],
    spec: &super::spec::RulesetSpec,
) -> Result<Vec<Decision>, RulesetError> {
    let include: Vec<CompiledSelector> = spec
        .include
        .iter()
        .map(compile_selector)
        .collect::<Result<_, _>>()?;
    let exclude: Vec<CompiledSelector> = spec
        .exclude
        .iter()
        .map(compile_selector)
        .collect::<Result<_, _>>()?;
    let refs = RefIndex::build(candidates);

    let mut decisions = Vec::with_capacity(candidates.len());
    for index in 0..candidates.len() {
        if candidates[index].kind() == DocumentKind::Filter {
            let excluded = exclude
                .iter()
                .position(|selector| selector.matches(index, candidates, &refs));
            decisions.push(match excluded {
                Some(selector) => Decision::Excluded { selector },
                None => Decision::NotSelected,
            });
            continue;
        }

        if let Some(selector) = exclude
            .iter()
            .position(|selector| selector.matches(index, candidates, &refs))
        {
            decisions.push(Decision::Excluded { selector });
            continue;
        }

        if include.is_empty() {
            decisions.push(Decision::Included { selector: None });
            continue;
        }

        match include
            .iter()
            .position(|selector| selector.matches(index, candidates, &refs))
        {
            Some(selector) => decisions.push(Decision::Included {
                selector: Some(selector),
            }),
            None => decisions.push(Decision::NotSelected),
        }
    }
    Ok(decisions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::source::RuleOrigin;
    use crate::ruleset::spec::{LogsourceSelector, RuleSelector, RulesetSpec};

    fn candidate(yaml: &str, file: &str) -> Candidate {
        let collection = crate::parse_sigma_yaml(yaml).unwrap();
        let doc = if let Some(rule) = collection.rules.into_iter().next() {
            CandidateDoc::Detection(rule)
        } else if let Some(rule) = collection.correlations.into_iter().next() {
            CandidateDoc::Correlation(rule)
        } else {
            CandidateDoc::Filter(collection.filters.into_iter().next().unwrap())
        };
        Candidate {
            doc,
            origin: RuleOrigin {
                source: 0,
                root: std::path::PathBuf::from("."),
                file: std::path::PathBuf::from(file),
                ordinal: 0,
            },
        }
    }

    fn detection(id: &str, title: &str, tags: &[&str], level: &str, file: &str) -> Candidate {
        let tags = tags
            .iter()
            .map(|tag| format!("        - {tag}\n"))
            .collect::<String>();
        candidate(
            &format!(
                "title: {title}\nid: {id}\nstatus: experimental\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    selection:\n        Field: value\n    condition: selection\ntags:\n{tags}level: {level}\n"
            ),
            file,
        )
    }

    fn select(spec: RulesetSpec, candidates: &[Candidate]) -> Vec<Decision> {
        decide(candidates, &spec).unwrap()
    }

    fn spec(include: Vec<RuleSelector>, exclude: Vec<RuleSelector>) -> RulesetSpec {
        RulesetSpec {
            sources: vec![std::path::PathBuf::from("rules")],
            include,
            exclude,
            ..Default::default()
        }
    }

    #[test]
    fn or_across_selectors_and_and_across_keys() {
        let candidates = vec![
            detection("a", "A", &["attack.t1059.001"], "high", "a.yml"),
            detection("b", "B", &["attack.t1059.001"], "low", "b.yml"),
            detection("c", "C", &["attack.t1071"], "high", "c.yml"),
        ];
        let include = vec![
            RuleSelector {
                tags: vec!["attack.t1059*".into()],
                level: vec!["high".into()],
                ..Default::default()
            },
            RuleSelector {
                id: vec!["C".into()],
                ..Default::default()
            },
        ];
        let decisions = select(spec(include, vec![]), &candidates);
        assert_eq!(decisions[0], Decision::Included { selector: Some(0) });
        assert_eq!(decisions[1], Decision::NotSelected);
        assert_eq!(decisions[2], Decision::Included { selector: Some(1) });
    }

    #[test]
    fn empty_include_admits_all_and_exclude_wins() {
        let candidates = vec![
            detection("a", "A", &[], "high", "a.yml"),
            detection("b", "B", &[], "low", "b.yml"),
        ];
        let exclude = vec![RuleSelector {
            id: vec!["A".into()],
            ..Default::default()
        }];
        let decisions = select(spec(vec![], exclude), &candidates);
        assert_eq!(decisions[0], Decision::Excluded { selector: 0 });
        assert_eq!(decisions[1], Decision::Included { selector: None });
    }

    #[test]
    fn path_globs_respect_separators() {
        let candidates = vec![detection("a", "A", &[], "high", "dir/a.yml")];
        let include = vec![RuleSelector {
            path: vec!["*.yml".into()],
            ..Default::default()
        }];
        let decisions = select(spec(include, vec![]), &candidates);
        assert_eq!(decisions[0], Decision::NotSelected);

        let include = vec![RuleSelector {
            path: vec!["**/*.yml".into()],
            ..Default::default()
        }];
        let decisions = select(spec(include, vec![]), &candidates);
        assert_eq!(decisions[0], Decision::Included { selector: Some(0) });
    }

    #[test]
    fn tag_glob_matches_nested_tag() {
        let candidates = vec![detection("a", "A", &["attack.t1059.001"], "high", "a.yml")];
        let include = vec![RuleSelector {
            tags: vec!["attack.t1059*".into()],
            ..Default::default()
        }];
        let decisions = select(spec(include, vec![]), &candidates);
        assert_eq!(decisions[0], Decision::Included { selector: Some(0) });
    }

    #[test]
    fn correlation_logsource_matches_through_a_chain() {
        let candidates = vec![
            detection("base", "Base", &[], "high", "base.yml"),
            candidate(
                "title: Chain\nid: chain\ncorrelation:\n    type: event_count\n    rules:\n        - base\n    timespan: 5m\n    condition:\n        gte: 2\n",
                "chain.yml",
            ),
            candidate(
                "title: Parent\nid: parent\ncorrelation:\n    type: event_count\n    rules:\n        - chain\n    timespan: 5m\n    condition:\n        gte: 2\n",
                "parent.yml",
            ),
        ];
        let include = vec![RuleSelector {
            logsource: Some(LogsourceSelector {
                product: vec!["WINDOWS".into()],
                ..Default::default()
            }),
            ..Default::default()
        }];
        let decisions = select(spec(include, vec![]), &candidates);
        assert_eq!(decisions[2], Decision::Included { selector: Some(0) });
    }

    #[test]
    fn a_deep_correlation_chain_does_not_exhaust_the_stack() {
        const DEPTH: usize = 2_000;
        let mut candidates = vec![detection("c0", "Base", &[], "high", "base.yml")];
        for depth in 1..=DEPTH {
            candidates.push(candidate(
                &format!(
                    "title: C{depth}\nid: c{depth}\ncorrelation:\n    type: event_count\n    rules:\n        - c{}\n    timespan: 5m\n    condition:\n        gte: 2\n",
                    depth - 1
                ),
                "chain.yml",
            ));
        }
        let include = vec![RuleSelector {
            logsource: Some(LogsourceSelector {
                product: vec!["windows".into()],
                ..Default::default()
            }),
            ..Default::default()
        }];
        let decisions = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || select(spec(include, vec![]), &candidates))
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(decisions[DEPTH], Decision::Included { selector: Some(0) });
    }

    #[test]
    fn level_and_status_are_exact_and_case_sensitive_enums() {
        let candidates = vec![detection("a", "A", &[], "high", "a.yml")];
        let include = vec![RuleSelector {
            level: vec!["HIGH".into()],
            ..Default::default()
        }];
        let error = decide(&candidates, &spec(include, vec![])).unwrap_err();
        assert!(error.to_string().contains("'HIGH'"), "{error}");

        let include = vec![RuleSelector {
            status: vec!["Stable".into()],
            ..Default::default()
        }];
        let error = decide(&candidates, &spec(include, vec![])).unwrap_err();
        assert!(error.to_string().contains("'Stable'"), "{error}");
    }

    #[test]
    fn filter_in_include_is_rejected_before_selection() {
        let candidates = vec![detection("a", "A", &[], "high", "a.yml")];
        let include = vec![RuleSelector {
            kind: vec!["filter".into()],
            ..Default::default()
        }];
        let loaded = crate::ruleset::LoadedSources {
            candidates,
            ..Default::default()
        };
        let error = crate::ruleset::resolve_loaded(
            "test",
            &spec(include, vec![]),
            loaded,
            &crate::ruleset::InlineOnlyOverlayLoader,
        )
        .unwrap_err();
        assert!(
            matches!(error, crate::ruleset::RulesetError::InvalidSpec(_)),
            "{error}"
        );
    }
}
