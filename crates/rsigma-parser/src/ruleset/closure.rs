//! Dependency closure, filter retention, and uniqueness checks.

use std::collections::HashMap;

use super::error::RulesetError;
use super::select::{Decision, RefIndex, decide};
use super::source::{Candidate, DocumentKind};
use super::spec::{DependencyPolicy, RulesetSpec};

/// The result of closure: one decision per candidate plus warnings.
#[derive(Debug)]
pub(crate) struct Closure {
    pub decisions: Vec<Decision>,
    pub warnings: Vec<String>,
}

/// True when a decision keeps the candidate in the resolved collection.
pub(crate) fn is_kept(decision: &Decision) -> bool {
    matches!(
        decision,
        Decision::Included { .. } | Decision::PulledIn { .. } | Decision::FilterKept
    )
}

/// Resolve dependency references under the configured policy, retain filters
/// whose targets survived, and reject duplicate ids and names.
pub(crate) fn close(
    name: &str,
    spec: &RulesetSpec,
    candidates: &[Candidate],
) -> Result<Closure, RulesetError> {
    let policy = match &spec.dependencies {
        Some(value) => DependencyPolicy::parse(value)
            .map_err(|e| RulesetError::InvalidSpec(vec![format!("ruleset '{name}': {e}")]))?,
        None => DependencyPolicy::Error,
    };
    let mut decisions = decide(candidates, spec).map_err(|e| e.named(name))?;
    let refs = RefIndex::build(candidates);
    let mut warnings = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    let mut iterations = 0;
    loop {
        iterations += 1;
        if iterations > candidates.len() + 1 {
            break;
        }
        let mut changed = false;

        for (index, candidate) in candidates.iter().enumerate() {
            if candidate.kind() != DocumentKind::Correlation || !is_kept(&decisions[index]) {
                continue;
            }
            let references = candidate.referenced_rules().to_vec();
            for reference in references {
                let resolved: Vec<usize> = refs
                    .resolve(&reference)
                    .into_iter()
                    .filter(|target| candidates[*target].kind() != DocumentKind::Filter)
                    .collect();
                if resolved.iter().any(|target| is_kept(&decisions[*target])) {
                    continue;
                }
                let reason = unresolved_reason(&reference, &resolved, &decisions);
                let subject = correlation_subject(candidate);

                match policy {
                    DependencyPolicy::Error => {
                        push_unique(&mut errors, format!("ruleset '{name}': {subject} {reason}"));
                    }
                    DependencyPolicy::Include => {
                        let pullable: Vec<usize> = resolved
                            .into_iter()
                            .filter(|target| decisions[*target] == Decision::NotSelected)
                            .collect();
                        if pullable.is_empty() {
                            push_unique(
                                &mut errors,
                                format!("ruleset '{name}': {subject} {reason}"),
                            );
                        }
                        for target in pullable {
                            decisions[target] = Decision::PulledIn {
                                by: correlation_label(candidate),
                            };
                            changed = true;
                        }
                    }
                    DependencyPolicy::Drop => {
                        warnings.push(format!(
                            "ruleset '{name}': dropped {subject} because it {reason}"
                        ));
                        decisions[index] = Decision::Dropped { reason };
                        changed = true;
                        break;
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }

    if !errors.is_empty() {
        return Err(RulesetError::Dependency(errors));
    }

    // Filters stay when they target nothing specific or at least one kept
    // detection rule.
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.kind() != DocumentKind::Filter
            || matches!(decisions[index], Decision::Excluded { .. })
        {
            continue;
        }
        let kept = match candidate.filter_targets() {
            None => true,
            Some(targets) => targets.iter().any(|target| {
                refs.resolve_filter_target(target)
                    .into_iter()
                    .any(|target| {
                        candidates[target].kind() == DocumentKind::Detection
                            && is_kept(&decisions[target])
                    })
            }),
        };
        decisions[index] = if kept {
            Decision::FilterKept
        } else {
            Decision::FilterOrphaned
        };
    }

    check_uniqueness(name, candidates, &decisions)?;

    Ok(Closure {
        decisions,
        warnings,
    })
}

/// The fixed-point loop revisits every kept correlation on each pass, so the
/// same unresolvable reference would otherwise be reported once per pass.
fn push_unique(errors: &mut Vec<String>, reason: String) {
    if !errors.contains(&reason) {
        errors.push(reason);
    }
}

fn correlation_label(candidate: &Candidate) -> String {
    candidate
        .id()
        .or_else(|| candidate.name())
        .unwrap_or_else(|| candidate.title())
        .to_string()
}

fn origin_label(origin: &super::source::RuleOrigin) -> String {
    format!("{}#{}", origin.file.display(), origin.ordinal)
}

fn correlation_subject(candidate: &Candidate) -> String {
    format!(
        "correlation '{}' from {}",
        candidate.title(),
        origin_label(&candidate.origin)
    )
}

/// Why `reference` resolves to no kept document, preferring the copy that
/// could still be selected when a forked id has several.
fn unresolved_reason(reference: &str, resolved: &[usize], decisions: &[Decision]) -> String {
    let because = if resolved.is_empty() {
        "exists in no source".to_string()
    } else if resolved
        .iter()
        .any(|index| decisions[*index] == Decision::NotSelected)
    {
        "is not matched by include".to_string()
    } else if let Some(selector) = resolved.iter().find_map(|index| match decisions[*index] {
        Decision::Excluded { selector } => Some(selector),
        _ => None,
    }) {
        format!("is excluded by exclude selector {selector}")
    } else {
        "was dropped".to_string()
    };
    format!("references '{reference}', which {because}")
}

fn check_uniqueness(
    name: &str,
    candidates: &[Candidate],
    decisions: &[Decision],
) -> Result<(), RulesetError> {
    let mut ids: HashMap<String, usize> = HashMap::new();
    let mut names: HashMap<String, usize> = HashMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if !is_kept(&decisions[index]) {
            continue;
        }
        if let Some(id) = candidate.id() {
            let key = id.to_ascii_lowercase();
            if let Some(previous) = ids.insert(key, index) {
                return Err(RulesetError::Duplicate(format!(
                    "ruleset '{name}': duplicate id '{id}' in {} and {}",
                    origin_label(&candidates[previous].origin),
                    origin_label(&candidate.origin)
                )));
            }
        }
        if let Some(candidate_name) = candidate.name()
            && let Some(previous) = names.insert(candidate_name.to_string(), index)
        {
            return Err(RulesetError::Duplicate(format!(
                "ruleset '{name}': duplicate name '{candidate_name}' in {} and {}",
                origin_label(&candidates[previous].origin),
                origin_label(&candidate.origin)
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::source::{CandidateDoc, RuleOrigin};
    use crate::ruleset::spec::{RuleSelector, RulesetSpec};

    fn candidate(yaml: &str, file: &str, ordinal: usize) -> Candidate {
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
                ordinal,
            },
        }
    }

    fn detection(id: &str, file: &str) -> Candidate {
        candidate(
            &format!(
                "title: Detection {id}\nid: {id}\nlogsource:\n    product: windows\ndetection:\n    selection:\n        Field: value\n    condition: selection\n"
            ),
            file,
            0,
        )
    }

    fn correlation(id: &str, refs: &[&str], file: &str) -> Candidate {
        let refs = refs
            .iter()
            .map(|r| format!("        - {r}\n"))
            .collect::<String>();
        candidate(
            &format!(
                "title: Correlation {id}\nid: {id}\ncorrelation:\n    type: event_count\n    rules:\n{refs}    timespan: 5m\n    condition:\n        gte: 2\n"
            ),
            file,
            0,
        )
    }

    fn spec(
        dependencies: &str,
        include: Vec<RuleSelector>,
        exclude: Vec<RuleSelector>,
    ) -> RulesetSpec {
        RulesetSpec {
            sources: vec![std::path::PathBuf::from("rules")],
            dependencies: Some(dependencies.into()),
            include,
            exclude,
            ..Default::default()
        }
    }

    fn all_kept(decisions: &[Decision]) -> Vec<bool> {
        decisions.iter().map(is_kept).collect()
    }

    #[test]
    fn error_policy_reports_missing_reference() {
        let candidates = vec![correlation("c", &["missing"], "c.yml")];
        let error = close("test", &spec("error", vec![], vec![]), &candidates).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("exists in no source"), "{message}");
    }

    #[test]
    fn error_policy_reports_excluded_reference() {
        let candidates = vec![detection("d", "d.yml"), correlation("c", &["d"], "c.yml")];
        let exclude = vec![RuleSelector {
            id: vec!["d".into()],
            ..Default::default()
        }];
        let error = close("test", &spec("error", vec![], exclude), &candidates).unwrap_err();
        assert!(
            error.to_string().contains("excluded by exclude selector 0"),
            "{error}"
        );
    }

    #[test]
    fn include_pulls_in_a_chain() {
        let candidates = vec![
            detection("base", "base.yml"),
            correlation("middle", &["base"], "middle.yml"),
            correlation("top", &["middle"], "top.yml"),
        ];
        let include = vec![RuleSelector {
            id: vec!["top".into()],
            ..Default::default()
        }];
        let closure = close("test", &spec("include", include, vec![]), &candidates).unwrap();
        assert_eq!(all_kept(&closure.decisions), [true, true, true]);
        assert!(matches!(closure.decisions[0], Decision::PulledIn { .. }));
    }

    #[test]
    fn include_refuses_an_excluded_rule() {
        let candidates = vec![
            detection("base", "base.yml"),
            correlation("top", &["base"], "top.yml"),
        ];
        let include = vec![RuleSelector {
            id: vec!["top".into()],
            ..Default::default()
        }];
        let exclude = vec![RuleSelector {
            id: vec!["base".into()],
            ..Default::default()
        }];
        let error = close("test", &spec("include", include, exclude), &candidates).unwrap_err();
        assert_eq!(
            error.to_string(),
            "ruleset 'test': correlation 'Correlation top' from top.yml#0 references 'base', which is excluded by exclude selector 0"
        );
    }

    /// A local fork shares its id with the vendored rule, and `path` excludes
    /// one copy. The other copy must still be pullable.
    fn forked(excluded_file: &str) -> (Vec<Candidate>, Vec<RuleSelector>, Vec<RuleSelector>) {
        let candidates = vec![
            detection("w1", "vendor.yml"),
            detection("w1", "fork.yml"),
            correlation("c", &["w1"], "c.yml"),
        ];
        let include = vec![RuleSelector {
            id: vec!["c".into()],
            ..Default::default()
        }];
        let exclude = vec![RuleSelector {
            path: vec![excluded_file.into()],
            ..Default::default()
        }];
        (candidates, include, exclude)
    }

    #[test]
    fn include_pulls_the_copy_of_a_fork_that_is_not_excluded() {
        for (excluded, pulled) in [("fork.yml", 0), ("vendor.yml", 1)] {
            let (candidates, include, exclude) = forked(excluded);
            let closure = close("test", &spec("include", include, exclude), &candidates).unwrap();
            assert!(
                matches!(closure.decisions[pulled], Decision::PulledIn { .. }),
                "{excluded}: {:?}",
                closure.decisions
            );
            assert!(matches!(
                closure.decisions[1 - pulled],
                Decision::Excluded { .. }
            ));
        }
    }

    #[test]
    fn error_policy_names_the_selectable_copy_of_a_fork() {
        let (candidates, include, exclude) = forked("fork.yml");
        let error = close("test", &spec("error", include, exclude), &candidates).unwrap_err();
        assert!(
            error
                .to_string()
                .ends_with("references 'w1', which is not matched by include"),
            "{error}"
        );
    }

    #[test]
    fn include_reports_each_unresolvable_reference_once() {
        // `pulls` changes a decision on the first pass, which forces a second
        // pass over `broken`.
        let candidates = vec![
            detection("base", "base.yml"),
            correlation("pulls", &["base"], "pulls.yml"),
            correlation("broken", &["missing"], "broken.yml"),
        ];
        let include = vec![RuleSelector {
            id: vec!["pulls".into(), "broken".into()],
            ..Default::default()
        }];
        let error = close("test", &spec("include", include, vec![]), &candidates).unwrap_err();
        let RulesetError::Dependency(reasons) = error else {
            panic!("expected a dependency error, got {error}");
        };
        assert_eq!(reasons.len(), 1, "{reasons:?}");
        assert!(reasons[0].contains("'missing'"), "{reasons:?}");
    }

    #[test]
    fn include_and_drop_handle_a_reference_in_no_source() {
        let candidates = vec![correlation("c", &["missing"], "c.yml")];
        let error = close("test", &spec("include", vec![], vec![]), &candidates).unwrap_err();
        assert!(
            error
                .to_string()
                .ends_with("references 'missing', which exists in no source"),
            "{error}"
        );

        let closure = close("test", &spec("drop", vec![], vec![]), &candidates).unwrap();
        assert_eq!(
            closure.decisions[0],
            Decision::Dropped {
                reason: "references 'missing', which exists in no source".into()
            }
        );
    }

    #[test]
    fn drop_cascades_to_a_parent() {
        let candidates = vec![
            detection("base", "base.yml"),
            correlation("middle", &["base"], "middle.yml"),
            correlation("top", &["middle"], "top.yml"),
        ];
        let exclude = vec![RuleSelector {
            id: vec!["base".into()],
            ..Default::default()
        }];
        let closure = close("test", &spec("drop", vec![], exclude), &candidates).unwrap();
        assert!(!is_kept(&closure.decisions[1]));
        assert!(!is_kept(&closure.decisions[2]));
        assert_eq!(
            closure.warnings,
            [
                "ruleset 'test': dropped correlation 'Correlation middle' from middle.yml#0 because it references 'base', which is excluded by exclude selector 0",
                "ruleset 'test': dropped correlation 'Correlation top' from top.yml#0 because it references 'middle', which was dropped",
            ]
        );
        assert_eq!(
            closure.decisions[2],
            Decision::Dropped {
                reason: "references 'middle', which was dropped".into()
            }
        );
    }

    #[test]
    fn references_resolve_by_name() {
        let mut base = detection("d", "d.yml");
        if let CandidateDoc::Detection(rule) = &mut base.doc {
            rule.name = Some("named_rule".into());
        }
        let candidates = vec![base, correlation("top", &["named_rule"], "top.yml")];
        let include = vec![RuleSelector {
            id: vec!["top".into()],
            ..Default::default()
        }];
        let closure = close("test", &spec("include", include, vec![]), &candidates).unwrap();
        assert!(is_kept(&closure.decisions[0]));
    }

    #[test]
    fn filter_any_is_kept_and_targeted_filters_follow_targets() {
        let candidates = vec![
            detection("d", "d.yml"),
            candidate(
                "title: Filter any\nlogsource:\n    product: windows\nfilter:\n    rules: any\n    selection:\n        Field: value\n    condition: selection\n",
                "any.yml",
                0,
            ),
            candidate(
                "title: Filter d\nlogsource:\n    product: windows\nfilter:\n    rules:\n        - d\n    selection:\n        Field: value\n    condition: selection\n",
                "d.yml",
                0,
            ),
            candidate(
                "title: Filter title\nlogsource:\n    product: windows\nfilter:\n    rules:\n        - Detection d\n    selection:\n        Field: value\n    condition: selection\n",
                "title.yml",
                0,
            ),
        ];
        let closure = close("test", &spec("error", vec![], vec![]), &candidates).unwrap();
        assert_eq!(closure.decisions[1], Decision::FilterKept);
        assert_eq!(closure.decisions[2], Decision::FilterKept);
        assert_eq!(closure.decisions[3], Decision::FilterKept);
    }

    #[test]
    fn filter_with_all_targets_excluded_is_orphaned() {
        let candidates = vec![
            detection("d", "d.yml"),
            candidate(
                "title: Filter d\nlogsource:\n    product: windows\nfilter:\n    rules:\n        - d\n    selection:\n        Field: value\n    condition: selection\n",
                "f.yml",
                0,
            ),
        ];
        let exclude = vec![RuleSelector {
            id: vec!["d".into()],
            ..Default::default()
        }];
        let closure = close("test", &spec("error", vec![], exclude), &candidates).unwrap();
        assert_eq!(closure.decisions[1], Decision::FilterOrphaned);
    }

    #[test]
    fn excluded_filter_is_excluded() {
        let candidates = vec![candidate(
            "title: Filter\nid: f\nlogsource:\n    product: windows\nfilter:\n    rules: any\n    selection:\n        Field: value\n    condition: selection\n",
            "f.yml",
            0,
        )];
        let exclude = vec![RuleSelector {
            id: vec!["f".into()],
            ..Default::default()
        }];
        let closure = close("test", &spec("error", vec![], exclude), &candidates).unwrap();
        assert!(matches!(closure.decisions[0], Decision::Excluded { .. }));
    }

    #[test]
    fn duplicate_ids_and_names_are_rejected() {
        let candidates = vec![detection("same", "a.yml"), detection("SAME", "b.yml")];
        let error = close("test", &spec("error", vec![], vec![]), &candidates).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("duplicate id"), "{message}");
        assert!(
            message.contains("a.yml#0") && message.contains("b.yml#0"),
            "{message}"
        );

        let mut first = detection("a", "a.yml");
        let mut second = detection("b", "b.yml");
        if let CandidateDoc::Detection(rule) = &mut first.doc {
            rule.name = Some("dup".into());
        }
        if let CandidateDoc::Detection(rule) = &mut second.doc {
            rule.name = Some("dup".into());
        }
        let error = close("test", &spec("error", vec![], vec![]), &[first, second]).unwrap_err();
        assert!(error.to_string().contains("duplicate name"), "{error}");
    }

    #[test]
    fn determinism() {
        let candidates = vec![detection("d", "d.yml"), correlation("c", &["d"], "c.yml")];
        let first = close("test", &spec("error", vec![], vec![]), &candidates).unwrap();
        let second = close("test", &spec("error", vec![], vec![]), &candidates).unwrap();
        assert_eq!(first.decisions, second.decisions);
    }
}
