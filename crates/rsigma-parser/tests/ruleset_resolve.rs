//! End-to-end ruleset resolution against the synthetic fixtures under
//! `tests/fixtures/ruleset/`.

use std::path::{Path, PathBuf};

use rsigma_parser::ruleset::{
    Decision, OverlayEntry, OverlayPatch, ResolveOptions, ResolvedRuleset, RuleEntry, RuleSelector,
    RulesetSpec, resolve_ruleset,
};
use rsigma_parser::{
    Level, emit_correlation_yaml, emit_filter_yaml, emit_rule_yaml, parse_sigma_yaml,
};

const W1: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const W2: &str = "aaaaaaaa-0000-4000-8000-000000000002";
const W3: &str = "aaaaaaaa-0000-4000-8000-000000000003";
const L1: &str = "bbbbbbbb-0000-4000-8000-000000000001";
const C1: &str = "cccccccc-0000-4000-8000-000000000001";
const C2: &str = "cccccccc-0000-4000-8000-000000000002";
const F1: &str = "dddddddd-0000-4000-8000-000000000001";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ruleset")
}

fn entry_by_id<'a>(resolved: &'a ResolvedRuleset, id: &str) -> &'a RuleEntry {
    resolved
        .entries
        .iter()
        .find(|entry| entry.id.as_deref() == Some(id))
        .unwrap_or_else(|| panic!("no entry for id '{id}'"))
}

fn entry_by_file<'a>(resolved: &'a ResolvedRuleset, file: &str) -> &'a RuleEntry {
    resolved
        .entries
        .iter()
        .find(|entry| entry.origin.file.as_path() == Path::new(file))
        .unwrap_or_else(|| panic!("no entry from '{file}'"))
}

fn included_by_tag() -> RulesetSpec {
    RulesetSpec {
        sources: vec![fixtures().join("vendor")],
        include: vec![RuleSelector {
            tags: vec!["attack.t1059*".into()],
            ..Default::default()
        }],
        dependencies: Some("include".into()),
        ..Default::default()
    }
}

#[test]
fn duplicate_id_fork_is_rejected_and_path_exclude_fixes_it() {
    let spec = RulesetSpec {
        sources: vec![fixtures().join("vendor"), fixtures().join("local")],
        ..Default::default()
    };
    let error = resolve_ruleset("dup", &spec, &ResolveOptions::default()).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("duplicate id"), "{message}");
    assert!(message.contains("windows/proc_creation.yml#0"), "{message}");
    assert!(message.contains("fork.yml#0"), "{message}");

    let spec = RulesetSpec {
        sources: vec![fixtures().join("vendor"), fixtures().join("local")],
        exclude: vec![RuleSelector {
            path: vec!["fork.yml".into()],
            ..Default::default()
        }],
        ..Default::default()
    };
    let resolved = resolve_ruleset("dup", &spec, &ResolveOptions::default()).unwrap();
    let fork = entry_by_file(&resolved, "fork.yml");
    assert!(
        matches!(fork.decision, Decision::Excluded { .. }),
        "{:?}",
        fork.decision
    );
    assert_eq!(
        resolved
            .collection
            .rules
            .iter()
            .filter(|rule| rule.id.as_deref() == Some(W1))
            .count(),
        1
    );
}

#[test]
fn include_pulls_correlation_dependencies() {
    let resolved =
        resolve_ruleset("vendor", &included_by_tag(), &ResolveOptions::default()).unwrap();
    assert!(
        matches!(
            entry_by_id(&resolved, W1).decision,
            Decision::Included { .. }
        ),
        "{:?}",
        entry_by_id(&resolved, W1).decision
    );
    assert!(
        matches!(
            entry_by_id(&resolved, W2).decision,
            Decision::Included { .. }
        ),
        "{:?}",
        entry_by_id(&resolved, W2).decision
    );
    assert!(
        matches!(
            entry_by_id(&resolved, W3).decision,
            Decision::PulledIn { .. }
        ),
        "{:?}",
        entry_by_id(&resolved, W3).decision
    );
    assert!(
        matches!(
            entry_by_id(&resolved, C1).decision,
            Decision::Included { .. }
        ),
        "{:?}",
        entry_by_id(&resolved, C1).decision
    );
    assert!(
        matches!(
            entry_by_id(&resolved, C2).decision,
            Decision::Included { .. }
        ),
        "{:?}",
        entry_by_id(&resolved, C2).decision
    );
    assert_eq!(entry_by_id(&resolved, F1).decision, Decision::FilterKept);
    assert!(resolved.collection.diagnostics.is_empty());
}

#[test]
fn error_policy_reports_the_unselected_dependency() {
    let mut spec = included_by_tag();
    spec.dependencies = Some("error".into());
    let error = resolve_ruleset("vendor", &spec, &ResolveOptions::default()).unwrap_err();
    let message = error.to_string();
    assert!(message.contains(W3), "{message}");
    assert!(message.contains("not matched by include"), "{message}");
}

#[test]
fn overlays_apply_from_files_and_inline_in_order() {
    let overlays = fixtures().join("overlays");
    let spec = RulesetSpec {
        sources: vec![fixtures().join("vendor")],
        overlays: vec![
            OverlayEntry {
                file: Some(overlays.join("levels.yml")),
                ..Default::default()
            },
            OverlayEntry {
                id: Some(W1.into()),
                set: Some(OverlayPatch {
                    level: Some("critical".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            OverlayEntry {
                file: Some(overlays.join("exemplars.yml")),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let resolved = resolve_ruleset("vendor", &spec, &ResolveOptions::default()).unwrap();

    let w1 = entry_by_id(&resolved, W1);
    let origins: Vec<String> = w1
        .overlays
        .iter()
        .map(|overlay| overlay.origin.to_string())
        .collect();
    assert_eq!(
        origins,
        [
            format!("{}:0", overlays.join("levels.yml").display()),
            "inline:1".to_string(),
            format!("{}:0", overlays.join("exemplars.yml").display()),
        ]
    );
    let rule = resolved
        .collection
        .rules
        .iter()
        .find(|rule| rule.id.as_deref() == Some(W1))
        .unwrap();
    assert_eq!(rule.level, Some(Level::Critical));
    assert!(rule.custom_attributes.contains_key("rsigma.exemplars"));

    let l1 = entry_by_id(&resolved, L1);
    assert_eq!(l1.overlays.len(), 2);
    assert_eq!(resolved.overlay_files.len(), 2);
}

#[test]
fn resolved_documents_survive_emit_and_reparse() {
    let overlays = fixtures().join("overlays");
    let spec = RulesetSpec {
        sources: vec![fixtures().join("vendor"), fixtures().join("local")],
        exclude: vec![RuleSelector {
            path: vec!["fork.yml".into()],
            ..Default::default()
        }],
        overlays: vec![
            OverlayEntry {
                file: Some(overlays.join("levels.yml")),
                ..Default::default()
            },
            OverlayEntry {
                file: Some(overlays.join("exemplars.yml")),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let resolved = resolve_ruleset("vendor", &spec, &ResolveOptions::default()).unwrap();
    assert!(!resolved.collection.rules.is_empty());
    assert!(!resolved.collection.correlations.is_empty());
    assert!(!resolved.collection.filters.is_empty());
    assert!(
        resolved
            .entries
            .iter()
            .any(|entry| !entry.overlays.is_empty()),
        "the round trip must cover overlaid documents"
    );

    for rule in &resolved.collection.rules {
        let emitted = emit_rule_yaml(rule);
        let reparsed = parse_sigma_yaml(&emitted).unwrap();
        assert_eq!(reparsed.rules.len(), 1);
        assert_eq!(&reparsed.rules[0], rule);
    }
    for rule in &resolved.collection.correlations {
        let emitted = emit_correlation_yaml(rule);
        let reparsed = parse_sigma_yaml(&emitted).unwrap();
        assert_eq!(reparsed.correlations.len(), 1);
        assert_eq!(&reparsed.correlations[0], rule);
    }
    for rule in &resolved.collection.filters {
        let emitted = emit_filter_yaml(rule);
        let reparsed = parse_sigma_yaml(&emitted).unwrap();
        assert_eq!(reparsed.filters.len(), 1);
        assert_eq!(&reparsed.filters[0], rule);
    }
}
