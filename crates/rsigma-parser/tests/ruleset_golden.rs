//! Golden test for the ruleset decision table.
//!
//! The table records every candidate, its decision, its origin, and the
//! overlays applied to it. Regenerate after an intentional change:
//!
//! ```sh
//! RSIGMA_UPDATE_GOLDEN=1 cargo test -p rsigma-parser --test ruleset_golden
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use rsigma_parser::ruleset::{
    Decision, OverlayEntry, OverlayPatch, ResolveOptions, ResolvedRuleset, RuleSelector,
    RulesetSpec, resolve_ruleset,
};

const W1: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const W2: &str = "aaaaaaaa-0000-4000-8000-000000000002";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ruleset")
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/ruleset")
}

fn decision_label(decision: &Decision) -> String {
    match decision {
        Decision::Included { selector } => match selector {
            Some(index) => format!("included:{index}"),
            None => "included".to_string(),
        },
        Decision::Excluded { selector } => format!("excluded:{selector}"),
        Decision::PulledIn { by } => format!("pulled_in:{by}"),
        Decision::Dropped { reason } => format!("dropped:{reason}"),
        Decision::FilterKept => "filter_kept".to_string(),
        Decision::FilterOrphaned => "filter_orphaned".to_string(),
        Decision::NotSelected => "not_selected".to_string(),
        other => other.as_str().to_string(),
    }
}

fn render(resolved: &ResolvedRuleset) -> String {
    let mut out = String::from("kind\tdecision\tid\ttitle\torigin\toverlays\n");
    for entry in &resolved.entries {
        let id = entry.id.clone().unwrap_or_else(|| "-".to_string());
        let origin = format!(
            "s{}:{}#{}",
            entry.origin.source,
            entry.origin.file.display(),
            entry.origin.ordinal
        );
        let overlays = if entry.overlays.is_empty() {
            "-".to_string()
        } else {
            entry
                .overlays
                .iter()
                .map(|overlay| overlay.origin.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            entry.kind.as_str(),
            decision_label(&entry.decision),
            id,
            entry.title,
            origin,
            overlays
        ));
    }
    out
}

#[test]
fn golden_selection_and_overlays() {
    let spec = RulesetSpec {
        sources: vec![fixtures().join("vendor")],
        include: vec![RuleSelector {
            tags: vec!["attack.t1059*".into()],
            ..Default::default()
        }],
        exclude: vec![RuleSelector {
            status: vec!["deprecated".into()],
            ..Default::default()
        }],
        dependencies: Some("include".into()),
        overlays: vec![
            OverlayEntry {
                id: Some(W1.into()),
                set: Some(OverlayPatch {
                    level: Some("high".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            OverlayEntry {
                id: Some(W2.into()),
                append: Some(OverlayPatch {
                    tags: Some(vec!["attack.t1059.005".into()]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let resolved = resolve_ruleset("vendor", &spec, &ResolveOptions::default()).unwrap();
    let actual = render(&resolved);

    let path = golden_dir().join("selection_overlays.txt");
    if std::env::var_os("RSIGMA_UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(golden_dir()).unwrap();
        fs::write(&path, &actual)
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
    }
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
        .replace("\r\n", "\n");
    assert_eq!(
        actual, expected,
        "ruleset golden mismatch; rerun with RSIGMA_UPDATE_GOLDEN=1"
    );
}
