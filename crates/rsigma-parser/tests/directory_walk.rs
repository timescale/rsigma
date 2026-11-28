//! Directory loading through links: cycles, duplicates, and entries that
//! resolve outside the directory being loaded.
//!
//! Directory links are symlinks on Unix and junctions on Windows, which need
//! no special rights. File symlinks are skipped where the platform refuses
//! them.

use std::fs;
use std::path::{Path, PathBuf};

use rsigma_parser::ruleset::{OverlayEntry, ResolveOptions, RulesetError, RulesetSpec};
use rsigma_parser::walk::{SkipReason, WalkOptions, walk_files};
use rsigma_parser::{
    DiagnosticKind, LintRule, SigmaCollection, lint_yaml_directory, parse_sigma_directory,
    parse_sigma_directory_with, ruleset::resolve_ruleset,
};

const SECRET: &str = "TOPSECRET-CONTENT-9f2c";

fn rule(title: &str) -> String {
    format!(
        "title: {title}\nlogsource:\n  product: windows\ndetection:\n  sel:\n    CommandLine: x\n  condition: sel\n"
    )
}

fn write(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

/// Link `link` to the directory `target`: a symlink on Unix, a junction on
/// Windows.
fn link_dir(target: &Path, link: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
    #[cfg(windows)]
    {
        let target = std::path::absolute(target).unwrap();
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(&target)
            .output()
            .unwrap();
        assert!(output.status.success(), "mklink /J failed: {output:?}");
    }
}

/// Symlink `link` to the file `target`, or return false where the platform
/// does not allow it.
fn link_file(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).unwrap();
        true
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }
}

/// The root of the filesystem (or of the system drive on Windows).
fn filesystem_root() -> PathBuf {
    #[cfg(windows)]
    {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        PathBuf::from(format!("{drive}\\"))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/")
    }
}

fn titles(collection: &SigmaCollection) -> Vec<String> {
    let mut titles: Vec<String> = collection.rules.iter().map(|r| r.title.clone()).collect();
    titles.sort();
    titles
}

fn skipped(collection: &SigmaCollection) -> Vec<String> {
    collection
        .diagnostics
        .iter()
        .filter(|d| d.kind == DiagnosticKind::SkippedPath)
        .map(|d| d.message.clone())
        .collect()
}

fn assert_no_leak(collection: &SigmaCollection, outside: &Path) {
    let outside = outside.to_string_lossy().to_string();
    for diagnostic in &collection.diagnostics {
        assert!(
            !diagnostic.message.contains(SECRET),
            "diagnostic leaks file content: {diagnostic:?}"
        );
        assert!(
            !diagnostic.message.contains(&outside),
            "diagnostic leaks the link target: {diagnostic:?}"
        );
    }
}

#[test]
fn self_referential_directory_link_loads_each_rule_once() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("rules");
    write(&root.join("a.yml"), &rule("A"));
    write(&root.join("sub/b.yml"), &rule("B"));
    link_dir(&root, &root.join("loop"));
    link_dir(&root.join("sub"), &root.join("sub/again"));

    let collection = parse_sigma_directory(&root).unwrap();
    assert_eq!(titles(&collection), ["A", "B"]);
    assert!(
        skipped(&collection).is_empty(),
        "{:?}",
        collection.diagnostics
    );
}

#[test]
fn ancestor_directory_link_loads_each_rule_once() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("rules");
    write(&root.join("top.yml"), &rule("Top"));
    write(&root.join("x/y/deep.yml"), &rule("Deep"));
    link_dir(&root, &root.join("x/y/up"));
    link_dir(&root.join("x"), &root.join("x/y/parent"));

    let collection = parse_sigma_directory(&root).unwrap();
    assert_eq!(titles(&collection), ["Deep", "Top"]);
    assert!(
        collection.diagnostics.is_empty(),
        "{:?}",
        collection.diagnostics
    );
}

#[test]
fn yaml_link_to_outside_file_is_neither_opened_nor_leaked() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("rules");
    let outside = dir.path().join("outside-secrets");
    write(&root.join("ok.yml"), &rule("Ok"));
    write(&outside.join("secret.yml"), &format!("title: [{SECRET}\n"));
    if !link_file(&outside.join("secret.yml"), &root.join("leak.yml")) {
        return;
    }

    let collection = parse_sigma_directory(&root).unwrap();
    assert_eq!(titles(&collection), ["Ok"]);
    let skipped = skipped(&collection);
    assert_eq!(skipped.len(), 1, "{:?}", collection.diagnostics);
    assert!(skipped[0].contains("leak.yml"), "{skipped:?}");
    assert!(
        skipped[0].contains("--follow-external-links"),
        "{skipped:?}"
    );
    assert_no_leak(&collection, &outside);

    let followed =
        parse_sigma_directory_with(&root, &WalkOptions::new().follow_external_links(true)).unwrap();
    assert!(followed.has_errors(), "following reads the outside file");
}

#[test]
fn directory_link_to_filesystem_root_is_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("rules");
    write(&root.join("ok.yml"), &rule("Ok"));
    link_dir(&filesystem_root(), &root.join("everything"));

    let collection = parse_sigma_directory(&root).unwrap();
    assert_eq!(titles(&collection), ["Ok"]);
    let skipped = skipped(&collection);
    assert_eq!(skipped.len(), 1, "{:?}", collection.diagnostics);
    assert!(skipped[0].contains("everything"), "{skipped:?}");
    assert_eq!(
        collection.diagnostics.len(),
        1,
        "{:?}",
        collection.diagnostics
    );
}

#[test]
fn outside_directory_link_is_skipped_unless_followed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("rules");
    let shared = dir.path().join("shared");
    write(&root.join("own.yml"), &rule("Own"));
    write(&shared.join("shared.yml"), &rule("Shared"));
    link_dir(&shared, &root.join("vendor"));
    link_dir(&shared, &root.join("vendor-again"));

    let confined = parse_sigma_directory(&root).unwrap();
    assert_eq!(titles(&confined), ["Own"]);
    assert_eq!(skipped(&confined).len(), 2);

    let followed =
        parse_sigma_directory_with(&root, &WalkOptions::new().follow_external_links(true)).unwrap();
    assert_eq!(titles(&followed), ["Own", "Shared"]);
    assert!(
        followed.diagnostics.is_empty(),
        "{:?}",
        followed.diagnostics
    );
}

#[test]
fn links_to_one_file_load_it_once() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("rules");
    write(&root.join("a.yml"), &rule("A"));
    if !link_file(&root.join("a.yml"), &root.join("b.yml")) {
        return;
    }
    link_file(&root.join("a.yml"), &root.join("c.yaml"));

    let collection = parse_sigma_directory(&root).unwrap();
    assert_eq!(titles(&collection), ["A"]);
    assert!(collection.diagnostics.is_empty());
}

#[test]
fn kubernetes_configmap_layout_loads_each_rule_once() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("rules");
    write(
        &root.join("..2026_11_28_17_00_00.1/rule.yml"),
        &rule("Mounted"),
    );
    link_dir(&root.join("..2026_11_28_17_00_00.1"), &root.join("..data"));
    link_file(&root.join("..data/rule.yml"), &root.join("rule.yml"));

    let collection = parse_sigma_directory(&root).unwrap();
    assert_eq!(titles(&collection), ["Mounted"]);
    assert!(
        collection.diagnostics.is_empty(),
        "{:?}",
        collection.diagnostics
    );
}

#[test]
fn broken_link_is_reported_without_its_target() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("rules");
    write(&root.join("ok.yml"), &rule("Ok"));
    let missing = dir.path().join("gone-target");
    write(&missing.join("x.yml"), "x");
    if !link_file(&missing.join("x.yml"), &root.join("broken.yml")) {
        return;
    }
    fs::remove_dir_all(&missing).unwrap();

    let walk = walk_files(&root, &WalkOptions::default()).unwrap();
    assert_eq!(walk.files.len(), 1);
    assert_eq!(walk.skipped.len(), 1);
    assert_eq!(walk.skipped[0].reason, SkipReason::Unresolvable);
    assert!(!walk.skipped[0].to_string().contains("gone-target"));
}

#[test]
fn lint_directory_skips_escapes_and_finishes_on_cycles() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("rules");
    let outside = dir.path().join("outside-secrets");
    write(&root.join("ok.yml"), &rule("Ok"));
    write(&outside.join("secret.yml"), &format!("title: [{SECRET}\n"));
    link_dir(&root, &root.join("loop"));
    link_dir(&outside, &root.join("escape"));

    let results = lint_yaml_directory(&root).unwrap();
    let linted: Vec<_> = results
        .iter()
        .filter(|r| r.warnings.iter().all(|w| w.rule != LintRule::SkippedPath))
        .collect();
    assert_eq!(linted.len(), 1, "{results:#?}");
    assert!(linted[0].path.ends_with("ok.yml"));
    let skipped: Vec<_> = results
        .iter()
        .flat_map(|r| &r.warnings)
        .filter(|w| w.rule == LintRule::SkippedPath)
        .collect();
    assert_eq!(skipped.len(), 1, "{results:#?}");
    for warning in results.iter().flat_map(|r| &r.warnings) {
        assert!(!warning.message.contains(SECRET), "{warning:?}");
    }
}

#[test]
fn ruleset_sources_skip_escapes_and_overlays_refuse_them() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("rules");
    let outside = dir.path().join("outside");
    write(&root.join("own.yml"), &rule("Own"));
    write(&outside.join("other.yml"), &rule("Other"));
    link_dir(&outside, &root.join("vendor"));
    link_dir(&root, &root.join("loop"));

    let spec = RulesetSpec {
        sources: vec![root.clone()],
        ..Default::default()
    };
    let resolved = resolve_ruleset("local", &spec, &ResolveOptions::default()).unwrap();
    assert_eq!(titles(&resolved.collection), ["Own"]);
    let followed = resolve_ruleset(
        "local",
        &spec,
        &ResolveOptions {
            follow_external_links: true,
            ..ResolveOptions::default()
        },
    )
    .unwrap();
    assert_eq!(titles(&followed.collection), ["Other", "Own"]);

    let overlays = dir.path().join("overlays");
    fs::create_dir_all(&overlays).unwrap();
    link_dir(&outside, &overlays.join("escape"));
    let spec = RulesetSpec {
        sources: vec![root.clone()],
        overlays: vec![OverlayEntry {
            dir: Some(overlays),
            ..Default::default()
        }],
        ..Default::default()
    };
    let error = resolve_ruleset("local", &spec, &ResolveOptions::default()).unwrap_err();
    assert!(matches!(error, RulesetError::Confinement { .. }), "{error}");
}
