//! Ruleset build planning, writing, and drift checks.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use rsigma_parser::ruleset::{Decision, DocumentKind, ResolvedRuleset, RulesetError, RulesetSpec};
use rsigma_parser::{emit_correlation_yaml, emit_filter_yaml, emit_rule_yaml};
use serde::Serialize;

use super::lock::{
    LOCK_VERSION, LockedDocument, LockedOverlayFile, LockedSource, Lockfile, content_sha256,
    lock_path, sha256_hex, source_digest, spec_digest,
};
use crate::fsutil::atomic_write;

/// One file a build would write, relative to the output directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlannedFile {
    pub rel: PathBuf,
    pub contents: String,
}

/// What a build actually changed.
#[derive(Debug, Serialize)]
pub(crate) struct WriteSummary {
    pub written: usize,
    pub unchanged: usize,
    pub removed: usize,
    pub documents: usize,
}

enum DocumentRef<'a> {
    Detection(&'a rsigma_parser::SigmaRule),
    Correlation(&'a rsigma_parser::CorrelationRule),
    Filter(&'a rsigma_parser::FilterRule),
}

impl DocumentRef<'_> {
    fn yaml(&self) -> String {
        match self {
            Self::Detection(rule) => emit_rule_yaml(rule),
            Self::Correlation(rule) => emit_correlation_yaml(rule),
            Self::Filter(rule) => emit_filter_yaml(rule),
        }
    }

    fn kind(&self) -> DocumentKind {
        match self {
            Self::Detection(_) => DocumentKind::Detection,
            Self::Correlation(_) => DocumentKind::Correlation,
            Self::Filter(_) => DocumentKind::Filter,
        }
    }

    fn id(&self) -> Option<&str> {
        match self {
            Self::Detection(rule) => rule.id.as_deref(),
            Self::Correlation(rule) => rule.id.as_deref(),
            Self::Filter(rule) => rule.id.as_deref(),
        }
    }

    fn title(&self) -> &str {
        match self {
            Self::Detection(rule) => &rule.title,
            Self::Correlation(rule) => &rule.title,
            Self::Filter(rule) => &rule.title,
        }
    }
}

fn is_kept(decision: &Decision) -> bool {
    matches!(
        decision,
        Decision::Included { .. } | Decision::PulledIn { .. } | Decision::FilterKept
    )
}

/// Pair every kept entry with its document, in candidate order.
fn kept_documents(
    resolved: &ResolvedRuleset,
) -> Vec<(&rsigma_parser::ruleset::RuleEntry, DocumentRef<'_>)> {
    let mut rules = resolved.collection.rules.iter();
    let mut correlations = resolved.collection.correlations.iter();
    let mut filters = resolved.collection.filters.iter();
    let mut out = Vec::new();
    for entry in &resolved.entries {
        if !is_kept(&entry.decision) {
            continue;
        }
        let document = match entry.kind {
            DocumentKind::Detection => rules.next().map(DocumentRef::Detection),
            DocumentKind::Correlation => correlations.next().map(DocumentRef::Correlation),
            DocumentKind::Filter => filters.next().map(DocumentRef::Filter),
        };
        if let Some(document) = document {
            out.push((entry, document));
        }
    }
    out
}

/// One kept document's manifest identity and canonical hash.
#[derive(Debug, Clone)]
pub(crate) struct ManifestDocument {
    pub kind: &'static str,
    pub id: Option<String>,
    pub title: String,
    pub sha256: String,
}

/// Every kept document with its kind, id, title, and canonical hash. The hash
/// matches the one the build lockfile records.
pub(crate) fn manifest_documents(resolved: &ResolvedRuleset) -> Vec<ManifestDocument> {
    let mut documents: Vec<ManifestDocument> = kept_documents(resolved)
        .into_iter()
        .filter(|(_, document)| document.kind() != DocumentKind::Filter)
        .map(|(entry, document)| {
            let yaml = document.yaml();
            ManifestDocument {
                kind: document.kind().as_str(),
                id: entry.id.clone(),
                title: document.title().to_string(),
                sha256: sha256_hex(yaml.as_bytes()),
            }
        })
        .collect();
    documents.sort_by(|a, b| {
        (a.kind, a.id.as_deref().unwrap_or(""), &a.title).cmp(&(
            b.kind,
            b.id.as_deref().unwrap_or(""),
            &b.title,
        ))
    });
    documents
}

/// Reject two id-less documents whose canonical text is identical: they would
/// map to the same hash-derived file name.
pub(crate) fn ensure_unique(resolved: &ResolvedRuleset) -> Result<(), RulesetError> {
    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (entry, document) in kept_documents(resolved) {
        if entry.id.is_none() {
            seen.entry(document.yaml())
                .or_default()
                .push(document.title().to_string());
        }
    }
    for (_, titles) in seen {
        if titles.len() > 1 {
            return Err(RulesetError::Duplicate(format!(
                "id-less documents with identical canonical text: {}",
                titles.join(", ")
            )));
        }
    }
    Ok(())
}

fn valid_stem(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn stem_for(id: Option<&str>, sha256: &str) -> String {
    match id {
        Some(id) if valid_stem(id) => id.to_ascii_lowercase(),
        _ => sha256[..16].to_string(),
    }
}

fn subdir(kind: DocumentKind) -> &'static str {
    match kind {
        DocumentKind::Detection => "rules",
        DocumentKind::Correlation => "correlations",
        DocumentKind::Filter => "filters",
    }
}

/// A path with `/` separators, for lockfiles and reports.
pub(crate) fn portable_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Compute every file and lockfile entry a build would produce.
pub(crate) fn plan_output(
    resolved: &ResolvedRuleset,
    spec: &RulesetSpec,
) -> (Vec<PlannedFile>, Lockfile) {
    let mut files = Vec::new();
    let mut documents = Vec::new();
    for (entry, document) in kept_documents(resolved) {
        let yaml = document.yaml();
        let sha256 = sha256_hex(yaml.as_bytes());
        let stem = stem_for(entry.id.as_deref(), &sha256);
        let rel = Path::new(subdir(document.kind())).join(format!("{stem}.yml"));
        files.push(PlannedFile {
            rel: rel.clone(),
            contents: yaml,
        });
        documents.push(LockedDocument {
            kind: document.kind().as_str().to_string(),
            id: document.id().map(str::to_string),
            title: document.title().to_string(),
            file: portable_path(&rel),
            origin: portable_path(&entry.origin.root.join(&entry.origin.file)),
            decision: entry.decision.as_str().to_string(),
            sha256,
            overlays: entry
                .overlays
                .iter()
                .map(|overlay| overlay.origin.to_string())
                .collect(),
        });
    }

    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    documents.sort_by(|a, b| {
        (a.kind.as_str(), a.file.as_str()).cmp(&(b.kind.as_str(), b.file.as_str()))
    });

    let sources: Vec<LockedSource> = spec
        .sources
        .iter()
        .enumerate()
        .map(|(index, path)| LockedSource {
            path: portable_path(path),
            files: resolved
                .files
                .iter()
                .filter(|file| file.source == index)
                .count(),
            sha256: source_digest(&resolved.files, index),
        })
        .collect();

    let mut overlay_files: Vec<LockedOverlayFile> = resolved
        .overlay_files
        .iter()
        .map(|file| LockedOverlayFile {
            path: portable_path(&file.path),
            sha256: content_sha256(&file.sha256_input),
        })
        .collect();
    overlay_files.sort_by(|a, b| a.path.cmp(&b.path));

    let lock = Lockfile {
        lock_version: LOCK_VERSION,
        ruleset: resolved.name.clone(),
        generator: format!("rsigma {}", env!("CARGO_PKG_VERSION")),
        spec_sha256: spec_digest(spec),
        sources,
        overlay_files,
        pipelines: spec.pipelines.clone(),
        documents,
    };
    (files, lock)
}

fn lockfile_contents(lock: &Lockfile) -> String {
    let mut text = serde_json::to_string_pretty(lock).unwrap_or_default();
    text.push('\n');
    text
}

fn stale_outputs(dir: &Path, desired: &BTreeSet<PathBuf>) -> Vec<PathBuf> {
    let mut stale = Vec::new();
    for name in ["rules", "correlations", "filters"] {
        let sub = dir.join(name);
        let Ok(entries) = fs::read_dir(&sub) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("yml") {
                continue;
            }
            let rel = Path::new(name).join(entry.file_name());
            if !desired.contains(&rel) {
                stale.push(rel);
            }
        }
    }
    stale.sort();
    stale
}

/// Write the planned files and lockfile into `dir`.
///
/// Refuses a non-empty directory without a lockfile unless `force` is set, and
/// only deletes stale `.yml` files inside the three generated subdirectories.
pub(crate) fn write_output(
    dir: &Path,
    plan: &[PlannedFile],
    lock: &Lockfile,
    force: bool,
) -> Result<WriteSummary, String> {
    let lock_file = lock_path(dir);
    if dir.exists() {
        let non_empty = fs::read_dir(dir)
            .map_err(|error| format!("cannot read {}: {error}", dir.display()))?
            .next()
            .is_some();
        if non_empty && !lock_file.is_file() && !force {
            return Err(format!(
                "{} is not empty and has no ruleset.lock.json; pass --force to write into it",
                dir.display()
            ));
        }
    }

    for name in ["", "rules", "correlations", "filters"] {
        let path = if name.is_empty() {
            dir.to_path_buf()
        } else {
            dir.join(name)
        };
        fs::create_dir_all(&path)
            .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    }

    let mut summary = WriteSummary {
        written: 0,
        unchanged: 0,
        removed: 0,
        documents: plan.len(),
    };

    for file in plan {
        let path = dir.join(&file.rel);
        if fs::read(&path).is_ok_and(|existing| existing == file.contents.as_bytes()) {
            summary.unchanged += 1;
            continue;
        }
        atomic_write(&path, &file.contents)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
        summary.written += 1;
    }

    let desired: BTreeSet<PathBuf> = plan.iter().map(|file| file.rel.clone()).collect();
    for rel in stale_outputs(dir, &desired) {
        let path = dir.join(&rel);
        fs::remove_file(&path)
            .map_err(|error| format!("cannot remove {}: {error}", path.display()))?;
        summary.removed += 1;
    }

    let contents = lockfile_contents(lock);
    if fs::read(&lock_file).is_ok_and(|existing| existing == contents.as_bytes()) {
        summary.unchanged += 1;
    } else {
        atomic_write(&lock_file, &contents)
            .map_err(|error| format!("cannot write {}: {error}", lock_file.display()))?;
        summary.written += 1;
    }

    Ok(summary)
}

/// Paths whose contents differ from what a build would write, including stale
/// generated files and the lockfile.
pub(crate) fn check_output(dir: &Path, plan: &[PlannedFile], lock: &Lockfile) -> Vec<PathBuf> {
    let mut drifted = Vec::new();
    for file in plan {
        let path = dir.join(&file.rel);
        if !fs::read(&path).is_ok_and(|existing| existing == file.contents.as_bytes()) {
            drifted.push(file.rel.clone());
        }
    }

    let desired: BTreeSet<PathBuf> = plan.iter().map(|file| file.rel.clone()).collect();
    drifted.extend(stale_outputs(dir, &desired));

    let lock_file = lock_path(dir);
    let contents = lockfile_contents(lock);
    if !fs::read(&lock_file).is_ok_and(|existing| existing == contents.as_bytes()) {
        drifted.push(PathBuf::from("ruleset.lock.json"));
    }

    drifted.sort();
    drifted.dedup();
    drifted
}

/// Write a resolved ruleset into a fresh temporary directory.
pub(crate) fn materialize_temp(
    resolved: &ResolvedRuleset,
    spec: &RulesetSpec,
) -> Result<tempfile::TempDir, String> {
    ensure_unique(resolved).map_err(|error| error.to_string())?;
    let dir = tempfile::tempdir()
        .map_err(|error| format!("cannot create a temporary directory: {error}"))?;
    let (plan, lock) = plan_output(resolved, spec);
    write_output(dir.path(), &plan, &lock, true)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::ruleset::{ResolveOptions, resolve_ruleset};

    #[test]
    fn stem_uses_a_valid_id_lowercased() {
        assert_eq!(stem_for(Some("ABC-1.2_x"), "sha"), "abc-1.2_x");
    }

    #[test]
    fn stem_hashes_an_invalid_id() {
        let sha = sha256_hex(b"canonical");
        assert_eq!(stem_for(Some("a/b"), &sha), sha[..16]);
    }

    #[test]
    fn stem_hashes_a_missing_id() {
        let sha = sha256_hex(b"canonical");
        assert_eq!(stem_for(None, &sha), sha[..16]);
    }

    #[test]
    fn plan_output_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rule.yml"),
            "title: Whoami\nid: aaaaaaaa-0000-4000-8000-000000000001\nlogsource:\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\\\whoami.exe'\n    condition: selection\n",
        )
        .unwrap();
        let spec = RulesetSpec {
            sources: vec![dir.path().to_path_buf()],
            ..Default::default()
        };
        let resolved = resolve_ruleset("test", &spec, &ResolveOptions::default()).unwrap();
        ensure_unique(&resolved).unwrap();
        let (first_files, first_lock) = plan_output(&resolved, &spec);
        let (second_files, second_lock) = plan_output(&resolved, &spec);
        assert_eq!(first_files, second_files);
        assert_eq!(
            serde_json::to_string(&first_lock).unwrap(),
            serde_json::to_string(&second_lock).unwrap()
        );
        assert_eq!(first_files.len(), 1);
        assert!(
            first_files[0]
                .rel
                .ends_with("aaaaaaaa-0000-4000-8000-000000000001.yml")
        );
    }
}
