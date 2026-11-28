//! External coverage inputs: the Atomic Red Team index, the SigmaHQ baseline
//! Navigator layer, and a user-supplied target technique list.
//!
//! Each loader accepts a local path (and, for atomics/baseline, an `http(s)`
//! URL fetched through a 7-day on-disk cache that mirrors the schema-download
//! pattern in [`crate::commands::lint`]). All loaders normalize to a set of
//! ATT&CK technique IDs. The atomics loader also retains per-technique test
//! metadata (`name`, `auto_generated_guid`, `supported_platforms`) and, for
//! an `index.yaml`, the outer tactic keys; unread fields are ignored, so
//! upstream schema drift beyond those fields is non-fatal.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Deserialize;

use super::normalize_technique;

/// Default Atomic Red Team technique index (a tactic -> technique map).
pub(crate) const DEFAULT_ATOMICS_URL: &str = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml";

/// Default SigmaHQ coverage heatmap (itself an ATT&CK Navigator layer).
pub(crate) const DEFAULT_BASELINE_URL: &str =
    "https://raw.githubusercontent.com/SigmaHQ/sigma/master/other/sigma_attack_nav_coverage.json";

/// An unordered set of technique IDs (the Atomic Red Team and SigmaHQ-baseline
/// cross-references).
pub(crate) struct CrossRef {
    pub(crate) ids: BTreeSet<String>,
}

/// One Atomic Red Team test: the fields a caller needs to name and invoke it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct AtomicTestMeta {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) auto_generated_guid: Option<String>,
    #[serde(default)]
    pub(crate) supported_platforms: Vec<String>,
}

impl AtomicTestMeta {
    /// GUID when present and non-empty. Upstream occasionally omits
    /// `auto_generated_guid`; never invent one.
    pub(crate) fn guid(&self) -> Option<&str> {
        self.auto_generated_guid
            .as_deref()
            .map(str::trim)
            .filter(|g| !g.is_empty())
    }
}

/// Per-technique Atomic Red Team catalog entry: tactic labels from the
/// index's outer keys (empty after a directory walk) plus the typed tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AtomicTechniqueMeta {
    pub(crate) tactics: BTreeSet<String>,
    pub(crate) tests: Vec<AtomicTestMeta>,
}

/// Technique id -> test metadata, keyed by the same normalized IDs as
/// [`CrossRef`].
pub(crate) type AtomicsCatalog = BTreeMap<String, AtomicTechniqueMeta>;

/// Atomic Red Team load result: the id set used by the coverage report, plus
/// the typed catalog the atomics-plan emit consumes.
pub(crate) struct AtomicsSource {
    pub(crate) cross_ref: CrossRef,
    pub(crate) catalog: AtomicsCatalog,
}

/// An ordered list of target technique IDs (deduplicated at load time).
pub(crate) struct Targets {
    pub(crate) ids: Vec<String>,
}

/// Cache freshness for downloaded inputs: 7 days, matching `rule lint`'s
/// schema cache.
const CACHE_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Read a spec that is either a local path or an `http(s)` URL. URLs are
/// fetched through the on-disk cache; paths are read directly.
fn fetch_or_read(spec: &str) -> Result<String, String> {
    if crate::fetch::is_remote(spec) {
        fetch_cached(spec)
    } else {
        std::fs::read_to_string(spec).map_err(|e| format!("could not read {spec}: {e}"))
    }
}

/// Resolve the cache path for a URL: `<cache>/rsigma/coverage/<hash>.<ext>`.
/// Uses the fixed-seed `DefaultHasher` so the name is stable across runs.
fn cache_path(url: &str) -> Option<PathBuf> {
    let dir = dirs::cache_dir()?.join("rsigma").join("coverage");
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    url.hash(&mut hasher);
    let hash = hasher.finish();
    let ext = if url.ends_with(".json") {
        "json"
    } else {
        "yaml"
    };
    Some(dir.join(format!("{hash:016x}.{ext}")))
}

fn is_fresh(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .map(|age| age.as_secs() < CACHE_MAX_AGE_SECS)
        .unwrap_or(false)
}

/// Download `url`, caching the body under the XDG cache dir. Falls back to a
/// stale cache copy when the network is unavailable; errors only when there is
/// neither a successful download nor any cached copy.
fn fetch_cached(url: &str) -> Result<String, String> {
    let cache = cache_path(url);

    if let Some(path) = &cache
        && is_fresh(path)
        && let Ok(body) = std::fs::read_to_string(path)
    {
        return Ok(body);
    }

    match crate::fetch::get_text(url) {
        Ok(body) => {
            if let Some(path) = &cache {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(path, &body);
            }
            Ok(body)
        }
        Err(e) => {
            if let Some(path) = &cache
                && let Ok(body) = std::fs::read_to_string(path)
            {
                eprintln!("warning: download of {url} failed ({e}); using stale cache");
                return Ok(body);
            }
            Err(format!("downloading {url}: {e}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Atomic Red Team
// ---------------------------------------------------------------------------

/// Resolve the Atomic Red Team technique set and the typed test catalog.
///
/// A directory is treated as an atomic-red-team `atomics/` checkout and walked
/// for per-technique YAML files (tactics stay empty: those files have no
/// tactic field); anything else is read as the `index.yaml` (local path or
/// URL), a `tactic -> {technique_id -> entry}` map.
pub(crate) fn load_atomics(spec: &str) -> Result<AtomicsSource, String> {
    if Path::new(spec).is_dir() {
        atomics_from_dir(Path::new(spec))
    } else {
        let raw = fetch_or_read(spec)?;
        parse_atomics_index(&raw)
    }
}

/// One index.yaml entry. Only `atomic_tests` is read; `technique` and any
/// other sibling keys are ignored so upstream schema drift is non-fatal.
#[derive(Deserialize, Default)]
struct IndexEntry {
    #[serde(default)]
    atomic_tests: Vec<AtomicTestMeta>,
}

/// Parse the atomic-red-team `index.yaml`. Inner keys are technique IDs
/// (only techniques that have atomics appear); outer keys are tactics.
pub(super) fn parse_atomics_index(raw: &str) -> Result<AtomicsSource, String> {
    let parsed: BTreeMap<String, BTreeMap<String, IndexEntry>> =
        yaml_serde::from_str(raw).map_err(|e| format!("parsing Atomic Red Team index: {e}"))?;

    let mut catalog = AtomicsCatalog::new();
    for (tactic, inner) in parsed {
        for (technique_id, entry) in inner {
            let Some(id) = normalize_technique(&technique_id) else {
                continue;
            };
            let meta = catalog.entry(id).or_default();
            if !tactic.is_empty() {
                meta.tactics.insert(tactic.clone());
            }
            merge_tests(&mut meta.tests, entry.atomic_tests);
        }
    }
    Ok(atomics_source(catalog))
}

/// The fields of a per-technique atomic YAML file that this loader reads.
#[derive(Deserialize, Default)]
struct AtomicDoc {
    attack_technique: Option<String>,
    #[serde(default)]
    atomic_tests: Vec<AtomicTestMeta>,
}

/// Walk an atomic-red-team `atomics/` directory, collecting technique IDs and
/// tests from `T*/T*.yaml` files (reading `attack_technique`, falling back to
/// the file stem when absent). Tactics are left empty.
fn atomics_from_dir(dir: &Path) -> Result<AtomicsSource, String> {
    let mut catalog = AtomicsCatalog::new();
    walk_atomics(dir, &mut catalog)?;
    if catalog.is_empty() {
        return Err(format!(
            "no Atomic Red Team technique files found under {}",
            dir.display()
        ));
    }
    Ok(atomics_source(catalog))
}

fn walk_atomics(dir: &Path, catalog: &mut AtomicsCatalog) -> Result<(), String> {
    let options = crate::walk_options()
        .accept(|path| path.extension().and_then(|e| e.to_str()) == Some("yaml"));
    let walk = rsigma_parser::walk::walk_files(dir, &options)
        .map_err(|e| format!("could not read atomics directory {}: {e}", dir.display()))?;
    for skipped in &walk.skipped {
        eprintln!("Warning: {skipped}");
    }
    for file in walk.files {
        let path = file.path;
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if !stem.starts_with('T') && !stem.starts_with('t') {
            continue;
        }
        let raw = std::fs::read_to_string(&path).unwrap_or_default();
        let doc = yaml_serde::from_str::<AtomicDoc>(&raw).unwrap_or_default();
        let id = doc
            .attack_technique
            .as_deref()
            .and_then(normalize_technique)
            .or_else(|| normalize_technique(stem));
        if let Some(id) = id {
            let meta = catalog.entry(id).or_default();
            merge_tests(&mut meta.tests, doc.atomic_tests);
        }
    }
    Ok(())
}

/// Dedup incoming tests onto `into` by GUID when both sides have one, else
/// by name. A technique listed under several tactics in `index.yaml` repeats
/// the same `atomic_tests` array; first-wins would depend on BTreeMap order
/// and drop tests that only appear on a later tactic key.
fn merge_tests(into: &mut Vec<AtomicTestMeta>, incoming: Vec<AtomicTestMeta>) {
    for test in incoming {
        let exists = into
            .iter()
            .any(|existing| match (existing.guid(), test.guid()) {
                (Some(a), Some(b)) => a == b,
                _ => !existing.name.is_empty() && existing.name == test.name,
            });
        if !exists {
            into.push(test);
        }
    }
}

fn atomics_source(catalog: AtomicsCatalog) -> AtomicsSource {
    AtomicsSource {
        cross_ref: CrossRef {
            ids: catalog.keys().cloned().collect(),
        },
        catalog,
    }
}

// ---------------------------------------------------------------------------
// SigmaHQ baseline (an ATT&CK Navigator layer)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BaselineLayer {
    #[serde(default)]
    techniques: Vec<BaselineTechnique>,
}

#[derive(Deserialize)]
struct BaselineTechnique {
    #[serde(rename = "techniqueID")]
    technique_id: String,
    #[serde(default)]
    score: Option<f64>,
    #[serde(default)]
    enabled: Option<bool>,
}

/// Resolve the set of technique IDs the baseline Navigator layer covers
/// (enabled and with a non-zero score, or no score at all).
pub(crate) fn load_baseline(spec: &str) -> Result<CrossRef, String> {
    let raw = fetch_or_read(spec)?;
    Ok(CrossRef {
        ids: parse_baseline_layer(&raw)?,
    })
}

fn parse_baseline_layer(raw: &str) -> Result<BTreeSet<String>, String> {
    let layer: BaselineLayer =
        serde_json::from_str(raw).map_err(|e| format!("parsing baseline layer: {e}"))?;
    let mut ids = BTreeSet::new();
    for t in layer.techniques {
        if t.enabled == Some(false) {
            continue;
        }
        if t.score.unwrap_or(1.0) <= 0.0 {
            continue;
        }
        if let Some(id) = normalize_technique(&t.technique_id) {
            ids.insert(id);
        }
    }
    Ok(ids)
}

// ---------------------------------------------------------------------------
// Target technique list
// ---------------------------------------------------------------------------

/// Read a target technique list: one technique ID per line, `#` comments and
/// blank lines ignored. Order is preserved and duplicates removed. Lines that
/// are not valid technique IDs are skipped with a warning.
pub(crate) fn load_targets(path: &Path) -> Result<Targets, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read targets file {}: {e}", path.display()))?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        match normalize_technique(trimmed) {
            Some(id) => {
                if seen.insert(id.clone()) {
                    out.push(id);
                }
            }
            None => eprintln!("warning: skipping invalid technique id in targets file: {trimmed}"),
        }
    }
    Ok(Targets { ids: out })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_atomics_index_inner_keys() {
        let raw = "\
execution:
  T1059:
    technique: {}
    atomic_tests: []
  T1059.001:
    technique: {}
defense-evasion:
  T1055:
    technique: {}
";
        let loaded = parse_atomics_index(raw).unwrap();
        let ids = &loaded.cross_ref.ids;
        assert!(ids.contains("T1059"));
        assert!(ids.contains("T1059.001"));
        assert!(ids.contains("T1055"));
        assert_eq!(ids.len(), 3);
        assert_eq!(loaded.catalog.len(), 3);
    }

    #[test]
    fn parses_atomics_index_tests_and_tactic_keys() {
        let raw = "\
execution:
  T1059.001:
    technique: { display_name: PowerShell }
    atomic_tests:
      - name: PowerShell
        auto_generated_guid: 11111111-1111-1111-1111-111111111111
        supported_platforms: [windows]
        executor: { name: powershell }
defense-evasion:
  T1059.001:
    technique: {}
    atomic_tests:
      - name: PowerShell
        auto_generated_guid: 11111111-1111-1111-1111-111111111111
        supported_platforms: [windows]
  T1566:
    technique: {}
    atomic_tests:
      - name: Phishing Attachment
        auto_generated_guid: 22222222-2222-2222-2222-222222222222
        supported_platforms: [windows, macos]
      - name: GUID-less phishing
        supported_platforms: [linux]
  T1027:
    technique: {}
    atomic_tests: []
";
        let loaded = parse_atomics_index(raw).unwrap();
        let ps = loaded.catalog.get("T1059.001").unwrap();
        assert_eq!(
            ps.tactics.iter().cloned().collect::<Vec<_>>(),
            vec!["defense-evasion".to_string(), "execution".to_string()]
        );
        assert_eq!(ps.tests.len(), 1);
        assert_eq!(ps.tests[0].name, "PowerShell");
        assert_eq!(
            ps.tests[0].guid(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(ps.tests[0].supported_platforms, vec!["windows"]);

        let phish = loaded.catalog.get("T1566").unwrap();
        assert_eq!(
            phish.tactics.iter().cloned().collect::<Vec<_>>(),
            vec!["defense-evasion".to_string()]
        );
        assert_eq!(phish.tests.len(), 2);
        assert_eq!(phish.tests[1].name, "GUID-less phishing");
        assert_eq!(phish.tests[1].guid(), None);
        assert_eq!(phish.tests[1].supported_platforms, vec!["linux"]);

        let empty = loaded.catalog.get("T1027").unwrap();
        assert!(empty.tests.is_empty());
        assert!(loaded.cross_ref.ids.contains("T1027"));
    }

    #[test]
    fn merges_tests_when_a_technique_appears_under_several_tactics() {
        // defense-evasion sorts before execution, so first-wins would keep
        // only the single defense-evasion test and drop the extra execution one.
        let raw = "\
execution:
  T1566:
    atomic_tests:
      - name: Spearphishing Attachment
        auto_generated_guid: 11111111-1111-1111-1111-111111111111
        supported_platforms: [windows]
      - name: Phishing via curl
        auto_generated_guid: 22222222-2222-2222-2222-222222222222
        supported_platforms: [linux]
defense-evasion:
  T1566:
    atomic_tests:
      - name: Spearphishing Attachment
        auto_generated_guid: 11111111-1111-1111-1111-111111111111
        supported_platforms: [windows]
";
        let loaded = parse_atomics_index(raw).unwrap();
        let phish = loaded.catalog.get("T1566").unwrap();
        assert_eq!(phish.tests.len(), 2);
        assert_eq!(
            phish.tactics.iter().cloned().collect::<Vec<_>>(),
            vec!["defense-evasion".to_string(), "execution".to_string()]
        );
    }

    #[test]
    fn dir_walk_retains_tests_and_leaves_tactics_empty() {
        let dir = tempfile::tempdir().unwrap();
        let tech = dir.path().join("T1566");
        std::fs::create_dir(&tech).unwrap();
        std::fs::write(
            tech.join("T1566.yaml"),
            "\
attack_technique: T1566
display_name: Phishing
atomic_tests:
  - name: Spearphishing Attachment
    auto_generated_guid: 33333333-3333-3333-3333-333333333333
    supported_platforms: [windows]
",
        )
        .unwrap();
        // A file without atomic_tests still contributes its technique id.
        let other = dir.path().join("T1059");
        std::fs::create_dir(&other).unwrap();
        std::fs::write(other.join("T1059.yaml"), "attack_technique: T1059\n").unwrap();

        let loaded = atomics_from_dir(dir.path()).unwrap();
        assert_eq!(loaded.cross_ref.ids.len(), 2);
        let phish = loaded.catalog.get("T1566").unwrap();
        assert!(phish.tactics.is_empty());
        assert_eq!(phish.tests.len(), 1);
        assert_eq!(phish.tests[0].name, "Spearphishing Attachment");
        assert_eq!(
            phish.tests[0].guid(),
            Some("33333333-3333-3333-3333-333333333333")
        );
        let parent = loaded.catalog.get("T1059").unwrap();
        assert!(parent.tactics.is_empty());
        assert!(parent.tests.is_empty());
    }

    #[test]
    fn parses_baseline_layer_filtering_zero_and_disabled() {
        let raw = r#"{
            "techniques": [
                {"techniqueID": "T1059", "score": 5},
                {"techniqueID": "T1003", "score": 0},
                {"techniqueID": "T1055", "enabled": false, "score": 3},
                {"techniqueID": "T1078"}
            ]
        }"#;
        let ids = parse_baseline_layer(raw).unwrap();
        assert!(ids.contains("T1059"));
        assert!(ids.contains("T1078")); // no score => kept
        assert!(!ids.contains("T1003")); // score 0 => dropped
        assert!(!ids.contains("T1055")); // disabled => dropped
    }

    #[test]
    fn targets_strips_comments_and_dedupes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("targets.txt");
        std::fs::write(
            &path,
            "# top techniques\nT1059\nt1003   # credential dumping\n\nT1059\nnot-a-technique\n",
        )
        .unwrap();
        let targets = load_targets(&path).unwrap();
        assert_eq!(targets.ids, vec!["T1059".to_string(), "T1003".to_string()]);
    }

    #[test]
    fn fetch_or_read_reads_local_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.yaml");
        std::fs::write(&path, "execution:\n  T1059: {}\n").unwrap();
        let body = fetch_or_read(path.to_str().unwrap()).unwrap();
        assert!(body.contains("T1059"));
    }
}
