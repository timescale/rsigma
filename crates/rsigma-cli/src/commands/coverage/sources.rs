//! External coverage inputs: the Atomic Red Team index, the SigmaHQ baseline
//! Navigator layer, and a user-supplied target technique list.
//!
//! Each loader accepts a local path (and, for atomics/baseline, an `http(s)`
//! URL fetched through a 7-day on-disk cache that mirrors the schema-download
//! pattern in [`crate::commands::lint`]). All loaders normalize to a set of
//! ATT&CK technique IDs; only technique IDs are read, so the upstream files'
//! exact schema/version is irrelevant beyond the fields touched here.

use std::collections::BTreeSet;
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
    if spec.starts_with("http://") || spec.starts_with("https://") {
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

    match ureq::get(url).call() {
        Ok(response) => {
            let body = response
                .into_body()
                .read_to_string()
                .map_err(|e| format!("reading response from {url}: {e}"))?;
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

/// Resolve the set of technique IDs that have Atomic Red Team tests.
///
/// A directory is treated as an atomic-red-team `atomics/` checkout and walked
/// for per-technique YAML files; anything else is read as the `index.yaml`
/// (local path or URL), a `tactic -> {technique_id -> entry}` map.
pub(crate) fn load_atomics(spec: &str) -> Result<CrossRef, String> {
    let ids = if Path::new(spec).is_dir() {
        atomic_ids_from_dir(Path::new(spec))?
    } else {
        let raw = fetch_or_read(spec)?;
        parse_atomics_index(&raw)?
    };
    Ok(CrossRef { ids })
}

/// Parse the technique IDs out of the atomic-red-team `index.yaml`. The index
/// is a `tactic -> {technique_id -> entry}` map; the inner keys are the
/// technique IDs (only techniques that have atomics appear).
fn parse_atomics_index(raw: &str) -> Result<BTreeSet<String>, String> {
    use serde::de::IgnoredAny;
    use std::collections::BTreeMap;

    let parsed: BTreeMap<String, BTreeMap<String, IgnoredAny>> =
        yaml_serde::from_str(raw).map_err(|e| format!("parsing Atomic Red Team index: {e}"))?;

    let mut ids = BTreeSet::new();
    for inner in parsed.values() {
        for technique_id in inner.keys() {
            if let Some(id) = normalize_technique(technique_id) {
                ids.insert(id);
            }
        }
    }
    Ok(ids)
}

/// The `attack_technique` field of a per-technique atomic YAML file.
#[derive(Deserialize)]
struct AtomicDoc {
    attack_technique: Option<String>,
}

/// Walk an atomic-red-team `atomics/` directory, collecting technique IDs from
/// `T*/T*.yaml` files (reading `attack_technique`, falling back to the file
/// stem when absent).
fn atomic_ids_from_dir(dir: &Path) -> Result<BTreeSet<String>, String> {
    let mut ids = BTreeSet::new();
    walk_atomics(dir, &mut ids)?;
    if ids.is_empty() {
        return Err(format!(
            "no Atomic Red Team technique files found under {}",
            dir.display()
        ));
    }
    Ok(ids)
}

fn walk_atomics(dir: &Path, ids: &mut BTreeSet<String>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("could not read atomics directory {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("could not read entry in {}: {e}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            walk_atomics(&path, ids)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if !stem.starts_with('T') && !stem.starts_with('t') {
                continue;
            }
            let id = std::fs::read_to_string(&path)
                .ok()
                .and_then(|raw| yaml_serde::from_str::<AtomicDoc>(&raw).ok())
                .and_then(|doc| doc.attack_technique)
                .and_then(|t| normalize_technique(&t))
                .or_else(|| normalize_technique(stem));
            if let Some(id) = id {
                ids.insert(id);
            }
        }
    }
    Ok(())
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
        let ids = parse_atomics_index(raw).unwrap();
        assert!(ids.contains("T1059"));
        assert!(ids.contains("T1059.001"));
        assert!(ids.contains("T1055"));
        assert_eq!(ids.len(), 3);
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
