//! Offline reader for versioned disposition-capture bundles.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use rsigma_runtime::{
    BundleKind, BundleManifest, ProvenanceLine, parse_manifest, parse_provenance,
};
use serde_json::Value;

/// False-positive and true-positive events collected for one detection rule.
#[derive(Debug, Default)]
pub(crate) struct RuleEvidence {
    pub rule_id: String,
    pub false_positives: Vec<Value>,
    pub true_positives: Vec<Value>,
}

/// Load every versioned bundle under `spool_dir` and group events by rule.
///
/// Malformed or unsupported bundles fail with a path-prefixed error. A rule
/// that has false-positive evidence and no true-positive protection also fails.
pub(crate) fn load_disposition_evidence(
    spool_dir: &Path,
    rule_filter: Option<&str>,
) -> Result<Vec<RuleEvidence>, String> {
    if !spool_dir.is_dir() {
        return Err(format!(
            "disposition spool {} is not a directory",
            spool_dir.display()
        ));
    }
    let mut by_rule: BTreeMap<String, RuleEvidence> = BTreeMap::new();
    for kind in ["tp", "fp"] {
        let parent = spool_dir.join(kind);
        if !parent.exists() {
            continue;
        }
        if is_symlink(&parent) {
            return Err(format!("{}: refusing to read a symlink", parent.display()));
        }
        let entries = fs::read_dir(&parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("{}: {e}", parent.display()))?;
            let path = entry.path();
            if is_symlink(&path) {
                return Err(format!("{}: refusing to read a symlink", path.display()));
            }
            if !path.is_dir() {
                continue;
            }
            let bundle = read_bundle(&path)?;
            ingest_bundle(&mut by_rule, bundle, rule_filter);
        }
    }
    // `ingest_bundle` already admits only matching rules when a filter is set,
    // so an empty map means nothing matched the selector by id or title.
    if let Some(selector) = rule_filter
        && by_rule.is_empty()
    {
        return Err(format!(
            "no disposition bundles contained evidence for {selector:?}"
        ));
    }
    let mut out = Vec::new();
    for (id, evidence) in by_rule {
        if evidence.false_positives.is_empty() {
            continue;
        }
        if evidence.true_positives.is_empty() {
            return Err(format!(
                "rule {id} has false-positive disposition evidence but no true-positive protection set"
            ));
        }
        out.push(evidence);
    }
    if out.is_empty() {
        return Err(format!(
            "no false-positive disposition evidence found under {}",
            spool_dir.display()
        ));
    }
    Ok(out)
}

struct LoadedBundle {
    manifest: BundleManifest,
    provenance: Vec<ProvenanceLine>,
}

fn read_bundle(dir: &Path) -> Result<LoadedBundle, String> {
    let manifest_path = dir.join("manifest.json");
    let provenance_path = dir.join("provenance").join("events.ndjson");
    let manifest_bytes = read_regular_file(&manifest_path)?;
    let manifest =
        parse_manifest(&manifest_bytes).map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    if manifest.kind != BundleKind::DetectionGroupBy {
        return Err(format!(
            "{}: unsupported bundle kind (only detection_group_by is accepted)",
            manifest_path.display()
        ));
    }
    match manifest.verdict.as_str() {
        "true_positive" | "benign_true_positive" | "false_positive" => {}
        other => {
            return Err(format!(
                "{}: unsupported verdict {other:?}",
                manifest_path.display()
            ));
        }
    }
    let provenance_bytes = read_regular_file(&provenance_path)?;
    let provenance = parse_provenance(&provenance_bytes)
        .map_err(|e| format!("{}: {e}", provenance_path.display()))?;
    Ok(LoadedBundle {
        manifest,
        provenance,
    })
}

fn ingest_bundle(
    by_rule: &mut BTreeMap<String, RuleEvidence>,
    bundle: LoadedBundle,
    rule_filter: Option<&str>,
) {
    let is_fp = bundle.manifest.verdict == "false_positive";
    for line in bundle.provenance {
        for matched in line.matches {
            if let Some(selector) = rule_filter
                && matched.rule_id != selector
                && matched.rule_title != selector
            {
                continue;
            }
            let entry = by_rule
                .entry(matched.rule_id.clone())
                .or_insert_with(|| RuleEvidence {
                    rule_id: matched.rule_id,
                    ..RuleEvidence::default()
                });
            let dest = if is_fp {
                &mut entry.false_positives
            } else {
                &mut entry.true_positives
            };
            dest.push(line.event.clone());
        }
    }
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>, String> {
    if is_symlink(path) {
        return Err(format!("{}: refusing to read a symlink", path.display()));
    }
    fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_runtime::{
        BUNDLE_FORMAT_VERSION, BundleKind, BundleManifest, BundleRule, bundle_id,
    };

    fn write_bundle(dir: &Path, verdict: &str, rule_id: &str, event: &Value) {
        write_bundle_titled(dir, verdict, rule_id, rule_id, event);
    }

    fn write_bundle_titled(dir: &Path, verdict: &str, rule_id: &str, title: &str, event: &Value) {
        fs::create_dir_all(dir.join("provenance")).unwrap();
        let manifest = BundleManifest {
            format_version: BUNDLE_FORMAT_VERSION,
            bundle_id: bundle_id("test"),
            kind: BundleKind::DetectionGroupBy,
            verdict: verdict.into(),
            scope: "detection".into(),
            incident_id: None,
            fingerprint: None,
            rule_ids: vec![rule_id.into()],
            rules: vec![BundleRule {
                id: rule_id.into(),
                title: title.into(),
            }],
            analyst: None,
            note: None,
            first_seen: 1,
            last_seen: 2,
            event_count: 1,
            byte_count: 1,
            coalesced_matches: 0,
            truncated: false,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let line = serde_json::json!({
            "event_digest": "ab",
            "captured_at": "2026-01-01T00:00:00Z",
            "matches": [{"rule_id": rule_id, "rule_title": title}],
            "event": event,
        });
        fs::write(dir.join("provenance/events.ndjson"), format!("{line}\n")).unwrap();
    }

    #[test]
    fn groups_fp_and_tp_by_rule() {
        let root = tempfile::tempdir().unwrap();
        write_bundle(
            &root.path().join("fp/one"),
            "false_positive",
            "r1",
            &serde_json::json!({"user":"fp"}),
        );
        write_bundle(
            &root.path().join("tp/one"),
            "true_positive",
            "r1",
            &serde_json::json!({"user":"tp"}),
        );
        let evidence = load_disposition_evidence(root.path(), None).unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].rule_id, "r1");
        assert_eq!(evidence[0].false_positives.len(), 1);
        assert_eq!(evidence[0].true_positives.len(), 1);
    }

    #[test]
    fn rule_filter_matches_by_title() {
        let root = tempfile::tempdir().unwrap();
        write_bundle_titled(
            &root.path().join("fp/one"),
            "false_positive",
            "r1",
            "Suspicious Notepad",
            &serde_json::json!({"user":"fp"}),
        );
        write_bundle_titled(
            &root.path().join("tp/one"),
            "true_positive",
            "r1",
            "Suspicious Notepad",
            &serde_json::json!({"user":"tp"}),
        );
        let evidence = load_disposition_evidence(root.path(), Some("Suspicious Notepad")).unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].rule_id, "r1");

        let err = load_disposition_evidence(root.path(), Some("Other Rule")).unwrap_err();
        assert!(err.contains("no disposition bundles contained evidence"));
    }

    #[test]
    fn fp_without_tp_fails() {
        let root = tempfile::tempdir().unwrap();
        write_bundle(
            &root.path().join("fp/one"),
            "false_positive",
            "r1",
            &serde_json::json!({"user":"fp"}),
        );
        let err = load_disposition_evidence(root.path(), None).unwrap_err();
        assert!(err.contains("no true-positive protection set"));
    }

    #[test]
    fn malformed_manifest_includes_path() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("fp/bad");
        fs::create_dir_all(dir.join("provenance")).unwrap();
        fs::write(dir.join("manifest.json"), b"{\"format_version\":99}").unwrap();
        fs::write(dir.join("provenance/events.ndjson"), b"{}\n").unwrap();
        let err = load_disposition_evidence(root.path(), None).unwrap_err();
        assert!(err.contains("manifest.json"));
    }
}
