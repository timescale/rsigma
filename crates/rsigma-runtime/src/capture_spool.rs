//! Versioned disposition-bundle format.
//!
//! The daemon writes these documents; offline readers validate them strictly.
//! Unknown major versions and malformed documents fail closed.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::capture::AdmittedMatch;

/// Current bundle format major version. Readers reject any other major.
pub const BUNDLE_FORMAT_VERSION: u32 = 1;

/// Supported bundle kinds. Other kinds are rejected by the tune reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleKind {
    /// Detection results grouped by a deterministic `group_by` incident id.
    DetectionGroupBy,
}

/// On-disk `manifest.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Format major version.
    pub format_version: u32,
    /// SHA-256 hex of the normalized original disposition identity.
    pub bundle_id: String,
    /// Capture identity contract this bundle satisfies.
    pub kind: BundleKind,
    /// Analyst verdict that produced the bundle.
    pub verdict: String,
    /// Disposition scope (`detection` or `incident`).
    pub scope: String,
    /// Incident id when the original disposition carried one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<String>,
    /// Dedup fingerprint when the original disposition carried one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Contributing rule identities.
    pub rule_ids: Vec<String>,
    /// Contributing rule id/title pairs.
    pub rules: Vec<BundleRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analyst: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub event_count: u64,
    pub byte_count: u64,
    /// Matches coalesced onto a shared event payload in one processing call.
    #[serde(default)]
    pub coalesced_matches: u64,
    #[serde(default)]
    pub truncated: bool,
    /// RFC 3339 creation time.
    pub created_at: String,
}

/// A contributing rule recorded on the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleRule {
    pub id: String,
    pub title: String,
}

/// One `provenance/events.ndjson` line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceLine {
    pub event_digest: String,
    pub captured_at: String,
    pub matches: Vec<AdmittedMatch>,
    pub event: Value,
}

/// Why a bundle document was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpoolReadError {
    /// JSON/NDJSON could not be parsed.
    Parse(String),
    /// A required field was missing or invalid.
    Invalid(String),
}

impl std::fmt::Display for SpoolReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(msg) | Self::Invalid(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for SpoolReadError {}

/// SHA-256 hex digest of the normalized original disposition identity.
pub fn bundle_id(identity: &str) -> String {
    hex::encode(Sha256::digest(identity.as_bytes()))
}

/// Canonical identity string for an original disposition.
pub fn disposition_identity(
    scope: &str,
    verdict: &str,
    incident_id: Option<&str>,
    fingerprint: Option<&str>,
    rule_id: Option<&str>,
) -> String {
    format!(
        "{scope}\u{1}{verdict}\u{1}{}\u{1}{}\u{1}{}",
        incident_id.unwrap_or(""),
        fingerprint.unwrap_or(""),
        rule_id.unwrap_or(""),
    )
}

/// Parse and validate a `manifest.json` document.
pub fn parse_manifest(bytes: &[u8]) -> Result<BundleManifest, SpoolReadError> {
    if bytes.len() > 1024 * 1024 {
        return Err(SpoolReadError::Invalid(
            "manifest exceeds the 1MiB read bound".to_string(),
        ));
    }
    let manifest: BundleManifest = serde_json::from_slice(bytes)
        .map_err(|e| SpoolReadError::Parse(format!("invalid manifest JSON: {e}")))?;
    if manifest.format_version != BUNDLE_FORMAT_VERSION {
        return Err(SpoolReadError::Invalid(format!(
            "unsupported bundle format_version {}",
            manifest.format_version
        )));
    }
    if manifest.bundle_id.len() != 64 || !manifest.bundle_id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(SpoolReadError::Invalid(
            "manifest.bundle_id must be a 64-character hex digest".to_string(),
        ));
    }
    if manifest.verdict.is_empty() {
        return Err(SpoolReadError::Invalid(
            "manifest.verdict must not be empty".to_string(),
        ));
    }
    if manifest.rule_ids.is_empty() {
        return Err(SpoolReadError::Invalid(
            "manifest.rule_ids must not be empty".to_string(),
        ));
    }
    Ok(manifest)
}

/// Parse and validate `provenance/events.ndjson`.
pub fn parse_provenance(bytes: &[u8]) -> Result<Vec<ProvenanceLine>, SpoolReadError> {
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(SpoolReadError::Invalid(
            "provenance exceeds the 32MiB read bound".to_string(),
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|e| SpoolReadError::Parse(format!("provenance is not UTF-8: {e}")))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rec: ProvenanceLine = serde_json::from_str(line).map_err(|e| {
            SpoolReadError::Parse(format!("invalid provenance on line {}: {e}", i + 1))
        })?;
        if rec.matches.is_empty() {
            return Err(SpoolReadError::Invalid(format!(
                "provenance line {} has no matches",
                i + 1
            )));
        }
        out.push(rec);
    }
    Ok(out)
}

/// Parse `corpus/events.ndjson` as bare JSON objects.
pub fn parse_corpus_events(bytes: &[u8]) -> Result<Vec<Value>, SpoolReadError> {
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(SpoolReadError::Invalid(
            "corpus exceeds the 32MiB read bound".to_string(),
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|e| SpoolReadError::Parse(format!("corpus is not UTF-8: {e}")))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|e| SpoolReadError::Parse(format!("invalid corpus on line {}: {e}", i + 1)))?;
        if !value.is_object() {
            return Err(SpoolReadError::Invalid(format!(
                "corpus line {} must be a JSON object",
                i + 1
            )));
        }
        out.push(value);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> BundleManifest {
        BundleManifest {
            format_version: BUNDLE_FORMAT_VERSION,
            bundle_id: bundle_id("incident\u{1}true_positive\u{1}inc\u{1}\u{1}"),
            kind: BundleKind::DetectionGroupBy,
            verdict: "true_positive".into(),
            scope: "incident".into(),
            incident_id: Some("inc".into()),
            fingerprint: None,
            rule_ids: vec!["r1".into()],
            rules: vec![BundleRule {
                id: "r1".into(),
                title: "Rule".into(),
            }],
            analyst: None,
            note: None,
            first_seen: 1,
            last_seen: 2,
            event_count: 1,
            byte_count: 10,
            coalesced_matches: 0,
            truncated: false,
            created_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn parse_manifest_rejects_unknown_version() {
        let mut m = manifest();
        m.format_version = 99;
        let err = parse_manifest(&serde_json::to_vec(&m).unwrap()).unwrap_err();
        assert!(err.to_string().contains("format_version"));
    }

    #[test]
    fn parse_provenance_and_corpus() {
        let line = ProvenanceLine {
            event_digest: "ab".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            matches: vec![AdmittedMatch {
                rule_id: "r1".into(),
                rule_title: "r1".into(),
                fingerprint: None,
            }],
            event: serde_json::json!({"user": "a"}),
        };
        let ndjson = format!("{}\n", serde_json::to_string(&line).unwrap());
        assert_eq!(parse_provenance(ndjson.as_bytes()).unwrap().len(), 1);
        assert_eq!(
            parse_corpus_events(b"{\"user\":\"a\"}\n").unwrap(),
            vec![serde_json::json!({"user": "a"})]
        );
    }

    #[test]
    fn bundle_id_is_stable_hex() {
        let id = bundle_id("x");
        assert_eq!(id.len(), 64);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(id, bundle_id("x"));
        assert_ne!(id, bundle_id("y"));
    }
}
