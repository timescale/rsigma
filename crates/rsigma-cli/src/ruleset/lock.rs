//! Deterministic build lockfiles for resolved rulesets.

use std::path::PathBuf;

use rsigma_parser::ruleset::{RulesetSpec, SourceFile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::build::portable_path;

/// The lockfile schema version understood by this build.
pub(crate) const LOCK_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Lockfile {
    pub lock_version: u32,
    pub ruleset: String,
    pub generator: String,
    pub spec_sha256: String,
    pub sources: Vec<LockedSource>,
    pub overlay_files: Vec<LockedOverlayFile>,
    pub pipelines: Vec<String>,
    pub documents: Vec<LockedDocument>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LockedSource {
    pub path: String,
    pub files: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LockedOverlayFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LockedDocument {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub title: String,
    pub file: String,
    pub origin: String,
    pub decision: String,
    pub sha256: String,
    pub overlays: Vec<String>,
}

/// Lowercase hex SHA-256 of `bytes`.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// SHA-256 of a source or overlay file with CRLF line endings read as LF, so
/// a checkout that converts line endings does not change the lockfile.
pub(crate) fn content_sha256(bytes: &[u8]) -> String {
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut iter = bytes.iter().peekable();
    while let Some(&byte) = iter.next() {
        if byte == b'\r' && iter.peek() == Some(&&b'\n') {
            continue;
        }
        normalized.push(byte);
    }
    sha256_hex(&normalized)
}

/// Digest over every file the walk read for `source`, as sorted
/// `<relative path>\0<content_sha256 of the file>\n` lines.
pub(crate) fn source_digest(files: &[SourceFile], source: usize) -> String {
    let mut lines: Vec<String> = files
        .iter()
        .filter(|file| file.source == source)
        .map(|file| {
            format!(
                "{}\0{}\n",
                portable_path(&file.relative),
                content_sha256(&file.sha256_input)
            )
        })
        .collect();
    lines.sort();
    sha256_hex(lines.concat().as_bytes())
}

/// SHA-256 of the spec's JSON serialization.
pub(crate) fn spec_digest(spec: &RulesetSpec) -> String {
    sha256_hex(&serde_json::to_vec(spec).unwrap_or_default())
}

/// A lockfile path, kept for callers that need to report where it lives.
pub(crate) fn lock_path(dir: &std::path::Path) -> PathBuf {
    dir.join("ruleset.lock.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_file(source: usize, relative: &str, bytes: &[u8]) -> SourceFile {
        SourceFile {
            source,
            path: PathBuf::from(relative),
            relative: PathBuf::from(relative),
            sha256_input: bytes.to_vec(),
        }
    }

    #[test]
    fn sha256_is_lowercase_hex() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn content_digests_ignore_crlf_line_endings() {
        assert_eq!(
            content_sha256(b"a: 1\r\nb: 2\r\n"),
            content_sha256(b"a: 1\nb: 2\n")
        );
        assert_ne!(content_sha256(b"a: 1\r"), content_sha256(b"a: 1"));
        let lf = [source_file(0, "r.yml", b"title: x\n")];
        let crlf = [source_file(0, "r.yml", b"title: x\r\n")];
        assert_eq!(source_digest(&lf, 0), source_digest(&crlf, 0));
    }

    #[test]
    fn source_digest_is_stable_and_order_independent() {
        let files = vec![
            source_file(0, "b.yml", b"b"),
            source_file(0, "a.yml", b"a"),
            source_file(1, "c.yml", b"c"),
        ];
        let first = source_digest(&files, 0);
        let mut reversed = files.clone();
        reversed.reverse();
        assert_eq!(first, source_digest(&reversed, 0));
        assert_ne!(first, source_digest(&files, 1));

        let mut changed = files.clone();
        changed[0].sha256_input = b"changed".to_vec();
        assert_ne!(first, source_digest(&changed, 0));
    }

    #[test]
    fn spec_digest_is_stable() {
        let spec: RulesetSpec =
            yaml_serde::from_str("sources: [./rules]\ninclude:\n  - tags: [attack.t1059*]\n")
                .unwrap();
        let same: RulesetSpec =
            yaml_serde::from_str("sources: [./rules]\ninclude:\n  - tags: [attack.t1059*]\n")
                .unwrap();
        assert_eq!(spec_digest(&spec), spec_digest(&same));
        assert_eq!(spec_digest(&spec).len(), 64);
    }
}
