//! Conformance-style validation corpus checks.

#![cfg(feature = "validate")]

use std::fs;
use std::path::{Path, PathBuf};

use rstix::{DiagnosticCode, Validator};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("conformance")
}

fn validation_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("validation")
}

fn read_json(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read fixture {}: {err}", path.display()))
}

fn collect_json_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if !dir.exists() {
        return files;
    }
    for entry in fs::read_dir(dir).unwrap_or_else(|err| panic!("read_dir {}: {err}", dir.display()))
    {
        let entry = entry.unwrap_or_else(|err| panic!("read_dir entry {}: {err}", dir.display()));
        let path = entry.path();
        if path.extension().and_then(|v| v.to_str()) == Some("json") {
            files.push(path);
        }
    }
    files.sort();
    files
}

fn collect_invalid_conformance_files() -> Vec<PathBuf> {
    const INFO_ONLY_VALIDATION_FIXTURES: &[&str] = &[
        "bundle-location-bad-region.json",
        "bundle-relationship-matrix-invalid.json",
    ];

    let mut files = collect_json_files(&corpus_root().join("invalid"));
    for file in collect_json_files(&validation_root()) {
        let Some(name) = file.file_name().and_then(|v| v.to_str()) else {
            continue;
        };
        if name.starts_with("bundle-")
            && name.ends_with(".json")
            && !INFO_ONLY_VALIDATION_FIXTURES.contains(&name)
        {
            files.push(file);
        }
    }
    files.sort();
    files.dedup();
    files
}

#[test]
fn conformance_valid_corpus_is_valid_under_interop_strict() {
    let validator = Validator::interop_strict();
    let valid_dir = corpus_root().join("valid");
    let files = collect_json_files(&valid_dir);
    assert!(
        !files.is_empty(),
        "no valid conformance fixtures found in {}",
        valid_dir.display()
    );
    for file in files {
        let json = read_json(&file);
        let report = validator.validate_json_str(&json);
        assert!(
            report.is_valid(),
            "expected interop_strict validity for {}",
            file.display()
        );
    }
}

#[test]
fn conformance_invalid_corpus_fails_interop_strict() {
    let validator = Validator::interop_strict();
    let files = collect_invalid_conformance_files();
    assert!(
        files.len() >= 10,
        "expected at least 10 invalid conformance fixtures, found {}",
        files.len()
    );
    for file in files {
        let json = read_json(&file);
        let report = validator.validate_json_str(&json);
        assert!(
            !report.is_valid(),
            "expected validation failure for {}",
            file.display()
        );
    }
}

#[test]
fn conformance_invalid_corpus_never_emits_false_e0001() {
    let validator = Validator::interop_strict();
    for file in collect_invalid_conformance_files() {
        let json = read_json(&file);
        let report = validator.validate_json_str(&json);
        assert!(
            report.with_code(DiagnosticCode::E0001).next().is_none(),
            "semantic invalid fixture {} must not emit STIX-E0001",
            file.display()
        );
    }
}

#[test]
fn conformance_versioning_corpus_has_w0003_or_w0004() {
    let validator = Validator::interop_strict();
    let versioning_dir = corpus_root().join("versioning");
    let files = collect_json_files(&versioning_dir);
    assert!(
        !files.is_empty(),
        "no versioning conformance fixtures found in {}",
        versioning_dir.display()
    );
    for file in files {
        let json = read_json(&file);
        let report = validator.validate_json_str(&json);
        let has_w0003 = report.with_code(DiagnosticCode::W0003).next().is_some();
        let has_w0004 = report.with_code(DiagnosticCode::W0004).next().is_some();
        assert!(
            has_w0003 || has_w0004,
            "expected STIX-W0003 or STIX-W0004 for {}",
            file.display()
        );
    }
}
