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

#[test]
fn conformance_valid_corpus_has_no_errors() {
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
            report.errors().next().is_none(),
            "expected no errors for {}",
            file.display()
        );
    }
}

#[test]
fn conformance_invalid_corpus_has_errors() {
    let validator = Validator::consumer_strict();
    let invalid_dir = corpus_root().join("invalid");
    let files = collect_json_files(&invalid_dir);
    assert!(
        !files.is_empty(),
        "no invalid conformance fixtures found in {}",
        invalid_dir.display()
    );
    for file in files {
        let json = read_json(&file);
        let report = validator.validate_json_str(&json);
        assert!(
            report.errors().next().is_some(),
            "expected errors for {}",
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
