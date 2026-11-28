//! Integration tests for `rsigma rule migrate-sources`.

use crate::common;

use common::{rsigma, temp_file};
use predicates::prelude::*;

const PIPELINE_WITH_SOURCES: &str = r#"
name: dynamic_ecs
priority: 50
sources:
  - id: threat_feed
    type: file
    path: /tmp/threat.json
    format: json
  - id: asset_db
    type: http
    url: https://example.com/assets
    format: json
    refresh: 1h
transformations:
  - type: value_placeholders
"#;

const PIPELINE_NO_SOURCES: &str = r#"
name: simple_mapping
priority: 10
transformations:
  - id: map_fields
    type: field_name_mapping
    mapping:
      CommandLine: process.command_line
"#;

#[test]
fn migrate_sources_single_strategy() {
    let pipe_file = temp_file(".yml", PIPELINE_WITH_SOURCES);
    let out_dir = tempfile::tempdir().unwrap();
    let out_file = out_dir.path().join("sources.yml");

    rsigma()
        .args([
            "rule",
            "migrate-sources",
            "-p",
            pipe_file.path().to_str().unwrap(),
            "-o",
            out_file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 source(s)"));

    let content = std::fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("sources:"));
    assert!(content.contains("threat_feed"));
    assert!(content.contains("asset_db"));

    // The pipeline file should no longer have a sources: block
    let pipeline_content = std::fs::read_to_string(pipe_file.path()).unwrap();
    assert!(!pipeline_content.contains("sources:"));
    assert!(pipeline_content.contains("transformations:"));
}

#[test]
fn migrate_sources_dry_run() {
    let pipe_file = temp_file(".yml", PIPELINE_WITH_SOURCES);
    let out_dir = tempfile::tempdir().unwrap();
    let out_file = out_dir.path().join("sources.yml");

    rsigma()
        .args([
            "rule",
            "migrate-sources",
            "-p",
            pipe_file.path().to_str().unwrap(),
            "-o",
            out_file.to_str().unwrap(),
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("sources:"))
        .stderr(predicate::str::contains("Dry run"));

    // Output file should NOT be created in dry-run mode
    assert!(!out_file.exists());
}

#[test]
fn migrate_sources_no_sources_found() {
    let pipe_file = temp_file(".yml", PIPELINE_NO_SOURCES);
    let out_dir = tempfile::tempdir().unwrap();
    let out_file = out_dir.path().join("sources.yml");

    rsigma()
        .args([
            "rule",
            "migrate-sources",
            "-p",
            pipe_file.path().to_str().unwrap(),
            "-o",
            out_file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("No sources found"));
}

#[test]
fn migrate_sources_per_pipeline_strategy() {
    let pipe1 = temp_file(".yml", PIPELINE_WITH_SOURCES);
    let out_dir = tempfile::tempdir().unwrap();

    rsigma()
        .args([
            "rule",
            "migrate-sources",
            "-p",
            pipe1.path().to_str().unwrap(),
            "-o",
            out_dir.path().to_str().unwrap(),
            "--strategy",
            "per-pipeline",
        ])
        .assert()
        .success();

    // Should have created a sources file in the output directory
    let entries: Vec<_> = std::fs::read_dir(out_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(!entries.is_empty(), "expected at least one output file");
}
