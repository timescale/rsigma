//! Tests for the removal of pipeline-embedded `sources:` blocks.
//!
//! Pipeline-level `sources:` was deprecated in v0.12.0 ([issue #135]), hidden
//! from docs in v0.13.0 ([issue #136]), and removed in v0.19.0 ([issue #137]).
//! A pipeline that still declares an inline `sources:` block is now a hard
//! parse error that points at `rsigma rule migrate-sources`. These tests pin
//! that behaviour across the CLI entry points that load pipelines.
//!
//! [issue #135]: https://github.com/timescale/rsigma/issues/135
//! [issue #136]: https://github.com/timescale/rsigma/issues/136
//! [issue #137]: https://github.com/timescale/rsigma/issues/137

use crate::common;

use common::{SIMPLE_RULE, rsigma, temp_file};
use predicates::prelude::*;

const PIPELINE_WITH_INLINE_SOURCES: &str = r#"
name: legacy_with_sources
priority: 50
sources:
  - id: threat_feed
    type: file
    path: /tmp/threat.json
    format: json
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

const REMOVAL_NEEDLE: &str = "inline 'sources:' block, which was removed in v0.19.0";

fn rules_dir(contents: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rule.yml"), contents).unwrap();
    dir
}

#[test]
fn pipeline_sources_is_hard_error_via_validate() {
    let rules = rules_dir(SIMPLE_RULE);
    let pipeline = temp_file(".yml", PIPELINE_WITH_INLINE_SOURCES);

    rsigma()
        .args([
            "rule",
            "validate",
            "-p",
            pipeline.path().to_str().unwrap(),
            rules.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(REMOVAL_NEEDLE))
        .stderr(predicate::str::contains("rsigma rule migrate-sources"))
        .stderr(predicate::str::contains("--source"));
}

#[test]
fn pipeline_sources_is_hard_error_via_eval() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let pipeline = temp_file(".yml", PIPELINE_WITH_INLINE_SOURCES);

    rsigma()
        .args([
            "engine",
            "eval",
            "-r",
            rule.path().to_str().unwrap(),
            "-p",
            pipeline.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "benign"}"#,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(REMOVAL_NEEDLE));
}

#[cfg(feature = "daemon")]
#[test]
fn pipeline_sources_is_hard_error_via_resolve() {
    let pipeline = temp_file(".yml", PIPELINE_WITH_INLINE_SOURCES);

    rsigma()
        .args([
            "pipeline",
            "resolve",
            "-p",
            pipeline.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(REMOVAL_NEEDLE));
}

#[test]
fn pipeline_without_sources_still_loads() {
    let rules = rules_dir(SIMPLE_RULE);
    let pipeline = temp_file(".yml", PIPELINE_NO_SOURCES);

    rsigma()
        .args([
            "rule",
            "validate",
            "-p",
            pipeline.path().to_str().unwrap(),
            rules.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(REMOVAL_NEEDLE).not());
}

#[test]
fn error_points_at_migration_command() {
    let rules = rules_dir(SIMPLE_RULE);
    let pipeline = temp_file(".yml", PIPELINE_WITH_INLINE_SOURCES);

    rsigma()
        .args([
            "rule",
            "validate",
            "-p",
            pipeline.path().to_str().unwrap(),
            rules.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "migrate-sources -p <pipeline> -o sources.yml",
        ));
}
