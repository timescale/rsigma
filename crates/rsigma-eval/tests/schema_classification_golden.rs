//! Golden fixture test for all schema-classification directories under
//! `tests/fixtures/schema-classification/<source>/`. Each directory must
//! contain exactly `test_event.json` and `expected_classification.yaml`.
//!
//! The walk test parses the JSON, classifies with the built-in classifier,
//! and asserts that the schema name, specificity, and derived logsource
//! match the expected YAML.
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use rsigma_eval::event::JsonEvent;
use rsigma_eval::schema::{SchemaClassifier, builtin_schema_logsource};
use serde::Deserialize;
use serde_json::Value;

/// The `logsource:` block of an expected classification.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedLogsource {
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    custom: HashMap<String, String>,
}

/// A parsed `expected_classification.yaml` fixture.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedClassification {
    schema: String,
    specificity: u32,
    #[serde(default)]
    logsource: ExpectedLogsource,
}

/// Discover all fixture directories, sorted for deterministic output.
fn fixture_dirs() -> Vec<PathBuf> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/schema-classification");
    let mut dirs: Vec<_> = fs::read_dir(&base)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", base.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

/// Classify one fixture directory and assert against its expectation.
fn run_fixture(dir: &Path) -> Result<(), String> {
    let event_path = dir.join("test_event.json");
    let expected_path = dir.join("expected_classification.yaml");

    let event_content = fs::read_to_string(&event_path)
        .map_err(|e| format!("cannot read {}: {e}", event_path.display()))?;
    let expected_content = fs::read_to_string(&expected_path)
        .map_err(|e| format!("cannot read {}: {e}", expected_path.display()))?;

    let expected: ExpectedClassification = yaml_serde::from_str(&expected_content)
        .map_err(|e| format!("in {}: bad expectation YAML: {e}", dir.display()))?;
    let event: Value = serde_json::from_str(&event_content)
        .map_err(|e| format!("in {}: invalid JSON: {e}", dir.display()))?;

    let classifier = SchemaClassifier::builtin();
    let result = classifier
        .classify(&JsonEvent::borrow(&event))
        .ok_or_else(|| format!("in {}: event matched no schema", dir.display()))?;

    if result.name != expected.schema {
        return Err(format!(
            "in {}: expected schema '{}' but got '{}'",
            dir.display(),
            expected.schema,
            result.name
        ));
    }
    if result.specificity != expected.specificity {
        return Err(format!(
            "in {}: expected specificity {} but got {}",
            dir.display(),
            expected.specificity,
            result.specificity
        ));
    }

    let logsource_map = builtin_schema_logsource();
    let derived = logsource_map.get(&result.name).ok_or_else(|| {
        format!(
            "in {}: no logsource mapping for schema '{}'",
            dir.display(),
            result.name
        )
    })?;

    if derived.product.as_deref() != expected.logsource.product.as_deref() {
        return Err(format!(
            "in {}: expected logsource product {:?} but got {:?}",
            dir.display(),
            expected.logsource.product.as_deref(),
            derived.product.as_deref()
        ));
    }
    if derived.service.as_deref() != expected.logsource.service.as_deref() {
        return Err(format!(
            "in {}: expected logsource service {:?} but got {:?}",
            dir.display(),
            expected.logsource.service.as_deref(),
            derived.service.as_deref()
        ));
    }
    for (key, val) in &expected.logsource.custom {
        if derived.custom.get(key).map(String::as_str) != Some(val.as_str()) {
            return Err(format!(
                "in {}: expected custom[{key:?}] = {val:?} but got {:?}",
                dir.display(),
                derived.custom.get(key).map(String::as_str)
            ));
        }
    }

    Ok(())
}

#[test]
fn schema_classification_walk_fixtures() {
    let dirs = fixture_dirs();
    assert!(
        !dirs.is_empty(),
        "no fixture directories under tests/fixtures/schema-classification/"
    );

    let errors: Vec<String> = dirs.iter().filter_map(|d| run_fixture(d).err()).collect();
    assert!(
        errors.is_empty(),
        "fixture failures:\n{}",
        errors.join("\n")
    );
}

#[test]
fn every_fixture_maps_to_a_known_schema() {
    // Each fixture's expected schema must be one the built-in classifier can
    // produce, so a fixture cannot reference a schema that no longer exists.
    let classifier = SchemaClassifier::builtin();
    let known: std::collections::HashSet<&str> = classifier.schema_names().into_iter().collect();
    for dir in fixture_dirs() {
        let expected_path = dir.join("expected_classification.yaml");
        let content = fs::read_to_string(&expected_path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", expected_path.display()));
        let expected: ExpectedClassification = yaml_serde::from_str(&content)
            .unwrap_or_else(|e| panic!("in {}: bad YAML: {e}", dir.display()));
        assert!(
            known.contains(expected.schema.as_str()),
            "fixture {} references unknown schema '{}'",
            dir.display(),
            expected.schema
        );
    }
}
