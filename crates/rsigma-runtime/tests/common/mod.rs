//! Shared helpers for the runtime integration tests.
//!
//! Integration test binaries include this module with `mod common;` and use
//! only the helpers they need, so unused items are expected in each binary.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use rsigma_eval::{
    CorrelationBody, DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader,
};
use rsigma_parser::{CorrelationType, Level};
use rsigma_runtime::{
    EnricherResources, EnrichersConfigError, EnrichersFile, EnrichmentPipeline, NoopMetrics,
    build_enrichers_full,
};
use serde_json::{Value, json};

/// Absolute path to a committed MMDB fixture.
pub fn mmdb_fixture(name: &str) -> String {
    format!("{}/tests/fixtures/mmdb/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn header(rule_id: &str) -> RuleHeader {
    RuleHeader {
        rule_title: "integration rule".into(),
        rule_id: Some(rule_id.into()),
        level: Some(Level::High),
        tags: vec![],
        custom_attributes: Arc::new(HashMap::new()),
        enrichments: None,
    }
}

/// A detection result with one matched field.
pub fn detection_result(field: &str, value: Value) -> EvaluationResult {
    EvaluationResult {
        header: header("rule-detection"),
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".into()],
            matched_fields: vec![FieldMatch::new(field, value)],
            event: None,
        }),
    }
}

/// A correlation result with one group-key pair.
pub fn correlation_result(field: &str, value: Value) -> EvaluationResult {
    let value = match value {
        Value::String(s) => s,
        other => other.to_string(),
    };
    EvaluationResult {
        header: header("rule-correlation"),
        body: ResultBody::Correlation(CorrelationBody {
            correlation_type: CorrelationType::EventCount,
            group_key: vec![(field.to_string(), value)],
            aggregated_value: 3.0,
            timespan_secs: 60,
            events: None,
            event_refs: None,
        }),
    }
}

/// Parse enrichers YAML and build the pipeline, failing the test on either
/// error.
pub fn build_pipeline(yaml: &str) -> EnrichmentPipeline {
    try_build_pipeline(yaml).expect("build enrichers pipeline")
}

/// Parse enrichers YAML and build the pipeline, returning the configuration
/// error instead of panicking.
pub fn try_build_pipeline(yaml: &str) -> Result<EnrichmentPipeline, EnrichersConfigError> {
    let file: EnrichersFile = yaml_serde::from_str(yaml).expect("parse enrichers yaml");
    build_enrichers_full(file, EnricherResources::default(), Arc::new(NoopMetrics))
}

/// The injected `geo` object from a result, panicking when it is absent.
pub fn geo_enrichment(result: &EvaluationResult) -> &Value {
    result
        .header
        .enrichments
        .as_ref()
        .and_then(|m| m.get("geo"))
        .expect("geo enrichment")
}

/// A YAML block for a single MMDB enricher on `db_path`.
pub fn mmdb_yaml(db_path: &str, key: &str, extra: &str) -> String {
    format!(
        r#"
enrichers:
  - id: geo
    kind: detection
    type: mmdb
    inject_field: geo
    db_path: {db_path}
    key: "{key}"
{extra}"#
    )
}

/// A YAML block for a single MMDB enricher on the City fixture, using the
/// detection namespace and the `SourceIp` field.
pub fn city_yaml(extra: &str) -> String {
    mmdb_yaml(
        &mmdb_fixture("city-test.mmdb"),
        "${detection.fields.SourceIp}",
        extra,
    )
}

/// A default object used by miss cases.
pub fn unknown_default() -> Value {
    json!({"country_code": "unknown"})
}

/// Rebuild every object with its keys in sorted order.
///
/// `serde_json`'s `preserve_order` feature switches maps from sorted to
/// insertion order, and feature unification turns it on for some workspace
/// builds and not others. Canonicalizing keeps one golden valid under both.
pub fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .map(|key| (key.clone(), canonical(&map[key])))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}
