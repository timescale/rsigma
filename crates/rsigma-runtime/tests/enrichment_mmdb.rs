//! MMDB enricher integration tests (`mmdb-enrich` feature).
//!
//! These exercise the YAML loader, the enrichment pipeline, and the error
//! policies end to end. Record decoding and field projection are covered by
//! the unit and golden tests.

#![cfg(feature = "mmdb-enrich")]

mod common;

use std::time::Duration;

use rsigma_runtime::EnrichersConfigError;
use serde_json::json;

use common::{
    build_pipeline, city_yaml, correlation_result, detection_result, geo_enrichment, mmdb_fixture,
    mmdb_yaml, try_build_pipeline, unknown_default,
};

#[tokio::test(flavor = "multi_thread")]
async fn correlation_kind_reads_the_group_key() {
    let yaml = format!(
        r#"
enrichers:
  - id: geo
    kind: correlation
    type: mmdb
    inject_field: geo
    db_path: {}
    key: "${{correlation.group_key.SourceIp}}"
"#,
        mmdb_fixture("city-test.mmdb")
    );
    let pipeline = build_pipeline(&yaml);
    let mut results = vec![correlation_result("SourceIp", json!("192.0.2.10"))];
    pipeline.run(&mut results).await;
    assert_eq!(geo_enrichment(&results[0])["country"]["iso_code"], "US");
}

#[tokio::test(flavor = "multi_thread")]
async fn detection_kind_skips_correlation_results() {
    let pipeline = build_pipeline(&city_yaml(""));
    let mut results = vec![correlation_result("SourceIp", json!("192.0.2.10"))];
    pipeline.run(&mut results).await;
    assert!(results[0].header.enrichments.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn scope_filter_excludes_non_matching_results() {
    let yaml = city_yaml("    scope:\n      rules: [no-such-rule]\n");
    let pipeline = build_pipeline(&yaml);
    let mut results = vec![detection_result("SourceIp", json!("192.0.2.10"))];
    pipeline.run(&mut results).await;
    assert!(results[0].header.enrichments.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn on_error_null_injects_null_for_a_non_ip_key() {
    let yaml = format!(
        r#"
enrichers:
  - id: geo
    kind: detection
    type: mmdb
    inject_field: geo
    db_path: {}
    key: "${{detection.fields.Host}}"
    on_error: null
"#,
        mmdb_fixture("city-test.mmdb")
    );
    let pipeline = build_pipeline(&yaml);
    let mut results = vec![detection_result("Host", json!("web-01"))];
    pipeline.run(&mut results).await;
    assert_eq!(geo_enrichment(&results[0]), &serde_json::Value::Null);
}

#[tokio::test(flavor = "multi_thread")]
async fn on_error_drop_removes_the_result() {
    let yaml = format!(
        r#"
enrichers:
  - id: geo
    kind: detection
    type: mmdb
    inject_field: geo
    db_path: {}
    key: "${{detection.fields.SourceIp}}"
    on_error: drop
"#,
        mmdb_fixture("city-test.mmdb")
    );
    let pipeline = build_pipeline(&yaml);
    let mut results = vec![
        detection_result("SourceIp", json!("web-01")),
        detection_result("SourceIp", json!("192.0.2.10")),
    ];
    pipeline.run(&mut results).await;
    assert_eq!(results.len(), 1);
    assert_eq!(geo_enrichment(&results[0])["country"]["iso_code"], "US");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_entries_on_one_database_both_enrich_after_a_file_swap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("city.mmdb");
    std::fs::copy(mmdb_fixture("city-test.mmdb"), &path).unwrap();

    let yaml = format!(
        r#"
enrichers:
  - id: geo_one
    kind: detection
    type: mmdb
    inject_field: geo_one
    db_path: {}
    key: "${{detection.fields.SourceIp}}"
    fields:
      country: country.iso_code
  - id: geo_two
    kind: detection
    type: mmdb
    inject_field: geo_two
    db_path: {}
    key: "${{detection.fields.SourceIp}}"
    fields:
      country: country.iso_code
"#,
        path.display(),
        path.display()
    );
    let pipeline = build_pipeline(&yaml);

    std::fs::copy(mmdb_fixture("city-test-updated.mmdb"), &path).unwrap();

    let mut results = vec![detection_result("SourceIp", json!("192.0.2.10"))];
    pipeline.run(&mut results).await;

    let updated = async {
        for _ in 0..200 {
            let countries = |result: &rsigma_eval::EvaluationResult| {
                let enrichments = result.header.enrichments.as_ref()?;
                Some((
                    enrichments["geo_one"]["country"].as_str()?.to_string(),
                    enrichments["geo_two"]["country"].as_str()?.to_string(),
                ))
            };
            if countries(&results[0]) == Some(("CA".to_string(), "CA".to_string())) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            results = vec![detection_result("SourceIp", json!("192.0.2.10"))];
            pipeline.run(&mut results).await;
        }
        panic!("database was not reloaded within the timeout");
    };
    updated.await;

    assert_eq!(results.len(), 1);
    let enrichments = results[0].header.enrichments.as_ref().unwrap();
    assert_eq!(enrichments["geo_one"]["country"], "CA");
    assert_eq!(enrichments["geo_two"]["country"], "CA");
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_database_fails_the_build() {
    let yaml = mmdb_yaml(
        "/definitely/not/here.mmdb",
        "${detection.fields.SourceIp}",
        "",
    );
    let err = try_build_pipeline(&yaml).unwrap_err();
    assert!(
        matches!(
            err,
            EnrichersConfigError::Database {
                ref enricher_id,
                ..
            } if enricher_id == "geo"
        ),
        "got {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn default_is_injected_on_a_miss() {
    let yaml = city_yaml("    default:\n      country_code: unknown\n");
    let pipeline = build_pipeline(&yaml);
    let mut results = vec![detection_result("SourceIp", json!("203.0.113.5"))];
    pipeline.run(&mut results).await;
    assert_eq!(geo_enrichment(&results[0]), &unknown_default());
}
