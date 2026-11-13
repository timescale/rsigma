//! Golden tests for the MMDB enricher (`mmdb-enrich` feature).
//!
//! Each case loads an enrichers YAML file, runs the resulting pipeline over one
//! result, and compares the injected `enrichments` map to a committed golden in
//! `tests/golden/mmdb/`. To regenerate after an intentional change:
//!
//! ```sh
//! RSIGMA_UPDATE_GOLDEN=1 cargo test -p rsigma-runtime --features mmdb-enrich --test mmdb_golden
//! ```

#![cfg(feature = "mmdb-enrich")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use rsigma_runtime::EnrichmentPipeline;
use serde_json::{Value, json};

use common::{
    build_pipeline, canonical, detection_result, geo_enrichment, mmdb_fixture, mmdb_yaml,
};

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/mmdb")
}

fn check(name: &str, enrichments: &serde_json::Map<String, Value>) {
    let path = golden_dir().join(format!("{name}.json"));
    let enrichments = Value::Object(enrichments.clone());
    let actual = format!(
        "{}\n",
        serde_json::to_string_pretty(&canonical(&enrichments)).unwrap()
    );

    if std::env::var_os("RSIGMA_UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(golden_dir()).unwrap();
        fs::write(&path, &actual)
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
    } else {
        let expected = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
            .replace("\r\n", "\n");
        assert_eq!(actual, expected, "MMDB golden mismatch for '{name}'");
    }
}

async fn run(name: &str, yaml: &str, field: &str, value: Value) {
    let pipeline: EnrichmentPipeline = build_pipeline(yaml);
    let mut results = vec![detection_result(field, value)];
    pipeline.run(&mut results).await;
    let enrichments = results[0]
        .header
        .enrichments
        .clone()
        .unwrap_or_else(|| panic!("case '{name}' injected no enrichments"));
    check(name, &enrichments);
}

#[tokio::test(flavor = "multi_thread")]
async fn full_city_record() {
    let yaml = mmdb_yaml(
        &mmdb_fixture("city-test.mmdb"),
        "${detection.fields.SourceIp}",
        "",
    );
    run("full-city", &yaml, "SourceIp", json!("192.0.2.10")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn city_projection() {
    let yaml = mmdb_yaml(
        &mmdb_fixture("city-test.mmdb"),
        "${detection.fields.SourceIp}",
        "    fields:\n      country: country.iso_code\n      subdivision: subdivisions.0.iso_code\n      latitude: location.latitude\n      city: city.names.en\n",
    );
    run("city-projection", &yaml, "SourceIp", json!("198.51.100.7")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ipv6_projection() {
    let yaml = mmdb_yaml(
        &mmdb_fixture("city-test.mmdb"),
        "${detection.fields.SourceIp}",
        "    fields:\n      country: country.iso_code\n      subdivision: subdivisions.0.iso_code\n      latitude: location.latitude\n",
    );
    run("ipv6-projection", &yaml, "SourceIp", json!("2001:db8::1")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn asn_projection() {
    let yaml = mmdb_yaml(
        &mmdb_fixture("asn-test.mmdb"),
        "${detection.fields.SourceIp}",
        "    fields:\n      asn: autonomous_system_number\n      organization: autonomous_system_organization\n",
    );
    run("asn-projection", &yaml, "SourceIp", json!("192.0.2.10")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn full_flat_record() {
    let yaml = mmdb_yaml(
        &mmdb_fixture("flat-test.mmdb"),
        "${detection.fields.SourceIp}",
        "",
    );
    run("flat-record", &yaml, "SourceIp", json!("192.0.2.10")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn miss_with_default() {
    let yaml = mmdb_yaml(
        &mmdb_fixture("city-test.mmdb"),
        "${detection.fields.SourceIp}",
        "    default:\n      country_code: unknown\n",
    );
    let pipeline = build_pipeline(&yaml);
    let mut results = vec![detection_result("SourceIp", json!("203.0.113.5"))];
    pipeline.run(&mut results).await;
    assert_eq!(
        geo_enrichment(&results[0]),
        &json!({"country_code": "unknown"})
    );
    check(
        "miss-default",
        results[0].header.enrichments.as_ref().unwrap(),
    );
}
