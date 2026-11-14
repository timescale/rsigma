//! Golden tests for the DNS enricher (`dns-enrich` feature).
//!
//! Each case starts the in-process stub nameserver, loads an enrichers YAML
//! file pointing at it, runs the resulting pipeline over one result, and
//! compares the injected `enrichments` map to a committed golden in
//! `tests/golden/dns/`. To regenerate after an intentional change:
//!
//! ```sh
//! RSIGMA_UPDATE_GOLDEN=1 cargo test -p rsigma-runtime --features dns-enrich --test dns_golden
//! ```

#![cfg(feature = "dns-enrich")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use rsigma_runtime::EnrichmentPipeline;
use serde_json::{Value, json};

use common::dns::StubDnsServer;
use common::{build_pipeline, canonical, detection_result, dns_yaml};

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/dns")
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
        assert_eq!(actual, expected, "DNS golden mismatch for '{name}'");
    }
}

async fn run(name: &str, record_type: &str, key: &str, value: Value, extra: &str) {
    let stub = StubDnsServer::start().await;
    let yaml = dns_yaml(stub.addr(), record_type, key, extra);
    let pipeline: EnrichmentPipeline = build_pipeline(&yaml);
    let mut results = vec![detection_result("Host", value)];
    pipeline.run(&mut results).await;
    let enrichments = results[0]
        .header
        .enrichments
        .clone()
        .unwrap_or_else(|| panic!("case '{name}' injected no enrichments"));
    check(name, &enrichments);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_records() {
    run(
        "a",
        "A",
        "${detection.fields.Host}",
        json!("host.example.com"),
        "",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn aaaa_records() {
    run(
        "aaaa",
        "AAAA",
        "${detection.fields.Host}",
        json!("host.example.com"),
        "",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ip_records() {
    run(
        "ip",
        "IP",
        "${detection.fields.Host}",
        json!("host.example.com"),
        "",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cname_chained_a_records() {
    run(
        "cname-chain",
        "A",
        "${detection.fields.Host}",
        json!("alias.example.com"),
        "",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ptr_v4() {
    run(
        "ptr-v4",
        "PTR",
        "${detection.fields.Host}",
        json!("192.0.2.10"),
        "",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ptr_v6() {
    run(
        "ptr-v6",
        "PTR",
        "${detection.fields.Host}",
        json!("2001:db8::10"),
        "",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mx_records() {
    run(
        "mx",
        "MX",
        "${detection.fields.Host}",
        json!("example.com"),
        "",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn txt_records() {
    run(
        "txt",
        "TXT",
        "${detection.fields.Host}",
        json!("example.com"),
        "",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ns_records() {
    run(
        "ns",
        "NS",
        "${detection.fields.Host}",
        json!("example.com"),
        "",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn srv_records() {
    run(
        "srv",
        "SRV",
        "${detection.fields.Host}",
        json!("_sip._tcp.example.com"),
        "",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn caa_records() {
    run(
        "caa",
        "CAA",
        "${detection.fields.Host}",
        json!("example.com"),
        "",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn soa_records() {
    run(
        "soa",
        "SOA",
        "${detection.fields.Host}",
        json!("example.com"),
        "",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn nxdomain_with_default() {
    run(
        "nxdomain-default",
        "A",
        "${detection.fields.Host}",
        json!("missing.example.com"),
        "    default: []\n",
    )
    .await;
}
