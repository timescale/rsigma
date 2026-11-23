//! DNS enricher integration tests (`dns-enrich` feature).
//!
//! These exercise the YAML loader, the enrichment pipeline, caching, and the
//! error policies end to end against the in-process stub nameserver. Answer
//! formatting is covered by the unit and golden tests.

#![cfg(feature = "dns-enrich")]

mod common;

use hickory_resolver::proto::rr::RecordType;
use rsigma_runtime::EnrichersConfigError;
use serde_json::json;

use common::dns::StubDnsServer;
use common::{build_pipeline, correlation_result, detection_result, dns_yaml, try_build_pipeline};

#[tokio::test(flavor = "multi_thread")]
async fn correlation_kind_reads_the_group_key() {
    let stub = StubDnsServer::start().await;
    let yaml = format!(
        r#"
enrichers:
  - id: resolved
    kind: correlation
    type: dns
    inject_field: resolved
    record_type: A
    key: "${{correlation.group_key.Host}}"
    nameservers: ["{}"]
"#,
        stub.addr()
    );
    let pipeline = build_pipeline(&yaml);
    let mut results = vec![correlation_result("Host", json!("host.example.com"))];
    pipeline.run(&mut results).await;

    assert_eq!(
        results[0].header.enrichments.as_ref().unwrap()["resolved"],
        json!(["192.0.2.10", "192.0.2.11"])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn detection_key_reads_an_unmatched_field_from_the_event() {
    let stub = StubDnsServer::start().await;
    let yaml = dns_yaml(stub.addr(), "A", "${detection.fields.Host}", "");
    let pipeline = build_pipeline(&yaml);
    let mut result = detection_result("EventType", json!("dns_query"));
    result.as_detection_mut().unwrap().event = Some(json!({"Host": "host.example.com"}));
    let mut results = vec![result];
    pipeline.run(&mut results).await;

    assert_eq!(
        results[0].header.enrichments.as_ref().unwrap()["resolved"],
        json!(["192.0.2.10", "192.0.2.11"])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn scope_filter_excludes_non_matching_results() {
    let stub = StubDnsServer::start().await;
    let yaml = dns_yaml(
        stub.addr(),
        "A",
        "${detection.fields.Host}",
        "    scope:\n      rules: [no-such-rule]\n",
    );
    let pipeline = build_pipeline(&yaml);
    let mut results = vec![detection_result("Host", json!("host.example.com"))];
    pipeline.run(&mut results).await;

    assert!(results[0].header.enrichments.is_none());
    assert_eq!(stub.total_queries(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_results_with_the_same_key_share_one_query() {
    let stub = StubDnsServer::start().await;
    let yaml = format!(
        "max_concurrent_enrichments: 1\n{}",
        dns_yaml(stub.addr(), "A", "${detection.fields.Host}", "")
    );
    let pipeline = build_pipeline(&yaml);
    let mut results = vec![
        detection_result("Host", json!("host.example.com")),
        detection_result("Host", json!("host.example.com")),
    ];
    pipeline.run(&mut results).await;

    assert_eq!(stub.query_count("host.example.com.", RecordType::A), 1);
    for result in &results {
        assert_eq!(
            result.header.enrichments.as_ref().unwrap()["resolved"],
            json!(["192.0.2.10", "192.0.2.11"])
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn nxdomain_is_cached_for_the_next_result() {
    let stub = StubDnsServer::start().await;
    let yaml = format!(
        "max_concurrent_enrichments: 1\n{}",
        dns_yaml(
            stub.addr(),
            "A",
            "${detection.fields.Host}",
            "    default: []\n"
        )
    );
    let pipeline = build_pipeline(&yaml);
    let mut results = vec![
        detection_result("Host", json!("missing.example.com")),
        detection_result("Host", json!("missing.example.com")),
    ];
    pipeline.run(&mut results).await;

    assert_eq!(stub.query_count("missing.example.com.", RecordType::A), 1);
    for result in &results {
        assert_eq!(
            result.header.enrichments.as_ref().unwrap()["resolved"],
            json!([])
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_null_default_injects_null_on_nxdomain() {
    let stub = StubDnsServer::start().await;
    let yaml = dns_yaml(
        stub.addr(),
        "A",
        "${detection.fields.Host}",
        "    default: null\n    on_error: skip\n",
    );
    let pipeline = build_pipeline(&yaml);
    let mut results = vec![detection_result("Host", json!("missing.example.com"))];
    pipeline.run(&mut results).await;

    assert_eq!(
        results[0].header.enrichments.as_ref().unwrap()["resolved"],
        json!(null)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn on_error_null_injects_null_for_a_timeout() {
    let stub = StubDnsServer::start().await;
    let yaml = dns_yaml(
        stub.addr(),
        "A",
        "${detection.fields.Host}",
        "    timeout: 300ms\n    on_error: null\n",
    );
    let pipeline = build_pipeline(&yaml);
    let mut results = vec![detection_result("Host", json!("slow.example.com"))];
    pipeline.run(&mut results).await;

    assert_eq!(
        results[0].header.enrichments.as_ref().unwrap()["resolved"],
        json!(null)
    );
    assert_eq!(stub.query_count("slow.example.com.", RecordType::A), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn on_error_drop_removes_a_servfail_result() {
    let stub = StubDnsServer::start().await;
    let yaml = dns_yaml(
        stub.addr(),
        "A",
        "${detection.fields.Host}",
        "    on_error: drop\n",
    );
    let pipeline = build_pipeline(&yaml);
    let mut results = vec![
        detection_result("Host", json!("broken.example.com")),
        detection_result("Host", json!("host.example.com")),
    ];
    pipeline.run(&mut results).await;

    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].header.enrichments.as_ref().unwrap()["resolved"],
        json!(["192.0.2.10", "192.0.2.11"])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unsupported_record_type_fails_the_build() {
    let stub = StubDnsServer::start().await;
    let yaml = dns_yaml(stub.addr(), "AXFR", "${detection.fields.Host}", "");
    let err = try_build_pipeline(&yaml).unwrap_err();

    match err {
        EnrichersConfigError::Scope {
            enricher_id,
            message,
        } => {
            assert_eq!(enricher_id, "resolved");
            assert!(message.contains("unsupported record_type"), "got {message}");
            assert!(message.contains("supported: IP"), "got {message}");
        }
        other => panic!("expected a Scope error, got {other:?}"),
    }
}
