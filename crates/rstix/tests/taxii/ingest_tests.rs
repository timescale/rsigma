use rstix::core::StixId;
use rstix::store::{MemoryStore, StixStore};
use rstix::taxii::{TaxiiFilter, ingest_collection};
use wiremock::Mock;
use wiremock::matchers::{method, path, query_param, query_param_is_missing};

use super::ingest_support::{
    api_root_url, minimal_indicator, taxii_json, wiremock_client_no_preflight,
};

const API_ROOT: &str = "/api1/";

#[tokio::test]
async fn ingest_collection_imports_paginated_objects() {
    let server = wiremock::MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param("limit", "1"))
        .and(query_param_is_missing("next"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": true,
                "next": "cursor-2",
                "objects": [minimal_indicator()]
            }),
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param("next", "cursor-2"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": false,
                "objects": [{
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--11111111-1111-1111-1111-111111111111",
                    "created": "2016-04-06T20:03:48.000Z",
                    "modified": "2016-04-06T20:03:48.000Z",
                    "indicator_types": ["malicious-activity"],
                    "pattern": "[ipv4-addr:value = '192.0.2.2']",
                    "pattern_type": "stix",
                    "valid_from": "2016-01-01T00:00:00Z"
                }]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let store = MemoryStore::new();
    let report = ingest_collection(&client, &store, &api, "col1", TaxiiFilter::new().limit(1))
        .await
        .expect("ingest");

    assert_eq!(report.import.objects_added, 2);
    assert!(
        store
            .get(&StixId::parse("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap())
            .expect("get")
            .is_some()
    );
    assert!(
        store
            .get(&StixId::parse("indicator--11111111-1111-1111-1111-111111111111").unwrap())
            .expect("get")
            .is_some()
    );
}

#[tokio::test]
async fn ingest_collection_is_idempotent() {
    let server = wiremock::MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": false,
                "objects": [minimal_indicator()]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let store = MemoryStore::new();
    let filter = TaxiiFilter::new();

    let first = ingest_collection(&client, &store, &api, "col1", filter.clone())
        .await
        .expect("first ingest");
    assert_eq!(first.import.objects_added, 1);

    let second = ingest_collection(&client, &store, &api, "col1", filter)
        .await
        .expect("second ingest");
    assert_eq!(second.import.objects_deduplicated, 1);
}

#[tokio::test]
async fn ingest_collection_resolves_forward_refs_across_pages() {
    let server = wiremock::MockServer::start().await;
    let api = api_root_url(&server);
    let indicator_id = "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f";

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param("limit", "1"))
        .and(query_param_is_missing("next"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": true,
                "next": "cursor-2",
                "objects": [{
                    "type": "report",
                    "spec_version": "2.1",
                    "id": "report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
                    "created": "2015-12-21T19:59:11.000Z",
                    "modified": "2015-12-21T19:59:11.000Z",
                    "name": "Forward ref report",
                    "published": "2016-01-20T17:00:00.000Z",
                    "report_types": ["threat-report"],
                    "object_refs": [indicator_id]
                }]
            }),
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param("next", "cursor-2"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": false,
                "objects": [minimal_indicator()]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let store = MemoryStore::new();
    let report = ingest_collection(&client, &store, &api, "col1", TaxiiFilter::new().limit(1))
        .await
        .expect("ingest");

    assert!(
        report.import.unresolved_references.is_empty(),
        "forward ref to indicator on page 2 must resolve after full ingest: {:?}",
        report.import.unresolved_references
    );
}

#[tokio::test]
async fn ingest_collection_stops_on_a_repeated_cursor() {
    let server = wiremock::MockServer::start().await;
    let api = api_root_url(&server);
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({ "more": true, "next": "same", "objects": [minimal_indicator()] }),
        ))
        .mount(&server)
        .await;
    let client = wiremock_client_no_preflight(&server);
    let store = MemoryStore::new();
    let err = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        ingest_collection(&client, &store, &api, "col1", TaxiiFilter::new()),
    )
    .await
    .expect("a repeating cursor must end the ingest")
    .expect_err("repeated cursor");
    assert!(matches!(
        err,
        rstix::taxii::IngestError::Taxii(rstix::taxii::TaxiiError::RepeatedPaginationCursor)
    ));
}

#[tokio::test]
async fn ingest_collection_stops_when_416_recovery_repeats_the_filter() {
    let server = wiremock::MockServer::start().await;
    let api = api_root_url(&server);
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .respond_with(taxii_json(416, serde_json::json!({ "title": "expired" })))
        .mount(&server)
        .await;
    let client = wiremock_client_no_preflight(&server);
    let store = MemoryStore::new();
    let err = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        ingest_collection(&client, &store, &api, "col1", TaxiiFilter::new()),
    )
    .await
    .expect("416 recovery must end")
    .expect_err("416");
    assert!(matches!(
        err,
        rstix::taxii::IngestError::Taxii(
            rstix::taxii::TaxiiError::RequestedRangeNotSatisfiable { .. }
        )
    ));
}
