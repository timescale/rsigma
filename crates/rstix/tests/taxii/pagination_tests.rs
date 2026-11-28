use futures::StreamExt;
use rstix::taxii::TaxiiFilter;
use wiremock::matchers::{method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::support::{
    TAXII_MEDIA_TYPE, api_root_url, minimal_indicator, taxii_json, wiremock_client_no_preflight,
};

const API_ROOT: &str = "/api1/";

#[tokio::test]
async fn cursor_pagination_returns_all_objects() {
    let server = MockServer::start().await;
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
                    "pattern": "[ipv4-addr:value = '192.0.2.1']",
                    "pattern_type": "stix",
                    "valid_from": "2016-01-01T00:00:00Z"
                }]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let mut stream = client.objects_stream(&api, "col1", TaxiiFilter::new().limit(1));
    let mut ids = Vec::new();
    while let Some(result) = stream.next().await {
        ids.push(result.unwrap().id().to_string());
    }
    assert_eq!(ids.len(), 2);
}

#[tokio::test]
async fn header_fallback_pagination_returns_all_objects() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param_is_missing("added_after"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(
                    serde_json::json!({
                        "more": true,
                        "objects": [minimal_indicator()]
                    })
                    .to_string(),
                    TAXII_MEDIA_TYPE,
                )
                .insert_header("x-taxii-date-added-last", "2016-04-06T20:03:48.000000Z"),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param("added_after", "2016-04-06T20:03:48.000000Z"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": false,
                "objects": [{
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--22222222-2222-2222-2222-222222222222",
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
    let mut stream = client.objects_stream(&api, "col1", TaxiiFilter::new());
    let count = stream.by_ref().count().await;
    assert_eq!(count, 2);
}

#[tokio::test]
async fn stops_when_more_true_but_follow_on_page_empty() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param_is_missing("added_after"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(
                    serde_json::json!({ "more": true, "objects": [minimal_indicator()] })
                        .to_string(),
                    TAXII_MEDIA_TYPE,
                )
                .insert_header("x-taxii-date-added-last", "2016-04-06T20:03:48.000000Z"),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param("added_after", "2016-04-06T20:03:48.000000Z"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({ "more": true, "objects": [] }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let mut stream = client.objects_stream(&api, "col1", TaxiiFilter::new());
    let count = stream.by_ref().count().await;
    assert_eq!(count, 1);
}

async fn repeating_server() -> MockServer {
    let server = MockServer::start().await;
    for (endpoint, key) in [
        ("collections/col1/objects/", "objects"),
        ("collections/col1/manifest/", "objects"),
        (
            "collections/col1/objects/indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f/",
            "objects",
        ),
        (
            "collections/col1/objects/indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f/versions/",
            "versions",
        ),
    ] {
        let item = if endpoint.ends_with("manifest/") {
            serde_json::json!({
                "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                "date_added": "2016-04-06T20:03:48.000000Z",
                "version": "2016-04-06T20:03:48.000Z",
                "media_type": "application/stix+json;version=2.1"
            })
        } else if key == "versions" {
            serde_json::json!("2016-04-06T20:03:48.000Z")
        } else {
            minimal_indicator()
        };
        Mock::given(method("GET"))
            .and(path(format!("{API_ROOT}{endpoint}")))
            .respond_with(taxii_json(
                200,
                serde_json::json!({ "more": true, "next": "same", key: [item] }),
            ))
            .mount(&server)
            .await;
    }
    server
}

async fn drain<T, S>(stream: S) -> Vec<Result<T, rstix::taxii::TaxiiError>>
where
    S: futures::Stream<Item = Result<T, rstix::taxii::TaxiiError>>,
{
    tokio::time::timeout(std::time::Duration::from_secs(10), stream.collect())
        .await
        .expect("a repeating cursor must end the stream")
}

#[tokio::test]
async fn streams_end_when_the_server_repeats_its_cursor() {
    use rstix::core::StixId;
    use rstix::taxii::{ObjectByIdFilter, TaxiiError, VersionsQueryFilter};

    let server = repeating_server().await;
    let api = api_root_url(&server);
    let client = wiremock_client_no_preflight(&server);
    let id = StixId::parse("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap();
    let repeated = |err: &TaxiiError| matches!(err, TaxiiError::RepeatedPaginationCursor);

    let objects = drain(client.objects_stream(&api, "col1", TaxiiFilter::new())).await;
    assert!(repeated(objects.last().unwrap().as_ref().unwrap_err()));
    let manifest = drain(client.manifest_stream(&api, "col1", TaxiiFilter::new())).await;
    assert!(repeated(manifest.last().unwrap().as_ref().unwrap_err()));
    let object =
        drain(client.object_stream(&api, "col1", id.clone(), ObjectByIdFilter::new())).await;
    assert!(repeated(object.last().unwrap().as_ref().unwrap_err()));
    let versions =
        drain(client.object_versions_stream(&api, "col1", id, VersionsQueryFilter::new())).await;
    assert!(repeated(versions.last().unwrap().as_ref().unwrap_err()));
}

#[tokio::test]
async fn stream_ends_when_416_recovery_repeats_the_filter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .respond_with(taxii_json(416, serde_json::json!({ "title": "expired" })))
        .mount(&server)
        .await;
    let client = wiremock_client_no_preflight(&server);
    let results =
        drain(client.objects_stream(api_root_url(&server), "col1", TaxiiFilter::new())).await;
    assert!(matches!(
        results.as_slice(),
        [Err(
            rstix::taxii::TaxiiError::RequestedRangeNotSatisfiable { .. }
        )]
    ));
}
