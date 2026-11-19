//! End-to-end wiremock coverage for conformance gaps (secondary audit list).

use std::time::Duration;

use base64::Engine;
use futures::StreamExt;
use rstix::core::StixId;
use std::sync::atomic::{AtomicUsize, Ordering};

use rstix::taxii::{
    ObjectByIdFilter, PollBudget, PollStop, PostSubmitPolicy, StatusState, TaxiiClient, TaxiiError,
    TaxiiFilter,
};
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use super::support::{
    api_root_url, minimal_indicator, readable_collection, taxii_json, wiremock_client,
    wiremock_client_no_preflight, wiremock_config,
};

const API_ROOT: &str = "/api1/";

#[tokio::test]
async fn read_not_permitted_blocks_objects() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "id": "col1",
                "title": "No read",
                "can_read": false,
                "can_write": true,
                "media_types": ["application/stix+json;version=2.1"]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let err = client
        .objects(&api, "col1", TaxiiFilter::new())
        .await
        .expect_err("read blocked");
    assert!(matches!(err, TaxiiError::ReadNotPermitted));
}

#[tokio::test]
async fn write_not_permitted_blocks_add_objects() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "id": "col1",
                "title": "Read-only",
                "can_read": true,
                "can_write": false,
                "media_types": ["application/stix+json;version=2.1"]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let err = client
        .add_objects(&api, "col1", &rstix::taxii::TaxiiEnvelope::new(vec![]))
        .await
        .expect_err("write blocked");
    assert!(matches!(err, TaxiiError::WriteNotPermitted));
}

#[tokio::test]
async fn rejects_invalid_content_type_on_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            serde_json::json!({ "title": "Server", "api_roots": [] }).to_string(),
            "text/plain",
        ))
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let err = client.discover().await.expect_err("wrong content-type");
    assert!(matches!(err, TaxiiError::InvalidContentType { .. }));
}

#[tokio::test]
async fn rejects_response_larger_than_max_bytes() {
    let server = MockServer::start().await;
    let huge = "x".repeat(4096);
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({ "title": huge, "api_roots": [] }),
        ))
        .mount(&server)
        .await;

    let client =
        TaxiiClient::new(wiremock_config(&server).max_response_bytes(512)).expect("client");
    let err = client.discover().await.expect_err("too large");
    assert!(matches!(err, TaxiiError::ResponseTooLarge { .. }));
}

#[tokio::test]
async fn poll_status_times_out() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}status/job-1/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "id": "job-1",
                "status": "pending",
                "total_count": 1,
                "success_count": 0,
                "failure_count": 0,
                "pending_count": 1
            }),
        ))
        .mount(&server)
        .await;

    let client = TaxiiClient::new(
        wiremock_config(&server)
            .status_poll_interval(Duration::from_millis(5))
            .status_max_polls(1),
    )
    .expect("client");
    let err = client
        .poll_status(&api, "job-1")
        .await
        .expect_err("timeout");
    assert!(matches!(err, TaxiiError::StatusPollTimeout { .. }));
}

#[tokio::test]
async fn object_stream_paginates_by_object_id() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);
    let object_id = StixId::parse("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap();

    Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/col1/objects/indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f/"
        )))
        .and(query_param_is_missing("next"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": true,
                "next": "p2",
                "objects": [minimal_indicator()]
            }),
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "{API_ROOT}collections/col1/objects/indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f/"
        )))
        .and(query_param("next", "p2"))
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
    let mut stream = client.object_stream(&api, "col1", object_id, ObjectByIdFilter::new());
    let count = stream.by_ref().count().await;
    assert_eq!(count, 2);
}

#[tokio::test]
async fn stream_errors_on_missing_pagination_headers() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": true,
                "objects": [minimal_indicator()]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client_no_preflight(&server);
    let mut stream = client.objects_stream(&api, "col1", TaxiiFilter::new());
    let err = stream.next().await.unwrap().expect_err("missing headers");
    assert!(matches!(err, TaxiiError::MissingPaginationHeaders));
}

#[tokio::test]
async fn stream_recovers_from_http_416() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param_is_missing("next"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": true,
                "next": "bad-cursor",
                "objects": [minimal_indicator()]
            }),
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param("next", "bad-cursor"))
        .respond_with(taxii_json(
            416,
            serde_json::json!({ "title": "range", "description": "bad cursor" }),
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .and(query_param_is_missing("next"))
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
    let mut ids = Vec::new();
    while let Some(result) = stream.next().await {
        ids.push(result.unwrap().id().to_string());
    }
    assert_eq!(ids.len(), 2);
}

#[tokio::test]
async fn add_objects_polls_until_complete_by_default() {
    let server = MockServer::start().await;
    let api = api_root_url(&server);

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/")))
        .respond_with(taxii_json(200, readable_collection()))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(API_ROOT))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "title": "Root",
                "versions": ["application/taxii+json;version=2.1"],
                "max_content_length": 1048576
            }),
        ))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .respond_with(taxii_json(
            202,
            serde_json::json!({
                "id": "status--1",
                "status": "pending",
                "total_count": 1,
                "success_count": 0,
                "failure_count": 0,
                "pending_count": 1
            }),
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}status/status--1/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "id": "status--1",
                "status": "complete",
                "total_count": 1,
                "success_count": 1,
                "failure_count": 0,
                "pending_count": 0
            }),
        ))
        .mount(&server)
        .await;

    let client = TaxiiClient::new(
        wiremock_config(&server)
            .post_submit(PostSubmitPolicy::PollUntilComplete)
            .capability(rstix::taxii::CapabilityPolicy::Enforce)
            .status_poll_interval(Duration::from_millis(5)),
    )
    .expect("client");
    let status = client
        .add_objects(&api, "col1", &rstix::taxii::TaxiiEnvelope::new(vec![]))
        .await
        .expect("polled to complete");
    assert_eq!(status.status, StatusState::Complete);
}

#[tokio::test]
async fn discovery_default_api_root_helper() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "title": "Server",
                "default": "https://taxii.example.com/api1/",
                "api_roots": ["https://taxii.example.com/api1/"]
            }),
        ))
        .mount(&server)
        .await;

    let client = wiremock_client(&server);
    let discovery = client.discover().await.expect("discovery");
    assert_eq!(
        discovery.default_api_root(),
        Some("https://taxii.example.com/api1/")
    );
}

#[tokio::test]
async fn basic_auth_injects_authorization_header() {
    let server = MockServer::start().await;
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("alice:hunter2")
    );
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .and(header("authorization", expected.as_str()))
        .respond_with(taxii_json(
            200,
            serde_json::json!({ "title": "Server", "api_roots": [] }),
        ))
        .mount(&server)
        .await;

    let client = TaxiiClient::new(
        wiremock_config(&server).auth(rstix::taxii::BasicAuth::new("alice", "hunter2")),
    )
    .expect("client");
    client.discover().await.expect("discover");
}

#[tokio::test]
async fn api_key_injects_custom_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .and(header("x-api-key", "secret-key"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({ "title": "Server", "api_roots": [] }),
        ))
        .mount(&server)
        .await;

    let client = TaxiiClient::new(
        wiremock_config(&server).auth(rstix::taxii::ApiKeyHeader::new("X-Api-Key", "secret-key")),
    )
    .expect("client");
    client.discover().await.expect("discover");
}

#[derive(Clone)]
struct Objects {
    mode: ObjectMode,
    hits: std::sync::Arc<AtomicUsize>,
}

#[derive(Clone, Copy)]
enum ObjectMode {
    /// `more: true` and a new `next` on every page.
    Endless,
    /// `more: true` and the same `next` on every page.
    SameCursor,
    /// HTTP 416 for every request.
    Range,
    /// Like `Endless`, but five objects per page whatever `limit` says.
    Wide,
}

impl Respond for Objects {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let hit = self.hits.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            ObjectMode::Endless => taxii_json(
                200,
                serde_json::json!({
                    "more": true,
                    "next": format!("page-{hit}"),
                    "objects": [minimal_indicator()]
                }),
            ),
            ObjectMode::SameCursor => taxii_json(
                200,
                serde_json::json!({
                    "more": true,
                    "next": "same",
                    "objects": [minimal_indicator()]
                }),
            ),
            ObjectMode::Wide => taxii_json(
                200,
                serde_json::json!({
                    "more": true,
                    "next": format!("page-{hit}"),
                    "objects": vec![minimal_indicator(); 5]
                }),
            ),
            ObjectMode::Range => taxii_json(
                416,
                serde_json::json!({ "title": "range", "description": "bad cursor" }),
            ),
        }
    }
}

async fn objects_server(mode: ObjectMode) -> (MockServer, Objects) {
    let server = MockServer::builder().start().await;
    let responder = Objects {
        mode,
        hits: std::sync::Arc::new(AtomicUsize::new(0)),
    };
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .respond_with(responder.clone())
        .mount(&server)
        .await;
    (server, responder)
}

fn small_budget() -> PollBudget {
    PollBudget::new(2, 8)
}

#[tokio::test]
async fn poll_object_pages_reports_budget_after_delivering_pages() {
    let (server, responder) = objects_server(ObjectMode::Endless).await;
    let client = wiremock_client_no_preflight(&server);
    let mut seen = 0usize;
    let stop = client
        .poll_object_pages(
            &api_root_url(&server),
            "col1",
            TaxiiFilter::new(),
            small_budget(),
            |page| seen += page.objects.len(),
        )
        .await
        .expect("poll");
    assert_eq!(stop, PollStop::Budget);
    assert_eq!(seen, 2);
    assert_eq!(responder.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn poll_object_pages_stops_at_the_object_budget_when_the_server_ignores_limit() {
    let (server, responder) = objects_server(ObjectMode::Wide).await;
    let client = wiremock_client_no_preflight(&server);
    let mut seen = 0usize;
    let stop = client
        .poll_object_pages(
            &api_root_url(&server),
            "col1",
            TaxiiFilter::new().limit(1),
            PollBudget::new(100, 8),
            |page| seen += page.objects.len(),
        )
        .await
        .expect("poll");
    assert_eq!(stop, PollStop::Budget);
    assert_eq!(seen, 10);
    assert_eq!(responder.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn poll_objects_stops_when_more_never_clears() {
    let (server, responder) = objects_server(ObjectMode::Endless).await;
    let client = wiremock_client_no_preflight(&server);
    let err = client
        .poll_objects(
            &api_root_url(&server),
            "col1",
            TaxiiFilter::new(),
            small_budget(),
        )
        .await
        .expect_err("budget");
    assert!(
        matches!(err, TaxiiError::PollBudgetExceeded { .. }),
        "{err}"
    );
    assert_eq!(responder.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn poll_objects_stops_when_the_cursor_repeats() {
    let (server, responder) = objects_server(ObjectMode::SameCursor).await;
    let client = wiremock_client_no_preflight(&server);
    let err = client
        .poll_objects(
            &api_root_url(&server),
            "col1",
            TaxiiFilter::new(),
            small_budget(),
        )
        .await
        .expect_err("cursor");
    assert!(matches!(err, TaxiiError::RepeatedPaginationCursor), "{err}");
    assert!(responder.hits.load(Ordering::SeqCst) <= 2);
}

#[tokio::test]
async fn poll_objects_stops_when_416_repeats_the_same_filter() {
    let (server, responder) = objects_server(ObjectMode::Range).await;
    let client = wiremock_client_no_preflight(&server);
    let err = client
        .poll_objects(
            &api_root_url(&server),
            "col1",
            TaxiiFilter::new(),
            small_budget(),
        )
        .await
        .expect_err("416");
    assert!(
        matches!(err, TaxiiError::RequestedRangeNotSatisfiable { .. }),
        "{err}"
    );
    assert_eq!(responder.hits.load(Ordering::SeqCst), 1);
}
