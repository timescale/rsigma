//! HTTP `Date` clock skew applied to `added_after`.

use rstix::core::TaxiiTimestamp;
use rstix::taxii::{PollBudget, PreflightPolicy, TaxiiClient, TaxiiFilter};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request};

use super::support::{api_root_url, minimal_indicator, taxii_json, wiremock_config};

fn envelope(objects: Vec<serde_json::Value>, more: bool) -> serde_json::Value {
    serde_json::json!({ "more": more, "objects": objects })
}

const COLLECTION: &str = "91a7b528-80eb-42ed-a74d-c6fbd5a26116";

fn http_date(offset_secs: i64) -> String {
    let at = time::OffsetDateTime::now_utc() + time::Duration::seconds(offset_secs);
    at.format(&time::format_description::well_known::Rfc2822)
        .expect("http date")
}

fn added_after(request: &Request) -> Option<String> {
    request
        .url
        .query_pairs()
        .find(|(k, _)| k == "added_after")
        .map(|(_, v)| v.into_owned())
}

async fn mount_discovery(server: &MockServer, date: &str) {
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(
            taxii_json(
                200,
                serde_json::json!({ "title": "Server", "api_roots": [] }),
            )
            .insert_header("Date", date),
        )
        .mount(server)
        .await;
}

fn objects_path() -> String {
    format!("/api1/collections/{COLLECTION}/objects/")
}

#[tokio::test]
async fn skew_shifts_only_the_callers_added_after() {
    let server = MockServer::start().await;
    mount_discovery(&server, &http_date(3600)).await;
    Mock::given(method("GET"))
        .and(path(objects_path()))
        .respond_with(move |request: &Request| {
            let page_two = added_after(request).as_deref() == Some("2030-01-01T00:00:00.000000Z");
            let (more, last) = if page_two {
                (false, "2030-01-02T00:00:00.000000Z")
            } else {
                (true, "2030-01-01T00:00:00.000000Z")
            };
            taxii_json(200, envelope(vec![minimal_indicator()], more))
                .insert_header("X-TAXII-Date-Added-Last", last)
                .insert_header("Date", http_date(3600))
        })
        .mount(&server)
        .await;

    let client = TaxiiClient::new(wiremock_config(&server).preflight(PreflightPolicy::Disabled))
        .expect("client");
    client.discover().await.expect("discover records skew");
    let since = TaxiiTimestamp::parse("2024-01-01T00:00:00Z").unwrap();
    client
        .poll_objects(
            &api_root_url(&server),
            COLLECTION,
            TaxiiFilter::new().added_after(since),
            PollBudget::new(10, 100),
        )
        .await
        .expect("poll");

    let sent: Vec<_> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == objects_path())
        .map(added_after)
        .collect();
    let first = sent[0].as_deref().expect("first added_after");
    let shifted = TaxiiTimestamp::parse(first).unwrap();
    let expected = TaxiiTimestamp::parse("2024-01-01T01:00:00Z").unwrap();
    assert!(
        shifted >= expected.adjust_seconds(-5) && shifted <= expected.adjust_seconds(5),
        "caller cursor is shifted by the server offset: {first}"
    );
    assert_eq!(
        sent[1].as_deref(),
        Some("2030-01-01T00:00:00.000000Z"),
        "server cursor is sent unchanged"
    );
}

#[tokio::test]
async fn skew_correction_can_be_turned_off() {
    let server = MockServer::start().await;
    mount_discovery(&server, &http_date(3600)).await;
    Mock::given(method("GET"))
        .and(path(objects_path()))
        .respond_with(taxii_json(200, envelope(vec![], false)))
        .mount(&server)
        .await;
    let client = TaxiiClient::new(
        wiremock_config(&server)
            .preflight(PreflightPolicy::Disabled)
            .clock_skew_correction(false),
    )
    .expect("client");
    client.discover().await.expect("discover");
    client
        .objects(
            &api_root_url(&server),
            COLLECTION,
            TaxiiFilter::new().added_after(TaxiiTimestamp::parse("2024-01-01T00:00:00Z").unwrap()),
        )
        .await
        .expect("objects");
    let request = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.url.path() == objects_path())
        .unwrap();
    assert_eq!(
        added_after(&request).as_deref(),
        Some("2024-01-01T00:00:00.000000Z")
    );
}

#[tokio::test]
async fn a_date_more_than_a_day_away_is_ignored() {
    for offset in [2 * 86_400, -2 * 86_400] {
        let server = MockServer::start().await;
        mount_discovery(&server, &http_date(offset)).await;
        Mock::given(method("GET"))
            .and(path(objects_path()))
            .respond_with(taxii_json(200, envelope(vec![], false)))
            .mount(&server)
            .await;
        let client =
            TaxiiClient::new(wiremock_config(&server).preflight(PreflightPolicy::Disabled))
                .expect("client");
        client.discover().await.expect("discover");
        client
            .objects(
                &api_root_url(&server),
                COLLECTION,
                TaxiiFilter::new()
                    .added_after(TaxiiTimestamp::parse("2024-01-01T00:00:00Z").unwrap()),
            )
            .await
            .expect("objects");
        let request = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.url.path() == objects_path())
            .unwrap();
        assert_eq!(
            added_after(&request).as_deref(),
            Some("2024-01-01T00:00:00.000000Z"),
            "offset {offset}"
        );
    }
}

#[tokio::test]
async fn extreme_cursor_with_skew_does_not_panic() {
    for (offset, cursor, expected) in [
        (
            3600,
            "9999-12-31T23:59:59.999999Z",
            "9999-12-31T23:59:59.999999Z",
        ),
        (-3600, "0000-01-01T00:00:00Z", "0000-01-01T00:00:00.000000Z"),
    ] {
        let server = MockServer::start().await;
        mount_discovery(&server, &http_date(offset)).await;
        Mock::given(method("GET"))
            .and(path(objects_path()))
            .respond_with(taxii_json(200, envelope(vec![], false)))
            .mount(&server)
            .await;
        let client =
            TaxiiClient::new(wiremock_config(&server).preflight(PreflightPolicy::Disabled))
                .expect("client");
        client.discover().await.expect("discover");
        client
            .objects(
                &api_root_url(&server),
                COLLECTION,
                TaxiiFilter::new().added_after(TaxiiTimestamp::parse(cursor).unwrap()),
            )
            .await
            .expect("objects");
        let request = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.url.path() == objects_path())
            .unwrap();
        assert_eq!(added_after(&request).as_deref(), Some(expected));
    }
}
