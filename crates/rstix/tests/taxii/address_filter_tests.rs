//! Address-filter behavior against a local TAXII mock.

use std::net::IpAddr;
use std::sync::Arc;

use rstix::taxii::{RetryPolicy, TaxiiClient, TaxiiClientConfig, TaxiiError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::support::{taxii_json, wiremock_config};

fn no_retry(config: TaxiiClientConfig) -> TaxiiClientConfig {
    config.retry_policy(RetryPolicy {
        max_attempts: 0,
        ..RetryPolicy::default()
    })
}

fn reject_loopback() -> Arc<dyn Fn(IpAddr) -> bool + Send + Sync> {
    Arc::new(|ip: IpAddr| !ip.is_loopback())
}

fn discovery_ok() -> ResponseTemplate {
    taxii_json(200, serde_json::json!({ "title": "Server" }))
}

#[tokio::test]
async fn literal_loopback_is_rejected_before_the_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(discovery_ok())
        .mount(&server)
        .await;

    let client =
        TaxiiClient::new(no_retry(wiremock_config(&server)).address_filter(reject_loopback()))
            .unwrap();
    let err = client.discover().await.expect_err("loopback literal");
    assert!(matches!(err, TaxiiError::DestinationRejected { .. }));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn hostname_resolving_to_loopback_is_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(discovery_ok())
        .mount(&server)
        .await;
    let port = url::Url::parse(&server.uri()).unwrap().port().unwrap();
    let client = TaxiiClient::new(
        no_retry(TaxiiClientConfig::new(format!("http://localhost:{port}")))
            .allow_insecure_http(true)
            .address_filter(reject_loopback()),
    )
    .unwrap();
    assert!(client.discover().await.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn filter_refuses_redirects() {
    let server = MockServer::start().await;
    let landed = format!("{}/taxii2/landed/", server.uri().trim_end_matches('/'));
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", landed))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/taxii2/landed/"))
        .respond_with(discovery_ok())
        .mount(&server)
        .await;

    let filtered = TaxiiClient::new(
        no_retry(wiremock_config(&server)).address_filter(Arc::new(|_: IpAddr| true)),
    )
    .unwrap();
    assert!(filtered.discover().await.is_err());
    let followed = filtered_paths(&server).await;
    assert!(followed.iter().all(|item| item == "/taxii2/"));

    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "location",
            format!("{}/taxii2/landed/", server.uri().trim_end_matches('/')),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/taxii2/landed/"))
        .respond_with(discovery_ok())
        .mount(&server)
        .await;
    let open = TaxiiClient::new(no_retry(wiremock_config(&server))).unwrap();
    open.discover().await.expect("redirect followed");
    assert!(
        filtered_paths(&server)
            .await
            .iter()
            .any(|item| item == "/taxii2/landed/")
    );
}

async fn filtered_paths(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .map(|request| request.url.path().to_owned())
        .collect()
}
