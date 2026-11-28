use std::time::Duration;

use rstix::taxii::{RetryPolicy, TaxiiClient, TaxiiError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

use super::support::{taxii_json, wiremock_config};

#[tokio::test]
async fn retries_503_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(taxii_json(
            503,
            serde_json::json!({ "title": "unavailable" }),
        ))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(taxii_json(
            200,
            serde_json::json!({ "title": "Server", "api_roots": [] }),
        ))
        .mount(&server)
        .await;

    let client = TaxiiClient::new(wiremock_config(&server).retry_policy(RetryPolicy {
        max_attempts: 2,
        initial_delay: Duration::from_millis(10),
        ..RetryPolicy::default()
    }))
    .expect("client");
    client.discover().await.expect("discover after retry");
}

#[tokio::test]
async fn does_not_retry_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(taxii_json(
            404,
            serde_json::json!({ "title": "missing", "description": "gone" }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let client = TaxiiClient::new(wiremock_config(&server).retry_policy(RetryPolicy {
        max_attempts: 3,
        initial_delay: Duration::from_millis(10),
        ..RetryPolicy::default()
    }))
    .expect("client");
    let err = client.discover().await.expect_err("404");
    assert!(matches!(err, TaxiiError::NotFound { .. }));
}

async fn rate_limited_with(retry_after: &str) -> (MockServer, TaxiiError, Duration) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(
            taxii_json(429, serde_json::json!({ "title": "slow down" }))
                .insert_header("Retry-After", retry_after),
        )
        .mount(&server)
        .await;
    let client = TaxiiClient::new(wiremock_config(&server).retry_policy(RetryPolicy {
        max_attempts: 3,
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_secs(2),
        ..RetryPolicy::default()
    }))
    .expect("client");
    let started = std::time::Instant::now();
    let err = tokio::time::timeout(Duration::from_secs(10), client.discover())
        .await
        .expect("discover must not sleep for the server's Retry-After")
        .expect_err("rate limited");
    (server, err, started.elapsed())
}

#[tokio::test]
async fn retry_after_beyond_max_delay_fails_without_sleeping() {
    for value in [
        "999999999",
        "18446744073709551615",
        "99999999999999999999999",
        "Fri, 31 Dec 9999 23:59:59 GMT",
    ] {
        let (server, err, elapsed) = rate_limited_with(value).await;
        assert!(
            elapsed < Duration::from_secs(2),
            "{value}: took {elapsed:?}"
        );
        assert!(
            matches!(
                err,
                TaxiiError::RateLimited {
                    retry_after: Some(_),
                    ..
                }
            ),
            "{value}: {err}"
        );
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "{value}: no retry"
        );
    }
}

#[tokio::test]
async fn retry_after_within_max_delay_is_honored() {
    let (server, err, elapsed) = rate_limited_with("1").await;
    assert!(matches!(err, TaxiiError::RateLimited { .. }), "{err}");
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
    assert!(elapsed >= Duration::from_secs(3), "slept {elapsed:?}");
}

#[tokio::test]
async fn retry_after_in_the_past_retries_at_once() {
    let (server, _, elapsed) = rate_limited_with("Thu, 01 Jan 1970 00:00:00 GMT").await;
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
    assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
}
