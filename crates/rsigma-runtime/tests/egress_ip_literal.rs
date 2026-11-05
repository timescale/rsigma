//! Egress policy enforcement for URLs the resolver never sees: IP-literal
//! hosts and redirect targets.
//!
//! Every test in this binary installs the same process-wide policy, the
//! `default` preset plus blocked RFC1918 private ranges, so loopback (where
//! `wiremock` listens) stays reachable while `10.255.255.1` is denied. A
//! denied request must fail with the policy's reason instead of attempting
//! the connection.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rsigma_eval::pipeline::sources::DataFormat;
use rsigma_eval::{DetectionBody, EvaluationResult, ResultBody, RuleHeader};
use rsigma_parser::Level;
use rsigma_runtime::sources::http::resolve_http;
use rsigma_runtime::{
    EgressPolicy, Enricher, EnricherKind, HttpEnricher, HttpResponseCache, OnError, Scope,
    build_default_http_client, set_default_egress_policy,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// An address the installed policy denies as private. It is unroutable, so a
/// request that wrongly reaches the connect stage would hang until timeout.
const DENIED_PRIVATE: &str = "http://10.255.255.1/latest";

/// Fail fast instead of waiting on the unroutable address.
const DEADLINE: Duration = Duration::from_secs(3);

fn install_policy() {
    let _ = set_default_egress_policy(EgressPolicy::default().with_block_private(true));
}

fn detection() -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "rule".to_string(),
            rule_id: Some("rule-id".to_string()),
            level: Some(Level::High),
            tags: vec![],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![],
            event: None,
        }),
    }
}

fn enricher(url: &str) -> HttpEnricher {
    HttpEnricher::new(
        "egress".to_string(),
        EnricherKind::Detection,
        "out".to_string(),
        "GET".to_string(),
        url.to_string(),
        Vec::new(),
        None,
        Duration::from_secs(10),
        OnError::Skip,
        Scope::default(),
        None,
        build_default_http_client().expect("build client"),
        HttpResponseCache::new(Duration::from_secs(0)),
    )
}

async fn enrich_err(url: &str) -> String {
    let started = Instant::now();
    let err = enricher(url)
        .enrich(&mut detection())
        .await
        .expect_err("request must be refused");
    assert!(
        started.elapsed() < DEADLINE,
        "denial must not wait on a connect"
    );
    err.to_string()
}

async fn redirect_server(location: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", location))
        .mount(&server)
        .await;
    server
}

#[tokio::test(flavor = "multi_thread")]
async fn enricher_refuses_link_local_ip_literal() {
    install_policy();
    let err = enrich_err("http://169.254.169.254/latest/meta-data/").await;
    assert!(
        err.contains("egress policy denied link-local address 169.254.169.254"),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn enricher_refuses_cloud_metadata_ipv6_literal() {
    install_policy();
    let err = enrich_err("http://[fd00:ec2::254]/latest/meta-data/").await;
    assert!(
        err.contains("egress policy denied cloud-metadata address fd00:ec2::254"),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn enricher_refuses_private_ip_literal_when_policy_blocks_private() {
    install_policy();
    let err = enrich_err(DENIED_PRIVATE).await;
    assert!(
        err.contains("egress policy denied private address 10.255.255.1"),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn enricher_does_not_follow_redirect_to_denied_ip_literal() {
    install_policy();
    let server = redirect_server(DENIED_PRIVATE).await;
    let err = enrich_err(&format!("{}/start", server.uri())).await;
    assert!(
        err.contains("egress policy denied private address 10.255.255.1"),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn enricher_follows_redirect_to_allowed_address() {
    install_policy();
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&target)
        .await;
    let server = redirect_server(&format!("{}/final", target.uri())).await;
    let mut result = detection();
    enricher(&format!("{}/start", server.uri()))
        .enrich(&mut result)
        .await
        .expect("redirect to loopback is allowed");
    assert_eq!(
        result.header.enrichments.as_ref().unwrap()["out"]["ok"],
        serde_json::json!(true)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn source_refuses_ip_literal() {
    install_policy();
    let started = Instant::now();
    let err = resolve_http(
        "http://169.254.169.254/latest/meta-data/",
        None,
        &HashMap::new(),
        None,
        DataFormat::Json,
        None,
        Some(Duration::from_secs(10)),
    )
    .await
    .expect_err("request must be refused");
    assert!(started.elapsed() < DEADLINE);
    assert!(
        err.to_string()
            .contains("egress policy denied link-local address 169.254.169.254"),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn source_does_not_follow_redirect_to_denied_ip_literal() {
    install_policy();
    let server = redirect_server(DENIED_PRIVATE).await;
    let started = Instant::now();
    let err = resolve_http(
        &format!("{}/feed", server.uri()),
        None,
        &HashMap::new(),
        None,
        DataFormat::Json,
        None,
        Some(Duration::from_secs(10)),
    )
    .await
    .expect_err("redirect must be refused");
    assert!(started.elapsed() < DEADLINE);
    assert!(
        err.to_string()
            .contains("egress policy denied private address 10.255.255.1"),
        "{err}"
    );
}

/// A server where `/hop/{i}` redirects to `/hop/{i + 1}` for `i < hops`, and
/// `/hop/{hops}` answers `200`.
async fn redirect_chain(hops: usize) -> MockServer {
    let server = MockServer::start().await;
    for i in 0..hops {
        Mock::given(method("GET"))
            .and(path(format!("/hop/{i}")))
            .respond_with(
                ResponseTemplate::new(302).insert_header("Location", format!("/hop/{}", i + 1)),
            )
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(format!("/hop/{hops}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&server)
        .await;
    server
}

#[tokio::test(flavor = "multi_thread")]
async fn enricher_follows_ten_redirects_and_refuses_the_eleventh() {
    install_policy();
    let ten = redirect_chain(10).await;
    enricher(&format!("{}/hop/0", ten.uri()))
        .enrich(&mut detection())
        .await
        .expect("ten redirects are followed");

    let eleven = redirect_chain(11).await;
    let err = enrich_err(&format!("{}/hop/0", eleven.uri())).await;
    assert!(err.contains("too many redirects"), "{err}");
}
