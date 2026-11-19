//! TAXII collection polling.

#![cfg(feature = "stix-source")]

mod common;

use std::time::Duration;

use common::taxii::{self, Server};
use rsigma_eval::pipeline::sources::{
    DynamicSource, ErrorPolicy, RefreshPolicy, SourceType, StixOptions, TaxiiAuthConfig,
};
use rsigma_runtime::EgressPolicy;
use rsigma_runtime::sources::{DefaultSourceResolver, SourceResolver};
use rstix::core::{StixTimestamp, TaxiiTimestamp};

const COLLECTION: &str = "91a7b528-80eb-42ed-a74d-c6fbd5a26116";

fn stamp(fraction: u32) -> String {
    TaxiiTimestamp::parse(&format!("2024-01-01T00:00:00.{fraction:06}Z"))
        .unwrap()
        .to_rfc3339()
}

fn options() -> StixOptions {
    StixOptions {
        min_confidence: None,
        observables: vec!["ipv4".to_owned()],
        max_indicators: 100_000,
    }
}

fn source(
    url: &str,
    on_error: ErrorPolicy,
    page_size: usize,
    auth: TaxiiAuthConfig,
) -> DynamicSource {
    DynamicSource {
        id: "ti".to_owned(),
        source_type: SourceType::Taxii {
            url: url.to_owned(),
            collection: COLLECTION.to_owned(),
            auth,
            page_size,
            stix: options(),
        },
        refresh: RefreshPolicy::Interval(Duration::from_secs(60)),
        timeout: Some(Duration::from_secs(5)),
        on_error,
        required: true,
        default: None,
    }
}

fn clock() -> StixTimestamp {
    StixTimestamp::parse("2026-06-01T00:00:00.000Z").unwrap()
}

async fn resolver(
    server: &Server,
    policy: EgressPolicy,
    on_error: ErrorPolicy,
    page_size: usize,
) -> DefaultSourceResolver {
    let declared = source(&server.url, on_error, page_size, TaxiiAuthConfig::default());
    let mut resolver = DefaultSourceResolver::new().with_stix_clock(clock());
    resolver
        .prepare_taxii_with(std::slice::from_ref(&declared), policy, true)
        .expect("prepare");
    resolver
}

fn ipv4(value: &serde_json::Value) -> Vec<String> {
    value["ipv4"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn full_poll_then_incremental_poll() {
    let server = Server::start(COLLECTION).await;
    server.push(
        &stamp(1),
        taxii::indicator(
            1,
            "2024-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.7']",
            "",
        ),
    );
    server.push(
        &stamp(2),
        taxii::indicator(
            2,
            "2024-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.8']",
            "",
        ),
    );
    let resolver = resolver(&server, EgressPolicy::permissive(), ErrorPolicy::Fail, 1).await;
    let declared = source(
        &server.url,
        ErrorPolicy::Fail,
        1,
        TaxiiAuthConfig::default(),
    );
    let first = resolver.resolve(&declared).await.expect("first poll");
    assert_eq!(ipv4(&first.data), ["198.51.100.7", "198.51.100.8"]);
    assert!(
        server
            .object_requests()
            .iter()
            .any(|url| url.contains("next=")),
        "first poll paginates: {:?}",
        server.object_requests()
    );

    server.push(
        &stamp(3),
        taxii::indicator(
            3,
            "2024-02-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.9']",
            "",
        ),
    );
    let second = resolver.resolve(&declared).await.expect("second poll");
    assert_eq!(
        ipv4(&second.data),
        ["198.51.100.7", "198.51.100.8", "198.51.100.9"]
    );
    let requests = server.object_requests();
    assert!(
        requests
            .last()
            .is_some_and(|url| url.contains("added_after=")),
        "incremental poll uses the cursor: {requests:?}"
    );
}

#[tokio::test]
async fn revocation_removes_the_indicator() {
    let server = Server::start(COLLECTION).await;
    server.push(
        &stamp(1),
        taxii::indicator(
            1,
            "2024-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.7']",
            "",
        ),
    );
    let resolver = resolver(&server, EgressPolicy::permissive(), ErrorPolicy::Fail, 50).await;
    let declared = source(
        &server.url,
        ErrorPolicy::Fail,
        50,
        TaxiiAuthConfig::default(),
    );
    let first = resolver.resolve(&declared).await.expect("first");
    assert_eq!(ipv4(&first.data), ["198.51.100.7"]);

    server.push(
        &stamp(2),
        taxii::indicator(
            1,
            "2025-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.7']",
            r#","revoked":true"#,
        ),
    );
    let second = resolver.resolve(&declared).await.expect("revocation");
    assert_eq!(ipv4(&second.data), Vec::<String>::new());
}

#[tokio::test]
async fn valid_until_expires_at_the_injected_clock() {
    let server = Server::start(COLLECTION).await;
    server.push(
        &stamp(1),
        taxii::indicator(
            1,
            "2024-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.7']",
            r#","valid_until":"2026-01-01T00:00:00.000Z""#,
        ),
    );
    let resolver = resolver(&server, EgressPolicy::permissive(), ErrorPolicy::Fail, 50).await;
    let declared = source(
        &server.url,
        ErrorPolicy::Fail,
        50,
        TaxiiAuthConfig::default(),
    );
    let value = resolver.resolve(&declared).await.expect("expired");
    assert_eq!(ipv4(&value.data), Vec::<String>::new());
    assert!(value.data.get("ipv4").is_some());
}

#[tokio::test]
async fn unauthorized_poll_keeps_the_cached_value() {
    let server = Server::start(COLLECTION).await;
    server.push(
        &stamp(1),
        taxii::indicator(
            1,
            "2024-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.7']",
            "",
        ),
    );
    server.unauthorized_after(1);
    let resolver = resolver(
        &server,
        EgressPolicy::permissive(),
        ErrorPolicy::UseCached,
        50,
    )
    .await;
    let declared = source(
        &server.url,
        ErrorPolicy::UseCached,
        50,
        TaxiiAuthConfig::default(),
    );
    let first = resolver.resolve(&declared).await.expect("first");
    assert_eq!(ipv4(&first.data), ["198.51.100.7"]);
    let second = resolver.resolve(&declared).await.expect("cached");
    assert!(second.from_cache);
    assert_eq!(ipv4(&second.data), ["198.51.100.7"]);

    server.unauthorized_after(usize::MAX);
    let third = resolver.resolve(&declared).await.expect("cursor kept");
    assert!(!third.from_cache);
    assert_eq!(ipv4(&third.data), ["198.51.100.7"]);
    assert!(
        server
            .object_requests()
            .last()
            .is_some_and(|url| url.contains("added_after=")),
        "failed poll keeps the cursor: {:?}",
        server.object_requests()
    );
}

#[tokio::test]
async fn over_count_page_is_rejected_and_keeps_the_previous_value() {
    let server = Server::start(COLLECTION).await;
    server.push(
        &stamp(1),
        taxii::indicator(
            1,
            "2024-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.7']",
            "",
        ),
    );
    let resolver = resolver(
        &server,
        EgressPolicy::permissive(),
        ErrorPolicy::UseCached,
        1,
    )
    .await;
    let declared = source(
        &server.url,
        ErrorPolicy::UseCached,
        1,
        TaxiiAuthConfig::default(),
    );
    let first = resolver.resolve(&declared).await.expect("first");
    assert_eq!(ipv4(&first.data), ["198.51.100.7"]);
    server.over_count(true);
    let second = resolver
        .resolve(&declared)
        .await
        .expect("cached after reject");
    assert!(second.from_cache);
    assert_eq!(ipv4(&second.data), ["198.51.100.7"]);

    server.over_count(false);
    let third = resolver.resolve(&declared).await.expect("state kept");
    assert_eq!(ipv4(&third.data), ["198.51.100.7"]);
    assert!(
        server
            .object_requests()
            .last()
            .is_some_and(|url| url.contains("added_after=")),
        "rejected page keeps the cursor: {:?}",
        server.object_requests()
    );
}

#[tokio::test]
async fn egress_policy_filters_the_collection_address() {
    let server = Server::start(COLLECTION).await;
    server.push(
        &stamp(1),
        taxii::indicator(
            1,
            "2024-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.7']",
            "",
        ),
    );
    let declared = source(
        &server.url,
        ErrorPolicy::Fail,
        50,
        TaxiiAuthConfig::default(),
    );

    let mut blocked = DefaultSourceResolver::new();
    let err = blocked
        .prepare_taxii_with(
            std::slice::from_ref(&declared),
            EgressPolicy::default().with_block_loopback(true),
            true,
        )
        .expect_err("loopback blocked");
    assert!(err.to_string().contains("loopback"), "{err}");
    assert_eq!(server.hits(), 0);

    let mut link_local = DefaultSourceResolver::new();
    let link = source(
        "http://169.254.169.254/api1/",
        ErrorPolicy::Fail,
        50,
        TaxiiAuthConfig::default(),
    );
    let err = link_local
        .prepare_taxii_with(std::slice::from_ref(&link), EgressPolicy::default(), true)
        .expect_err("link-local blocked");
    assert!(err.to_string().contains("169.254.169.254"), "{err}");

    let resolver = resolver(&server, EgressPolicy::permissive(), ErrorPolicy::Fail, 50).await;
    let value = resolver.resolve(&declared).await.expect("permissive");
    assert_eq!(ipv4(&value.data), ["198.51.100.7"]);
    assert!(server.hits() > 0);
}

#[tokio::test]
async fn missing_auth_env_names_the_variable() {
    let source = source(
        "https://taxii.example/api1/",
        ErrorPolicy::Fail,
        50,
        TaxiiAuthConfig {
            bearer_token_env: Some("RSIGMA_TEST_TAXII_TOKEN_MISSING".to_owned()),
            ..TaxiiAuthConfig::default()
        },
    );
    let mut resolver = DefaultSourceResolver::new();
    let err = resolver
        .prepare_taxii_with(
            std::slice::from_ref(&source),
            EgressPolicy::permissive(),
            false,
        )
        .expect_err("missing env");
    assert!(
        err.to_string().contains("RSIGMA_TEST_TAXII_TOKEN_MISSING"),
        "{err}"
    );
}
