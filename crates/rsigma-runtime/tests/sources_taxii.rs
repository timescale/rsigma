//! TAXII collection polling.

#![cfg(feature = "stix-source")]

mod common;

use std::time::Duration;

use common::taxii::{self, DateHeader, Server};
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

#[tokio::test]
async fn collection_larger_than_the_budget_loads_across_polls() {
    let server = Server::start(COLLECTION).await;
    for n in 1..=20u8 {
        server.push(
            &stamp(u32::from(n)),
            taxii::indicator(
                n,
                "2024-01-01T00:00:00.000Z",
                "[ipv4-addr:value = '198.51.100.99']",
                r#","valid_until":"2021-01-01T00:00:00.000Z""#,
            ),
        );
    }
    for n in 21..=30u8 {
        let octet = n - 20;
        server.push(
            &stamp(u32::from(n)),
            taxii::indicator(
                n,
                "2024-01-01T00:00:00.000Z",
                &format!("[ipv4-addr:value = '198.51.100.{octet}']"),
                "",
            ),
        );
    }
    let (declared, resolver) = capped(&server, 10, 5);
    let first = resolver.resolve(&declared).await.expect("first window");
    assert_eq!(ipv4(&first.data), Vec::<String>::new());
    let second = resolver.resolve(&declared).await.expect("second window");
    assert_eq!(ipv4(&second.data), sorted_ipv4(1..=9));
    let third = resolver.resolve(&declared).await.expect("third window");
    assert_eq!(ipv4(&third.data), sorted_ipv4(1..=10));
    assert!(
        server
            .object_requests()
            .iter()
            .any(|url| url.contains("added_after=")),
        "later poll continues: {:?}",
        server.object_requests()
    );
}

/// A source capped at `max_indicators`, whose poll budget is that plus one page.
fn capped(
    server: &Server,
    max_indicators: usize,
    page_size: usize,
) -> (DynamicSource, DefaultSourceResolver) {
    let mut stix = options();
    stix.max_indicators = max_indicators;
    let declared = DynamicSource {
        id: "ti".to_owned(),
        source_type: SourceType::Taxii {
            url: server.url.clone(),
            collection: COLLECTION.to_owned(),
            auth: TaxiiAuthConfig::default(),
            page_size,
            stix,
        },
        refresh: RefreshPolicy::Interval(Duration::from_secs(60)),
        timeout: Some(Duration::from_secs(5)),
        on_error: ErrorPolicy::Fail,
        required: true,
        default: None,
    };
    let mut resolver = DefaultSourceResolver::new().with_stix_clock(clock());
    resolver
        .prepare_taxii_with(
            std::slice::from_ref(&declared),
            EgressPolicy::permissive(),
            true,
        )
        .expect("prepare");
    (declared, resolver)
}

fn push_ipv4(server: &Server, n: u8, added: u32, confidence: u8) {
    server.push(
        &stamp(added),
        taxii::indicator(
            n,
            "2024-01-01T00:00:00.000Z",
            &format!("[ipv4-addr:value = '198.51.100.{n}']"),
            &format!(r#","confidence":{confidence}"#),
        ),
    );
}

fn sorted_ipv4(octets: impl IntoIterator<Item = u8>) -> Vec<String> {
    let mut values: Vec<String> = octets
        .into_iter()
        .map(|n| format!("198.51.100.{n}"))
        .collect();
    values.sort();
    values
}

#[tokio::test]
async fn budget_stop_inside_a_shared_added_date_reads_the_rest_next_poll() {
    let server = Server::start(COLLECTION).await;
    for n in 1..=12u8 {
        push_ipv4(&server, n, u32::from(n), 10);
    }
    for n in 13..=20u8 {
        push_ipv4(&server, n, 13, 90);
    }
    let (declared, resolver) = capped(&server, 10, 5);
    let first = resolver.resolve(&declared).await.expect("first window");
    assert_eq!(
        ipv4(&first.data),
        sorted_ipv4([1, 2, 3, 4, 5, 6, 7, 13, 14, 15])
    );
    let second = resolver.resolve(&declared).await.expect("second window");
    assert_eq!(
        ipv4(&second.data),
        sorted_ipv4([1, 2, 13, 14, 15, 16, 17, 18, 19, 20])
    );
}

#[tokio::test]
async fn added_date_run_longer_than_the_budget_fails() {
    let server = Server::start(COLLECTION).await;
    for n in 1..=20u8 {
        push_ipv4(&server, n, 1, 10);
    }
    let (declared, resolver) = capped(&server, 10, 5);
    resolver.resolve(&declared).await.expect("first window");
    let err = resolver
        .resolve(&declared)
        .await
        .expect_err("the cursor cannot move");
    assert!(
        err.to_string()
            .contains("did not advance X-TAXII-Date-Added-Last"),
        "{err}"
    );
}

#[tokio::test]
async fn budget_stop_without_an_added_date_fails() {
    let server = Server::start(COLLECTION).await;
    server.date_header(DateHeader::Never);
    for n in 1..=20u8 {
        push_ipv4(&server, n, u32::from(n), 10);
    }
    let (declared, resolver) = capped(&server, 10, 5);
    let err = resolver
        .resolve(&declared)
        .await
        .expect_err("no cursor to continue from");
    assert!(
        err.to_string()
            .contains("did not advance X-TAXII-Date-Added-Last"),
        "{err}"
    );
}

#[tokio::test]
async fn finished_poll_keeps_the_latest_added_date_when_the_last_page_has_none() {
    let server = Server::start(COLLECTION).await;
    server.date_header(DateHeader::NotOnLastPage);
    for n in 1..=3u8 {
        push_ipv4(&server, n, u32::from(n), 10);
    }
    let (declared, resolver) = capped(&server, 100, 2);
    resolver.resolve(&declared).await.expect("first poll");
    resolver.resolve(&declared).await.expect("second poll");
    let requests = server.object_requests();
    assert!(
        requests
            .last()
            .is_some_and(|url| url.contains("added_after=2024-01-01T00%3A00%3A00.000002Z")),
        "cursor from the last page that had a date: {requests:?}"
    );
}

#[tokio::test]
async fn failed_poll_keeps_the_cursor_after_applying_a_page() {
    let server = Server::start(COLLECTION).await;
    for n in 1..=2u8 {
        push_ipv4(&server, n, u32::from(n), 10);
    }
    server.unauthorized_after(1);
    let (declared, resolver) = capped(&server, 100, 1);
    resolver
        .resolve(&declared)
        .await
        .expect_err("second page is unauthorized");
    server.unauthorized_after(usize::MAX);
    let value = resolver.resolve(&declared).await.expect("retry");
    assert_eq!(ipv4(&value.data), sorted_ipv4([1, 2]));
    let requests = server.object_requests();
    assert_eq!(requests.len(), 4, "{requests:?}");
    assert!(
        !requests[2].contains("added_after="),
        "the retry starts from the old cursor: {requests:?}"
    );
}
