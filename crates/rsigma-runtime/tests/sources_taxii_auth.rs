//! Bearer auth is read from the process environment.
//!
//! This binary is separate from `sources_taxii` so `set_var` does not run
//! while those tests read the environment.

#![cfg(feature = "stix-source")]

mod common;

use std::time::Duration;

use common::taxii::{self, Server};
use rsigma_eval::pipeline::sources::{
    DynamicSource, ErrorPolicy, RefreshPolicy, SourceType, StixOptions, TaxiiAuthConfig,
};
use rsigma_runtime::EgressPolicy;
use rsigma_runtime::sources::{DefaultSourceResolver, SourceResolver};
use rstix::core::StixTimestamp;

const COLLECTION: &str = "91a7b528-80eb-42ed-a74d-c6fbd5a26116";

fn clock() -> StixTimestamp {
    StixTimestamp::parse("2026-06-01T00:00:00.000Z").unwrap()
}

fn source(url: &str, auth: TaxiiAuthConfig) -> DynamicSource {
    DynamicSource {
        id: "ti".to_owned(),
        source_type: SourceType::Taxii {
            url: url.to_owned(),
            collection: COLLECTION.to_owned(),
            auth,
            page_size: 50,
            stix: StixOptions {
                min_confidence: None,
                observables: vec!["ipv4".to_owned()],
                max_indicators: 100_000,
            },
        },
        refresh: RefreshPolicy::Interval(Duration::from_secs(60)),
        timeout: Some(Duration::from_secs(5)),
        on_error: ErrorPolicy::Fail,
        required: true,
        default: None,
    }
}

#[tokio::test]
async fn bearer_token_is_sent_from_the_environment() {
    let var = "RSIGMA_TEST_TAXII_BEARER_TOKEN";
    unsafe { std::env::set_var(var, "s3cret-token") };
    let server = Server::start(COLLECTION).await;
    server.push(
        "2024-01-01T00:00:00.000001Z",
        taxii::indicator(
            1,
            "2024-01-01T00:00:00.000Z",
            "[ipv4-addr:value = '198.51.100.7']",
            "",
        ),
    );
    let declared = source(
        &server.url,
        TaxiiAuthConfig {
            bearer_token_env: Some(var.to_owned()),
            ..TaxiiAuthConfig::default()
        },
    );
    let mut resolver = DefaultSourceResolver::new().with_stix_clock(clock());
    resolver
        .prepare_taxii_with(
            std::slice::from_ref(&declared),
            EgressPolicy::permissive(),
            true,
        )
        .expect("prepare");
    unsafe { std::env::remove_var(var) };
    resolver.resolve(&declared).await.expect("poll");
    assert_eq!(server.authorizations(), ["Bearer s3cret-token"]);
}
