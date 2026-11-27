//! `NatsConnectConfig::connect` to a NATS server that requires TLS returns an
//! error instead of panicking (#772). With the `otlp` feature, aws-lc-rs and
//! ring are both compiled in, so async-nats finds no process-default rustls
//! provider unless one is pinned first.
//!
//! One test per file: the default provider is process-wide, so a test that
//! pins it would hide a regression from any other test in the same binary.

#![cfg(all(feature = "nats", feature = "otlp"))]

mod common;

use std::time::Duration;

use rsigma_runtime::NatsConnectConfig;

#[tokio::test]
async fn connect_to_a_tls_required_server_errors_without_panicking() {
    let url = common::nats_tls::tls_required_server().await;
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        NatsConnectConfig::new(url).connect(),
    )
    .await
    .expect("connect did not return");
    assert!(result.is_err());
}
