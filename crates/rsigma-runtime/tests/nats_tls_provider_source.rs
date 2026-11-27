//! A dynamic NATS source's resolution (`sources::nats::resolve_nats_initial`)
//! on a NATS server that requires TLS returns an error instead of panicking
//! (#772). With the `otlp` feature, aws-lc-rs and ring are both compiled in, so
//! async-nats finds no process-default rustls provider unless one is pinned
//! first.
//!
//! One test per file: the default provider is process-wide, so a test that
//! pins it would hide a regression from any other test in the same binary.

#![cfg(all(feature = "nats", feature = "otlp"))]

mod common;

use std::time::Duration;

use rsigma_eval::pipeline::sources::DataFormat;
use rsigma_runtime::sources::nats::resolve_nats_initial;

#[tokio::test]
async fn nats_source_on_a_tls_required_server_errors_without_panicking() {
    let url = common::nats_tls::tls_required_server().await;
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        resolve_nats_initial(&url, "rsigma.iocs", DataFormat::Json, None),
    )
    .await
    .expect("resolve did not return");
    assert!(result.is_err());
}
