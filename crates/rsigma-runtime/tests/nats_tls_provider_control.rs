//! The dynamic sources' control subject (`sources::refresh::nats_control_loop`)
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

use rsigma_runtime::NatsConnectConfig;
use rsigma_runtime::sources::refresh::nats_control_loop;

#[tokio::test]
async fn control_subject_on_a_tls_required_server_errors_without_panicking() {
    let url = common::nats_tls::tls_required_server().await;
    let (trigger_tx, _trigger_rx) = tokio::sync::mpsc::channel(1);
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        nats_control_loop(
            &NatsConnectConfig::new(url),
            "rsigma.control.resolve",
            trigger_tx,
        ),
    )
    .await
    .expect("the control loop did not return");
    assert!(result.is_err());
}
