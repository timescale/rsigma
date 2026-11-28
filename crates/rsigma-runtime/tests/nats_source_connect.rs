//! Dynamic NATS sources (the initial resolve, push subscriptions, and the
//! control subject) connect with the operator's NATS authentication and TLS
//! settings: a required TLS connection never falls back to cleartext, and
//! configured credentials reach the server.

#![cfg(feature = "nats")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::nats_tls::{RecordingServer, plain_recording_server};
use rsigma_eval::pipeline::sources::{
    DataFormat, DynamicSource, ErrorPolicy, RefreshPolicy, SourceType,
};
use rsigma_runtime::sources::SourceResolver;
use rsigma_runtime::sources::refresh::nats_control_loop;
use rsigma_runtime::{DefaultSourceResolver, NatsConnectConfig, RefreshScheduler};

fn nats_source(id: &str, url: &str, subject: &str, refresh: RefreshPolicy) -> DynamicSource {
    DynamicSource {
        id: id.to_string(),
        source_type: SourceType::Nats {
            url: url.to_string(),
            subject: subject.to_string(),
            format: DataFormat::Json,
            extract: None,
        },
        refresh,
        timeout: None,
        on_error: ErrorPolicy::Fail,
        required: true,
        default: None,
    }
}

fn require_tls() -> NatsConnectConfig {
    NatsConnectConfig {
        token: Some("s3cr3t-token".into()),
        require_tls: true,
        ..Default::default()
    }
}

fn user_password() -> NatsConnectConfig {
    NatsConnectConfig {
        username: Some("rsigma".into()),
        password: Some("hunter2".into()),
        ..Default::default()
    }
}

/// Nothing but the server's greeting was answered: no credentials, no
/// subscription, no cleartext protocol at all.
fn assert_nothing_sent(server: &RecordingServer) {
    let received = server.received();
    for needle in ["CONNECT", "SUB ", "s3cr3t-token"] {
        assert!(
            !received.contains(needle),
            "the client sent {needle:?} to a server without TLS: {received:?}"
        );
    }
}

#[tokio::test]
async fn required_tls_fails_the_initial_resolve_without_a_subscription() {
    let server = plain_recording_server().await;
    let resolver = DefaultSourceResolver::new().with_nats_config(require_tls());
    let source = nats_source("iocs", &server.url, "iocs", RefreshPolicy::OnDemand);

    let error = tokio::time::timeout(Duration::from_secs(10), resolver.resolve(&source))
        .await
        .expect("resolve did not return")
        .expect_err("a server without TLS must fail the resolve");
    assert!(error.to_string().contains("does not offer"), "{error}");
    assert_eq!(server.connections(), 1);
    assert_nothing_sent(&server);
}

#[tokio::test]
async fn required_tls_fails_the_push_subscription() {
    let server = plain_recording_server().await;
    let resolver = Arc::new(DefaultSourceResolver::new().with_nats_config(require_tls()));
    let source = nats_source("feed", &server.url, "feed", RefreshPolicy::Push);

    let handle = RefreshScheduler::new().run(vec![source], resolver);
    server.wait_for_connection().await;
    assert_nothing_sent(&server);
    handle.abort();
}

#[tokio::test]
async fn required_tls_fails_the_control_subscription() {
    let server = plain_recording_server().await;
    let config = NatsConnectConfig {
        url: server.url.clone(),
        ..require_tls()
    };
    let (trigger_tx, _trigger_rx) = tokio::sync::mpsc::channel(1);

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        nats_control_loop(&config, "rsigma.control.resolve", trigger_tx),
    )
    .await
    .expect("the control loop did not return");
    assert!(result.is_err());
    assert_nothing_sent(&server);
}

#[tokio::test]
async fn the_initial_resolve_presents_credentials() {
    let server = plain_recording_server().await;
    let resolver = DefaultSourceResolver::new().with_nats_config(user_password());
    let source = nats_source("iocs", &server.url, "iocs", RefreshPolicy::OnDemand);

    let value = resolver.resolve(&source).await.expect("resolve");
    assert_eq!(value.data, serde_json::Value::Null);
    let received = server.received();
    assert!(received.contains(r#""user":"rsigma""#), "{received}");
    assert!(received.contains(r#""pass":"hunter2""#), "{received}");
    assert!(received.contains("SUB iocs "), "{received}");
}

#[tokio::test]
async fn the_push_subscription_presents_credentials() {
    let server = plain_recording_server().await;
    let config = NatsConnectConfig {
        token: Some("push-token".into()),
        ..Default::default()
    };
    let resolver = Arc::new(DefaultSourceResolver::new().with_nats_config(config));
    let source = nats_source("feed", &server.url, "feed", RefreshPolicy::Push);

    let handle = RefreshScheduler::new().run(vec![source], resolver);
    server.wait_for("SUB feed ").await;
    let received = server.received();
    assert!(
        received.contains(r#""auth_token":"push-token""#),
        "{received}"
    );
    handle.abort();
}

#[tokio::test]
async fn the_control_subscription_presents_credentials() {
    let server = plain_recording_server().await;
    let config = NatsConnectConfig {
        url: server.url.clone(),
        ..user_password()
    };
    let (trigger_tx, _trigger_rx) = tokio::sync::mpsc::channel(1);

    let control = tokio::spawn(async move {
        nats_control_loop(&config, "rsigma.control.resolve", trigger_tx).await
    });
    server.wait_for("SUB rsigma.control.resolve ").await;
    let received = server.received();
    assert!(received.contains(r#""user":"rsigma""#), "{received}");
    assert!(received.contains(r#""pass":"hunter2""#), "{received}");
    control.abort();
}

/// A wrapping resolver that forwards the NATS settings keeps them for the
/// scheduler's push subscriptions.
#[tokio::test]
async fn the_scheduler_reads_the_settings_from_the_resolver() {
    struct Wrapper(DefaultSourceResolver);

    #[async_trait::async_trait]
    impl SourceResolver for Wrapper {
        async fn resolve(
            &self,
            source: &DynamicSource,
        ) -> Result<rsigma_runtime::ResolvedValue, rsigma_runtime::SourceError> {
            self.0.resolve(source).await
        }

        fn nats_connect_config(&self) -> NatsConnectConfig {
            self.0.nats_connect_config()
        }
    }

    let server = plain_recording_server().await;
    let resolver = Arc::new(Wrapper(
        DefaultSourceResolver::new().with_nats_config(user_password()),
    ));
    let source = nats_source("feed", &server.url, "feed", RefreshPolicy::Push);
    let handle = RefreshScheduler::new().run(vec![source], resolver);
    server.wait_for("SUB feed ").await;
    assert!(server.received().contains(r#""user":"rsigma""#));
    handle.abort();
}
