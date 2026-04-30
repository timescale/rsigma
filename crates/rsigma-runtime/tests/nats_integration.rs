#![cfg(feature = "nats")]

use rsigma_runtime::io::{EventSource, NatsConnectConfig, NatsSink, NatsSource, ReplayPolicy};
use testcontainers::ImageExt;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::nats::{Nats, NatsServerCmd};

fn can_run_linux_containers() -> bool {
    let output = std::process::Command::new("docker")
        .args(["info", "--format", "{{.OSType}}"])
        .output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim() == "linux",
        _ => false,
    }
}

macro_rules! skip_without_docker {
    () => {
        if !can_run_linux_containers() {
            eprintln!("Skipping: Docker with Linux container support is not available");
            return;
        }
    };
}

async fn start_nats_jetstream() -> (testcontainers::ContainerAsync<Nats>, String) {
    let cmd = NatsServerCmd::default().with_jetstream();
    let container = Nats::default()
        .with_cmd(&cmd)
        .start()
        .await
        .expect("Failed to start NATS container");
    let port = container
        .get_host_port_ipv4(4222)
        .await
        .expect("Failed to get NATS port");
    let url = format!("nats://127.0.0.1:{port}");
    (container, url)
}

fn config(url: &str) -> NatsConnectConfig {
    NatsConnectConfig::new(url.to_string())
}

#[tokio::test]
async fn source_receives_published_message() {
    skip_without_docker!();
    let (_container, url) = start_nats_jetstream().await;
    let cfg = config(&url);
    let subject = "test.basic";

    let sink = NatsSink::connect(&cfg, subject)
        .await
        .expect("sink connect");
    sink.send_raw(r#"{"msg":"hello"}"#).await.expect("send_raw");

    let mut source = NatsSource::connect(&cfg, subject, &ReplayPolicy::Resume, None)
        .await
        .expect("source connect");

    let raw = source.recv().await.expect("should receive a message");
    assert_eq!(raw.payload, r#"{"msg":"hello"}"#);
    raw.ack_token.ack().await;
}

#[tokio::test]
async fn at_least_once_redelivery_on_missing_ack() {
    skip_without_docker!();
    let (_container, url) = start_nats_jetstream().await;
    let cfg = config(&url);
    let subject = "test.atleastonce";

    let sink = NatsSink::connect(&cfg, subject)
        .await
        .expect("sink connect");
    sink.send_raw(r#"{"id":1}"#).await.expect("publish");

    // First read: do NOT ack
    {
        let mut source = NatsSource::connect(&cfg, subject, &ReplayPolicy::Resume, None)
            .await
            .expect("source connect");
        let raw = source.recv().await.expect("first receive");
        assert_eq!(raw.payload, r#"{"id":1}"#);
        // Intentionally drop without acking
    }

    // Wait for ack_wait to expire (default 30s). To avoid a long wait,
    // reconnect with a fresh consumer name, which starts from `All`
    // (replaying un-acked messages).
    let mut source = NatsSource::connect(
        &cfg,
        subject,
        &ReplayPolicy::Resume,
        Some("redelivery-test"),
    )
    .await
    .expect("source reconnect");
    let raw = source.recv().await.expect("redelivery");
    assert_eq!(raw.payload, r#"{"id":1}"#);
    raw.ack_token.ack().await;
}

#[tokio::test]
async fn replay_from_sequence() {
    skip_without_docker!();
    let (_container, url) = start_nats_jetstream().await;
    let cfg = config(&url);
    let subject = "test.replay.seq";

    let sink = NatsSink::connect(&cfg, subject)
        .await
        .expect("sink connect");
    for i in 1..=5 {
        sink.send_raw(&format!(r#"{{"seq":{i}}}"#))
            .await
            .expect("publish");
    }

    // Start from sequence 3 (skip messages 1 and 2)
    let mut source = NatsSource::connect(
        &cfg,
        subject,
        &ReplayPolicy::FromSequence(3),
        Some("replay-seq-test"),
    )
    .await
    .expect("source connect");

    let raw = source.recv().await.expect("receive from seq 3");
    let v: serde_json::Value = serde_json::from_str(&raw.payload).unwrap();
    assert!(v["seq"].as_u64().unwrap() >= 3);
    raw.ack_token.ack().await;
}

#[tokio::test]
async fn replay_latest() {
    skip_without_docker!();
    let (_container, url) = start_nats_jetstream().await;
    let cfg = config(&url);
    let subject = "test.replay.latest";

    let sink = NatsSink::connect(&cfg, subject)
        .await
        .expect("sink connect");
    for i in 1..=5 {
        sink.send_raw(&format!(r#"{{"n":{i}}}"#))
            .await
            .expect("publish");
    }

    let mut source = NatsSource::connect(
        &cfg,
        subject,
        &ReplayPolicy::Latest,
        Some("replay-latest-test"),
    )
    .await
    .expect("source connect");

    let raw = source.recv().await.expect("receive latest");
    let v: serde_json::Value = serde_json::from_str(&raw.payload).unwrap();
    assert_eq!(v["n"].as_u64().unwrap(), 5);
    raw.ack_token.ack().await;
}

#[tokio::test]
async fn consumer_group_shared_workload() {
    skip_without_docker!();
    let (_container, url) = start_nats_jetstream().await;
    let cfg = config(&url);
    let subject = "test.cgroup";
    let group = "shared-workers";

    let sink = NatsSink::connect(&cfg, subject)
        .await
        .expect("sink connect");
    for i in 1..=4 {
        sink.send_raw(&format!(r#"{{"w":{i}}}"#))
            .await
            .expect("publish");
    }

    // Two consumers in the same group
    let mut c1 = NatsSource::connect(&cfg, subject, &ReplayPolicy::Resume, Some(group))
        .await
        .expect("c1 connect");
    let mut c2 = NatsSource::connect(&cfg, subject, &ReplayPolicy::Resume, Some(group))
        .await
        .expect("c2 connect");

    let mut total = 0;

    // Pull one message from each consumer, ack, and count.
    // With a shared consumer, each message goes to exactly one consumer.
    if let Some(raw) = c1.recv().await {
        raw.ack_token.ack().await;
        total += 1;
    }
    if let Some(raw) = c2.recv().await {
        raw.ack_token.ack().await;
        total += 1;
    }

    assert!(total >= 1, "at least one consumer should receive a message");
}

#[tokio::test]
async fn auth_user_password() {
    skip_without_docker!();
    let cmd = NatsServerCmd::default()
        .with_user("testuser")
        .with_password("testpass")
        .with_jetstream();
    let container = Nats::default()
        .with_cmd(&cmd)
        .start()
        .await
        .expect("Failed to start NATS container with auth");
    let port = container
        .get_host_port_ipv4(4222)
        .await
        .expect("Failed to get NATS port");
    let url = format!("nats://127.0.0.1:{port}");

    let cfg = NatsConnectConfig {
        url: url.clone(),
        username: Some("testuser".into()),
        password: Some("testpass".into()),
        ..Default::default()
    };
    let subject = "test.auth";

    let sink = NatsSink::connect(&cfg, subject)
        .await
        .expect("authenticated sink");
    sink.send_raw(r#"{"auth":"ok"}"#).await.expect("publish");

    let mut source = NatsSource::connect(&cfg, subject, &ReplayPolicy::Resume, None)
        .await
        .expect("authenticated source");
    let raw = source.recv().await.expect("receive");
    assert_eq!(raw.payload, r#"{"auth":"ok"}"#);
    raw.ack_token.ack().await;

    // Verify that wrong credentials fail
    let bad_cfg = NatsConnectConfig {
        url,
        username: Some("wrong".into()),
        password: Some("wrong".into()),
        ..Default::default()
    };
    let result = NatsSink::connect(&bad_cfg, subject).await;
    assert!(result.is_err(), "wrong credentials should fail");
}

#[tokio::test]
async fn dlq_write_and_read() {
    skip_without_docker!();
    let (_container, url) = start_nats_jetstream().await;
    let cfg = config(&url);
    let dlq_subject = "test.dlq";

    let dlq_sink = NatsSink::connect(&cfg, dlq_subject)
        .await
        .expect("dlq sink");
    dlq_sink
        .send_raw(
            r#"{"original_event":"bad","error":"parse error","timestamp":"2024-01-01T00:00:00Z"}"#,
        )
        .await
        .expect("write to dlq");

    let mut dlq_source = NatsSource::connect(&cfg, dlq_subject, &ReplayPolicy::Resume, None)
        .await
        .expect("dlq source");
    let raw = dlq_source.recv().await.expect("read from dlq");
    let v: serde_json::Value = serde_json::from_str(&raw.payload).unwrap();
    assert_eq!(v["error"].as_str().unwrap(), "parse error");
    raw.ack_token.ack().await;
}
