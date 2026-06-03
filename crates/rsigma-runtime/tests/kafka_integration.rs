#![cfg(feature = "kafka")]

use std::time::Duration;

use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication};
use rdkafka::client::DefaultClientContext;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rsigma_runtime::io::{EventSource, KafkaConnectConfig, KafkaSink, KafkaSource};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::kafka::Kafka;

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

async fn start_kafka() -> (testcontainers::ContainerAsync<Kafka>, String) {
    let container = Kafka::default()
        .start()
        .await
        .expect("Failed to start Kafka container");
    let port = container
        .get_host_port_ipv4(9093)
        .await
        .expect("Failed to get Kafka port");
    let brokers = format!("127.0.0.1:{port}");
    (container, brokers)
}

async fn create_topic(brokers: &str, topic: &str) {
    let admin: AdminClient<DefaultClientContext> = ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .create()
        .expect("admin client");
    let new_topic = NewTopic::new(topic, 1, TopicReplication::Fixed(1));
    admin
        .create_topics(&[new_topic], &AdminOptions::default())
        .await
        .expect("create topic");
    tokio::time::sleep(Duration::from_millis(500)).await;
}

async fn produce_message(brokers: &str, topic: &str, payload: &str) {
    let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .set("message.timeout.ms", "5000")
        .create()
        .expect("producer");
    producer
        .send(
            FutureRecord::to(topic).payload(payload),
            Duration::from_secs(5),
        )
        .await
        .expect("produce");
}

fn config(brokers: &str) -> KafkaConnectConfig {
    KafkaConnectConfig::new(brokers.to_string(), "rsigma-test".to_string())
}

#[tokio::test]
async fn source_receives_produced_message() {
    skip_without_docker!();
    let (_container, brokers) = start_kafka().await;
    let topic = "test-basic";
    create_topic(&brokers, topic).await;
    produce_message(&brokers, topic, r#"{"msg":"hello"}"#).await;

    let cfg = config(&brokers);
    let mut source =
        KafkaSource::connect(&cfg, &[topic.to_string()]).expect("source connect");

    let raw = tokio::time::timeout(Duration::from_secs(10), source.recv())
        .await
        .expect("timeout waiting for message")
        .expect("should receive a message");
    assert_eq!(raw.payload, r#"{"msg":"hello"}"#);
    raw.ack_token.ack().await;
}

#[tokio::test]
async fn sink_produces_message() {
    skip_without_docker!();
    let (_container, brokers) = start_kafka().await;
    let topic = "test-sink";
    create_topic(&brokers, topic).await;

    let cfg = config(&brokers);
    let sink = KafkaSink::connect(&cfg, topic).expect("sink connect");
    sink.send_raw(r#"{"detection":"brute_force"}"#)
        .await
        .expect("send_raw");

    let mut source =
        KafkaSource::connect(&cfg, &[topic.to_string()]).expect("source connect");
    let raw = tokio::time::timeout(Duration::from_secs(10), source.recv())
        .await
        .expect("timeout")
        .expect("should receive");
    assert_eq!(raw.payload, r#"{"detection":"brute_force"}"#);
    raw.ack_token.ack().await;
}

#[tokio::test]
async fn multi_topic_subscription() {
    skip_without_docker!();
    let (_container, brokers) = start_kafka().await;
    create_topic(&brokers, "multi-a").await;
    create_topic(&brokers, "multi-b").await;

    produce_message(&brokers, "multi-a", r#"{"from":"a"}"#).await;
    produce_message(&brokers, "multi-b", r#"{"from":"b"}"#).await;

    let cfg = config(&brokers);
    let mut source = KafkaSource::connect(
        &cfg,
        &["multi-a".to_string(), "multi-b".to_string()],
    )
    .expect("source connect");

    let mut payloads = Vec::new();
    for _ in 0..2 {
        let raw = tokio::time::timeout(Duration::from_secs(10), source.recv())
            .await
            .expect("timeout")
            .expect("should receive");
        payloads.push(raw.payload.clone());
        raw.ack_token.ack().await;
    }
    payloads.sort();
    assert_eq!(payloads, vec![r#"{"from":"a"}"#, r#"{"from":"b"}"#]);
}
