//! E2E tests for the `rsigma daemon` binary with NATS source/sink.
//!
//! Each test starts a NATS JetStream container via testcontainers, spawns
//! the daemon binary with `--input nats://... --output nats://...`, publishes
//! events through NATS, and verifies detection output on NATS subjects.
//!
//! IMPORTANT: The test subscribers use core NATS pub/sub (not JetStream consumers),
//! which is fire-and-forget, so each output subscriber must be created BEFORE
//! events are published to avoid missing messages.

#![cfg(feature = "daemon-nats")]

mod common;

use common::{SIMPLE_RULE, temp_file};
use futures::StreamExt;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;
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

fn rsigma_bin() -> String {
    assert_cmd::cargo::cargo_bin("rsigma")
        .to_str()
        .unwrap()
        .to_string()
}

struct DaemonProcess {
    child: std::process::Child,
}

impl DaemonProcess {
    fn spawn(args: &[&str]) -> Self {
        let child = Command::new(rsigma_bin())
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn rsigma daemon");
        Self { child }
    }

    fn wait_for_ready(&mut self, marker: &str) {
        let stderr = self.child.stderr.take().unwrap();
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = line.unwrap();
            if line.contains(marker) {
                break;
            }
        }
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

const BRUTE_FORCE_RULES: &str = r#"
title: Failed Login
id: 00000000-0000-0000-0000-000000000010
status: test
logsource:
    category: auth
    product: generic
detection:
    selection:
        EventType: login_failure
    condition: selection
level: low
---
title: Brute Force
correlation:
    type: event_count
    rules:
        - 00000000-0000-0000-0000-000000000010
    group-by:
        - src_ip
    timespan: 5m
    condition:
        gte: 3
level: high
"#;

async fn publish_and_flush(client: &async_nats::Client, subject: &str, payload: &str) {
    client
        .publish(subject.to_string(), bytes::Bytes::from(payload.to_string()))
        .await
        .expect("publish");
    client.flush().await.expect("flush");
}

async fn collect_messages(
    sub: &mut async_nats::Subscriber,
    count: usize,
    timeout: Duration,
) -> Vec<String> {
    let mut messages = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    while messages.len() < count {
        let remaining = deadline - tokio::time::Instant::now();
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, sub.next()).await {
            Ok(Some(msg)) => {
                messages.push(String::from_utf8_lossy(&msg.payload).to_string());
            }
            _ => break,
        }
    }
    messages
}

#[tokio::test]
async fn daemon_nats_single_detection() {
    skip_without_docker!();
    let (_container, nats_url) = start_nats_jetstream().await;
    let rule = temp_file(".yml", SIMPLE_RULE);

    let input = format!("{nats_url}/e2e.cli.input.single");
    let output = format!("{nats_url}/e2e.cli.output.single");

    let client = async_nats::connect(&nats_url).await.unwrap();
    let mut output_sub = client
        .subscribe("e2e.cli.output.single".to_string())
        .await
        .unwrap();

    let mut daemon = DaemonProcess::spawn(&[
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        &input,
        "--output",
        &output,
        "--api-addr",
        "127.0.0.1:0",
    ]);
    daemon.wait_for_ready("Sink started");

    publish_and_flush(
        &client,
        "e2e.cli.input.single",
        r#"{"CommandLine":"run malware.exe"}"#,
    )
    .await;
    publish_and_flush(
        &client,
        "e2e.cli.input.single",
        r#"{"CommandLine":"notepad.exe"}"#,
    )
    .await;

    let msgs = collect_messages(&mut output_sub, 1, Duration::from_secs(10)).await;
    assert_eq!(msgs.len(), 1, "expected 1 detection, got {}", msgs.len());
    let parsed: serde_json::Value = serde_json::from_str(&msgs[0]).unwrap();
    assert_eq!(parsed["rule_title"].as_str().unwrap(), "Test Rule");
}

#[tokio::test]
async fn daemon_nats_no_match_no_output() {
    skip_without_docker!();
    let (_container, nats_url) = start_nats_jetstream().await;
    let rule = temp_file(".yml", SIMPLE_RULE);

    let input = format!("{nats_url}/e2e.cli.input.benign");
    let output = format!("{nats_url}/e2e.cli.output.benign");

    let client = async_nats::connect(&nats_url).await.unwrap();
    let mut output_sub = client
        .subscribe("e2e.cli.output.benign".to_string())
        .await
        .unwrap();

    let mut daemon = DaemonProcess::spawn(&[
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        &input,
        "--output",
        &output,
        "--api-addr",
        "127.0.0.1:0",
    ]);
    daemon.wait_for_ready("Sink started");

    publish_and_flush(
        &client,
        "e2e.cli.input.benign",
        r#"{"CommandLine":"notepad.exe"}"#,
    )
    .await;
    publish_and_flush(
        &client,
        "e2e.cli.input.benign",
        r#"{"CommandLine":"calc.exe"}"#,
    )
    .await;

    let msgs = collect_messages(&mut output_sub, 1, Duration::from_secs(3)).await;
    assert!(
        msgs.is_empty(),
        "benign events should produce no output, got: {msgs:?}"
    );
}

#[tokio::test]
async fn daemon_nats_correlation() {
    skip_without_docker!();
    let (_container, nats_url) = start_nats_jetstream().await;
    let rule = temp_file(".yml", BRUTE_FORCE_RULES);

    let input = format!("{nats_url}/e2e.cli.input.corr");
    let output = format!("{nats_url}/e2e.cli.output.corr");

    let client = async_nats::connect(&nats_url).await.unwrap();
    let mut output_sub = client
        .subscribe("e2e.cli.output.corr".to_string())
        .await
        .unwrap();

    let mut daemon = DaemonProcess::spawn(&[
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        &input,
        "--output",
        &output,
        "--api-addr",
        "127.0.0.1:0",
        "--no-detections",
    ]);
    daemon.wait_for_ready("Sink started");

    for i in 1..=4 {
        publish_and_flush(
            &client,
            "e2e.cli.input.corr",
            &format!(r#"{{"EventType":"login_failure","src_ip":"10.0.0.1","attempt":{i}}}"#),
        )
        .await;
    }

    let msgs = collect_messages(&mut output_sub, 1, Duration::from_secs(10)).await;
    assert!(!msgs.is_empty(), "correlation should fire after 3+ events");
    let parsed: serde_json::Value = serde_json::from_str(&msgs[0]).unwrap();
    assert_eq!(parsed["rule_title"].as_str().unwrap(), "Brute Force");
}

#[tokio::test]
async fn daemon_nats_fanout() {
    skip_without_docker!();
    let (_container, nats_url) = start_nats_jetstream().await;
    let rule = temp_file(".yml", SIMPLE_RULE);

    let input = format!("{nats_url}/e2e.cli.input.fanout");
    let output_a = format!("{nats_url}/e2e.cli.output.fanout.a");
    let output_b = format!("{nats_url}/e2e.cli.output.fanout.b");

    let client = async_nats::connect(&nats_url).await.unwrap();
    let mut sub_a = client
        .subscribe("e2e.cli.output.fanout.a".to_string())
        .await
        .unwrap();
    let mut sub_b = client
        .subscribe("e2e.cli.output.fanout.b".to_string())
        .await
        .unwrap();

    let mut daemon = DaemonProcess::spawn(&[
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--input",
        &input,
        "--output",
        &output_a,
        "--output",
        &output_b,
        "--api-addr",
        "127.0.0.1:0",
    ]);
    daemon.wait_for_ready("Sink started");

    publish_and_flush(
        &client,
        "e2e.cli.input.fanout",
        r#"{"CommandLine":"malware.exe"}"#,
    )
    .await;

    let msgs_a = collect_messages(&mut sub_a, 1, Duration::from_secs(10)).await;
    let msgs_b = collect_messages(&mut sub_b, 1, Duration::from_secs(10)).await;

    assert_eq!(msgs_a.len(), 1, "sink A should receive detection");
    assert_eq!(msgs_b.len(), 1, "sink B should receive detection");
    assert_eq!(
        msgs_a[0], msgs_b[0],
        "both sinks should get identical output"
    );
}
