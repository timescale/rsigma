#![cfg(feature = "nats")]

use std::sync::Arc;

use rsigma_eval::CorrelationConfig;
use rsigma_runtime::input::SyslogConfig;
use rsigma_runtime::io::{EventSource, NatsConnectConfig, NatsSink, NatsSource, ReplayPolicy};
use rsigma_runtime::{InputFormat, LogProcessor, NoopMetrics, RuntimeEngine};
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

fn write_rules(dir: &std::path::Path, files: &[(&str, &str)]) {
    for (name, content) in files {
        std::fs::write(dir.join(name), content).unwrap();
    }
}

fn build_processor(rules_dir: &std::path::Path) -> LogProcessor {
    let corr_config = CorrelationConfig::default();
    let mut engine = RuntimeEngine::new(rules_dir.to_path_buf(), vec![], corr_config, false);
    engine.load_rules().unwrap();
    LogProcessor::new(engine, Arc::new(NoopMetrics))
}

// ---- Sigma rules used across tests ----

const RULE_WHOAMI: &str = r#"
title: Detect Whoami Execution
id: d5b8d8a0-0001-0000-0000-000000000001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;

const RULE_PROXY_SESSION: &str = r#"
title: Okta User Session Start Via An Anonymising Proxy Service
id: bde30855-5c53-4c18-ae90-1ff79ebc9578
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventType: 'user.session.start'
        securityContext.isProxy: 'true'
    condition: selection
level: high
"#;

const RULE_MFA_DEACTIVATED: &str = r#"
title: Okta MFA Reset or Deactivated
id: 50e068d7-1e6b-4054-87e5-0a592c40c7e0
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventType:
            - user.mfa.factor.deactivate
            - user.mfa.factor.reset_all
    condition: selection
level: medium
"#;

const RULE_ADMIN_ROLE: &str = r#"
title: Okta Admin Role Assigned to an User or Group
id: 413d4a81-6c98-4479-9863-014785fd579c
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventType:
            - group.privilege.grant
            - user.account.privilege.grant
    condition: selection
level: medium
"#;

const RULE_IDP_CREATED: &str = r#"
title: Okta Identity Provider Created
id: 969c7590-8c19-4797-8c1b-23155de6e7ac
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventType: 'system.idp.lifecycle.create'
    condition: selection
level: medium
"#;

const RULE_CORRELATION: &str = r#"
title: Okta Cross-Tenant Impersonation Sequence
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
correlation:
    type: temporal_ordered
    rules:
        - bde30855-5c53-4c18-ae90-1ff79ebc9578
        - 50e068d7-1e6b-4054-87e5-0a592c40c7e0
        - 413d4a81-6c98-4479-9863-014785fd579c
        - 969c7590-8c19-4797-8c1b-23155de6e7ac
    group-by:
        - actor.alternateId
    timespan: 30m
level: critical
"#;

// ---- Okta events from the streaming article ----

const OKTA_EVENTS: &[&str] = &[
    // 1. Bob's normal login (noise, no detection)
    r#"{"eventType":"user.session.start","actor":{"alternateId":"bob@acme.com","displayName":"Bob Smith","type":"User"},"outcome":{"result":"SUCCESS"},"client":{"ipAddress":"192.168.1.100"},"securityContext":{"isProxy":false},"published":"2023-08-15T13:55:00.000Z"}"#,
    // 2. Attacker proxy session (detection: proxy rule)
    r#"{"eventType":"user.session.start","actor":{"alternateId":"superadmin@acme.com","displayName":"IT Admin","type":"User"},"outcome":{"result":"SUCCESS"},"client":{"ipAddress":"198.51.100.23"},"securityContext":{"isProxy":true},"published":"2023-08-15T14:05:00.000Z"}"#,
    // 3. MFA deactivation (detection: MFA rule)
    r#"{"eventType":"user.mfa.factor.deactivate","actor":{"alternateId":"superadmin@acme.com","displayName":"IT Admin","type":"User"},"outcome":{"result":"SUCCESS"},"client":{"ipAddress":"198.51.100.23"},"securityContext":{"isProxy":true},"published":"2023-08-15T14:12:00.000Z"}"#,
    // 4. Ops team app update (noise, no detection)
    r#"{"eventType":"application.lifecycle.update","actor":{"alternateId":"ops@acme.com","displayName":"Ops Team","type":"User"},"outcome":{"result":"SUCCESS"},"client":{"ipAddress":"10.0.0.50"},"securityContext":{"isProxy":false},"published":"2023-08-15T14:15:00.000Z"}"#,
    // 5. Admin privilege grant (detection: admin role rule)
    r#"{"eventType":"user.account.privilege.grant","actor":{"alternateId":"superadmin@acme.com","displayName":"IT Admin","type":"User"},"outcome":{"result":"SUCCESS"},"client":{"ipAddress":"198.51.100.23"},"securityContext":{"isProxy":true},"published":"2023-08-15T14:18:00.000Z"}"#,
    // 6. Rogue IdP created (detection: IdP rule + correlation fires)
    r#"{"eventType":"system.idp.lifecycle.create","actor":{"alternateId":"superadmin@acme.com","displayName":"IT Admin","type":"User"},"outcome":{"result":"SUCCESS"},"client":{"ipAddress":"198.51.100.23"},"securityContext":{"isProxy":true},"published":"2023-08-15T14:25:00.000Z"}"#,
];

/// Scenario from the streaming article: basic single-rule detection through NATS.
///
/// Publish a process creation event to NATS, run it through the engine,
/// and verify the detection appears on the output subject.
#[tokio::test]
async fn e2e_single_detection_through_nats() {
    skip_without_docker!();
    let (_container, url) = start_nats_jetstream().await;
    let cfg = config(&url);

    let tmp = tempfile::tempdir().unwrap();
    write_rules(tmp.path(), &[("whoami.yml", RULE_WHOAMI)]);
    let processor = build_processor(tmp.path());

    let input_subject = "e2e.events.whoami";
    let output_subject = "e2e.detections.whoami";

    let input_sink = NatsSink::connect(&cfg, input_subject).await.unwrap();
    let output_sink = NatsSink::connect(&cfg, output_subject).await.unwrap();

    // Publish a matching event and a non-matching event
    input_sink
        .send_raw(r#"{"CommandLine":"cmd /c whoami","EventID":1}"#)
        .await
        .unwrap();
    input_sink
        .send_raw(r#"{"CommandLine":"dir","EventID":2}"#)
        .await
        .unwrap();

    // Read from input, process, write detections to output
    let mut source = NatsSource::connect(&cfg, input_subject, &ReplayPolicy::Resume, None)
        .await
        .unwrap();

    for _ in 0..2 {
        let raw = source.recv().await.expect("event from source");
        let results = processor.process_batch_with_format(&[raw.payload], &InputFormat::Json, None);
        for result in &results {
            if !result.detections.is_empty() || !result.correlations.is_empty() {
                let json = serde_json::to_string(result).unwrap();
                output_sink.send_raw(&json).await.unwrap();
            }
        }
        raw.ack_token.ack().await;
    }

    // Read from output and verify
    let mut output_source = NatsSource::connect(&cfg, output_subject, &ReplayPolicy::Resume, None)
        .await
        .unwrap();
    let detection_raw = output_source.recv().await.expect("detection on output");
    let v: serde_json::Value = serde_json::from_str(&detection_raw.payload).unwrap();
    assert!(
        v["detections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["rule_title"].as_str().unwrap() == "Detect Whoami Execution")
    );
    detection_raw.ack_token.ack().await;
}

/// Scenario from the streaming article: non-matching events produce no output.
///
/// Publish events that don't match any loaded rule and verify no detections
/// appear on the output subject.
#[tokio::test]
async fn e2e_no_detection_for_benign_events() {
    skip_without_docker!();
    let (_container, url) = start_nats_jetstream().await;
    let cfg = config(&url);

    let tmp = tempfile::tempdir().unwrap();
    write_rules(tmp.path(), &[("whoami.yml", RULE_WHOAMI)]);
    let processor = build_processor(tmp.path());

    let input_subject = "e2e.events.benign";
    let output_subject = "e2e.detections.benign";

    let input_sink = NatsSink::connect(&cfg, input_subject).await.unwrap();
    NatsSink::connect(&cfg, output_subject).await.unwrap();

    // Publish only non-matching events
    input_sink
        .send_raw(r#"{"CommandLine":"dir /w","EventID":1}"#)
        .await
        .unwrap();
    input_sink
        .send_raw(r#"{"CommandLine":"hostname","EventID":2}"#)
        .await
        .unwrap();

    let mut source = NatsSource::connect(&cfg, input_subject, &ReplayPolicy::Resume, None)
        .await
        .unwrap();

    let mut detection_count = 0;
    for _ in 0..2 {
        let raw = source.recv().await.expect("event from source");
        let results = processor.process_batch_with_format(&[raw.payload], &InputFormat::Json, None);
        for result in &results {
            detection_count += result.detections.len() + result.correlations.len();
        }
        raw.ack_token.ack().await;
    }
    assert_eq!(detection_count, 0, "benign events should produce no output");
}

/// Core scenario from the streaming article: Okta cross-tenant impersonation.
///
/// Publish 6 Okta System Log events through NATS. Expect 4 individual
/// detections and 1 temporal_ordered correlation alert (critical) when
/// the fourth attack-step event completes the sequence.
#[tokio::test]
async fn e2e_okta_cross_tenant_impersonation_correlation() {
    skip_without_docker!();
    let (_container, url) = start_nats_jetstream().await;
    let cfg = config(&url);

    let tmp = tempfile::tempdir().unwrap();
    write_rules(
        tmp.path(),
        &[
            ("proxy_session.yml", RULE_PROXY_SESSION),
            ("mfa_deactivated.yml", RULE_MFA_DEACTIVATED),
            ("admin_role.yml", RULE_ADMIN_ROLE),
            ("idp_created.yml", RULE_IDP_CREATED),
            ("correlation.yml", RULE_CORRELATION),
        ],
    );
    let processor = build_processor(tmp.path());

    let input_subject = "e2e.events.okta";
    let output_subject = "e2e.detections.okta";

    let input_sink = NatsSink::connect(&cfg, input_subject).await.unwrap();
    let output_sink = NatsSink::connect(&cfg, output_subject).await.unwrap();

    // Publish all 6 Okta events
    for event in OKTA_EVENTS {
        input_sink.send_raw(event).await.unwrap();
    }

    // Process all events through the engine
    let mut source = NatsSource::connect(&cfg, input_subject, &ReplayPolicy::Resume, None)
        .await
        .unwrap();

    let mut total_detections = 0;
    let mut total_correlations = 0;
    let mut output_messages = 0;

    for _ in 0..OKTA_EVENTS.len() {
        let raw = source.recv().await.expect("event from source");
        let results = processor.process_batch_with_format(&[raw.payload], &InputFormat::Json, None);
        for result in &results {
            total_detections += result.detections.len();
            total_correlations += result.correlations.len();
            if !result.detections.is_empty() || !result.correlations.is_empty() {
                let json = serde_json::to_string(result).unwrap();
                output_sink.send_raw(&json).await.unwrap();
                output_messages += 1;
            }
        }
        raw.ack_token.ack().await;
    }

    // 4 individual detections: proxy session, MFA deactivation, admin role, IdP created
    assert_eq!(
        total_detections, 4,
        "expected 4 individual detections from the attack chain"
    );

    // 1 correlation: temporal_ordered fires when the 4th detection completes the sequence
    assert_eq!(
        total_correlations, 1,
        "expected 1 temporal_ordered correlation alert"
    );

    // Verify the correlation output on the NATS output subject.
    // Each ProcessResult with output is one message (the last event carries
    // both a detection and the correlation in a single result).
    let mut output_source = NatsSource::connect(&cfg, output_subject, &ReplayPolicy::Resume, None)
        .await
        .unwrap();

    let mut found_correlation = false;
    for _ in 0..output_messages {
        let raw = output_source.recv().await.expect("output message");
        let v: serde_json::Value = serde_json::from_str(&raw.payload).unwrap();
        if let Some(corrs) = v["correlations"].as_array() {
            for c in corrs {
                if c["rule_title"].as_str() == Some("Okta Cross-Tenant Impersonation Sequence") {
                    assert_eq!(c["level"].as_str(), Some("critical"));
                    found_correlation = true;
                }
            }
        }
        raw.ack_token.ack().await;
    }
    assert!(
        found_correlation,
        "should find the correlation alert in output"
    );
}

/// Scenario from the streaming article: fan-out to multiple NATS output subjects.
///
/// Detections should appear on both output subjects simultaneously.
#[tokio::test]
async fn e2e_fanout_to_multiple_nats_sinks() {
    skip_without_docker!();
    let (_container, url) = start_nats_jetstream().await;
    let cfg = config(&url);

    let tmp = tempfile::tempdir().unwrap();
    write_rules(tmp.path(), &[("whoami.yml", RULE_WHOAMI)]);
    let processor = build_processor(tmp.path());

    let input_subject = "e2e.events.fanout";
    let output_a = "e2e.detections.fanout.a";
    let output_b = "e2e.detections.fanout.b";

    let input_sink = NatsSink::connect(&cfg, input_subject).await.unwrap();
    let sink_a = NatsSink::connect(&cfg, output_a).await.unwrap();
    let sink_b = NatsSink::connect(&cfg, output_b).await.unwrap();

    input_sink
        .send_raw(r#"{"CommandLine":"whoami /all","EventID":1}"#)
        .await
        .unwrap();

    let mut source = NatsSource::connect(&cfg, input_subject, &ReplayPolicy::Resume, None)
        .await
        .unwrap();
    let raw = source.recv().await.expect("event");
    let results = processor.process_batch_with_format(&[raw.payload], &InputFormat::Json, None);
    for result in &results {
        if !result.detections.is_empty() {
            let json = serde_json::to_string(result).unwrap();
            sink_a.send_raw(&json).await.unwrap();
            sink_b.send_raw(&json).await.unwrap();
        }
    }
    raw.ack_token.ack().await;

    // Verify both sinks received the detection
    let mut src_a = NatsSource::connect(&cfg, output_a, &ReplayPolicy::Resume, None)
        .await
        .unwrap();
    let mut src_b = NatsSource::connect(&cfg, output_b, &ReplayPolicy::Resume, None)
        .await
        .unwrap();

    let det_a = src_a.recv().await.expect("detection on sink A");
    let det_b = src_b.recv().await.expect("detection on sink B");
    assert_eq!(
        det_a.payload, det_b.payload,
        "both sinks should get identical output"
    );
    det_a.ack_token.ack().await;
    det_b.ack_token.ack().await;
}

/// Scenario: syslog-formatted events streamed through NATS.
///
/// Send syslog lines through NATS, process them with the syslog input
/// format, and verify that keyword-based rules detect matches.
#[tokio::test]
async fn e2e_syslog_through_nats() {
    skip_without_docker!();
    let (_container, url) = start_nats_jetstream().await;
    let cfg = config(&url);

    let syslog_rule = r#"
title: Detect sudo usage
id: d5b8d8a0-0002-0000-0000-000000000001
logsource:
    product: linux
    service: auth
detection:
    keywords:
        - 'sudo'
    condition: keywords
level: low
"#;

    let tmp = tempfile::tempdir().unwrap();
    write_rules(tmp.path(), &[("sudo.yml", syslog_rule)]);
    let processor = build_processor(tmp.path());

    let input_subject = "e2e.events.syslog";

    let input_sink = NatsSink::connect(&cfg, input_subject).await.unwrap();

    // RFC 3164 syslog message
    input_sink
        .send_raw("<38>Apr 25 14:30:00 web01 sudo: admin : TTY=pts/0 ; COMMAND=/bin/bash")
        .await
        .unwrap();

    let mut source = NatsSource::connect(&cfg, input_subject, &ReplayPolicy::Resume, None)
        .await
        .unwrap();
    let raw = source.recv().await.expect("syslog event");
    let results = processor.process_batch_with_format(
        &[raw.payload],
        &InputFormat::Syslog(SyslogConfig::default()),
        None,
    );
    let det_count: usize = results.iter().map(|r| r.detections.len()).sum();
    assert_eq!(det_count, 1, "syslog message should trigger sudo detection");
    raw.ack_token.ack().await;
}

/// Scenario from the first article: event_count correlation (brute force).
///
/// Publish multiple failed login events through NATS and verify the
/// event_count correlation fires once the threshold is reached.
#[tokio::test]
async fn e2e_brute_force_event_count_correlation() {
    skip_without_docker!();
    let (_container, url) = start_nats_jetstream().await;
    let cfg = config(&url);

    let failed_login_rule = r#"
title: Failed Login
id: f0f0f0f0-0001-0000-0000-000000000001
logsource:
    product: generic
    service: auth
detection:
    selection:
        eventType: 'login.failed'
    condition: selection
level: low
"#;

    let brute_force_correlation = r#"
title: Brute Force Detection
id: f0f0f0f0-0002-0000-0000-000000000001
correlation:
    type: event_count
    rules:
        - f0f0f0f0-0001-0000-0000-000000000001
    group-by:
        - src_ip
    timespan: 5m
    condition:
        gte: 5
level: high
"#;

    let tmp = tempfile::tempdir().unwrap();
    write_rules(
        tmp.path(),
        &[
            ("failed_login.yml", failed_login_rule),
            ("brute_force.yml", brute_force_correlation),
        ],
    );
    let processor = build_processor(tmp.path());

    let input_subject = "e2e.events.bruteforce";

    let input_sink = NatsSink::connect(&cfg, input_subject).await.unwrap();

    // Publish 6 failed login events from the same IP
    for i in 1..=6 {
        input_sink
            .send_raw(&format!(
                r#"{{"eventType":"login.failed","src_ip":"10.0.0.1","attempt":{i}}}"#
            ))
            .await
            .unwrap();
    }

    let mut source = NatsSource::connect(&cfg, input_subject, &ReplayPolicy::Resume, None)
        .await
        .unwrap();

    let mut total_detections = 0;
    let mut total_correlations = 0;

    for _ in 0..6 {
        let raw = source.recv().await.expect("event");
        let results = processor.process_batch_with_format(&[raw.payload], &InputFormat::Json, None);
        for result in &results {
            total_detections += result.detections.len();
            total_correlations += result.correlations.len();
        }
        raw.ack_token.ack().await;
    }

    assert_eq!(total_detections, 6, "each failed login should detect");
    assert!(
        total_correlations >= 1,
        "brute force correlation should fire after 5+ events"
    );
}
