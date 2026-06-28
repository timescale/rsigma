//! E2E tests for the daemon's `--webhook` flag.
//!
//! Each test spawns `rsigma engine daemon` with a webhook config pointed at a
//! `wiremock` server, sends a detection-triggering event over `--input http`,
//! and asserts on the request the webhook made (rendered body and headers),
//! the retry / DLQ behavior, kind/scope filtering, env-header interpolation,
//! and that a stalled webhook never blocks a co-configured file sink.

#![cfg(feature = "daemon")]

mod common;

use std::time::Duration;

use common::{DaemonProcess, SIMPLE_RULE, http_post, poll_until, temp_file};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

const MATCHING_EVENT: &str = r#"{"CommandLine":"run malware.exe"}"#;

/// Detection webhook posting a rendered JSON body plus a static header.
const WEBHOOK_CFG: &str = r#"
webhooks:
  - id: slack
    kind: detection
    url: __URL__/hook
    headers:
      X-Source: rsigma
    body: '{"text":"${detection.rule.title}: ${detection.fields.CommandLine}"}'
"#;

/// Webhook whose Authorization header is an env-var template.
const WEBHOOK_AUTH_CFG: &str = r#"
webhooks:
  - id: slack
    kind: detection
    url: __URL__/hook
    headers:
      Authorization: "Bearer ${RSIGMA_TEST_WEBHOOK_TOKEN}"
    body: '{"text":"${detection.rule.title}"}'
"#;

/// Webhook that HMAC-signs deliveries using a secret from the environment.
const WEBHOOK_SIGNED_CFG: &str = r#"
webhooks:
  - id: slack
    kind: detection
    url: __URL__/hook
    body: '{"text":"${detection.rule.title}"}'
    signing:
      secret_env: RSIGMA_TEST_WEBHOOK_SECRET
"#;

/// Webhook scoped to a level the test rule (high) does not carry.
const WEBHOOK_SCOPED_CFG: &str = r#"
webhooks:
  - id: slack
    kind: detection
    url: __URL__/hook
    body: '{"text":"${detection.rule.title}"}'
    scope:
      levels: [critical]
"#;

/// HTTPS webhook trusting a private CA, retrying once so the unreachable
/// delivery reaches the DLQ quickly.
const TLS_CFG: &str = r#"
webhooks:
  - id: internal
    kind: detection
    url: https://127.0.0.1:1/hook
    body: '{"text":"${detection.rule.title}"}'
    retry:
      attempts: 1
    tls:
      ca: __CA__
"#;

/// Webhook with fast retry tuning so the retry loop runs within the test.
const WEBHOOK_RETRY_CFG: &str = r#"
webhooks:
  - id: slack
    kind: detection
    url: __URL__/hook
    body: '{"text":"${detection.rule.title}"}'
    retry:
      attempts: 3
      backoff: 100ms
      max_backoff: 300ms
"#;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Start a wiremock server that answers every POST with `status`.
fn mock_server(rt: &tokio::runtime::Runtime, status: u16) -> MockServer {
    rt.block_on(async {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&s)
            .await;
        s
    })
}

fn request_count(rt: &tokio::runtime::Runtime, server: &MockServer) -> usize {
    rt.block_on(server.received_requests())
        .map(|r| r.len())
        .unwrap_or(0)
}

#[test]
fn webhook_delivers_rendered_body_and_headers() {
    let rt = rt();
    let server = mock_server(&rt, 200);
    let webhook = temp_file(".yml", &WEBHOOK_CFG.replace("__URL__", &server.uri()));
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--webhook", webhook.path().to_str().unwrap()],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), MATCHING_EVENT);
    assert_eq!(status, 200);

    let req = poll_until(Duration::from_secs(5), || {
        rt.block_on(server.received_requests())
            .unwrap_or_default()
            .into_iter()
            .next()
    })
    .expect("webhook never made a request");

    assert_eq!(
        req.headers.get("x-source").and_then(|v| v.to_str().ok()),
        Some("rsigma"),
        "the static header should be sent",
    );
    let body: serde_json::Value =
        serde_json::from_slice(&req.body).expect("rendered body must be valid JSON");
    assert_eq!(
        body["text"], "Test Rule: run malware.exe",
        "the body should interpolate the rule title and matched field",
    );
}

#[test]
fn webhook_permanent_4xx_routes_to_dlq() {
    let rt = rt();
    let server = mock_server(&rt, 400);
    let webhook = temp_file(".yml", &WEBHOOK_CFG.replace("__URL__", &server.uri()));
    let rule = temp_file(".yml", SIMPLE_RULE);
    let dlq = temp_file(".ndjson", "");
    let dlq_spec = format!("file://{}", dlq.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--webhook",
            webhook.path().to_str().unwrap(),
            "--dlq",
            &dlq_spec,
        ],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), MATCHING_EVENT);
    assert_eq!(status, 200);

    let dlqd = poll_until(Duration::from_secs(10), || {
        let s = std::fs::read_to_string(dlq.path()).unwrap_or_default();
        (s.contains("webhook slack") && s.contains("HTTP 400")).then_some(())
    });
    assert!(
        dlqd.is_some(),
        "a permanent 4xx should route to the DLQ with the webhook id and status",
    );
    // A permanent failure must not be retried: exactly one request.
    assert_eq!(
        request_count(&rt, &server),
        1,
        "permanent 4xx must not retry"
    );
}

#[test]
fn webhook_retries_then_exhausts_to_dlq() {
    let rt = rt();
    let server = mock_server(&rt, 500);
    let webhook = temp_file(".yml", &WEBHOOK_RETRY_CFG.replace("__URL__", &server.uri()));
    let rule = temp_file(".yml", SIMPLE_RULE);
    let dlq = temp_file(".ndjson", "");
    let dlq_spec = format!("file://{}", dlq.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--webhook",
            webhook.path().to_str().unwrap(),
            "--dlq",
            &dlq_spec,
        ],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), MATCHING_EVENT);
    assert_eq!(status, 200);

    // attempts: 3 => one initial try plus two retries.
    let dlqd = poll_until(Duration::from_secs(10), || {
        let s = std::fs::read_to_string(dlq.path()).unwrap_or_default();
        (s.contains("webhook slack") && s.contains("HTTP 500")).then_some(())
    });
    assert!(
        dlqd.is_some(),
        "a retryable 5xx should exhaust retries into the DLQ"
    );
    assert!(
        request_count(&rt, &server) >= 2,
        "the webhook should have retried at least once before the DLQ",
    );
}

#[test]
fn webhook_scope_filter_skips_out_of_scope() {
    let rt = rt();
    let server = mock_server(&rt, 200);
    let webhook = temp_file(
        ".yml",
        &WEBHOOK_SCOPED_CFG.replace("__URL__", &server.uri()),
    );
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = temp_file(".ndjson", "");
    let out_spec = format!("file://{}", out.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--webhook",
            webhook.path().to_str().unwrap(),
            "--output",
            &out_spec,
        ],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), MATCHING_EVENT);
    assert_eq!(status, 200);

    // The detection reaches the file sink (so we know the event matched)...
    let landed = poll_until(Duration::from_secs(5), || {
        std::fs::read_to_string(out.path())
            .unwrap_or_default()
            .contains("Test Rule")
            .then_some(())
    });
    assert!(landed.is_some(), "detection should reach the file sink");

    // ...but the level-scoped-out webhook made no request. Give the webhook
    // worker (dispatched alongside the file sink) a moment to have skipped.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        request_count(&rt, &server),
        0,
        "a webhook scoped to critical must not fire for a high-severity detection",
    );
}

#[test]
fn webhook_env_header_is_interpolated() {
    let rt = rt();
    let server = mock_server(&rt, 200);
    let webhook = temp_file(".yml", &WEBHOOK_AUTH_CFG.replace("__URL__", &server.uri()));
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http_with_args_env(
        rule.path().to_str().unwrap(),
        &["--webhook", webhook.path().to_str().unwrap()],
        &[("RSIGMA_TEST_WEBHOOK_TOKEN", "secret-xyz")],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), MATCHING_EVENT);
    assert_eq!(status, 200);

    let req = poll_until(Duration::from_secs(5), || {
        rt.block_on(server.received_requests())
            .unwrap_or_default()
            .into_iter()
            .next()
    })
    .expect("webhook never made a request");
    assert_eq!(
        req.headers
            .get("authorization")
            .and_then(|v| v.to_str().ok()),
        Some("Bearer secret-xyz"),
        "the env-var header secret should be interpolated at render time",
    );
}

#[test]
fn webhook_signs_requests_when_configured() {
    let rt = rt();
    let server = mock_server(&rt, 200);
    let webhook = temp_file(
        ".yml",
        &WEBHOOK_SIGNED_CFG.replace("__URL__", &server.uri()),
    );
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http_with_args_env(
        rule.path().to_str().unwrap(),
        &["--webhook", webhook.path().to_str().unwrap()],
        &[("RSIGMA_TEST_WEBHOOK_SECRET", "test-secret")],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), MATCHING_EVENT);
    assert_eq!(status, 200);

    let req = poll_until(Duration::from_secs(5), || {
        rt.block_on(server.received_requests())
            .unwrap_or_default()
            .into_iter()
            .next()
    })
    .expect("webhook never made a request");

    // The default scheme is Standard Webhooks: a signed id, timestamp, and a
    // versioned signature are present.
    assert!(
        req.headers.get("webhook-id").is_some(),
        "missing webhook-id header",
    );
    assert!(
        req.headers.get("webhook-timestamp").is_some(),
        "missing webhook-timestamp header",
    );
    let sig = req
        .headers
        .get("webhook-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        sig.starts_with("v1,"),
        "expected a v1 signature, got {sig:?}",
    );
}

#[test]
fn webhook_tls_with_ca_routes_unreachable_to_dlq() {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    // A private CA the webhook is told to trust. The endpoint is unreachable,
    // so the handshake never happens; this exercises tls.ca file reading, the
    // TLS client build, and the delivery path into the DLQ end to end.
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
    let ca = temp_file(".pem", &ca_pem);

    let cfg = TLS_CFG.replace("__CA__", &ca.path().display().to_string());
    let webhook = temp_file(".yml", &cfg);
    let rule = temp_file(".yml", SIMPLE_RULE);
    let dlq = temp_file(".ndjson", "");
    let dlq_spec = format!("file://{}", dlq.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--webhook",
            webhook.path().to_str().unwrap(),
            "--dlq",
            &dlq_spec,
        ],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), MATCHING_EVENT);
    assert_eq!(status, 200);

    let dlqd = poll_until(Duration::from_secs(10), || {
        std::fs::read_to_string(dlq.path())
            .unwrap_or_default()
            .contains("webhook internal")
            .then_some(())
    });
    assert!(
        dlqd.is_some(),
        "an https webhook with a custom CA should build TLS and route the unreachable delivery to the DLQ",
    );
}

#[test]
fn webhook_does_not_block_file_sink_under_fanout() {
    // The webhook targets a closed port; the co-configured file sink must
    // still receive the detection, proving per-sink worker isolation.
    let webhook = temp_file(
        ".yml",
        &WEBHOOK_CFG.replace("__URL__", "http://127.0.0.1:1"),
    );
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = temp_file(".ndjson", "");
    let out_spec = format!("file://{}", out.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--webhook",
            webhook.path().to_str().unwrap(),
            "--output",
            &out_spec,
        ],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), MATCHING_EVENT);
    assert_eq!(status, 200);

    let landed = poll_until(Duration::from_secs(5), || {
        std::fs::read_to_string(out.path())
            .unwrap_or_default()
            .contains("Test Rule")
            .then_some(())
    });
    assert!(
        landed.is_some(),
        "an unreachable webhook must not block the file sink behind it",
    );
}
