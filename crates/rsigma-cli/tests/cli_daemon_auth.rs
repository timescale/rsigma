//! E2E tests for daemon API authentication (`--api-token-env` and the
//! `daemon.api.auth` config block): the 200/401/403 matrix across read,
//! write, reload, and ingest permissions, the always-open health endpoints,
//! anonymous permissions, the auth-failure counter, and startup validation.

#![cfg(feature = "daemon")]

mod common;

use common::{
    DaemonProcess, SIMPLE_RULE, http_delete_bearer, http_get, http_get_bearer, http_post,
    http_post_bearer, spawn_expect_failure, temp_file,
};
use std::time::Duration;

/// A config file enabling auth with one token per built-in role, one custom
/// role, and anonymous metrics read.
const AUTH_CONFIG: &str = r#"
daemon:
  api:
    auth:
      anonymous_permissions: ["metrics:read"]
      roles:
        triage-bot: ["*:read", "silences:write"]
      tokens:
        - name: viewer
          role: reader
          token_env: TEST_TOKEN_READER
        - name: op
          role: operator
          token_env: TEST_TOKEN_OPERATOR
        - name: shipper
          role: ingest
          token_env: TEST_TOKEN_INGEST
        - name: root
          role: admin
          token_env: TEST_TOKEN_ADMIN
        - name: bot
          role: triage-bot
          token_env: TEST_TOKEN_BOT
"#;

/// A valid silence body (the auth tests only care about the status code, but
/// authorized requests should exercise the real handler, not a 400 path).
const SILENCE: &str = r#"{
    "matchers": [{"selector": "match.CommandLine", "op": "=~", "value": "malware.*"}],
    "comment": "auth test",
    "created_by": "tests"
}"#;

const TOKEN_ENV: &[(&str, &str)] = &[
    ("TEST_TOKEN_READER", "tok-reader"),
    ("TEST_TOKEN_OPERATOR", "tok-operator"),
    ("TEST_TOKEN_INGEST", "tok-ingest"),
    ("TEST_TOKEN_ADMIN", "tok-admin"),
    ("TEST_TOKEN_BOT", "tok-bot"),
];

fn spawn_with_auth_config(rule_path: &str) -> (DaemonProcess, tempfile::NamedTempFile) {
    let config = temp_file(".yaml", AUTH_CONFIG);
    let daemon = DaemonProcess::spawn_http_with_args_env(
        rule_path,
        &["--config", config.path().to_str().unwrap()],
        TOKEN_ENV,
    );
    (daemon, config)
}

// ---------------------------------------------------------------------------
// --api-token-env (single admin token)
// ---------------------------------------------------------------------------

#[test]
fn flag_token_gates_everything_but_health() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http_with_args_env(
        rule.path().to_str().unwrap(),
        &["--api-token-env", "TEST_API_TOKEN"],
        &[("TEST_API_TOKEN", "hunter2")],
    );

    // Liveness probes stay open.
    let (status, _) = http_get(&daemon.url("/healthz"));
    assert_eq!(status, 200);
    let (status, _) = http_get(&daemon.url("/readyz"));
    assert_eq!(status, 200);

    // Everything else is 401 without the token...
    for path in ["/metrics", "/api/v1/status", "/api/v1/rules"] {
        let (status, _) = http_get(&daemon.url(path));
        assert_eq!(status, 401, "GET {path} without token");
    }
    let (status, _) = http_post(&daemon.url("/api/v1/events"), "{}");
    assert_eq!(status, 401);

    // ...and 200 with it (admin covers every permission).
    let (status, _) = http_get_bearer(&daemon.url("/api/v1/status"), "hunter2");
    assert_eq!(status, 200);
    let (status, _) = http_get_bearer(&daemon.url("/metrics"), "hunter2");
    assert_eq!(status, 200);
    let (status, body) = http_post_bearer(
        &daemon.url("/api/v1/events"),
        "hunter2",
        r#"{"CommandLine":"malware.exe"}"#,
    );
    assert_eq!(status, 200, "{body}");

    // A wrong token is 401, not a fallback to anonymous.
    let (status, _) = http_get_bearer(&daemon.url("/api/v1/status"), "wrong");
    assert_eq!(status, 401);
}

#[test]
fn unauthorized_gets_www_authenticate_header_and_json_error() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http_with_args_env(
        rule.path().to_str().unwrap(),
        &["--api-token-env", "TEST_API_TOKEN"],
        &[("TEST_API_TOKEN", "hunter2")],
    );

    let (status, body) = http_get(&daemon.url("/api/v1/status"));
    assert_eq!(status, 401);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"], "missing or invalid bearer token");
}

// ---------------------------------------------------------------------------
// daemon.api.auth config block (roles + permissions matrix)
// ---------------------------------------------------------------------------

#[test]
fn reader_reads_but_cannot_write() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let (daemon, _config) = spawn_with_auth_config(rule.path().to_str().unwrap());

    for path in ["/api/v1/status", "/api/v1/rules", "/api/v1/silences"] {
        let (status, _) = http_get_bearer(&daemon.url(path), "tok-reader");
        assert_eq!(status, 200, "reader GET {path}");
    }
    let (status, body) = http_post_bearer(&daemon.url("/api/v1/silences"), "tok-reader", SILENCE);
    assert_eq!(status, 403, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        v["error"].as_str().unwrap().contains("silences:write"),
        "403 body should name the missing permission: {body}"
    );
    let (status, _) = http_post_bearer(&daemon.url("/api/v1/reload"), "tok-reader", "");
    assert_eq!(status, 403);
    let (status, _) = http_post_bearer(&daemon.url("/api/v1/events"), "tok-reader", "{}");
    assert_eq!(status, 403, "reader cannot ingest");
}

#[test]
fn operator_writes_but_cannot_reload() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let (daemon, _config) = spawn_with_auth_config(rule.path().to_str().unwrap());

    let (status, body) = http_post_bearer(&daemon.url("/api/v1/silences"), "tok-operator", SILENCE);
    assert_eq!(status, 201, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let id = v["id"].as_str().expect("silence id").to_string();

    let (status, _) = http_delete_bearer(
        &daemon.url(&format!("/api/v1/silences/{id}")),
        "tok-operator",
    );
    assert_eq!(status, 200, "operator can delete its silence");

    let (status, _) = http_post_bearer(&daemon.url("/api/v1/reload"), "tok-operator", "");
    assert_eq!(status, 403, "reload needs reload:execute (admin)");
}

#[test]
fn admin_can_reload() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let (daemon, _config) = spawn_with_auth_config(rule.path().to_str().unwrap());

    // The file watcher may fill the reload channel on startup; retry until a
    // slot opens (matches the unauthenticated reload test).
    let mut status = 0;
    for _ in 0..10 {
        (status, _) = http_post_bearer(&daemon.url("/api/v1/reload"), "tok-admin", "");
        if status == 200 {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_eq!(status, 200);
}

#[test]
fn ingest_token_ships_events_but_cannot_read_or_operate() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let (daemon, _config) = spawn_with_auth_config(rule.path().to_str().unwrap());

    let (status, body) = http_post_bearer(
        &daemon.url("/api/v1/events"),
        "tok-ingest",
        r#"{"CommandLine":"malware.exe"}"#,
    );
    assert_eq!(status, 200, "{body}");

    let (status, _) = http_get_bearer(&daemon.url("/api/v1/status"), "tok-ingest");
    assert_eq!(status, 403, "ingest token cannot read status");
    let (status, _) = http_post_bearer(&daemon.url("/api/v1/silences"), "tok-ingest", SILENCE);
    assert_eq!(status, 403, "ingest token cannot create silences");
}

#[test]
fn custom_role_grants_its_permission_set() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let (daemon, _config) = spawn_with_auth_config(rule.path().to_str().unwrap());

    let (status, _) = http_get_bearer(&daemon.url("/api/v1/status"), "tok-bot");
    assert_eq!(status, 200, "triage-bot has *:read");
    let (status, body) = http_post_bearer(&daemon.url("/api/v1/silences"), "tok-bot", SILENCE);
    assert_eq!(status, 201, "{body}");
    let (status, _) = http_post_bearer(&daemon.url("/api/v1/dispositions"), "tok-bot", "{}");
    assert_eq!(status, 403, "triage-bot lacks dispositions:write");
}

#[test]
fn anonymous_permissions_keep_metrics_open() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let (daemon, _config) = spawn_with_auth_config(rule.path().to_str().unwrap());

    let (status, body) = http_get(&daemon.url("/metrics"));
    assert_eq!(status, 200, "anonymous metrics:read");
    assert!(body.contains("rsigma_events_processed_total"));

    let (status, _) = http_get(&daemon.url("/api/v1/status"));
    assert_eq!(status, 401, "anonymous grant does not extend to status");
}

#[test]
fn auth_failures_counter_tracks_rejections() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let (daemon, _config) = spawn_with_auth_config(rule.path().to_str().unwrap());

    // One 401 (no token) and one 403 (reader posting a silence).
    let (status, _) = http_get(&daemon.url("/api/v1/status"));
    assert_eq!(status, 401);
    let (status, _) = http_post_bearer(&daemon.url("/api/v1/silences"), "tok-reader", "{}");
    assert_eq!(status, 403);

    let (status, body) = http_get(&daemon.url("/metrics"));
    assert_eq!(status, 200);
    assert!(
        body.contains(r#"rsigma_api_auth_failures_total{reason="unauthorized"}"#),
        "metrics should count the 401: {body}"
    );
    assert!(
        body.contains(r#"rsigma_api_auth_failures_total{reason="forbidden"}"#),
        "metrics should count the 403: {body}"
    );
}

// ---------------------------------------------------------------------------
// OTLP/HTTP ingest (feature-gated)
// ---------------------------------------------------------------------------

/// `POST /v1/logs` carries the same `events:ingest` permission as
/// `POST /api/v1/events`: no token is 401, a read token is 403, and the
/// shipper token is accepted.
#[cfg(feature = "daemon-otlp")]
#[test]
fn otlp_http_requires_ingest_permission() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let (daemon, _config) = spawn_with_auth_config(rule.path().to_str().unwrap());

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let body = r#"{"resourceLogs":[]}"#;

    let resp = agent
        .post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/json")
        .send(body)
        .expect("OTLP POST failed");
    assert_eq!(resp.status().as_u16(), 401, "no token");

    let resp = agent
        .post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/json")
        .header("authorization", "Bearer tok-reader")
        .send(body)
        .expect("OTLP POST failed");
    assert_eq!(resp.status().as_u16(), 403, "read token cannot ingest");

    let resp = agent
        .post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/json")
        .header("authorization", "Bearer tok-ingest")
        .send(body)
        .expect("OTLP POST failed");
    assert_eq!(resp.status().as_u16(), 200, "ingest token accepted");
}

// ---------------------------------------------------------------------------
// Startup validation
// ---------------------------------------------------------------------------

#[test]
fn missing_token_env_fails_startup() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let stderr = spawn_expect_failure(
        &[
            "engine",
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
            "--api-token-env",
            "DEFINITELY_UNSET_TOKEN_VAR",
        ],
        Duration::from_secs(10),
    );
    assert!(
        stderr.contains("DEFINITELY_UNSET_TOKEN_VAR"),
        "startup error should name the missing variable: {stderr}"
    );
}

#[test]
fn flag_and_config_block_are_mutually_exclusive() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let config = temp_file(".yaml", AUTH_CONFIG);
    let stderr = spawn_expect_failure(
        &[
            "engine",
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
            "--config",
            config.path().to_str().unwrap(),
            "--api-token-env",
            "TEST_API_TOKEN",
        ],
        Duration::from_secs(10),
    );
    assert!(
        stderr.contains("cannot be combined"),
        "startup should reject flag + config block: {stderr}"
    );
}

#[test]
fn unknown_role_fails_startup() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let config = temp_file(
        ".yaml",
        r#"
daemon:
  api:
    auth:
      tokens:
        - name: a
          role: nonexistent
          token_env: TEST_TOKEN_A
"#,
    );
    let stderr = spawn_expect_failure(
        &[
            "engine",
            "daemon",
            "-r",
            rule.path().to_str().unwrap(),
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
            "--config",
            config.path().to_str().unwrap(),
        ],
        Duration::from_secs(10),
    );
    assert!(
        stderr.contains("unknown role"),
        "startup should reject the unknown role: {stderr}"
    );
}
