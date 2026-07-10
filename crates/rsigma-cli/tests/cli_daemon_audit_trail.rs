//! E2E tests for the control-plane API audit trail (`--state-db`).

#![cfg(feature = "daemon")]

mod common;

use common::{DaemonProcess, SIMPLE_RULE, http_get, http_get_bearer, http_post_bearer, temp_file};
use std::time::Duration;

const AUTH_CONFIG: &str = r#"
daemon:
  api:
    auth:
      tokens:
        - name: op
          role: operator
          token_env: TEST_TOKEN_OPERATOR
        - name: reader
          role: reader
          token_env: TEST_TOKEN_READER
"#;

const SILENCE: &str = r#"{
    "matchers": [{"selector": "match.CommandLine", "op": "=~", "value": "malware.*"}],
    "comment": "audit test",
    "created_by": "tests"
}"#;

#[test]
fn mutation_is_audited_with_token_and_status() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");
    let config = temp_file(".yaml", AUTH_CONFIG);

    let daemon = DaemonProcess::spawn_http_with_args_env(
        rule.path().to_str().unwrap(),
        &[
            "--config",
            config.path().to_str().unwrap(),
            "--state-db",
            db.to_str().unwrap(),
        ],
        &[
            ("TEST_TOKEN_OPERATOR", "tok-operator"),
            ("TEST_TOKEN_READER", "tok-reader"),
        ],
    );

    let (status, body) = http_post_bearer(&daemon.url("/api/v1/silences"), "tok-operator", SILENCE);
    assert_eq!(status, 201, "{body}");

    // Give the async audit write a moment to land in SQLite.
    std::thread::sleep(Duration::from_millis(200));

    let (status, body) = http_get_bearer(&daemon.url("/api/v1/audit"), "tok-reader");
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["count"], 1);
    let entry = &v["entries"][0];
    assert_eq!(entry["method"], "POST");
    assert_eq!(entry["endpoint"], "/api/v1/silences");
    assert_eq!(entry["token"], "op");
    assert_eq!(entry["status"], 201);
    assert!(entry["payload_digest"].as_str().unwrap().len() == 64);

    // Read-only calls are not recorded.
    let (status, _) = http_get_bearer(&daemon.url("/api/v1/silences"), "tok-reader");
    assert_eq!(status, 200);
    std::thread::sleep(Duration::from_millis(200));
    let (status, body) = http_get_bearer(&daemon.url("/api/v1/audit"), "tok-reader");
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["count"], 1, "GET should not append audit rows: {body}");
}

#[test]
fn audit_endpoint_disabled_without_state_db() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let (status, body) = http_get(&daemon.url("/api/v1/audit"));
    assert_eq!(status, 503, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"], "audit trail disabled");
}

const SMALL_BODY_CONFIG: &str = r#"
daemon:
  api:
    audit:
      max_body_bytes: 16
    auth:
      tokens:
        - name: op
          role: operator
          token_env: TEST_TOKEN_OPERATOR
        - name: reader
          role: reader
          token_env: TEST_TOKEN_READER
"#;

#[test]
fn oversized_body_is_rejected_and_recorded() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");
    let config = temp_file(".yaml", SMALL_BODY_CONFIG);

    let daemon = DaemonProcess::spawn_http_with_args_env(
        rule.path().to_str().unwrap(),
        &[
            "--config",
            config.path().to_str().unwrap(),
            "--state-db",
            db.to_str().unwrap(),
        ],
        &[
            ("TEST_TOKEN_OPERATOR", "tok-operator"),
            ("TEST_TOKEN_READER", "tok-reader"),
        ],
    );

    // The silence body is well over the 16-byte cap, so the audit middleware
    // rejects it with 413 before the handler runs.
    let (status, body) = http_post_bearer(&daemon.url("/api/v1/silences"), "tok-operator", SILENCE);
    assert_eq!(status, 413, "{body}");

    std::thread::sleep(Duration::from_millis(200));

    let (status, body) = http_get_bearer(&daemon.url("/api/v1/audit"), "tok-reader");
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["count"], 1,
        "the rejected attempt should be recorded: {body}"
    );
    let entry = &v["entries"][0];
    assert_eq!(entry["status"], 413);
    assert!(
        entry["payload_digest"].is_null(),
        "no digest for a rejected body: {body}"
    );
}
