//! E2E tests for the API listener policy: a non-loopback TCP bind refuses to
//! serve plaintext without `--allow-plaintext` and refuses to serve
//! unauthenticated requests without `--allow-unauthenticated`, in every
//! build. Loopback and `unix://` addresses are exempt.

#![cfg(feature = "daemon")]

use crate::common;

use std::time::Duration;

use common::{
    DaemonProcess, SIMPLE_RULE, http_get, http_get_bearer, spawn_expect_failure, temp_file,
};

fn public_bind_args<'a>(rule: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "engine",
        "daemon",
        "-r",
        rule,
        "--input",
        "http",
        "--api-addr",
        "0.0.0.0:0",
    ];
    args.extend_from_slice(extra);
    args
}

#[test]
fn public_plaintext_bind_refuses_to_start() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let stderr = spawn_expect_failure(
        &public_bind_args(rule.path().to_str().unwrap(), &[]),
        Duration::from_secs(5),
    );
    assert!(
        stderr.contains("refusing to bind plaintext"),
        "expected plaintext refusal in stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("--allow-plaintext"),
        "stderr should mention the opt-out flag, got: {stderr}"
    );
}

#[test]
fn public_plaintext_bind_without_auth_refuses_to_start() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let stderr = spawn_expect_failure(
        &public_bind_args(rule.path().to_str().unwrap(), &["--allow-plaintext"]),
        Duration::from_secs(5),
    );
    assert!(
        stderr.contains("without authentication"),
        "expected unauthenticated-bind refusal in stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("--allow-unauthenticated"),
        "stderr should mention the opt-out flag, got: {stderr}"
    );
}

#[test]
fn loopback_bind_needs_no_opt_in() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());
    let (status, body) = http_get(&daemon.url("/healthz"));
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "ok");
}

#[test]
fn public_bind_with_both_opt_outs_starts() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(&public_bind_args(
        rule.path().to_str().unwrap(),
        &["--allow-plaintext", "--allow-unauthenticated"],
    ));
    let (status, _) = http_get(&daemon.url("/api/v1/status"));
    assert_eq!(status, 200, "the opted-out API is anonymous");
}

#[test]
fn public_bind_with_a_token_starts_and_enforces_it() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_with_env(
        &public_bind_args(
            rule.path().to_str().unwrap(),
            &["--allow-plaintext", "--api-token-env", "RSIGMA_TEST_TOKEN"],
        ),
        &[("RSIGMA_TEST_TOKEN", "s3cret")],
    );
    let (status, _) = http_get(&daemon.url("/api/v1/status"));
    assert_eq!(status, 401);
    let (status, _) = http_get_bearer(&daemon.url("/api/v1/status"), "s3cret");
    assert_eq!(status, 200);
}

/// Both opt-outs are also config keys, and `daemon.api.tls.allow_plaintext`
/// applies even in a build without `daemon-tls`.
#[test]
fn opt_outs_are_honored_from_the_config_file() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let config = temp_file(
        ".yaml",
        "daemon:\n  api:\n    allow_unauthenticated: true\n    tls:\n      allow_plaintext: true\n",
    );
    let daemon = DaemonProcess::spawn(&public_bind_args(
        rule.path().to_str().unwrap(),
        &["--config", config.path().to_str().unwrap()],
    ));
    let (status, _) = http_get(&daemon.url("/healthz"));
    assert_eq!(status, 200);
}
