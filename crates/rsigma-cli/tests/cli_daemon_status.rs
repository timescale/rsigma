//! E2E tests for `rsigma engine status`, the client that queries a running
//! daemon's `/api/v1/status` endpoint and renders it through the shared
//! output layer.

#![cfg(feature = "daemon")]

mod common;

use common::{DaemonProcess, SIMPLE_RULE, rsigma, temp_file};
use predicates::prelude::*;

#[test]
fn status_default_ndjson_against_running_daemon() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    // Piped stdout (not a TTY) defaults to a single NDJSON line.
    rsigma()
        .args(["engine", "status", "--addr", daemon.api_addr()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\":\"running\""))
        .stdout(predicate::str::contains("\"detection_rules\":1"));
}

#[test]
fn status_table_format() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    rsigma()
        .args([
            "engine",
            "status",
            "--addr",
            daemon.api_addr(),
            "--output-format",
            "table",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("METRIC"))
        .stdout(predicate::str::contains("detection_rules"))
        .stdout(predicate::str::contains("uptime"));
}

#[test]
fn status_json_format() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    rsigma()
        .args([
            "engine",
            "status",
            "--addr",
            daemon.api_addr(),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\""))
        .stdout(predicate::str::contains("running"));
}

#[test]
fn status_unreachable_daemon_exits_config_error() {
    // Port 1 is reserved and never has the daemon listening, so the connection
    // is refused and the command exits with the config-error code.
    rsigma()
        .args(["engine", "status", "--addr", "127.0.0.1:1"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("could not reach"));
}
