//! `rsigma mcp serve` startup checks for path confinement.

#![cfg(feature = "mcp")]

mod common;

use std::time::Duration;

use common::rsigma;
use predicates::prelude::*;

const UNCONFINED_WARNING: &str = "--rules-dir is not set";

#[test]
fn http_without_rules_dir_refuses_to_start() {
    let cwd = tempfile::tempdir().unwrap();
    rsigma()
        .current_dir(cwd.path())
        .args(["mcp", "serve", "--http", "127.0.0.1:0"])
        .timeout(Duration::from_secs(10))
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "refusing to serve --http without --rules-dir",
        ));
}

#[test]
fn http_with_allow_unconfined_paths_starts() {
    let cwd = tempfile::tempdir().unwrap();
    let output = rsigma()
        .current_dir(cwd.path())
        .args([
            "mcp",
            "serve",
            "--http",
            "127.0.0.1:0",
            "--allow-unconfined-paths",
        ])
        .timeout(Duration::from_secs(2))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("MCP Streamable HTTP server listening"),
        "{stderr}"
    );
    assert!(!stderr.contains(UNCONFINED_WARNING), "{stderr}");
}

#[test]
fn http_with_allow_unconfined_paths_from_config_starts() {
    let cwd = tempfile::tempdir().unwrap();
    let config = cwd.path().join("mcp.yaml");
    std::fs::write(&config, "mcp:\n  allow_unconfined_paths: true\n").unwrap();
    let output = rsigma()
        .current_dir(cwd.path())
        .args(["mcp", "serve", "--http", "127.0.0.1:0", "--config"])
        .arg(&config)
        .timeout(Duration::from_secs(2))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("MCP Streamable HTTP server listening"),
        "{stderr}"
    );
}

#[test]
fn http_with_rules_dir_starts() {
    let cwd = tempfile::tempdir().unwrap();
    let rules = tempfile::tempdir().unwrap();
    let output = rsigma()
        .current_dir(cwd.path())
        .args(["mcp", "serve", "--http", "127.0.0.1:0", "--rules-dir"])
        .arg(rules.path())
        .timeout(Duration::from_secs(2))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("MCP Streamable HTTP server listening"),
        "{stderr}"
    );
}

#[test]
fn stdio_without_rules_dir_warns() {
    let cwd = tempfile::tempdir().unwrap();
    rsigma()
        .current_dir(cwd.path())
        .args(["mcp", "serve"])
        .write_stdin("")
        .timeout(Duration::from_secs(10))
        .assert()
        .stderr(predicate::str::contains(UNCONFINED_WARNING));
}

#[test]
fn stdio_with_rules_dir_does_not_warn() {
    let cwd = tempfile::tempdir().unwrap();
    let rules = tempfile::tempdir().unwrap();
    rsigma()
        .current_dir(cwd.path())
        .args(["mcp", "serve", "--rules-dir"])
        .arg(rules.path())
        .write_stdin("")
        .timeout(Duration::from_secs(10))
        .assert()
        .stderr(predicate::str::contains(UNCONFINED_WARNING).not());
}
