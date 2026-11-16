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
fn stdio_resolves_a_ruleset_from_the_config() {
    let cwd = tempfile::tempdir().unwrap();
    let rules = cwd.path().join("rules");
    std::fs::create_dir(&rules).unwrap();
    std::fs::write(
        rules.join("rule.yml"),
        r#"title: Whoami Execution
id: 8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a
status: test
description: Detects whoami
author: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: medium
tags:
    - attack.execution
"#,
    )
    .unwrap();
    std::fs::write(
        cwd.path().join("rsigma.yaml"),
        r#"rulesets:
  overlay:
    sources:
      - rules/rule.yml
    overlays:
      - id: 8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a
        set:
          custom_attributes:
            rsigma.exemplars:
              - name: overlaid
                expect: match
                event:
                  CommandLine: cmd /c whoami
"#,
    )
    .unwrap();

    let stdin = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"test_exemplars","arguments":{"ruleset":"overlay"}}}"#,
        "\n",
    );

    let output = rsigma()
        .current_dir(cwd.path())
        .args(["mcp", "serve", "--config", "rsigma.yaml", "--rules-dir"])
        .arg(&rules)
        .write_stdin(stdin)
        .timeout(Duration::from_secs(10))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let response: serde_json::Value = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value["id"] == serde_json::json!(2))
        .unwrap_or_else(|| panic!("no tool response in {stdout}"));
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let report: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(report["ok"], serde_json::json!(true));
    assert_eq!(report["report"]["results"][0]["name"], "overlaid");
    assert_eq!(
        report["report"]["results"][0]["passed"],
        serde_json::json!(true)
    );
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
