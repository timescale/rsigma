//! Project config files (`.rsigmarc`, `./rsigma.yaml`) cannot set
//! security-sensitive keys; `--config` and the user config still can.
//!
//! Every child runs with an empty `XDG_CONFIG_HOME` so the developer's own
//! `~/.config/rsigma/config.yaml` cannot leak into the result.

#![cfg(feature = "mcp")]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use common::{rsigma, rsigma_bin};
use predicates::prelude::*;

/// A project file that tries to point the MCP server at a daemon and turn on
/// the mutating operate tools.
const OPERATE_GATES: &str =
    "mcp:\n  daemon_url: http://127.0.0.1:9\n  allow_operate_writes: true\n";

fn ignored(key: &str) -> String {
    format!("warning: ignoring '{key}' from project config")
}

/// Run `rsigma mcp serve` over stdio in `cwd`, list its tools, and return the
/// tool names plus everything it wrote to stderr.
fn list_tools(cwd: &Path, xdg: &Path, extra_args: &[&str]) -> (Vec<String>, String) {
    let mut child = Command::new(rsigma_bin())
        .args(["mcp", "serve"])
        .args(extra_args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rsigma mcp serve");

    let mut stdin = child.stdin.take().unwrap();
    for message in [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"trust-test","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    ] {
        writeln!(stdin, "{message}").unwrap();
    }

    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
                let _ = tx.send(Err(line));
                return;
            };
            if value["id"] == 2 {
                let _ = tx.send(Ok(value));
                return;
            }
        }
    });
    let response = rx.recv_timeout(Duration::from_secs(20));
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let response = response
        .unwrap_or_else(|_| panic!("no tools/list response; stderr: {stderr}"))
        .unwrap_or_else(|line| panic!("non-JSON line on the stdio transport: {line}"));

    let names = response["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list failed: {response}"))
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect();
    (names, stderr)
}

#[test]
fn rsigmarc_above_cwd_cannot_enable_operate_tools() {
    let project = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join(".rsigmarc"), OPERATE_GATES).unwrap();
    let nested = project.path().join("rules/windows");
    std::fs::create_dir_all(&nested).unwrap();

    let (tools, stderr) = list_tools(&nested, xdg.path(), &[]);

    assert!(tools.iter().any(|t| t == "lint_rules"), "{tools:?}");
    assert!(!tools.iter().any(|t| t == "list_silences"), "{tools:?}");
    assert!(!tools.iter().any(|t| t == "create_silence"), "{tools:?}");
    assert!(stderr.contains(&ignored("mcp.daemon_url")), "{stderr}");
    assert!(
        stderr.contains(&ignored("mcp.allow_operate_writes")),
        "{stderr}"
    );
}

#[test]
fn rsigma_yaml_cannot_enable_operate_tools() {
    let project = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("rsigma.yaml"), OPERATE_GATES).unwrap();

    let (tools, stderr) = list_tools(project.path(), xdg.path(), &[]);

    assert!(!tools.iter().any(|t| t == "create_silence"), "{tools:?}");
    assert!(stderr.contains(&ignored("mcp.daemon_url")), "{stderr}");
}

#[test]
fn explicit_config_enables_operate_tools() {
    let project = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let config = project.path().join("rsigma.yaml");
    std::fs::write(&config, OPERATE_GATES).unwrap();

    let (tools, stderr) = list_tools(
        project.path(),
        xdg.path(),
        &["--config", config.to_str().unwrap()],
    );

    assert!(tools.iter().any(|t| t == "list_silences"), "{tools:?}");
    assert!(tools.iter().any(|t| t == "create_silence"), "{tools:?}");
    assert!(!stderr.contains("warning: ignoring"), "{stderr}");
}

#[test]
fn user_config_enables_operate_tools() {
    let project = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    std::fs::create_dir(xdg.path().join("rsigma")).unwrap();
    std::fs::write(xdg.path().join("rsigma/config.yaml"), OPERATE_GATES).unwrap();

    let (tools, stderr) = list_tools(project.path(), xdg.path(), &[]);

    assert!(tools.iter().any(|t| t == "create_silence"), "{tools:?}");
    assert!(!stderr.contains("warning: ignoring"), "{stderr}");
}

#[test]
fn project_config_cannot_unconfine_the_http_transport() {
    let project = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("rsigma.yaml"),
        "mcp:\n  allow_unconfined_paths: true\n",
    )
    .unwrap();
    rsigma()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .args(["mcp", "serve", "--http", "127.0.0.1:0"])
        .timeout(Duration::from_secs(10))
        .assert()
        .code(3)
        .stderr(predicate::str::contains(ignored(
            "mcp.allow_unconfined_paths",
        )))
        .stderr(predicate::str::contains(
            "refusing to serve --http without --rules-dir",
        ));
}

#[test]
fn config_validate_reports_ignored_keys() {
    let project = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join(".rsigmarc"), OPERATE_GATES).unwrap();

    let output = rsigma()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .args(["config", "validate", "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let keys: Vec<&str> = envelope["ignored_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["key"].as_str().unwrap())
        .collect();
    assert_eq!(keys, ["mcp.daemon_url", "mcp.allow_operate_writes"]);
    assert!(
        envelope["ignored_keys"][0]["file"]
            .as_str()
            .unwrap()
            .ends_with(".rsigmarc")
    );

    rsigma()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .args(["config", "validate"])
        .assert()
        .success()
        .stderr(predicate::str::contains(ignored("mcp.daemon_url")));
}

#[test]
fn config_show_omits_ignored_keys() {
    let project = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("rsigma.yaml"), OPERATE_GATES).unwrap();

    let output = rsigma()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .args(["config", "show", "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        envelope["config"]["mcp"]["daemon_url"].is_null(),
        "{envelope}"
    );
    assert_eq!(envelope["ignored_keys"][0]["key"], "mcp.daemon_url");
}

#[test]
fn project_lint_config_cannot_read_outside_the_project() {
    let project = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret.txt");
    std::fs::write(&secret, "SECRET-TOKEN-abc123\n").unwrap();
    std::fs::write(
        project.path().join("rsigma.yaml"),
        format!("mcp:\n  lint_config: {}\n", secret.display()),
    )
    .unwrap();

    let (tools, stderr) = list_tools(project.path(), xdg.path(), &[]);
    assert!(!tools.is_empty());
    assert!(stderr.contains(&ignored("mcp.lint_config")), "{stderr}");
    assert!(!stderr.contains("SECRET-TOKEN"), "{stderr}");
}
