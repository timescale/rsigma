//! Project config files (`.rsigmarc`, `./rsigma.yaml`) cannot point
//! `engine daemon` at enrichers, sinks, or sources, or weaken its listener
//! guards; the same file passed with `--config` still can.
//!
//! Every child runs with an empty `XDG_CONFIG_HOME` so the developer's own
//! `~/.config/rsigma/config.yaml` cannot leak into the result.

#![cfg(all(feature = "daemon", unix))]

mod common;

use std::path::Path;
use std::process::Command as StdCommand;
use std::time::Duration;

use common::{DaemonProcess, http_post, poll_until, rsigma, rsigma_bin};
use predicates::prelude::*;

const RULE: &str = r#"
title: Encoded PowerShell
id: 00000000-0000-0000-0000-0000000000ab
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "powershell -enc"
    condition: selection
level: high
"#;

/// A checkout whose `rsigma.yaml` loads a `command` enricher that creates
/// `marker` when it runs. Returns the checkout and the marker path.
fn checkout_with_command_enricher() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker");
    std::fs::write(dir.path().join("rule.yml"), RULE).unwrap();
    std::fs::write(
        dir.path().join("enrich.yml"),
        format!(
            "enrichers:\n  - id: probe\n    kind: detection\n    type: command\n    inject_field: probe\n    command: [\"/usr/bin/touch\", \"{}\"]\n    on_error: skip\n",
            marker.display()
        ),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("rsigma.yaml"),
        "daemon:\n  enrichers: ./enrich.yml\n",
    )
    .unwrap();
    (dir, marker)
}

/// Start the daemon in `cwd`, send one matching event, and wait until its
/// detection reaches the file sink, so every enricher has run by the time
/// this returns.
fn detect_once(cwd: &Path, xdg: &Path, extra_args: &[&str]) -> DaemonProcess {
    let output = cwd.join("detections.ndjson");
    let mut command = StdCommand::new(rsigma_bin());
    command
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .args(["engine", "daemon", "-r", "rule.yml", "--input", "http"])
        .args(["--api-addr", "127.0.0.1:0"])
        .arg("--output")
        .arg(format!("file://{}", output.display()))
        .args(extra_args);
    let daemon = DaemonProcess::spawn_command(command);

    let (status, _) = http_post(
        &daemon.url("/api/v1/events"),
        r#"{"CommandLine":"powershell -enc QQA="}"#,
    );
    assert_eq!(status, 200);
    poll_until(Duration::from_secs(10), || {
        let text = std::fs::read_to_string(&output).ok()?;
        text.lines().any(|line| !line.is_empty()).then_some(())
    })
    .expect("detection never reached the file sink");
    daemon
}

#[test]
fn rsigma_yaml_cannot_load_a_command_enricher() {
    let (dir, marker) = checkout_with_command_enricher();
    let xdg = tempfile::tempdir().unwrap();
    let daemon = detect_once(dir.path(), xdg.path(), &[]);

    assert!(!marker.exists(), "the planted command enricher ran");
    let stderr = daemon.stderr_lines().join("\n");
    assert!(
        stderr.contains("warning: ignoring 'daemon.enrichers' from project config"),
        "{stderr}"
    );
}

#[test]
fn explicit_config_loads_the_command_enricher() {
    let (dir, marker) = checkout_with_command_enricher();
    let xdg = tempfile::tempdir().unwrap();
    let _daemon = detect_once(dir.path(), xdg.path(), &["--config", "rsigma.yaml"]);

    poll_until(Duration::from_secs(5), || marker.exists().then_some(()))
        .expect("the enricher from --config never ran");
}

#[test]
fn project_config_cannot_open_an_unauthenticated_public_listener() {
    let dir = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rule.yml"), RULE).unwrap();
    std::fs::write(
        dir.path().join(".rsigmarc"),
        "daemon:\n  api:\n    addr: 0.0.0.0:0\n    allow_unauthenticated: true\n    tls:\n      allow_plaintext: true\n",
    )
    .unwrap();

    rsigma()
        .current_dir(dir.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .args(["engine", "daemon", "-r", "rule.yml", "--input", "http"])
        .timeout(Duration::from_secs(10))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "ignoring 'daemon.api.allow_unauthenticated' from project config",
        ))
        .stderr(predicate::str::contains(
            "ignoring 'daemon.api.tls.allow_plaintext' from project config",
        ))
        .stderr(predicate::str::contains(
            "refusing to bind plaintext on non-loopback address",
        ));
}
