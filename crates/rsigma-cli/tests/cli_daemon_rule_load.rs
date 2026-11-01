//! How the daemon treats rules that fail to parse, at startup and on reload.

#![cfg(feature = "daemon")]

mod common;

use common::{DaemonProcess, SIMPLE_RULE, http_get, poll_until, rsigma};
use predicates::str::contains;
use std::time::Duration;
use tempfile::TempDir;

const BROKEN_RULE: &str = r#"
title: Broken Rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|contains: "evil"
    condition: selection and (
"#;

fn rules_dir(rules: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    for (name, yaml) in rules {
        std::fs::write(dir.path().join(name), yaml).unwrap();
    }
    dir
}

fn metric(daemon: &DaemonProcess, name: &str) -> Option<i64> {
    let (_, body) = http_get(&daemon.url("/metrics"));
    body.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' ')?.parse().ok())
}

#[test]
fn startup_exits_when_every_rule_fails_to_parse() {
    let dir = rules_dir(&[("broken.yml", BROKEN_RULE)]);
    rsigma()
        .args(["engine", "daemon", "-r"])
        .arg(dir.path())
        .args(["--api-addr", "127.0.0.1:0"])
        .write_stdin("")
        .assert()
        .code(2)
        .stderr(contains("every rule failed to parse"));
}

#[test]
fn startup_with_strict_rules_exits_on_any_parse_error() {
    let dir = rules_dir(&[("good.yml", SIMPLE_RULE), ("broken.yml", BROKEN_RULE)]);
    rsigma()
        .args(["engine", "daemon", "-r"])
        .arg(dir.path())
        .args(["--api-addr", "127.0.0.1:0", "--strict-rules"])
        .write_stdin("")
        .assert()
        .code(2)
        .stderr(contains("strict rule loading"));
}

#[test]
fn strict_rules_config_key_applies() {
    let rules = rules_dir(&[("good.yml", SIMPLE_RULE), ("broken.yml", BROKEN_RULE)]);
    let config_dir = TempDir::new().unwrap();
    let config = config_dir.path().join("rsigma.yaml");
    std::fs::write(&config, "daemon:\n  engine:\n    strict_rules: true\n").unwrap();
    rsigma()
        .args(["engine", "daemon", "--config"])
        .arg(&config)
        .arg("-r")
        .arg(rules.path())
        .args(["--api-addr", "127.0.0.1:0"])
        .write_stdin("")
        .assert()
        .code(2)
        .stderr(contains("strict rule loading"));
}

#[test]
fn partial_load_reports_parse_errors_metric() {
    let dir = rules_dir(&[("good.yml", SIMPLE_RULE), ("broken.yml", BROKEN_RULE)]);
    let daemon = DaemonProcess::spawn_http(dir.path().to_str().unwrap());

    assert_eq!(metric(&daemon, "rsigma_detection_rules_loaded"), Some(1));
    assert_eq!(metric(&daemon, "rsigma_rule_parse_errors"), Some(1));
}

#[test]
fn reload_keeps_rules_when_every_rule_fails_to_parse() {
    let dir = rules_dir(&[("good.yml", SIMPLE_RULE)]);
    let daemon = DaemonProcess::spawn_http(dir.path().to_str().unwrap());
    assert_eq!(metric(&daemon, "rsigma_detection_rules_loaded"), Some(1));

    std::fs::write(dir.path().join("good.yml"), BROKEN_RULE).unwrap();
    let failed = poll_until(Duration::from_secs(10), || {
        metric(&daemon, "rsigma_reloads_failed_total").filter(|n| *n >= 1)
    });
    assert!(failed.is_some(), "the reload should fail");

    assert_eq!(metric(&daemon, "rsigma_detection_rules_loaded"), Some(1));
    assert_eq!(metric(&daemon, "rsigma_rule_parse_errors"), Some(0));
    let (status, body) = http_get(&daemon.url("/readyz"));
    assert_eq!(status, 200, "{body}");
}
