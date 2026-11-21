//! End-to-end coverage for daemons running named rulesets.

#![cfg(feature = "daemon")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::thread::sleep;
use std::time::{Duration, Instant};

use common::{DaemonProcess, http_get, http_post, rsigma};
use predicates::prelude::*;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rulesets_daemon")
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn fixture_copy() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    copy_tree(&fixtures(), dir.path());
    dir
}

fn spawn_config(dir: &Path, output: &Path, config: &str, extra: &[&str]) -> DaemonProcess {
    let mut command = StdCommand::new(common::rsigma_bin());
    command
        .current_dir(dir)
        .args([
            "engine",
            "daemon",
            "--config",
            config,
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
            "--output",
            &format!("file://{}", output.display()),
        ])
        .args(extra);
    DaemonProcess::spawn_command(command)
}

fn spawn(dir: &Path, output: &Path, extra: &[&str]) -> DaemonProcess {
    spawn_config(dir, output, "rsigma.yaml", extra)
}

fn wait_for_lines(path: &Path, count: usize, timeout: Duration) -> Vec<String> {
    let deadline = Instant::now() + timeout;
    loop {
        let lines: Vec<String> = fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect();
        if lines.len() >= count {
            return lines;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for {count} output lines in {}: {lines:?}",
                path.display()
            );
        }
        sleep(Duration::from_millis(50));
    }
}

fn wait_for_reload(daemon: &DaemonProcess, success: bool, timeout: Duration) {
    let needle = if success {
        "Rules and pipelines reloaded"
    } else {
        "Failed to reload rules"
    };
    let deadline = Instant::now() + timeout;
    loop {
        if daemon
            .stderr_lines()
            .iter()
            .any(|line| line.contains(needle))
        {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for '{needle}'; stderr: {:?}",
                daemon.stderr_lines()
            );
        }
        sleep(Duration::from_millis(100));
    }
}

fn metrics(daemon: &DaemonProcess) -> String {
    let (status, body) = http_get(&daemon.url("/metrics"));
    assert_eq!(status, 200);
    body
}

fn wait_for_metric(daemon: &DaemonProcess, line: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let body = metrics(daemon);
        if body.lines().any(|l| l == line) {
            return;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for metric line {line:?}: {body}");
        }
        sleep(Duration::from_millis(50));
    }
}

#[test]
fn http_events_fire_in_every_ruleset() {
    let dir = fixture_copy();
    let output = dir.path().join("out.ndjson");
    let daemon = spawn(dir.path(), &output, &[]);
    assert_eq!(
        http_post(
            &daemon.url("/api/v1/events"),
            r#"{"Image":"whoami","User":"alice"}"#,
        )
        .0,
        200
    );
    let lines = wait_for_lines(&output, 2, Duration::from_secs(5));
    assert!(
        lines
            .iter()
            .any(|line| line.contains("\"ruleset\":\"win_a\""))
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("\"ruleset\":\"win_b\""))
    );
}

#[test]
fn when_binds_cloud_events_and_reports_skips() {
    let dir = fixture_copy();
    let output = dir.path().join("out.ndjson");
    let daemon = spawn(dir.path(), &output, &[]);
    let windows = r#"{"Image":"whoami","User":"alice"}"#;
    assert_eq!(http_post(&daemon.url("/api/v1/events"), windows).0, 200);
    let lines = wait_for_lines(&output, 2, Duration::from_secs(5));
    assert!(
        lines
            .iter()
            .all(|line| !line.contains("\"ruleset\":\"cloud\"")),
        "{lines:?}"
    );
    wait_for_metric(
        &daemon,
        "rsigma_ruleset_events_skipped_total{ruleset=\"cloud\"} 1",
        Duration::from_secs(5),
    );

    assert_eq!(
        http_post(
            &daemon.url("/api/v1/events"),
            r#"{"eventVersion":"1.0","eventSource":"s3.amazonaws.com","eventID":"e1","userIdentity":{"name":"alice"}}"#,
        )
        .0,
        200
    );
    let lines = wait_for_lines(&output, 3, Duration::from_secs(5));
    assert!(lines[2].contains("\"ruleset\":\"cloud\""), "{lines:?}");
    let m = metrics(&daemon);
    assert!(
        m.lines()
            .any(|l| l == "rsigma_ruleset_events_skipped_total{ruleset=\"cloud\"} 1"),
        "a CloudTrail event must not count as skipped: {m}"
    );
}

#[test]
fn reload_reflects_overlay_changes_and_keeps_the_old_engine_on_failure() {
    let dir = fixture_copy();
    let output = dir.path().join("out.ndjson");
    let daemon = spawn(dir.path(), &output, &[]);
    let event = r#"{"Image":"whoami","User":"alice"}"#;
    http_post(&daemon.url("/api/v1/events"), event);
    let lines = wait_for_lines(&output, 2, Duration::from_secs(5));
    assert!(lines.iter().any(|line| line.contains("\"level\":\"high\"")));

    fs::write(
        dir.path().join("overlays/level.yml"),
        "- id: 11111111-1111-4111-8111-111111111111\n  set:\n    level: critical\n",
    )
    .unwrap();
    wait_for_reload(&daemon, true, Duration::from_secs(10));
    http_post(&daemon.url("/api/v1/events"), event);
    let lines = wait_for_lines(&output, 4, Duration::from_secs(5));
    assert!(
        lines[2..]
            .iter()
            .any(|line| line.contains("\"level\":\"critical\"")),
        "{lines:?}"
    );

    fs::write(dir.path().join("overlays/level.yml"), "title: [unclosed\n").unwrap();
    wait_for_reload(&daemon, false, Duration::from_secs(10));
    http_post(&daemon.url("/api/v1/events"), event);
    let lines = wait_for_lines(&output, 6, Duration::from_secs(5));
    assert!(
        lines[4..]
            .iter()
            .any(|line| line.contains("\"level\":\"critical\"")),
        "the old engine must keep serving after a failed reload: {lines:?}"
    );
    wait_for_metric(
        &daemon,
        "rsigma_reloads_failed_total 1",
        Duration::from_secs(5),
    );
}

#[test]
fn reload_follows_source_rule_edits() {
    let dir = fixture_copy();
    let output = dir.path().join("out.ndjson");
    let daemon = spawn(dir.path(), &output, &[]);
    let rule = dir.path().join("rules/win.yml");
    fs::write(
        &rule,
        fs::read_to_string(&rule)
            .unwrap()
            .replace("level: low", "level: medium"),
    )
    .unwrap();
    wait_for_reload(&daemon, true, Duration::from_secs(10));
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"Image":"whoami","User":"alice"}"#,
    );
    let lines = wait_for_lines(&output, 2, Duration::from_secs(5));
    let win_b = lines
        .iter()
        .find(|line| line.contains("\"ruleset\":\"win_b\""))
        .expect("win_b match");
    assert!(win_b.contains("\"level\":\"medium\""), "{win_b}");
}

#[test]
fn reload_follows_ruleset_pipeline_edits() {
    let dir = fixture_copy();
    fs::create_dir_all(dir.path().join("pipelines")).unwrap();
    let pipeline = dir.path().join("pipelines/map.yml");
    let mapping = |field: &str| {
        format!(
            "name: map\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      Image: {field}\n"
        )
    };
    fs::write(&pipeline, mapping("process.executable")).unwrap();
    fs::write(
        dir.path().join("pipe.yaml"),
        "rulesets:\n  mapped:\n    sources: [rules]\n    include:\n      - id: [11111111-1111-4111-8111-111111111111]\n    pipelines: [pipelines/map.yml]\ndaemon:\n  rulesets: [mapped]\n",
    )
    .unwrap();
    let output = dir.path().join("out.ndjson");
    let daemon = spawn_config(dir.path(), &output, "pipe.yaml", &[]);
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"process.executable":"whoami"}"#,
    );
    wait_for_lines(&output, 1, Duration::from_secs(5));

    fs::write(&pipeline, mapping("proc.exe")).unwrap();
    wait_for_reload(&daemon, true, Duration::from_secs(10));
    http_post(&daemon.url("/api/v1/events"), r#"{"proc.exe":"whoami"}"#);
    let lines = wait_for_lines(&output, 2, Duration::from_secs(5));
    assert!(lines[1].contains("\"ruleset\":\"mapped\""), "{lines:?}");
}

#[test]
fn status_and_rules_report_rulesets() {
    let dir = fixture_copy();
    let output = dir.path().join("out.ndjson");
    let daemon = spawn(dir.path(), &output, &[]);

    let (status, rules) = http_get(&daemon.url("/api/v1/rules"));
    assert_eq!(status, 200);
    assert!(rules.contains("\"rulesets\""), "{rules}");
    assert!(!rules.contains("\"rules_path\""), "{rules}");
    assert!(rules.contains("win_a"), "{rules}");

    let (status, body) = http_get(&daemon.url("/api/v1/status"));
    assert_eq!(status, 200);
    assert!(body.contains("\"rulesets\""), "{body}");
    assert!(body.contains("cloud"), "{body}");

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
        .stdout(predicate::str::contains("rulesets.win_a.detection_rules"))
        .stdout(
            predicate::str::is_match(r"rulesets\.cloud\.when_schemas\s+aws_cloudtrail").unwrap(),
        );
}

#[test]
fn metrics_families_appear_on_the_first_scrape() {
    let dir = fixture_copy();
    let output = dir.path().join("out.ndjson");
    let daemon = spawn(dir.path(), &output, &[]);
    let before = metrics(&daemon);
    for family in [
        "rsigma_ruleset_rules_loaded",
        "rsigma_ruleset_matches_total",
        "rsigma_ruleset_events_skipped_total",
    ] {
        assert!(before.contains(family), "{before}");
    }
    assert!(
        before.contains("rsigma_ruleset_rules_loaded{kind=\"detection\",ruleset=\"win_a\"}"),
        "{before}"
    );
}

#[test]
fn cli_errors_exit_three_or_clap_two() {
    rsigma()
        .current_dir(fixtures())
        .args([
            "engine",
            "daemon",
            "--ruleset",
            "win_a",
            "--rules",
            "rules",
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
        ])
        .assert()
        .failure()
        .code(2);

    rsigma()
        .current_dir(fixtures())
        .args([
            "engine",
            "daemon",
            "--config",
            "rsigma.yaml",
            "--ruleset",
            "win_a",
            "--ruleset",
            "win_b",
            "--schema-routing",
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
        ])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("exactly one"));

    let dir = fixture_copy();
    fs::write(
        dir.path().join("bad-when.yaml"),
        "rulesets:\n  cloud:\n    sources: [cloud]\ndaemon:\n  rulesets:\n    - name: cloud\n      when:\n        schemas: [nope]\n",
    )
    .unwrap();
    rsigma()
        .current_dir(dir.path())
        .args([
            "engine",
            "daemon",
            "--config",
            "bad-when.yaml",
            "--input",
            "http",
            "--api-addr",
            "127.0.0.1:0",
        ])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("nope"));
}

#[test]
fn correlation_state_survives_a_restart_per_ruleset() {
    let dir = fixture_copy();
    let state_db = dir.path().join("state.db");
    let first_out = dir.path().join("first.ndjson");
    let daemon = spawn_config(
        dir.path(),
        &first_out,
        "state.yaml",
        &[
            "--state-db",
            state_db.to_str().unwrap(),
            "--state-save-interval",
            "1",
        ],
    );
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"Image":"whoami","timestamp":"2026-01-01T00:00:00Z"}"#,
    );
    sleep(Duration::from_secs(2));
    drop(daemon);

    let second_out = dir.path().join("second.ndjson");
    let daemon = spawn_config(
        dir.path(),
        &second_out,
        "state.yaml",
        &["--state-db", state_db.to_str().unwrap()],
    );
    http_post(
        &daemon.url("/api/v1/events"),
        r#"{"Image":"whoami","timestamp":"2026-01-01T00:00:30Z"}"#,
    );
    let lines = wait_for_lines(&second_out, 1, Duration::from_secs(5));
    assert!(lines[0].contains("\"ruleset\":\"corr\""), "{lines:?}");
    assert!(
        lines[0].contains("\"correlation_type\":\"event_count\""),
        "{lines:?}"
    );
}

#[test]
fn batch_run_refuses_a_single_engine_snapshot_across_several_rulesets() {
    let dir = fixture_copy();
    let state_db = dir.path().join("state.db");
    let batch = |rules: &[&str]| {
        let mut cmd = rsigma();
        cmd.current_dir(dir.path())
            .args(["engine", "daemon"])
            .args(rules)
            .args([
                "--input",
                "stdin",
                "--api-addr",
                "127.0.0.1:0",
                "--state-db",
                state_db.to_str().unwrap(),
                "--no-detections",
            ]);
        cmd
    };

    // A single-engine snapshot with state cannot be split across several rulesets.
    batch(&["-r", "corr"])
        .write_stdin("{\"Image\":\"whoami\",\"timestamp\":\"2026-01-01T00:00:00Z\"}\n")
        .assert()
        .success();

    batch(&["--config", "rsigma.yaml"])
        .write_stdin("{\"Image\":\"whoami\",\"timestamp\":\"2026-01-01T00:00:30Z\"}\n")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("Stored state cannot be restored"));
}
