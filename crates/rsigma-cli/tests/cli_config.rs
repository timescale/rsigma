//! Integration tests for the `rsigma config` group and config-driven commands.
//!
//! These exercise the real binary end to end (file IO, exit codes, JSON output,
//! and the config -> command flow). Per-field precedence is covered by unit
//! tests in `commands::{daemon,eval}` and `config::resolve`, so it is not
//! duplicated here. Explicit `--config` keeps every test hermetic (it bypasses
//! the system/user discovery chain).

mod common;

use common::{rsigma, temp_file};
use predicates::prelude::*;

const RULE: &str = "title: Test\nlogsource:\n  category: test\ndetection:\n  sel:\n    foo: bar\n  condition: sel\n";

#[test]
fn init_writes_template_that_validates_clean() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("rsigma.yaml");

    rsigma()
        .args(["config", "init", "-o", cfg.to_str().unwrap()])
        .assert()
        .success();
    assert!(cfg.exists(), "init should write the template");

    rsigma()
        .args(["config", "validate", "-c", cfg.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Config is valid."));

    let output = rsigma()
        .args([
            "config",
            "validate",
            "-c",
            cfg.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(v["ok"], serde_json::json!(true));
    assert!(
        v["unknown_keys"].as_array().unwrap().is_empty(),
        "the committed template must not carry unknown keys"
    );
}

#[test]
fn init_refuses_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("rsigma.yaml");
    std::fs::write(&cfg, "version: 1\n").unwrap();

    rsigma()
        .args(["config", "init", "-o", cfg.to_str().unwrap()])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("refusing to overwrite"));

    rsigma()
        .args(["config", "init", "-o", cfg.to_str().unwrap(), "--force"])
        .assert()
        .success();
}

#[test]
fn validate_warns_unknown_keys_and_strict_fails() {
    let cfg = temp_file(".yaml", "version: 1\nbogus_key: true\n");
    let path = cfg.path().to_str().unwrap();

    rsigma()
        .args(["config", "validate", "-c", path])
        .assert()
        .success()
        .stderr(predicate::str::contains("unknown key 'bogus_key'"));

    rsigma()
        .args(["config", "validate", "-c", path, "--strict"])
        .assert()
        .failure()
        .code(3);
}

#[test]
fn validate_missing_explicit_file_errors() {
    rsigma()
        .args([
            "config",
            "validate",
            "-c",
            "/tmp/no_such_rsigma_config.yaml",
        ])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("could not read config"));
}

#[test]
fn schema_emits_json_schema() {
    rsigma()
        .args(["config", "schema"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"$schema\""))
        .stdout(predicate::str::contains("RsigmaConfigPartial"));
}

#[test]
fn show_json_reports_value_sources() {
    let cfg = temp_file(".yaml", "daemon:\n  api:\n    addr: \"9.9.9.9:1\"\n");
    let output = rsigma()
        .args([
            "config",
            "show",
            "-c",
            cfg.path().to_str().unwrap(),
            "--for",
            "daemon",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        v["config"]["daemon"]["api"]["addr"],
        serde_json::json!("9.9.9.9:1")
    );
    assert_eq!(v["sources"]["daemon.api.addr"], serde_json::json!("file"));
    // A value with no file override is reported as a default.
    assert_eq!(
        v["sources"]["daemon.input.batch_size"],
        serde_json::json!("default")
    );
}

#[test]
fn path_prints_explicit_config() {
    let cfg = temp_file(".yaml", "version: 1\n");
    rsigma()
        .args(["config", "path", "-c", cfg.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(cfg.path().to_str().unwrap()));
}

#[test]
fn eval_reads_rules_from_config() {
    let dir = tempfile::tempdir().unwrap();
    let rule = dir.path().join("rule.yml");
    std::fs::write(&rule, RULE).unwrap();
    let cfg = dir.path().join("rsigma.yaml");
    std::fs::write(&cfg, format!("eval:\n  rules: {}\n", rule.display())).unwrap();

    rsigma()
        .args(["engine", "eval", "--config", cfg.to_str().unwrap()])
        .write_stdin("{\"foo\":\"bar\"}\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"rule_title\":\"Test\""));
}

#[test]
fn eval_flag_overrides_config_rules() {
    let dir = tempfile::tempdir().unwrap();
    let rule = dir.path().join("rule.yml");
    std::fs::write(&rule, RULE).unwrap();
    // The config points rules at a bogus path; the explicit --rules must win.
    let cfg = dir.path().join("rsigma.yaml");
    std::fs::write(&cfg, "eval:\n  rules: /nonexistent/bogus/path\n").unwrap();

    rsigma()
        .args([
            "engine",
            "eval",
            "--config",
            cfg.to_str().unwrap(),
            "--rules",
            rule.to_str().unwrap(),
        ])
        .write_stdin("{\"foo\":\"bar\"}\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"rule_title\":\"Test\""));
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_dry_run_uses_config_values() {
    let cfg = temp_file(
        ".yaml",
        "daemon:\n  rules: /tmp/myrules\n  api:\n    addr: \"1.2.3.4:5\"\n",
    );
    rsigma()
        .args([
            "engine",
            "daemon",
            "--config",
            cfg.path().to_str().unwrap(),
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("rules: /tmp/myrules"))
        .stdout(predicate::str::contains("addr: 1.2.3.4:5"));
}
