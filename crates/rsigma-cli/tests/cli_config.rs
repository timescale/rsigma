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
fn validate_fails_on_unknown_keys_with_or_without_strict() {
    let cfg = temp_file(".yaml", "version: 1\nbogus_key: true\n");
    let path = cfg.path().to_str().unwrap();

    rsigma()
        .args(["config", "validate", "-c", path])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("error: unknown key 'bogus_key'"))
        .stderr(predicate::str::contains("1 unknown key(s) found"));

    rsigma()
        .args(["config", "validate", "-c", path, "--strict"])
        .assert()
        .failure()
        .code(3);

    let output = rsigma()
        .args(["config", "validate", "-c", path, "--format", "json"])
        .assert()
        .failure()
        .code(3)
        .get_output()
        .stdout
        .clone();
    let envelope: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(envelope["ok"], serde_json::json!(false));
    assert_eq!(envelope["unknown_keys"][0]["key"], "bogus_key");
}

#[test]
fn strict_flag_is_hidden_from_help() {
    rsigma()
        .args(["config", "validate", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--strict").not());
}

#[test]
fn unknown_key_stops_a_command_that_reads_the_config() {
    let cfg = temp_file(
        ".yaml",
        "version: 1\nbogus_key: true\neval:\n  bogus_nested: 1\n",
    );
    let rule = temp_file(".yml", RULE);

    rsigma()
        .args([
            "engine",
            "eval",
            "--config",
            cfg.path().to_str().unwrap(),
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"foo": "bar"}"#,
        ])
        .assert()
        .failure()
        .code(3)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "error: unknown config key 'bogus_key'",
        ))
        .stderr(predicate::str::contains(
            "error: unknown config key 'eval.bogus_nested'",
        ));
}

#[test]
fn config_validate_accepts_daemon_thread_sizing() {
    let cfg = temp_file(
        ".yaml",
        "version: 1\ndaemon:\n  runtime:\n    worker_threads: 2\n    detect_threads: 4\n    detect_inflight: 2\n",
    );
    rsigma()
        .args(["config", "validate", "-c", cfg.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Config is valid."));
}

#[cfg(feature = "daemon")]
#[test]
fn a_zero_buffer_size_in_the_config_stops_the_daemon() {
    let cfg = temp_file(
        ".yaml",
        "version: 1\ndaemon:\n  input:\n    buffer_size: 0\n",
    );
    let rule = temp_file(".yml", RULE);

    rsigma()
        .args([
            "engine",
            "daemon",
            "--config",
            cfg.path().to_str().unwrap(),
            "--rules",
            rule.path().to_str().unwrap(),
            "--api-addr",
            "127.0.0.1:0",
        ])
        .write_stdin("")
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains(
            "Invalid daemon.input.buffer_size 0: must be at least 1",
        ));
}

#[test]
fn show_still_prints_a_config_with_unknown_keys() {
    let cfg = temp_file(".yaml", "version: 1\nbogus_key: true\n");

    rsigma()
        .args(["config", "show", "-c", cfg.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("daemon"));
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
        .stdout(predicate::str::contains("RsigmaConfigPartial"))
        .stdout(predicate::str::contains("\"rulesets\""))
        .stdout(predicate::str::contains("RulesetSpec"));
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

#[cfg(feature = "daemon")]
#[test]
fn daemon_egress_policy_reads_from_config() {
    // The engine.egress_policy config key must reach the daemon. Use
    // `--dry-run` so we never actually start a daemon (the test runner
    // would otherwise spin forever on stdin).
    let cfg = temp_file(
        ".yaml",
        "daemon:\n  rules: /tmp/myrules\n  engine:\n    egress_policy: strict\n",
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
        .stdout(predicate::str::contains("egress_policy: strict"));
}

#[cfg(feature = "daemon")]
#[test]
fn daemon_rejects_invalid_egress_policy_value() {
    // clap's `value_parser = [...]` should reject anything off the
    // allowed list before we even hit the daemon's own check.
    rsigma()
        .args([
            "engine",
            "daemon",
            "--rules",
            "/tmp/nope",
            "--egress-policy",
            "yolo",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("egress-policy"));
}

#[cfg(feature = "daemon")]
#[test]
fn invalid_global_output_format_in_config_warns_then_falls_back() {
    // Bad `global.output_format` used to be ignored silently. Now the
    // CLI prints a stderr warning and reverts to the TTY-aware
    // default. The command itself still succeeds because the bad
    // value is treated as "unset" by `warn_invalid_global_output`.
    // Use `engine daemon --dry-run` because it accepts `--config` and
    // exits without trying to bind any sockets.
    let cfg = temp_file(
        ".yaml",
        "global:\n  output_format: xml\ndaemon:\n  rules: /tmp/myrules\n",
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
        .stderr(
            predicate::str::contains("invalid global.output_format 'xml'")
                .and(predicate::str::contains("ignoring value")),
        );
}

#[cfg(feature = "daemon")]
#[test]
fn invalid_global_color_in_config_warns_then_falls_back() {
    let cfg = temp_file(
        ".yaml",
        "global:\n  color: rainbow\ndaemon:\n  rules: /tmp/myrules\n",
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
        .stderr(predicate::str::contains("invalid global.color 'rainbow'"));
}

#[cfg(feature = "daemon")]
#[test]
fn valid_global_output_in_config_emits_no_warning() {
    let cfg = temp_file(
        ".yaml",
        "global:\n  output_format: ndjson\n  color: never\ndaemon:\n  rules: /tmp/myrules\n",
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
        .stderr(
            predicate::str::contains("invalid global.output_format")
                .not()
                .and(predicate::str::contains("invalid global.color").not()),
        );
}

#[test]
fn rulesets_merge_by_name_across_layers() {
    let project = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(xdg.path().join("rsigma")).unwrap();
    std::fs::write(
        xdg.path().join("rsigma/config.yaml"),
        "rulesets:\n  shared:\n    description: from the user config\n    sources: [user-rules]\n  user_only:\n    sources: [user-only]\n",
    )
    .unwrap();
    std::fs::write(
        project.path().join("rsigma.yaml"),
        "rulesets:\n  shared:\n    sources: [project-rules]\n  project_only:\n    sources: [project-only]\n",
    )
    .unwrap();

    let output = rsigma()
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .args(["config", "show", "--for", "rulesets", "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let rulesets = &envelope["config"]["rulesets"];
    assert_eq!(
        rulesets["shared"]["sources"],
        serde_json::json!(["project-rules"])
    );
    assert!(
        rulesets["shared"].get("description").is_none(),
        "the project entry replaces the user entry whole: {rulesets}"
    );
    assert_eq!(
        rulesets["user_only"]["sources"],
        serde_json::json!(["user-only"])
    );
    assert_eq!(
        rulesets["project_only"]["sources"],
        serde_json::json!(["project-only"])
    );
    assert_eq!(
        envelope["sources"]["rulesets.shared.sources"],
        serde_json::json!("file")
    );
}

#[test]
fn validate_reports_semantic_errors_by_config_path() {
    let cfg = temp_file(
        ".yaml",
        "rulesets:\n  local:\n    sources: [./rules]\neval:\n  rulesets: [local, nope]\nconvert:\n  defaults:\n    target: postgres\n  groups:\n    a:\n      ruleset: local\n      output: build/a.sql\n    b:\n      ruleset: local\n      output: ./build/a.sql\n    c:\n      ruleset: missing\n      output: build/a.sql.manifest.json\n",
    );
    let output = rsigma()
        .args([
            "config",
            "validate",
            "-c",
            cfg.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .failure()
        .code(3)
        .get_output()
        .stdout
        .clone();
    let envelope: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let errors: Vec<(String, String)> = envelope["semantic_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|error| {
            (
                error["path"].as_str().unwrap().to_string(),
                error["message"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let expected = [
        (
            "eval.rulesets",
            "eval.rulesets names unknown ruleset 'nope'",
        ),
        (
            "convert.groups.c",
            "convert group 'c' names unknown ruleset 'missing'",
        ),
        (
            "convert.groups.b",
            "convert groups 'a' and 'b' both write ./build/a.sql",
        ),
        (
            "convert.groups.c",
            "convert groups 'a' and 'c' both write build/a.sql.manifest.json",
        ),
    ];
    assert_eq!(
        errors,
        expected
            .iter()
            .map(|(path, message)| (path.to_string(), message.to_string()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn validate_rejects_an_unknown_selector_key() {
    let cfg = temp_file(
        ".yaml",
        "rulesets:\n  local:\n    sources: [./rules]\n    include:\n      - tagz: [attack.t1059]\n",
    );
    let path = cfg.path().to_str().unwrap();

    rsigma()
        .args(["config", "validate", "-c", path])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("unknown key 'tagz'"))
        .stderr(predicate::str::contains("did you mean 'tags'"));

    let output = rsigma()
        .args(["config", "validate", "-c", path, "--format", "json"])
        .assert()
        .failure()
        .code(3)
        .get_output()
        .stdout
        .clone();
    let envelope: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(envelope["ok"], serde_json::json!(false));
    let errors = envelope["semantic_errors"].as_array().unwrap();
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(
        errors
            .iter()
            .all(|error| error["path"] == serde_json::json!("rulesets.local"))
    );
    assert!(errors.iter().any(|error| {
        error["message"]
            .as_str()
            .unwrap()
            .contains("unknown key 'tagz'")
    }));
}

#[test]
fn validate_rejects_a_bad_ruleset_name() {
    let cfg = temp_file(".yaml", "rulesets:\n  Bad-Name:\n    sources: [./rules]\n");
    rsigma()
        .args(["config", "validate", "-c", cfg.path().to_str().unwrap()])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("invalid ruleset name 'Bad-Name'"));
}

#[test]
fn show_rulesets_section() {
    let cfg = temp_file(
        ".yaml",
        "rulesets:\n  local:\n    sources: [./rules]\n    include:\n      - tags: [attack.t1059*]\n",
    );
    let output = rsigma()
        .args([
            "config",
            "show",
            "-c",
            cfg.path().to_str().unwrap(),
            "--for",
            "rulesets",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let envelope: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        envelope["config"]["rulesets"]["local"]["sources"],
        serde_json::json!(["./rules"])
    );
    assert_eq!(
        envelope["config"]["rulesets"]["local"]["include"][0]["tags"],
        serde_json::json!(["attack.t1059*"])
    );
    assert_eq!(
        envelope["sources"]["rulesets.local.sources"],
        serde_json::json!("file")
    );
    assert!(
        envelope["sources"]
            .as_object()
            .unwrap()
            .keys()
            .all(|key| key.starts_with("rulesets.")),
        "only the rulesets section should be shown"
    );
}

/// Top-level `rsigma.yaml` sections.
const CONFIG_SECTIONS: &[&str] = &[
    "version",
    "global",
    "daemon",
    "eval",
    "backtest",
    "coverage",
    "scorecard",
    "visibility",
    "doc",
    "hygiene",
    "mcp",
    "rulesets",
    "convert",
];

/// Fenced `yaml` and `yml` blocks in the docs and READMEs whose top-level
/// keys are all `rsigma.yaml` sections, as `(path:line, text)`.
fn documented_config_blocks(root: &std::path::Path) -> Vec<(String, String)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for path in entries.flatten().map(|e| e.path()) {
            if path.is_dir() {
                if path.file_name().is_none_or(|n| n != "node_modules") {
                    walk(&path, out);
                }
            } else if path.extension().is_some_and(|e| e == "md") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(&root.join("docs/content"), &mut files);
    walk(&root.join("skills"), &mut files);
    walk(&root.join("crates"), &mut files);
    files.push(root.join("README.md"));
    files.sort();

    let mut blocks = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).unwrap();
        let file = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string()
            .replace('\\', "/");
        let mut open: Option<(usize, usize, String)> = None;
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            let indent = line.len() - trimmed.len();
            match &mut open {
                None if trimmed == "```yaml" || trimmed == "```yml" => {
                    open = Some((index + 1, indent, String::new()));
                }
                None => {}
                Some((start, _, body)) if trimmed.starts_with("```") => {
                    let value: Option<yaml_serde::Value> = yaml_serde::from_str(body).ok();
                    let keys: Option<Vec<String>> = value.as_ref().and_then(|v| {
                        v.as_mapping().map(|m| {
                            m.keys()
                                .filter_map(|k| k.as_str().map(String::from))
                                .collect()
                        })
                    });
                    if let Some(keys) = keys
                        && !keys.is_empty()
                        && keys.iter().all(|k| CONFIG_SECTIONS.contains(&k.as_str()))
                    {
                        blocks.push((format!("{file}:{start}"), std::mem::take(body)));
                    }
                    open = None;
                }
                Some((_, fence_indent, body)) => {
                    body.push_str(line.get(*fence_indent..).unwrap_or(line.trim_start()));
                    body.push('\n');
                }
            }
        }
    }
    blocks
}

#[test]
fn documented_rsigma_yaml_examples_validate() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if !root.join("docs/content").is_dir() {
        eprintln!("docs/content not found, skipping documented config checks");
        return;
    }
    let blocks = documented_config_blocks(&root);
    let mut failures = Vec::new();
    for (location, text) in &blocks {
        let cfg = temp_file(".yaml", text);
        let output = rsigma()
            .args([
                "config",
                "validate",
                "-c",
                cfg.path().to_str().unwrap(),
                "--format",
                "json",
            ])
            .output()
            .unwrap();
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|e| panic!("{location}: no JSON envelope ({e})"));
        if let Some(keys) = envelope["unknown_keys"]
            .as_array()
            .filter(|k| !k.is_empty())
        {
            failures.push(format!("{location}: unknown keys {keys:?}"));
        }
        if let Some(error) = envelope["error"].as_str() {
            failures.push(format!("{location}: {error}"));
        }
    }
    assert!(
        failures.is_empty(),
        "documented rsigma.yaml examples fail to validate:\n{}",
        failures.join("\n")
    );
    assert!(
        blocks.len() >= 26,
        "expected at least 26 documented rsigma.yaml examples, found {}",
        blocks.len()
    );
}
