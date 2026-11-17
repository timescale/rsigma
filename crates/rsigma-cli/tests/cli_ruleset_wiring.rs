//! Integration tests for `--ruleset` on the rule-loading commands.
//!
//! Every test works on a writable copy of the ruleset fixtures, so a test can
//! add configs and overlays without disturbing the committed fixtures.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::rsigma_isolated as rsigma;
use serde_json::Value;

const W1: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const L1: &str = "bbbbbbbb-0000-4000-8000-000000000001";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rulesets")
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

/// A writable copy of the fixtures.
fn fixture_copy() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    copy_tree(&fixtures(), dir.path());
    dir
}

fn write_file(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

fn run(dir: &Path, args: &[&str]) -> Output {
    let mut command = rsigma();
    command.current_dir(dir).args(args);
    command.output().expect("run rsigma")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_str(stdout(output).trim()).unwrap()
}

fn eval_ruleset_config() -> &'static str {
    "rulesets:
  vendor:
    sources:
      - vendor
    include:
      - id: [bbbbbbbb-0000-4000-8000-000000000001]
    dependencies: include
    pipelines: [sysmon]
eval:
  ruleset: vendor
"
}

fn eval_conflict_config() -> &'static str {
    "rulesets:
  vendor:
    sources:
      - vendor
    include:
      - id: [bbbbbbbb-0000-4000-8000-000000000001]
    dependencies: include
eval:
  rules: vendor
  ruleset: vendor
"
}

fn dangling_config() -> &'static str {
    "rulesets:
  dangling:
    sources:
      - vendor
    include:
      - id: [cccccccc-0000-4000-8000-000000000001]
    dependencies: drop
"
}

fn hunt_config() -> &'static str {
    "rulesets:
  detections:
    sources:
      - vendor
    include:
      - kind: [detection]
    dependencies: include
"
}

fn test_pass_config() -> &'static str {
    "rulesets:
  overlay:
    sources:
      - vendor
    include:
      - id: [aaaaaaaa-0000-4000-8000-000000000001]
    dependencies: include
    overlays:
      - file: overlays/test.yml
    pipelines: [sysmon]
"
}

fn test_fail_config() -> &'static str {
    "rulesets:
  overlay:
    sources:
      - vendor
    include:
      - id: [aaaaaaaa-0000-4000-8000-000000000001]
    dependencies: include
    overlays:
      - file: overlays/test-fail.yml
    pipelines: [sysmon]
"
}

fn pass_overlay() -> &'static str {
    "- id: aaaaaaaa-0000-4000-8000-000000000001
  set:
    custom_attributes:
      rsigma.exemplars:
        - name: whoami fires
          expect: match
          event:
            Image: C:\\Windows\\System32\\whoami.exe
            User: SYSTEM
            EventID: 1
"
}

fn fail_overlay() -> &'static str {
    "- id: aaaaaaaa-0000-4000-8000-000000000001
  set:
    custom_attributes:
      rsigma.exemplars:
        - name: whoami fires
          expect: match
          event:
            Image: C:\\Windows\\System32\\cmd.exe
            User: SYSTEM
            EventID: 1
"
}

#[test]
fn ruleset_and_rules_conflict_at_the_parser() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "engine",
            "eval",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--rules",
            "vendor",
            "-e",
            "{}",
        ],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("cannot be used with"));
}

#[test]
fn eval_ruleset_matches_the_expected_detection() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "engine",
            "eval",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--event",
            r#"{"Image":"C:\\Windows\\System32\\whoami.exe","User":"SYSTEM","EventID":1}"#,
            "--emit-detections",
            "--output-format",
            "json",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let value = json_stdout(&output);
    assert_eq!(value["rule_id"], serde_json::json!(W1));
    assert_eq!(value["level"], serde_json::json!("critical"));
    assert_eq!(
        value["custom_attributes"]["rsigma.exemplars"][0]["name"],
        serde_json::json!("whoami fires")
    );
}

#[test]
fn eval_reads_ruleset_from_the_config() {
    let dir = fixture_copy();
    write_file(dir.path(), "eval-ruleset.yaml", eval_ruleset_config());
    let output = run(
        dir.path(),
        &[
            "engine",
            "eval",
            "--config",
            "eval-ruleset.yaml",
            "--event",
            r#"{"EventType":"login"}"#,
            "--output-format",
            "json",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let value = json_stdout(&output);
    assert_eq!(value["rule_id"], serde_json::json!(L1));
}

#[test]
fn eval_rejects_rules_and_ruleset_in_the_same_config() {
    let dir = fixture_copy();
    write_file(dir.path(), "eval-conflict.yaml", eval_conflict_config());
    let output = run(
        dir.path(),
        &[
            "engine",
            "eval",
            "--config",
            "eval-conflict.yaml",
            "--event",
            "{}",
        ],
    );
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("set either eval.rules or eval.ruleset"));
}

/// Every config section that accepts a ruleset points at `vendor`, whose
/// pipeline is sysmon.
fn section_ruleset_config() -> &'static str {
    "rulesets:
  vendor:
    sources: [vendor]
    pipelines: [sysmon]
eval:
  ruleset: vendor
backtest:
  ruleset: vendor
coverage:
  ruleset: vendor
hygiene:
  ruleset: vendor
"
}

/// Every config section that accepts rules points at `local`.
fn section_rules_config() -> &'static str {
    "rulesets:
  vendor:
    sources: [vendor]
eval:
  rules: local
backtest:
  rules: local
coverage:
  rules: [local]
hygiene:
  rules: [local]
"
}

#[test]
fn explicit_rules_beat_a_configured_ruleset() {
    let dir = fixture_copy();
    write_file(dir.path(), "sections.yaml", section_ruleset_config());
    fs::write(dir.path().join("corpus.ndjson"), "{}\n").unwrap();
    let config = ["--config", "sections.yaml", "-r", "local"];

    let eval = run(
        dir.path(),
        &[&["engine", "eval"], &config[..], &["--event", "{}"]].concat(),
    );
    assert!(eval.status.success(), "{}", stderr(&eval));
    assert!(
        stderr(&eval).contains("Loaded 2 rules from local"),
        "{}",
        stderr(&eval)
    );
    assert!(!stderr(&eval).contains("sysmon"), "{}", stderr(&eval));

    let backtest = run(
        dir.path(),
        &[
            &["rule", "backtest"],
            &config[..],
            &["--corpus", "corpus.ndjson", "--output-format", "json"],
        ]
        .concat(),
    );
    assert!(backtest.status.success(), "{}", stderr(&backtest));
    assert_eq!(json_stdout(&backtest)["summary"]["rules_loaded"], 2);

    let coverage = run(dir.path(), &[&["rule", "coverage"], &config[..]].concat());
    assert!(coverage.status.success(), "{}", stderr(&coverage));
    assert!(
        stderr(&coverage).contains("from 2/2 tagged rules"),
        "{}",
        stderr(&coverage)
    );

    let hygiene = run(
        dir.path(),
        &[
            &["rule", "hygiene"],
            &config[..],
            &["--output-format", "json"],
        ]
        .concat(),
    );
    assert!(hygiene.status.success(), "{}", stderr(&hygiene));
    assert_eq!(json_stdout(&hygiene)["summary"]["rules_total"], 2);
}

#[test]
fn an_explicit_ruleset_beats_configured_rules() {
    let dir = fixture_copy();
    write_file(dir.path(), "sections.yaml", section_rules_config());
    fs::write(dir.path().join("corpus.ndjson"), "{}\n").unwrap();
    let config = ["--config", "sections.yaml", "--ruleset", "vendor"];

    let eval = run(
        dir.path(),
        &[&["engine", "eval"], &config[..], &["--event", "{}"]].concat(),
    );
    assert!(eval.status.success(), "{}", stderr(&eval));
    assert!(
        stderr(&eval).contains("from ruleset vendor"),
        "{}",
        stderr(&eval)
    );

    let backtest = run(
        dir.path(),
        &[
            &["rule", "backtest"],
            &config[..],
            &["--corpus", "corpus.ndjson", "--output-format", "json"],
        ]
        .concat(),
    );
    assert!(backtest.status.success(), "{}", stderr(&backtest));
    assert_eq!(json_stdout(&backtest)["summary"]["rules_loaded"], 10);

    let coverage = run(dir.path(), &[&["rule", "coverage"], &config[..]].concat());
    assert!(coverage.status.success(), "{}", stderr(&coverage));
    assert!(
        stderr(&coverage).contains("from 10/10 tagged rules"),
        "{}",
        stderr(&coverage)
    );

    let hygiene = run(
        dir.path(),
        &[
            &["rule", "hygiene"],
            &config[..],
            &["--output-format", "json"],
        ]
        .concat(),
    );
    assert!(hygiene.status.success(), "{}", stderr(&hygiene));
    assert_eq!(json_stdout(&hygiene)["summary"]["rules_total"], 10);
}

#[test]
fn backtest_coverage_and_hygiene_read_the_ruleset_from_the_config() {
    let dir = fixture_copy();
    write_file(dir.path(), "sections.yaml", section_ruleset_config());
    fs::write(dir.path().join("corpus.ndjson"), "{}\n").unwrap();

    let backtest = run(
        dir.path(),
        &[
            "rule",
            "backtest",
            "--config",
            "sections.yaml",
            "--corpus",
            "corpus.ndjson",
            "--output-format",
            "json",
        ],
    );
    assert!(backtest.status.success(), "{}", stderr(&backtest));
    assert_eq!(json_stdout(&backtest)["summary"]["rules_loaded"], 10);

    let coverage = run(
        dir.path(),
        &["rule", "coverage", "--config", "sections.yaml"],
    );
    assert!(coverage.status.success(), "{}", stderr(&coverage));
    assert!(
        stderr(&coverage).contains("from 10/10 tagged rules"),
        "{}",
        stderr(&coverage)
    );

    let hygiene = run(
        dir.path(),
        &[
            "rule",
            "hygiene",
            "--config",
            "sections.yaml",
            "--output-format",
            "json",
        ],
    );
    assert!(hygiene.status.success(), "{}", stderr(&hygiene));
    assert_eq!(json_stdout(&hygiene)["summary"]["rules_total"], 10);
}

#[test]
fn backtest_coverage_and_hygiene_reject_rules_and_ruleset_in_one_section() {
    let dir = fixture_copy();
    write_file(
        dir.path(),
        "both.yaml",
        "rulesets:
  vendor:
    sources: [vendor]
backtest:
  rules: local
  ruleset: vendor
coverage:
  rules: [local]
  ruleset: vendor
hygiene:
  rules: [local]
  ruleset: vendor
",
    );
    fs::write(dir.path().join("corpus.ndjson"), "{}\n").unwrap();
    for (command, extra) in [
        ("backtest", vec!["--corpus", "corpus.ndjson"]),
        ("coverage", vec![]),
        ("hygiene", vec![]),
    ] {
        let output = run(
            dir.path(),
            &[&["rule", command, "--config", "both.yaml"], &extra[..]].concat(),
        );
        assert_eq!(
            output.status.code(),
            Some(3),
            "{command}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(&format!("set either {command}.rules or {command}.ruleset")),
            "{command}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn single_path_commands_accept_a_path_without_detection_rules() {
    let dir = fixture_copy();
    fs::create_dir(dir.path().join("filters")).unwrap();
    fs::copy(
        dir.path().join("vendor/filter.yml"),
        dir.path().join("filters/filter.yml"),
    )
    .unwrap();
    let eval = run(dir.path(), &["engine", "eval", "-r", "filters", "-e", "{}"]);
    assert!(eval.status.success(), "{}", stderr(&eval));
    let fields = run(dir.path(), &["rule", "fields", "-r", "filters"]);
    assert!(fields.status.success(), "{}", stderr(&fields));
    assert!(stdout(&fields).contains("User"), "{}", stdout(&fields));
}

#[test]
fn explicit_pipeline_overrides_the_ruleset_pipeline() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "engine",
            "eval",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--pipeline",
            "ecs_windows",
            "--event",
            r#"{"process.executable":"C:\\Windows\\System32\\whoami.exe","User":"SYSTEM"}"#,
            "--emit-detections",
            "--output-format",
            "json",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("Loaded builtin pipeline: ecs_windows"));
    let value = json_stdout(&output);
    assert_eq!(value["rule_id"], serde_json::json!(W1));
    assert_eq!(
        value["matched_fields"][0]["field"],
        serde_json::json!("process.executable")
    );
}

#[test]
fn the_ruleset_pipeline_applies_without_an_explicit_flag() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "engine",
            "eval",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--event",
            r#"{"process.executable":"C:\\Windows\\System32\\whoami.exe","User":"SYSTEM"}"#,
            "--emit-detections",
            "--output-format",
            "json",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("Loaded builtin pipeline: sysmon"));
    assert!(stderr(&output).contains("No matches."));
}

#[test]
fn rule_test_replays_an_overlaid_exemplar() {
    let dir = fixture_copy();
    write_file(dir.path(), "overlays/test.yml", pass_overlay());
    write_file(dir.path(), "test-pass.yaml", test_pass_config());
    let output = run(
        dir.path(),
        &[
            "rule",
            "test",
            "--ruleset",
            "overlay",
            "--config",
            "test-pass.yaml",
            "--output-format",
            "json",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let value = json_stdout(&output);
    assert_eq!(value["summary"]["passed"], serde_json::json!(1));
    assert_eq!(value["summary"]["failed"], serde_json::json!(0));
}

#[test]
fn rule_test_fails_on_an_overlaid_exemplar_written_to_fail() {
    let dir = fixture_copy();
    write_file(dir.path(), "overlays/test-fail.yml", fail_overlay());
    write_file(dir.path(), "test-fail.yaml", test_fail_config());
    let output = run(
        dir.path(),
        &[
            "rule",
            "test",
            "--ruleset",
            "overlay",
            "--config",
            "test-fail.yaml",
            "--output-format",
            "json",
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let value = json_stdout(&output);
    assert_eq!(value["summary"]["failed"], serde_json::json!(1));
    assert_eq!(
        value["results"][0]["diagnostic"],
        serde_json::json!("the rule did not match the event")
    );
}

#[test]
fn rule_doc_reports_overlaid_ads_validation() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "rule",
            "doc",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--output-format",
            "json",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let value = json_stdout(&output);
    assert_eq!(value["summary"]["total_rules"], serde_json::json!(4));
    let rule = value["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["id"] == serde_json::json!(L1))
        .unwrap();
    let blind_spots = rule["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|section| section["id"] == serde_json::json!("blind_spots"))
        .unwrap();
    assert_eq!(blind_spots["present"], serde_json::json!(true));
}

#[test]
fn rule_doc_rejects_scaffold_with_a_ruleset() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "rule",
            "doc",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--scaffold",
        ],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("cannot be used with '--scaffold'"));
}

#[test]
fn rule_validate_passes_when_drop_removes_a_dangling_reference() {
    let dir = fixture_copy();
    write_file(dir.path(), "dangling.yaml", dangling_config());
    let output = run(
        dir.path(),
        &[
            "rule",
            "validate",
            "--ruleset",
            "dangling",
            "--config",
            "dangling.yaml",
            "--verbose",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("dropped correlation"));
    assert!(stdout(&output).contains("Parsed 0 documents from ruleset dangling"));
}

#[test]
fn backend_convert_uses_the_resolved_ruleset() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "backend",
            "convert",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "-t",
            "test",
            "-s",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Image endswith"), "{text}");
    assert!(text.contains("whoami.exe"), "{text}");
    assert!(
        !text.contains("EventID=1"),
        "the sysmon pipeline leaked: {text}"
    );
    assert!(!stderr(&output).contains("sysmon"), "{}", stderr(&output));
}

/// A stand-in sigma-cli that records the rules directory it was given and the
/// documents in it, prints one query, and exits with `code`.
#[cfg(unix)]
fn fake_sigma_cli(dir: &Path, code: i32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let script = dir.join("fake-sigma");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nfor last; do :; done\nprintf '%s' \"$last\" > \"{record}.dir\"\nfind \"$last\" -name '*.yml' -exec cat {{}} + > \"{record}.rules\"\necho 'fake query'\nexit {code}\n",
            record = dir.join("record").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    script
}

#[cfg(unix)]
#[test]
fn delegated_convert_passes_the_materialized_ruleset_and_cleans_up() {
    for code in [0, 1] {
        let dir = fixture_copy();
        let script = fake_sigma_cli(dir.path(), code);
        let output = rsigma()
            .current_dir(dir.path())
            .env("RSIGMA_SIGMA_CLI", &script)
            .args([
                "backend",
                "convert",
                "--ruleset",
                "vendor",
                "--config",
                "vendor-only.yaml",
                "-t",
                "not_a_native_target",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.success(), code == 0, "{}", stderr(&output));
        if code == 0 {
            assert!(
                stdout(&output).contains("fake query"),
                "{}",
                stdout(&output)
            );
        }
        let rules = fs::read_to_string(dir.path().join("record.rules")).unwrap();
        assert!(rules.contains(W1), "{rules}");
        assert!(rules.contains("level: critical"), "{rules}");
        let materialized = fs::read_to_string(dir.path().join("record.dir")).unwrap();
        assert!(
            !Path::new(&materialized).exists(),
            "exit {code}: {materialized} was left behind"
        );
    }
}

#[test]
fn pipeline_diff_uses_only_the_explicit_pipeline() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "pipeline",
            "diff",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "-p",
            "ecs_windows",
            "--output-format",
            "table",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("process.executable"), "{text}");
    assert!(
        !text.contains("sysmon_"),
        "the sysmon pipeline leaked: {text}"
    );
    assert!(!stderr(&output).contains("sysmon"), "{}", stderr(&output));
}

#[test]
fn hunt_run_builds_queries_from_a_ruleset() {
    let dir = fixture_copy();
    write_file(dir.path(), "hunt.yaml", hunt_config());
    let output = run(
        dir.path(),
        &[
            "hunt",
            "run",
            "--ruleset",
            "detections",
            "--config",
            "hunt.yaml",
            "-t",
            "postgres",
            "--since",
            "2026-07-01T00:00:00Z",
            "--until",
            "2026-07-02T00:00:00Z",
            "--emit",
            "sql",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("-- rule: Windows whoami execution"), "{text}");
    assert!(text.contains("SELECT * FROM"), "{text}");
}

#[test]
fn explain_accepts_a_ruleset() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "engine",
            "explain",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--event",
            r#"{"Image":"C:\\Windows\\System32\\whoami.exe","User":"SYSTEM","EventID":1}"#,
            "--output-format",
            "table",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Windows whoami execution"), "{text}");
    assert!(text.contains("MATCH"), "{text}");
}

#[test]
fn fields_accepts_a_ruleset() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "rule",
            "fields",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--output-format",
            "table",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("Unique fields"));
}

#[test]
fn tune_accepts_a_ruleset() {
    let dir = fixture_copy();
    let fp = dir.path().join("tune-fp.ndjson");
    let tp = dir.path().join("tune-tp.ndjson");
    fs::write(
        &fp,
        "{\"EventType\":\"login\",\"User\":\"svc_backup\"}\n{\"EventType\":\"login\",\"User\":\"svc_backup\"}\n",
    )
    .unwrap();
    fs::write(&tp, "{\"EventType\":\"login\",\"User\":\"attacker\"}\n").unwrap();
    let output = run(
        dir.path(),
        &[
            "rule",
            "tune",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--rule",
            L1,
            "--fp",
            &format!("@{}", fp.display()),
            "--tp",
            &format!("@{}", tp.display()),
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("Tuning filter for Linux SSH login"));
}

#[test]
fn backtest_accepts_a_ruleset() {
    let dir = fixture_copy();
    let corpus = dir.path().join("corpus.ndjson");
    fs::write(
        &corpus,
        "{\"Image\":\"C:\\\\Windows\\\\System32\\\\whoami.exe\",\"User\":\"SYSTEM\",\"EventID\":1}\n{\"EventType\":\"login\"}\n",
    )
    .unwrap();
    let output = run(
        dir.path(),
        &[
            "rule",
            "backtest",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--corpus",
            corpus.to_str().unwrap(),
            "--output-format",
            "table",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Windows whoami execution"), "{text}");
    assert!(text.contains("Linux SSH login"), "{text}");
}

#[test]
fn coverage_accepts_a_ruleset() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "rule",
            "coverage",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("Coverage:"));
}

#[test]
fn visibility_accepts_a_ruleset() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "rule",
            "visibility",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("Visibility:"));
}

#[test]
fn hygiene_accepts_a_ruleset() {
    let dir = fixture_copy();
    let output = run(
        dir.path(),
        &[
            "rule",
            "hygiene",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("Linux SSH login"));
}

#[test]
fn eval_on_the_build_output_matches_the_ruleset() {
    let dir = fixture_copy();
    let out = dir.path().join("out");
    let build = run(
        dir.path(),
        &[
            "ruleset",
            "build",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "-o",
            out.to_str().unwrap(),
        ],
    );
    assert!(build.status.success(), "{}", stderr(&build));

    let event = r#"{"Image":"C:\\Windows\\System32\\whoami.exe","User":"SYSTEM","EventID":1}"#;
    let from_ruleset = run(
        dir.path(),
        &[
            "engine",
            "eval",
            "--ruleset",
            "vendor",
            "--config",
            "vendor-only.yaml",
            "--event",
            event,
            "--emit-detections",
            "--output-format",
            "json",
        ],
    );
    assert!(from_ruleset.status.success(), "{}", stderr(&from_ruleset));
    let from_build = run(
        dir.path(),
        &[
            "engine",
            "eval",
            "--rules",
            out.to_str().unwrap(),
            "--pipeline",
            "sysmon",
            "--event",
            event,
            "--emit-detections",
            "--output-format",
            "json",
        ],
    );
    assert!(from_build.status.success(), "{}", stderr(&from_build));
    let mut ruleset_value: serde_json::Value =
        serde_json::from_str(stdout(&from_ruleset).trim()).unwrap();
    assert_eq!(ruleset_value["ruleset"], serde_json::json!("vendor"));
    ruleset_value.as_object_mut().unwrap().remove("ruleset");
    let build_value: serde_json::Value = serde_json::from_str(stdout(&from_build).trim()).unwrap();
    assert_eq!(ruleset_value, build_value);
}
