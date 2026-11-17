//! End-to-end coverage for multi-ruleset evaluation.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{assert_golden, assert_json_golden, rsigma};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rulesets_eval")
}

fn run(args: &[&str]) -> Output {
    let mut command = rsigma();
    command.current_dir(fixtures()).args(args);
    command.output().expect("run rsigma")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn stats_lines(stderr: &str) -> String {
    stderr
        .lines()
        .filter(|line| line.starts_with("Processed ") || line.starts_with("ruleset "))
        .map(|line| format!("{line}\n"))
        .collect()
}

fn dump_json(stderr: &str) -> String {
    let marker = "--- correlation state snapshot ---\n";
    let start = stderr.find(marker).expect("dump header") + marker.len();
    let end = stderr[start..]
        .find("\nProcessed ")
        .map(|offset| start + offset)
        .unwrap_or(stderr.len());
    let value: serde_json::Value = serde_json::from_str(&stderr[start..end]).unwrap();
    let text = serde_json::to_string_pretty(&value).unwrap();
    format!("{text}\n")
}

/// Write a config into a scratch directory, with `{root}` standing for the
/// fixture directory, so the committed fixtures stay read-only.
fn write_config(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let root = fixtures().display().to_string().replace('\\', "/");
    let path = dir.path().join("rsigma.yaml");
    fs::write(&path, body.replace("{root}", &root)).unwrap();
    path
}

fn eval_with_config(config: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["engine", "eval", "--config", config.to_str().unwrap()];
    args.extend_from_slice(extra);
    run(&args)
}

fn assert_config_error(output: &Output, expected: &str) {
    assert_eq!(output.status.code(), Some(3), "{}", stderr(output));
    assert!(
        stderr(output).contains(expected),
        "expected {expected:?} in: {}",
        stderr(output)
    );
}

#[test]
fn two_rulesets_emit_each_pipeline_result_in_order() {
    let output = run(&[
        "engine",
        "eval",
        "--ruleset",
        "win_a",
        "--ruleset",
        "win_b",
        "--event",
        "@events.ndjson",
        "--emit-detections",
        "--output-format",
        "ndjson",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert_eq!(text.matches("\"ruleset\":\"win_a\"").count(), 3, "{text}");
    assert_eq!(text.matches("\"ruleset\":\"win_b\"").count(), 3, "{text}");
    assert_golden("eval_rulesets/two_rulesets.ndjson", &text);
}

#[test]
fn config_when_binds_cloud_events_and_reports_skips() {
    let output = run(&[
        "engine",
        "eval",
        "--config",
        "rsigma.yaml",
        "--event",
        "@events.ndjson",
        "--output-format",
        "ndjson",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("\"ruleset\":\"cloud\""), "{text}");
    assert_golden("eval_rulesets/when.ndjson", &text);
    let stats = stats_lines(&stderr(&output));
    assert!(stats.contains(
        "ruleset cloud: 1 detection matches, 0 correlation matches, 1 events skipped by when"
    ));
    assert_golden("eval_rulesets/stats.txt", &stats);
}

#[test]
fn the_same_correlation_counts_separately_per_ruleset() {
    let output = run(&[
        "engine",
        "eval",
        "--config",
        "rsigma.yaml",
        "--event",
        "@correlation.ndjson",
        "--dump-correlation-state",
        "--output-format",
        "ndjson",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert_eq!(
        text.matches("\"correlation_type\":\"event_count\"").count(),
        2,
        "{text}"
    );
    let dump = dump_json(&stderr(&output));
    assert!(dump.contains("\"win_a\""), "{dump}");
    assert!(dump.contains("\"win_b\""), "{dump}");
    assert_json_golden("eval_rulesets/dump_state.json", &dump);
}

#[test]
fn table_and_csv_prefix_the_ruleset_column() {
    let event = r#"{"Image":"whoami","process.executable":"whoami","User":"alice"}"#;
    let table = run(&[
        "engine",
        "eval",
        "--ruleset",
        "win_a",
        "--ruleset",
        "win_b",
        "--event",
        event,
        "--emit-detections",
        "--output-format",
        "table",
    ]);
    assert!(table.status.success(), "{}", stderr(&table));
    assert_golden("eval_rulesets/table.txt", &stdout(&table));

    let csv = run(&[
        "engine",
        "eval",
        "--ruleset",
        "win_a",
        "--ruleset",
        "win_b",
        "--event",
        event,
        "--emit-detections",
        "--output-format",
        "csv",
    ]);
    assert!(csv.status.success(), "{}", stderr(&csv));
    assert_golden("eval_rulesets/csv.csv", &stdout(&csv));
}

#[test]
fn fail_on_detection_fires_on_the_second_ruleset() {
    let event = r#"{"eventVersion":"1.0","eventSource":"s3.amazonaws.com","eventID":"e1","userIdentity":{"name":"alice"}}"#;
    let output = run(&[
        "engine",
        "eval",
        "--ruleset",
        "win_a",
        "--ruleset",
        "cloud",
        "--event",
        event,
        "--output-format",
        "ndjson",
        "--fail-on-detection",
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stdout(&output).contains("\"ruleset\":\"cloud\""));
}

#[test]
fn schema_routing_rejects_multiple_rulesets() {
    let output = run(&[
        "engine",
        "eval",
        "--ruleset",
        "win_a",
        "--ruleset",
        "win_b",
        "--schema-routing",
        "--event",
        "{}",
    ]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("exactly one --ruleset"));
}

#[test]
fn schema_routing_rejects_a_ruleset_with_pipelines() {
    let output = run(&[
        "engine",
        "eval",
        "--ruleset",
        "win_a",
        "--schema-routing",
        "--event",
        "{}",
    ]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("conflict with --schema-routing"));
}

#[test]
fn unknown_when_schema_exits_three() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(
        &dir,
        "rulesets:
  cloud:
    sources: ['{root}/cloud']
eval:
  rulesets:
    - name: cloud
      when:
        schemas: [not_a_schema]
",
    );
    assert_config_error(
        &eval_with_config(&config, &["--event", "{}"]),
        "not_a_schema",
    );
}

#[test]
fn conflicting_rule_shapes_in_config_exit_three() {
    let cases = [
        (
            "eval:\n  ruleset: win_a\n  rulesets: [win_a]\n",
            "set either eval.ruleset or eval.rulesets",
        ),
        (
            "eval:\n  rules: '{root}/rules'\n  rulesets: [win_a]\n",
            "set either eval.rules or eval.ruleset/eval.rulesets",
        ),
        (
            "eval:\n  rulesets: [win_a, win_a]\n",
            "duplicate ruleset name 'win_a'",
        ),
        (
            "eval:\n  rulesets:\n    - name: win_a\n      bogus: 1\n",
            "ruleset 'win_a' has unknown keys: bogus",
        ),
        (
            "eval:\n  rulesets:\n    - name: win_a\n      when:\n        schemas: [aws_cloudtrail]\n        bogus: 1\n",
            "ruleset 'win_a' has unknown `when` keys: bogus",
        ),
    ];
    for (eval, expected) in cases {
        let dir = tempfile::tempdir().unwrap();
        let config = write_config(
            &dir,
            &format!("rulesets:\n  win_a:\n    sources: ['{{root}}/rules']\n{eval}"),
        );
        assert_config_error(&eval_with_config(&config, &["--event", "{}"]), expected);
    }
}

#[test]
fn schema_routing_rejects_a_when_binding() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(
        &dir,
        "rulesets:
  cloud:
    sources: ['{root}/cloud']
eval:
  rulesets:
    - name: cloud
      when:
        schemas: [aws_cloudtrail]
",
    );
    assert_config_error(
        &eval_with_config(&config, &["--schema-routing", "--event", "{}"]),
        "cannot use `when` with --schema-routing",
    );
}

#[test]
fn a_ruleset_without_pipelines_uses_the_eval_pipelines() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(
        &dir,
        "rulesets:
  plain:
    sources: ['{root}/rules']
    include:
      - id: [11111111-1111-4111-8111-111111111111]
eval:
  pipelines: ['{root}/pipelines/rename_image.yml']
  rulesets: [plain]
",
    );
    let output = eval_with_config(
        &config,
        &[
            "--event",
            r#"{"process.executable":"whoami"}"#,
            "--output-format",
            "ndjson",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("\"ruleset\":\"plain\""),
        "{}",
        stdout(&output)
    );
}

#[test]
fn an_empty_rulesets_list_falls_back_to_eval_ruleset() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(
        &dir,
        "rulesets:
  plain:
    sources: ['{root}/rules']
    include:
      - id: [11111111-1111-4111-8111-111111111111]
eval:
  ruleset: plain
  rulesets: []
",
    );
    let output = eval_with_config(
        &config,
        &[
            "--event",
            r#"{"Image":"whoami"}"#,
            "--output-format",
            "ndjson",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("\"ruleset\":\"plain\""),
        "{}",
        stdout(&output)
    );
}

#[test]
fn config_validate_reports_ruleset_list_errors() {
    for (section, body, expected) in [
        (
            "eval",
            "eval:\n  rulesets: [win_a, nope]\n",
            "eval.rulesets names unknown ruleset 'nope'",
        ),
        (
            "eval",
            "eval:\n  rulesets:\n    - name: win_a\n      bogus: 1\n",
            "bogus",
        ),
        (
            "daemon",
            "daemon:\n  rulesets: [win_a, win_a]\n",
            "duplicate ruleset name 'win_a'",
        ),
        (
            "daemon",
            "daemon:\n  rules: '{root}/rules'\n  rulesets: [win_a]\n",
            "set either daemon.rules or daemon.rulesets",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let config = write_config(
            &dir,
            &format!("rulesets:\n  win_a:\n    sources: ['{{root}}/rules']\n{body}"),
        );
        let output = run(&["config", "validate", "-c", config.to_str().unwrap()]);
        assert!(!output.status.success(), "{section}: {}", stderr(&output));
        let text = format!("{}{}", stdout(&output), stderr(&output));
        assert!(
            text.contains(expected),
            "{section}: expected {expected:?} in: {text}"
        );
    }
}
