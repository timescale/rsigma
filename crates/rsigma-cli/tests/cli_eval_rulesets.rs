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

fn write_config(name: &str, body: &str) -> PathBuf {
    let path = fixtures().join(name);
    fs::write(&path, body).unwrap();
    path
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
    let config = write_config(
        "when-unknown.yaml",
        "rulesets:
  cloud:
    sources: [cloud]
eval:
  rulesets:
    - name: cloud
      when:
        schemas: [not_a_schema]
",
    );
    let output = run(&[
        "engine",
        "eval",
        "--config",
        config.to_str().unwrap(),
        "--event",
        "{}",
    ]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("not_a_schema"));
}

#[test]
fn single_and_list_rulesets_conflict_in_config() {
    let config = write_config(
        "both-shapes.yaml",
        "rulesets:
  win_a:
    sources: [rules]
eval:
  ruleset: win_a
  rulesets: [win_a]
",
    );
    let output = run(&[
        "engine",
        "eval",
        "--config",
        config.to_str().unwrap(),
        "--event",
        "{}",
    ]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("set either eval.ruleset or eval.rulesets"));
}

#[test]
fn duplicate_ruleset_names_exit_three() {
    let config = write_config(
        "duplicate.yaml",
        "rulesets:
  win_a:
    sources: [rules]
eval:
  rulesets: [win_a, win_a]
",
    );
    let output = run(&[
        "engine",
        "eval",
        "--config",
        config.to_str().unwrap(),
        "--event",
        "{}",
    ]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("duplicate ruleset name"));
}
