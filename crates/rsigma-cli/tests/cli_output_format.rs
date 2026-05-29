//! Integration tests for the global `--output-format` / `--color` /
//! `--quiet` / `--no-stats` flags.
//!
//! Each test exercises a representative subcommand against the same simple
//! rule + event fixtures so the format dimension is covered without
//! duplicating per-command tests.

mod common;

use common::{SIMPLE_RULE, rsigma, temp_file};
use predicates::prelude::*;

/// JSON detection format is the explicit baseline -- one line, the
/// detection envelope on stdout.
#[test]
fn eval_output_format_json_emits_compact_object() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "malware"}"#,
            "--output-format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let trimmed = stdout.trim();
    assert!(
        trimmed.starts_with('{') && trimmed.ends_with('}'),
        "expected a single JSON object, got: {trimmed}",
    );
    // Compact: no newlines inside the body.
    assert_eq!(trimmed.matches('\n').count(), 0);
    assert!(trimmed.contains("\"rule_title\":\"Test Rule\""));
}

/// `--output-format ndjson` makes the stream explicitly compact and
/// line-oriented, matching what jq / fluent-bit expect when consuming
/// detection NDJSON.
#[test]
fn eval_output_format_ndjson_is_line_oriented() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "malware"}"#,
            "--output-format",
            "ndjson",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // NDJSON: every non-empty stdout line is a valid JSON value.
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let _: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("invalid NDJSON line: {line:?}: {e}"));
    }
}

#[test]
fn eval_output_format_table_renders_columns() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "malware"}"#,
            "--output-format",
            "table",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("LEVEL"), "missing LEVEL header: {stdout}");
    assert!(stdout.contains("RULE"), "missing RULE header: {stdout}");
    assert!(stdout.contains("TYPE"), "missing TYPE header: {stdout}");
    assert!(stdout.contains("DETAIL"), "missing DETAIL header: {stdout}");
    assert!(stdout.contains("Test Rule"), "missing rule row: {stdout}");
}

#[test]
fn eval_output_format_csv_has_header_and_row() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "malware"}"#,
            "--output-format",
            "csv",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines().filter(|l| !l.trim().is_empty());
    assert_eq!(lines.next(), Some("LEVEL,RULE,TYPE,DETAIL"));
    let row = lines.next().expect("at least one data row");
    assert!(row.starts_with("high,Test Rule,detection,"), "row: {row}");
}

#[test]
fn eval_output_format_tsv_uses_tabs() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "malware"}"#,
            "--output-format",
            "tsv",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines().filter(|l| !l.trim().is_empty());
    assert_eq!(lines.next(), Some("LEVEL\tRULE\tTYPE\tDETAIL"));
    let row = lines.next().expect("data row");
    assert_eq!(row.matches('\t').count(), 3);
}

/// `--quiet` drops both the "Loaded N rules" line and any trailing
/// summary, leaving only the matched JSON.
#[test]
fn eval_quiet_suppresses_stats_and_progress() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "malware"}"#,
            "--quiet",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("Loaded"),
        "expected no progress lines under --quiet, got: {stderr}",
    );
}

/// `--no-stats` keeps progress (`Loaded N rules`) but drops the trailing
/// summary line. For the single-event evaluation path the summary lives
/// only in the stream-mode branches, so we exercise an NDJSON file.
#[test]
fn eval_no_stats_keeps_progress_drops_summary() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let events = temp_file(
        ".ndjson",
        "{\"CommandLine\": \"malware\"}\n{\"CommandLine\": \"benign\"}\n",
    );
    let out = rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            &format!("@{}", events.path().display()),
            "--no-stats",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Loaded"),
        "--no-stats should keep progress, got: {stderr}",
    );
    assert!(
        !stderr.contains("Processed"),
        "--no-stats should drop summary, got: {stderr}",
    );
}

/// `--color always` forces ANSI codes on the lint summary even when
/// stdout is not a TTY (the subprocess pipe in `assert_cmd` is not).
#[test]
fn lint_color_always_emits_ansi_codes() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "rule",
            "lint",
            rule.path().to_str().unwrap(),
            "--color",
            "always",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\x1b["),
        "--color always should emit ANSI escapes: {stdout}",
    );
}

#[test]
fn lint_color_never_strips_ansi_codes() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "rule",
            "lint",
            rule.path().to_str().unwrap(),
            "--color",
            "never",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("\x1b["),
        "--color never should strip ANSI escapes: {stdout}",
    );
}

/// `lint --output-format json` returns the structured `{summary, findings}`
/// envelope and bypasses the human renderer entirely.
#[test]
fn lint_output_format_json_emits_envelope() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "rule",
            "lint",
            rule.path().to_str().unwrap(),
            "--output-format",
            "json",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(value.get("summary").is_some(), "missing summary: {stdout}");
    assert!(
        value.get("findings").is_some(),
        "missing findings: {stdout}"
    );
}

#[test]
fn lint_output_format_csv_lists_findings() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "rule",
            "lint",
            rule.path().to_str().unwrap(),
            "--output-format",
            "csv",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines().filter(|l| !l.trim().is_empty());
    assert_eq!(
        lines.next(),
        Some("PATH,SEVERITY,RULE,LINE,MESSAGE"),
        "header mismatch in {stdout}",
    );
}

/// `rsigma rule fields` keeps its legacy table view as the default; the
/// deprecated `--json` flag is still honoured as a hidden alias for
/// `--output-format json`.
#[test]
fn fields_legacy_json_alias_emits_envelope() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "rule",
            "fields",
            "-r",
            rule.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(value.get("summary").is_some());
    assert!(value.get("fields").is_some());
}

#[test]
fn fields_output_format_csv_writes_field_rows() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "rule",
            "fields",
            "-r",
            rule.path().to_str().unwrap(),
            "--output-format",
            "csv",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines().filter(|l| !l.trim().is_empty());
    assert_eq!(lines.next(), Some("FIELD,RULES,SOURCES"));
    assert!(
        lines.next().is_some_and(|r| r.starts_with("CommandLine,")),
        "expected first CSV row to be CommandLine in {stdout}",
    );
}

/// The `RSIGMA_GLOBAL__OUTPUT_FORMAT` env layer drives the format when no
/// flag is passed, mirroring the rest of the `RSIGMA_*` env scheme.
#[test]
fn env_layer_sets_output_format() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .env("RSIGMA_GLOBAL__OUTPUT_FORMAT", "json")
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "malware"}"#,
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let trimmed = stdout.trim();
    assert!(
        trimmed.starts_with('{'),
        "expected env-driven JSON, got: {trimmed}",
    );
}

/// `global.output_format` in the config file works just like the env var.
/// `--config` replaces the discovery chain so this is hermetic.
#[test]
fn config_file_sets_output_format() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let cfg = temp_file(
        ".yaml",
        "global:\n  output_format: json\neval:\n  fail_on_detection: false\n",
    );
    let out = rsigma()
        .args([
            "engine",
            "eval",
            "--config",
            cfg.path().to_str().unwrap(),
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "malware"}"#,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let trimmed = stdout.trim();
    assert!(
        trimmed.starts_with('{') && trimmed.contains("\"rule_title\":"),
        "expected config-driven JSON, got: {trimmed}",
    );
}

/// Flag wins over env, env wins over file -- this is the layered precedence
/// the config plan formalised. CLI > env > config > default.
#[test]
fn flag_beats_env_for_output_format() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .env("RSIGMA_GLOBAL__OUTPUT_FORMAT", "ndjson")
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "malware"}"#,
            "--output-format",
            "csv",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("LEVEL,RULE,TYPE,DETAIL"),
        "expected CSV (flag) to beat NDJSON (env): {stdout}",
    );
}

/// `--output-format json` on `backend convert` wraps the queries in a
/// `{target, format, queries: [...]}` envelope so agents can branch on
/// per-query metadata without parsing free text.
#[test]
fn convert_output_format_json_wraps_queries() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "-t",
            "test",
            "--output-format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("valid convert envelope");
    assert_eq!(value["target"], serde_json::json!("test"));
    assert!(value["queries"].as_array().is_some_and(|a| !a.is_empty()));
}

/// `convert` does not have a tabular shape, so `--output-format csv` warns
/// once on stderr and falls back to the raw query text on stdout.
#[test]
fn convert_falls_back_to_text_for_csv() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "-t",
            "test",
            "--output-format",
            "csv",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stderr.contains("not supported by `backend convert`"),
        "expected fallback warning, got: {stderr}",
    );
    // Raw text on stdout (the existing path).
    assert!(
        !stdout.starts_with('{'),
        "expected raw query text, got: {stdout}"
    );
}

#[test]
fn quiet_suppresses_convert_fallback_warning() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "-t",
            "test",
            "--output-format",
            "csv",
            "--quiet",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("not supported"),
        "--quiet should drop the fallback notice, got: {stderr}",
    );
    // Cope with `_ = out;`-style unused binding warnings on some compilers.
    let _ = predicate::always();
}
