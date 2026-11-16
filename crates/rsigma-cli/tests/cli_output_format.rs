//! Integration tests for the global `--output-format` / `--color` /
//! `--quiet` / `--no-stats` flags.
//!
//! Each test exercises a representative subcommand against the same simple
//! rule + event fixtures so the format dimension is covered without
//! duplicating per-command tests.

mod common;

use common::{SIMPLE_RULE, rsigma, temp_file, validate_ocsf_finding};
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

/// `--finding-format ocsf` emits one OCSF class-2004 finding per match.
#[test]
fn eval_finding_format_ocsf_emits_detection_finding() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "malware"}"#,
            "--finding-format",
            "ocsf",
            "--quiet",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| !l.trim().is_empty())
        .expect("finding line");
    let finding: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
    assert_eq!(finding["class_uid"], 2004);
    assert_eq!(finding["metadata"]["version"], "1.1.0");
    assert!(finding["finding_info"]["title"].is_string());
    validate_ocsf_finding(&finding);
}

/// `--finding-format ocsf` composes with JSON output and honors `--ocsf-version`.
#[test]
fn eval_finding_format_ocsf_sets_version_and_profile() {
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
            "--finding-format",
            "ocsf",
            "--ocsf-version",
            "1.3.0",
            "--quiet",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let finding: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON finding");
    assert_eq!(finding["class_uid"], 2004);
    assert_eq!(finding["metadata"]["version"], "1.3.0");
    assert_eq!(finding["metadata"]["profiles"][0], "security_control");
    validate_ocsf_finding(&finding);
}

/// OCSF findings cannot be projected as a table.
#[test]
fn eval_finding_format_ocsf_rejects_table() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "malware"}"#,
            "--output-format",
            "table",
            "--finding-format",
            "ocsf",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "--finding-format ocsf requires --output-format json or ndjson",
        ));
}

/// Builds without the `ocsf` feature must reject the flag instead of printing
/// a native JSON finding.
#[test]
fn finding_format_ocsf_requires_the_ocsf_feature() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine": "malware"}"#,
            "--finding-format",
            "ocsf",
            "--quiet",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    if cfg!(feature = "ocsf") {
        assert!(out.status.success(), "stderr={stderr}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("\"class_uid\""),
            "the feature build emits a finding"
        );
    } else {
        assert_eq!(out.status.code(), Some(3), "stderr={stderr}");
        assert!(
            stderr.contains("not available"),
            "expected a feature error, got: {stderr}"
        );
        assert!(
            out.stdout.is_empty(),
            "a build without OCSF must not write a finding"
        );
    }
}

/// `ocsf` is a finding format, not a global output format.
#[test]
fn output_format_ocsf_is_rejected() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "rule",
            "lint",
            rule.path().to_str().unwrap(),
            "--output-format",
            "ocsf",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("ocsf"));
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

/// Explicit `--output-format ndjson` on convert emits one query record per line.
#[test]
fn convert_output_format_ndjson_is_one_query_per_line() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "-t",
            "test",
            "--output-format",
            "ndjson",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut saw = false;
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let value: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("invalid NDJSON: {line:?}: {e}"));
        assert_eq!(value["target"], "test");
        assert!(value.get("query").is_some());
        saw = true;
    }
    assert!(saw, "expected at least one NDJSON query record");
}

#[test]
fn targets_output_format_csv_lists_native_rows() {
    let out = rsigma()
        .env("RSIGMA_SIGMA_CLI", "/nonexistent/rsigma-test-sigma-cli")
        .args(["backend", "targets", "--output-format", "csv"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines().filter(|l| !l.trim().is_empty());
    assert_eq!(lines.next(), Some("PROVIDER,NAME,DESCRIPTION"));
    assert!(
        lines.any(|l| l.starts_with("native,postgres,")),
        "missing postgres row in {stdout}"
    );
}

#[test]
fn validate_output_format_json_emits_summary_envelope() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rule.yml"), SIMPLE_RULE).unwrap();
    let out = rsigma()
        .args([
            "rule",
            "validate",
            dir.path().to_str().unwrap(),
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
    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("validate JSON envelope");
    assert!(value.get("summary").is_some());
    assert_eq!(value["summary"]["detection_rules"], 1);
}

#[test]
fn parse_table_warns_and_falls_back_to_json() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = rsigma()
        .args([
            "rule",
            "parse",
            rule.path().to_str().unwrap(),
            "--output-format",
            "table",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stderr.contains("not supported by `rule parse`"),
        "expected unsupported warning, got: {stderr}"
    );
    let _: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON fallback");
}

#[test]
fn reverse_csv_warns_and_keeps_yaml() {
    let out = rsigma()
        .args([
            "rule",
            "reverse",
            "--from",
            "lucene",
            "EventID:1",
            "--logsource-product",
            "windows",
            "--output-format",
            "csv",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stderr.contains("not supported by `rule reverse`"),
        "expected warning, got: {stderr}"
    );
    assert!(
        stdout.contains("title:") || stdout.contains("detection:"),
        "expected Sigma YAML, got: {stdout}"
    );
}

#[test]
fn config_path_csv_emits_source_path_rows() {
    let cfg = temp_file(".yaml", "version: 1\n");
    let out = rsigma()
        .args([
            "config",
            "path",
            "-c",
            cfg.path().to_str().unwrap(),
            "--output-format",
            "csv",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("SOURCE,PATH"),
        "missing CSV header in {stdout}"
    );
    assert!(
        stdout.contains(cfg.path().file_name().unwrap().to_str().unwrap()),
        "missing path row in {stdout}"
    );
}

#[test]
fn config_validate_local_format_beats_global_output_format() {
    let cfg = temp_file(".yaml", "version: 1\n");
    let out = rsigma()
        .args([
            "config",
            "validate",
            "-c",
            cfg.path().to_str().unwrap(),
            "--format",
            "json",
            "--output-format",
            "csv",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stderr.contains("local --format takes precedence"),
        "expected precedence warning, got: {stderr}"
    );
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON from --format");
    assert_eq!(value["ok"], true);
}

#[test]
fn config_short_path_supplies_global_output_format() {
    let cfg = temp_file(".yaml", "version: 1\nglobal:\n  output_format: csv\n");
    let out = rsigma()
        .args(["config", "show", "-c", cfg.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).starts_with("PATH,VALUE,SOURCE\n"),
        "expected CSV selected from -c config, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn invalid_environment_format_falls_back_to_config_file() {
    let cfg = temp_file(".yaml", "version: 1\nglobal:\n  output_format: csv\n");
    let out = rsigma()
        .env("RSIGMA_GLOBAL__OUTPUT_FORMAT", "xml")
        .args(["config", "show", "--config", cfg.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).starts_with("PATH,VALUE,SOURCE\n"),
        "expected file CSV fallback, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid global.output_format 'xml'"));
}

#[test]
fn convert_output_path_warns_when_output_format_is_ignored() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let output = tempfile::NamedTempFile::new().unwrap();
    let out = rsigma()
        .args([
            "backend",
            "convert",
            rule.path().to_str().unwrap(),
            "-t",
            "test",
            "--output-format",
            "json",
            "--output",
            output.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--output always writes raw query text"),
        "expected precedence warning, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn pipeline_diff_csv_emits_per_rule_rows() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let pipe = temp_file(
        ".yml",
        r#"
name: rename
priority: 10
transformations:
  - id: rename_cmd
    type: field_name_mapping
    mapping:
      CommandLine: process.command_line
"#,
    );
    let out = rsigma()
        .args([
            "pipeline",
            "diff",
            "-r",
            rule.path().to_str().unwrap(),
            "-p",
            pipe.path().to_str().unwrap(),
            "--output-format",
            "csv",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut reader = csv::ReaderBuilder::new().from_reader(stdout.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .unwrap()
        .iter()
        .map(str::to_string)
        .collect();
    assert_eq!(
        headers,
        vec![
            "RULE_TITLE",
            "RULE_ID",
            "CHANGED",
            "APPLIED_ITEMS",
            "BEFORE",
            "AFTER"
        ]
    );
    assert!(reader.records().next().is_some());
}
