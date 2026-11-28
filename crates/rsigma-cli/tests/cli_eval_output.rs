//! Integration tests for `engine eval -o/--output <PATH>`: results go to the
//! file in the resolved format while stdout stays empty and the summary stays
//! on stderr.

use crate::common;

use std::fs;
use std::path::Path;

use common::{SIMPLE_RULE, rsigma, temp_file};
use predicates::prelude::*;

/// Two matching events and one that does not match [`SIMPLE_RULE`].
const EVENTS: &str = r#"{"CommandLine": "run malware.exe"}
{"CommandLine": "notepad.exe"}
{"CommandLine": "more malware"}
"#;

fn eval_to_file(rule: &Path, events: &Path, out: &Path, extra: &[&str]) -> std::process::Output {
    let events_arg = format!("@{}", events.display());
    let mut args = vec![
        "engine",
        "eval",
        "-r",
        rule.to_str().unwrap(),
        "-e",
        &events_arg,
        "-o",
        out.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    rsigma().args(&args).output().unwrap()
}

#[test]
fn output_defaults_to_ndjson_and_keeps_stdout_empty() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let events = temp_file(".ndjson", EVENTS);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("detections.ndjson");

    let res = eval_to_file(rule.path(), events.path(), &out, &[]);
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(res.status.success(), "stderr={stderr}");
    assert!(res.stdout.is_empty(), "stdout should be empty");
    assert!(
        stderr.contains("Processed 3 events, 2 matches."),
        "stderr={stderr}"
    );

    let written = fs::read_to_string(&out).unwrap();
    let lines: Vec<&str> = written.lines().collect();
    assert_eq!(lines.len(), 2, "file={written}");
    for line in lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["rule_title"], "Test Rule");
    }
}

#[test]
fn output_honors_pretty() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let events = temp_file(".ndjson", EVENTS);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("detections.json");

    let res = eval_to_file(rule.path(), events.path(), &out, &["--pretty"]);
    assert!(res.status.success());
    let written = fs::read_to_string(&out).unwrap();
    let docs: Vec<serde_json::Value> = serde_json::Deserializer::from_str(&written)
        .into_iter()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(docs.len(), 2);
    assert!(written.lines().count() > 2, "expected pretty-printed JSON");
}

#[test]
fn output_honors_explicit_csv_format() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let events = temp_file(".ndjson", EVENTS);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("detections.csv");

    let res = eval_to_file(
        rule.path(),
        events.path(),
        &out,
        &["--output-format", "csv"],
    );
    assert!(res.status.success());
    assert!(res.stdout.is_empty());
    let written = fs::read_to_string(&out).unwrap();
    let lines: Vec<&str> = written.lines().collect();
    assert_eq!(lines[0], "LEVEL,RULE,TYPE,DETAIL");
    assert_eq!(lines.len(), 3, "file={written}");
    assert!(lines[1].starts_with("high,Test Rule,detection,"));
}

#[test]
fn output_honors_explicit_table_format() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let events = temp_file(".ndjson", EVENTS);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("detections.txt");

    let res = eval_to_file(
        rule.path(),
        events.path(),
        &out,
        &["--output-format", "table"],
    );
    assert!(res.status.success());
    assert!(res.stdout.is_empty());
    let written = fs::read_to_string(&out).unwrap();
    assert!(written.starts_with("LEVEL"), "file={written}");
    assert_eq!(written.matches("Test Rule").count(), 2);
}

#[test]
fn output_truncates_existing_file() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let events = temp_file(".ndjson", "{\"CommandLine\": \"notepad.exe\"}\n");
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("detections.ndjson");
    fs::write(&out, "stale content from a previous run\n").unwrap();

    let res = eval_to_file(rule.path(), events.path(), &out, &[]);
    assert!(res.status.success());
    assert_eq!(fs::read_to_string(&out).unwrap(), "");
}

#[test]
fn output_is_flushed_when_fail_on_detection_exits_1() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let events = temp_file(".ndjson", EVENTS);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("detections.ndjson");

    let res = eval_to_file(rule.path(), events.path(), &out, &["--fail-on-detection"]);
    assert_eq!(res.status.code(), Some(1));
    assert_eq!(fs::read_to_string(&out).unwrap().lines().count(), 2);
}

#[test]
fn output_from_config_file() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let events = temp_file(".ndjson", EVENTS);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("detections.ndjson");
    let config = temp_file(
        ".yml",
        &format!("eval:\n  output: {}\n", out.to_str().unwrap()),
    );

    let events_arg = format!("@{}", events.path().display());
    rsigma()
        .args([
            "engine",
            "eval",
            "--config",
            config.path().to_str().unwrap(),
            "-r",
            rule.path().to_str().unwrap(),
            "-e",
            &events_arg,
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
    assert_eq!(fs::read_to_string(&out).unwrap().lines().count(), 2);
}

#[test]
fn output_to_missing_directory_is_a_config_error() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let events = temp_file(".ndjson", EVENTS);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("missing").join("detections.ndjson");

    let res = eval_to_file(rule.path(), events.path(), &out, &[]);
    assert_eq!(res.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&res.stderr).contains("cannot create output file"));
}

#[test]
fn output_matching_input_file_is_rejected() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let events = temp_file(".ndjson", EVENTS);

    let res = eval_to_file(rule.path(), events.path(), events.path(), &[]);
    assert_eq!(res.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&res.stderr).contains("is the --event input file"));
    assert_eq!(fs::read_to_string(events.path()).unwrap(), EVENTS);
}

#[cfg(feature = "evtx")]
#[test]
fn output_with_evtx_input() {
    let rule = temp_file(
        ".yml",
        r#"
title: EVTX Logon
id: 00000000-0000-0000-0000-000000000002
logsource:
    product: windows
detection:
    selection:
        Event.System.EventID: 4624
    condition: selection
level: medium
"#,
    );
    let evtx = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../rsigma-runtime/tests/fixtures/security.evtx"
    ));
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("detections.ndjson");

    let res = eval_to_file(rule.path(), evtx, &out, &[]);
    assert!(
        res.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&res.stderr)
    );
    assert!(res.stdout.is_empty());
    let written = fs::read_to_string(&out).unwrap();
    assert!(written.lines().count() > 0);
    for line in written.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["rule_title"], "EVTX Logon");
    }
}
