//! Integration coverage for `rsigma rule tune` boundaries.

mod common;

use common::{rsigma, temp_file};
use predicates::prelude::*;

const FILTER_GOLDEN: &str = include_str!("golden/tune_filter.yaml");
const EXPECTATION_DIFF_GOLDEN: &str = include_str!("golden/tune_expectation_diff.txt");

const RULE: &str = r#"
title: Suspicious Backup Tool
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\backup.exe'
    condition: selection
level: medium
"#;

const FALSE_POSITIVES: &str = concat!(
    r#"{"Image":"C:\\Program Files\\Veeam\\backup.exe","User":"svc_backup"}"#,
    "\n",
    r#"{"Image":"C:\\Program Files\\Veeam\\backup.exe","User":"svc_backup"}"#,
    "\n",
);

const TRUE_POSITIVES: &str = concat!(
    r#"{"Image":"C:\\Temp\\backup.exe","User":"attacker"}"#,
    "\n"
);

fn normalize_id(yaml: &str) -> String {
    yaml.lines()
        .map(|line| {
            if line.starts_with("id: ") {
                "id: <ID>".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn tune_from_files_matches_golden() {
    let rule = temp_file(".yml", RULE);
    let fp = temp_file(".ndjson", FALSE_POSITIVES);
    let tp = temp_file(".ndjson", TRUE_POSITIVES);

    let output = rsigma()
        .args([
            "rule",
            "tune",
            "--rules",
            rule.path().to_str().unwrap(),
            "--fp",
            &format!("@{}", fp.path().display()),
            "--tp",
            &format!("@{}", tp.path().display()),
        ])
        .output()
        .expect("run tune");

    assert!(output.status.success());
    let yaml = String::from_utf8(output.stdout).expect("utf8");
    assert_eq!(
        normalize_id(&yaml).trim_end(),
        FILTER_GOLDEN.trim_end(),
        "filter YAML drifted from golden"
    );
}

#[test]
fn emitted_filter_lints_and_suppresses_only_false_positives() {
    let rule = temp_file(".yml", RULE);
    let fp = temp_file(".ndjson", FALSE_POSITIVES);
    let tp = temp_file(".ndjson", TRUE_POSITIVES);
    let output = rsigma()
        .args([
            "rule",
            "tune",
            "-r",
            rule.path().to_str().unwrap(),
            "--fp",
            &format!("@{}", fp.path().display()),
            "--tp",
            &format!("@{}", tp.path().display()),
        ])
        .output()
        .expect("run tune");
    assert!(output.status.success());
    let filter = temp_file(".yml", &String::from_utf8(output.stdout).unwrap());

    rsigma()
        .args(["rule", "lint", filter.path().to_str().unwrap()])
        .assert()
        .success();

    let rules = tempfile::tempdir().unwrap();
    std::fs::copy(rule.path(), rules.path().join("rule.yml")).unwrap();
    std::fs::copy(filter.path(), rules.path().join("filter.yml")).unwrap();
    let all_events = temp_file(".ndjson", &format!("{FALSE_POSITIVES}{TRUE_POSITIVES}"));
    rsigma()
        .args([
            "engine",
            "eval",
            "--rules",
            rules.path().to_str().unwrap(),
            "--event",
            &format!("@{}", all_events.path().display()),
            "--include-event",
            "--output-format",
            "ndjson",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("attacker"))
        .stdout(predicate::str::contains("svc_backup").not());
}

#[test]
fn report_json_contains_closed_verification() {
    let rule = temp_file(".yml", RULE);
    let fp = temp_file(".ndjson", FALSE_POSITIVES);
    let tp = temp_file(".ndjson", TRUE_POSITIVES);

    rsigma()
        .args([
            "rule",
            "tune",
            "-r",
            rule.path().to_str().unwrap(),
            "--fp",
            &format!("@{}", fp.path().display()),
            "--tp",
            &format!("@{}", tp.path().display()),
            "--emit",
            "report",
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"false_positives_after\": 0"))
        .stdout(predicate::str::contains("\"true_positives_after\": 1"));
}

#[test]
fn pipeline_mapped_fields_are_emitted_and_verified() {
    let rule = temp_file(".yml", RULE);
    let pipeline = temp_file(
        ".yml",
        r#"
name: ecs-ish
priority: 10
transformations:
  - id: rename_image
    type: field_name_mapping
    mapping:
      Image: process.executable
"#,
    );
    let fp = temp_file(
        ".ndjson",
        concat!(
            r#"{"process":{"executable":"C:\\Program Files\\Veeam\\backup.exe"},"User":"svc_backup"}"#,
            "\n",
            r#"{"process":{"executable":"C:\\Program Files\\Veeam\\backup.exe"},"User":"svc_backup"}"#,
            "\n",
        ),
    );
    let tp = temp_file(
        ".ndjson",
        concat!(
            r#"{"process":{"executable":"C:\\Temp\\backup.exe"},"User":"svc_backup"}"#,
            "\n",
        ),
    );

    rsigma()
        .args([
            "rule",
            "tune",
            "-r",
            rule.path().to_str().unwrap(),
            "-p",
            pipeline.path().to_str().unwrap(),
            "--fp",
            &format!("@{}", fp.path().display()),
            "--tp",
            &format!("@{}", tp.path().display()),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("process.executable"))
        .stdout(predicate::str::contains("\n        Image:").not());
}

#[test]
fn expectations_report_contains_paste_ready_golden_diff() {
    let rule = temp_file(".yml", RULE);
    let expectations = temp_file(
        ".yml",
        r#"
expectations:
  - rule: 929a690e-bef0-4204-a928-ef5e620d6fcc
    at_least: 1
"#,
    );
    let output = rsigma()
        .args([
            "rule",
            "tune",
            "-r",
            rule.path().to_str().unwrap(),
            "--tp",
            r#"{"Image":"C:\\Temp\\backup.exe","User":"attacker"}"#,
            "--expectations",
            expectations.path().to_str().unwrap(),
            "--emit",
            "report",
            "--output-format",
            "table",
        ])
        .write_stdin(FALSE_POSITIVES)
        .output()
        .expect("run tune expectation diff");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let diff = stdout
        .split_once("# Backtest expectation diff\n")
        .map(|(_, diff)| diff)
        .expect("expectation diff marker");
    assert_eq!(diff.trim_end(), EXPECTATION_DIFF_GOLDEN.trim_end());
}

#[test]
fn multiple_rules_require_an_explicit_target() {
    let rules = temp_file(
        ".yml",
        &format!(
            "{RULE}\n---\n{}",
            RULE.replace("Suspicious Backup Tool", "Other Rule")
                .replace("929a690e-bef0-4204-a928-ef5e620d6fcc", "other-rule")
        ),
    );
    let fp = temp_file(".ndjson", FALSE_POSITIVES);
    let tp = temp_file(".ndjson", TRUE_POSITIVES);

    rsigma()
        .args([
            "rule",
            "tune",
            "-r",
            rules.path().to_str().unwrap(),
            "--fp",
            &format!("@{}", fp.path().display()),
            "--tp",
            &format!("@{}", tp.path().display()),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("pass --rule"));
}

const NOTEPAD_RULE: &str = r#"
title: Suspicious Notepad
id: notepad-rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\notepad.exe'
    condition: selection
level: medium
"#;

const NOTEPAD_FPS: [&str; 2] = [
    r#"{"Image":"C:\\Windows\\System32\\notepad.exe","User":"analyst"}"#,
    r#"{"Image":"C:\\Windows\\System32\\notepad.exe","User":"analyst"}"#,
];
const NOTEPAD_TP: &str = r#"{"Image":"C:\\Temp\\notepad.exe","User":"attacker"}"#;

fn write_disposition_bundle(
    root: &std::path::Path,
    kind: &str,
    name: &str,
    verdict: &str,
    rule_id: &str,
    rule_title: &str,
    events: &[&str],
) {
    let dir = root.join(kind).join(name);
    std::fs::create_dir_all(dir.join("corpus")).unwrap();
    std::fs::create_dir_all(dir.join("provenance")).unwrap();
    let mut bundle_id: String = name.bytes().map(|b| format!("{b:02x}")).collect();
    while bundle_id.len() < 64 {
        bundle_id.push('0');
    }
    let bundle_id: String = bundle_id.chars().take(64).collect();
    let manifest = serde_json::json!({
        "format_version": 1,
        "bundle_id": bundle_id,
        "kind": "detection_group_by",
        "verdict": verdict,
        "scope": "detection",
        "rule_ids": [rule_id],
        "rules": [{"id": rule_id, "title": rule_title}],
        "first_seen": 1,
        "last_seen": 2,
        "event_count": events.len(),
        "byte_count": 1,
        "created_at": "2026-01-01T00:00:00Z"
    });
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let mut corpus = String::new();
    let mut provenance = String::new();
    for event in events {
        corpus.push_str(event);
        corpus.push('\n');
        let parsed: serde_json::Value = serde_json::from_str(event).unwrap();
        let line = serde_json::json!({
            "event_digest": "ab",
            "captured_at": "2026-01-01T00:00:00Z",
            "matches": [{"rule_id": rule_id, "rule_title": rule_title}],
            "event": parsed,
        });
        provenance.push_str(&serde_json::to_string(&line).unwrap());
        provenance.push('\n');
    }
    std::fs::write(dir.join("corpus/events.ndjson"), corpus).unwrap();
    std::fs::write(dir.join("provenance/events.ndjson"), provenance).unwrap();
}

fn two_rule_spool() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    write_disposition_bundle(
        root.path(),
        "fp",
        "backup-fp",
        "false_positive",
        "929a690e-bef0-4204-a928-ef5e620d6fcc",
        "Suspicious Backup Tool",
        &[
            r#"{"Image":"C:\\Program Files\\Veeam\\backup.exe","User":"svc_backup"}"#,
            r#"{"Image":"C:\\Program Files\\Veeam\\backup.exe","User":"svc_backup"}"#,
        ],
    );
    write_disposition_bundle(
        root.path(),
        "tp",
        "backup-tp",
        "true_positive",
        "929a690e-bef0-4204-a928-ef5e620d6fcc",
        "Suspicious Backup Tool",
        &[r#"{"Image":"C:\\Temp\\backup.exe","User":"attacker"}"#],
    );
    write_disposition_bundle(
        root.path(),
        "fp",
        "notepad-fp",
        "false_positive",
        "notepad-rule",
        "Suspicious Notepad",
        &NOTEPAD_FPS,
    );
    write_disposition_bundle(
        root.path(),
        "tp",
        "notepad-tp",
        "true_positive",
        "notepad-rule",
        "Suspicious Notepad",
        &[NOTEPAD_TP],
    );
    root
}

#[test]
fn from_dispositions_matches_multi_rule_goldens() {
    let rules = temp_file(".yml", &format!("{RULE}\n---\n{NOTEPAD_RULE}"));
    let spool = two_rule_spool();

    let yaml = rsigma()
        .args([
            "rule",
            "tune",
            "--rules",
            rules.path().to_str().unwrap(),
            "--from-dispositions",
            spool.path().to_str().unwrap(),
        ])
        .output()
        .expect("run tune yaml");
    assert!(
        yaml.status.success(),
        "{}",
        String::from_utf8_lossy(&yaml.stderr)
    );
    let yaml_out = normalize_id(&String::from_utf8(yaml.stdout).unwrap());
    assert_eq!(
        yaml_out.trim_end(),
        include_str!("golden/tune_from_dispositions.yaml").trim_end()
    );

    let report = rsigma()
        .args([
            "rule",
            "tune",
            "--rules",
            rules.path().to_str().unwrap(),
            "--from-dispositions",
            spool.path().to_str().unwrap(),
            "--emit",
            "report",
            "--output-format",
            "json",
        ])
        .output()
        .expect("run tune json");
    assert!(report.status.success());
    let json_out = normalize_tune_json(&String::from_utf8(report.stdout).unwrap());
    assert_eq!(
        json_out.trim_end(),
        include_str!("golden/tune_from_dispositions.json").trim_end()
    );

    let text = rsigma()
        .args([
            "rule",
            "tune",
            "--rules",
            rules.path().to_str().unwrap(),
            "--from-dispositions",
            spool.path().to_str().unwrap(),
            "--emit",
            "report",
            "--output-format",
            "table",
        ])
        .output()
        .expect("run tune text");
    assert!(text.status.success());
    let text_out = normalize_id(&String::from_utf8(text.stdout).unwrap());
    assert_eq!(
        text_out.trim_end(),
        include_str!("golden/tune_from_dispositions.txt").trim_end()
    );
}

fn normalize_tune_json(raw: &str) -> String {
    let mut value: serde_json::Value = serde_json::from_str(raw).expect("json report");
    if let Some(items) = value.as_array_mut() {
        for item in items {
            if let Some(yaml) = item.get_mut("filter_yaml").and_then(|v| v.as_str()) {
                item["filter_yaml"] = serde_json::Value::String(normalize_id(yaml));
            }
        }
    }
    // The optional `evtx` feature enables serde_json's `preserve_order`, which
    // flips map serialization from key-sorted to insertion order. Sort keys
    // recursively so the golden comparison is feature-independent.
    sort_json_keys(&mut value);
    serde_json::to_string_pretty(&value).unwrap()
}

fn sort_json_keys(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(String, serde_json::Value)> =
                std::mem::take(map).into_iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            for (_, v) in &mut entries {
                sort_json_keys(v);
            }
            map.extend(entries);
        }
        serde_json::Value::Array(items) => {
            for item in items {
                sort_json_keys(item);
            }
        }
        _ => {}
    }
}

#[test]
fn from_dispositions_requires_tp_protection() {
    let rules = temp_file(".yml", RULE);
    let spool = tempfile::tempdir().unwrap();
    write_disposition_bundle(
        spool.path(),
        "fp",
        "backup-fp",
        "false_positive",
        "929a690e-bef0-4204-a928-ef5e620d6fcc",
        "Suspicious Backup Tool",
        &[
            r#"{"Image":"C:\\Program Files\\Veeam\\backup.exe","User":"svc_backup"}"#,
            r#"{"Image":"C:\\Program Files\\Veeam\\backup.exe","User":"svc_backup"}"#,
        ],
    );
    rsigma()
        .args([
            "rule",
            "tune",
            "--rules",
            rules.path().to_str().unwrap(),
            "--from-dispositions",
            spool.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no true-positive protection set"));
}

#[test]
fn from_dispositions_rejects_malformed_bundles() {
    let rules = temp_file(".yml", RULE);
    let spool = tempfile::tempdir().unwrap();
    let dir = spool.path().join("fp/bad");
    std::fs::create_dir_all(dir.join("provenance")).unwrap();
    std::fs::write(dir.join("manifest.json"), b"{\"format_version\":99}").unwrap();
    std::fs::write(dir.join("provenance/events.ndjson"), b"{}\n").unwrap();
    rsigma()
        .args([
            "rule",
            "tune",
            "--rules",
            rules.path().to_str().unwrap(),
            "--from-dispositions",
            spool.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("manifest.json"));
}

#[test]
fn from_dispositions_conflicts_with_manual_corpora() {
    let rules = temp_file(".yml", RULE);
    let spool = tempfile::tempdir().unwrap();
    rsigma()
        .args([
            "rule",
            "tune",
            "--rules",
            rules.path().to_str().unwrap(),
            "--from-dispositions",
            spool.path().to_str().unwrap(),
            "--tp",
            r#"{"Image":"C:\\Temp\\backup.exe"}"#,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn malformed_corpus_record_fails_closed() {
    let rule = temp_file(".yml", RULE);
    let fp = temp_file(".ndjson", FALSE_POSITIVES);
    let tp = temp_file(
        ".ndjson",
        concat!(
            r#"{"Image":"C:\\Temp\\backup.exe","User":"attacker"}"#,
            "\nnot-json\n",
        ),
    );

    rsigma()
        .args([
            "rule",
            "tune",
            "-r",
            rule.path().to_str().unwrap(),
            "--fp",
            &format!("@{}", fp.path().display()),
            "--tp",
            &format!("@{}", tp.path().display()),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "tuning requires the complete corpus",
        ));
}
