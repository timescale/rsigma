use std::sync::Arc;

use rsigma_eval::{CorrelationConfig, ProcessResultExt};
use rsigma_runtime::{LogProcessor, NoopMetrics, RuntimeEngine};

fn build_processor(rules_yaml: &str) -> (LogProcessor, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let rule_path = dir.path().join("test.yml");
    std::fs::write(&rule_path, rules_yaml).unwrap();

    let mut engine = RuntimeEngine::new(rule_path, vec![], CorrelationConfig::default(), false);
    engine.load_rules().unwrap();
    let proc = LogProcessor::new(engine, Arc::new(NoopMetrics));
    (proc, dir)
}

fn identity_filter(v: serde_json::Value) -> Vec<serde_json::Value> {
    vec![v]
}

#[test]
fn happy_path_single_detection() {
    let (proc, _dir) = build_processor(
        r#"
title: Suspicious Process
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "powershell"
    condition: selection
level: high
"#,
    );

    let batch = vec![
        r#"{"CommandLine": "powershell -enc ABC", "Image": "cmd.exe"}"#.to_string(),
        r#"{"CommandLine": "notepad.exe", "Image": "explorer.exe"}"#.to_string(),
    ];
    let results = proc.process_batch_lines(&batch, &identity_filter);

    assert_eq!(results.len(), 2);
    assert_eq!(
        results[0].detection_count(),
        1,
        "powershell line should match"
    );
    assert_eq!(
        results[0].detections().next().unwrap().header.rule_title,
        "Suspicious Process",
        "detection should carry the rule title"
    );
    assert!(
        results[1].detection_count() == 0,
        "notepad line should not match"
    );
}

#[test]
fn no_match_yields_empty_detections() {
    let (proc, _dir) = build_processor(
        r#"
title: Never Matches
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 99999
    condition: selection
"#,
    );

    let batch = vec![r#"{"EventID": 1}"#.to_string()];
    let results = proc.process_batch_lines(&batch, &identity_filter);

    assert_eq!(results.len(), 1);
    assert!(results[0].detection_count() == 0);
}

#[test]
fn reload_picks_up_new_rules() {
    let dir = tempfile::tempdir().unwrap();
    let rule_path = dir.path().join("rule.yml");
    std::fs::write(
        &rule_path,
        r#"
title: Original
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#,
    )
    .unwrap();

    let mut engine = RuntimeEngine::new(
        rule_path.clone(),
        vec![],
        CorrelationConfig::default(),
        false,
    );
    engine.load_rules().unwrap();
    let proc = LogProcessor::new(engine, Arc::new(NoopMetrics));

    let batch = vec![r#"{"EventID": 42}"#.to_string()];
    let results = proc.process_batch_lines(&batch, &identity_filter);
    assert!(
        results[0].detection_count() == 0,
        "should not match EventID=42 yet"
    );

    std::fs::write(
        &rule_path,
        r#"
title: Updated
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 42
    condition: selection
"#,
    )
    .unwrap();

    proc.reload_rules().expect("reload should succeed");

    let results = proc.process_batch_lines(&batch, &identity_filter);
    assert_eq!(
        results[0].detection_count(),
        1,
        "reloaded rule should match"
    );
    assert_eq!(
        results[0].detections().next().unwrap().header.rule_title,
        "Updated"
    );
}

const GOOD_RULE: &str = r#"
title: Good
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 1
    condition: selection
"#;

const BROKEN_RULE: &str = r#"
title: Broken
status: test
logsource:
    category: test
detection:
    selection:
        EventID: 2
    condition: selection and (
"#;

fn rules_dir(rules: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (name, yaml) in rules {
        std::fs::write(dir.path().join(name), yaml).unwrap();
    }
    dir
}

fn engine_for(dir: &tempfile::TempDir) -> RuntimeEngine {
    RuntimeEngine::new(
        dir.path().to_path_buf(),
        vec![],
        CorrelationConfig::default(),
        false,
    )
}

#[test]
fn load_fails_when_every_rule_fails_to_parse() {
    let dir = rules_dir(&[("broken.yml", BROKEN_RULE)]);
    let err = engine_for(&dir).load_rules().unwrap_err();
    assert!(err.contains("every rule failed to parse"), "{err}");
}

#[test]
fn load_skips_broken_rules_and_counts_them() {
    let dir = rules_dir(&[("good.yml", GOOD_RULE), ("broken.yml", BROKEN_RULE)]);
    let mut engine = engine_for(&dir);
    let stats = engine.load_rules().unwrap();
    assert_eq!(stats.detection_rules, 1);
    assert_eq!(stats.parse_errors, 1);
    assert_eq!(engine.stats().parse_errors, 1);
}

#[test]
fn empty_rules_dir_still_loads() {
    let dir = rules_dir(&[]);
    let stats = engine_for(&dir).load_rules().unwrap();
    assert_eq!(stats.detection_rules, 0);
    assert_eq!(stats.parse_errors, 0);
}

#[test]
fn strict_rules_rejects_any_parse_error() {
    let dir = rules_dir(&[("good.yml", GOOD_RULE), ("broken.yml", BROKEN_RULE)]);
    let mut engine = engine_for(&dir);
    engine.set_strict_rules(true);
    let err = engine.load_rules().unwrap_err();
    assert!(err.contains("strict rule loading"), "{err}");
}

#[test]
fn reload_keeps_rules_when_every_rule_fails_to_parse() {
    let dir = rules_dir(&[("good.yml", GOOD_RULE)]);
    let mut engine = engine_for(&dir);
    engine.load_rules().unwrap();
    let proc = LogProcessor::new(engine, Arc::new(NoopMetrics));

    std::fs::write(dir.path().join("good.yml"), BROKEN_RULE).unwrap();
    assert!(proc.reload_rules().is_err());

    let batch = vec![r#"{"EventID": 1}"#.to_string()];
    let results = proc.process_batch_lines(&batch, &identity_filter);
    assert_eq!(
        results[0].detection_count(),
        1,
        "previous rules stay active"
    );
}

#[test]
fn reload_keeps_strict_rules() {
    let dir = rules_dir(&[("good.yml", GOOD_RULE)]);
    let mut engine = engine_for(&dir);
    engine.set_strict_rules(true);
    engine.load_rules().unwrap();
    let proc = LogProcessor::new(engine, Arc::new(NoopMetrics));

    std::fs::write(dir.path().join("broken.yml"), BROKEN_RULE).unwrap();
    let err = proc.reload_rules().unwrap_err();
    assert!(err.contains("strict rule loading"), "{err}");
    assert_eq!(proc.stats().detection_rules, 1);
}
