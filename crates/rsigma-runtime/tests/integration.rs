use std::sync::Arc;

use rsigma_eval::CorrelationConfig;
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

fn identity_filter(v: &serde_json::Value) -> Vec<serde_json::Value> {
    vec![v.clone()]
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
        results[0].detections.len(),
        1,
        "powershell line should match"
    );
    assert_eq!(
        results[0].detections[0].rule_title, "Suspicious Process",
        "detection should carry the rule title"
    );
    assert!(
        results[1].detections.is_empty(),
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
    assert!(results[0].detections.is_empty());
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
        results[0].detections.is_empty(),
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
    assert_eq!(results[0].detections.len(), 1, "reloaded rule should match");
    assert_eq!(results[0].detections[0].rule_title, "Updated");
}
