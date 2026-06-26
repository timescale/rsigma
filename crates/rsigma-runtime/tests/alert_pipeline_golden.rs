//! Golden wire-shape tests for the alert pipeline's dedup summary records.
//!
//! These pin the NDJSON shape of the `repeat` and `resolved` records so a
//! downstream consumer's parser cannot be broken by an accidental field
//! rename or reordering.

use std::collections::HashMap;
use std::sync::Arc;

use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
use rsigma_parser::Level;
use rsigma_runtime::{DedupStore, NoopMetrics, parse_alert_pipeline_config};

fn detection() -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "Malware execution".to_string(),
            rule_id: Some("rule-1".to_string()),
            level: Some(Level::High),
            tags: vec!["attack.t1059".to_string()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![FieldMatch::new(
                "CommandLine",
                serde_json::json!("malware.exe"),
            )],
            event: Some(serde_json::json!({"CommandLine": "malware.exe"})),
        }),
    }
}

#[test]
fn dedup_repeat_and_resolved_wire_shape() {
    let pipeline = parse_alert_pipeline_config(
        "dedup:\n  fingerprint: [rule, match.CommandLine]\n  repeat_interval: 10s\n  resolve_timeout: 30s\n",
    )
    .unwrap();
    let mut store = DedupStore::default();
    let m = NoopMetrics;

    // First fire opens the alert; a second fire folds in.
    let _ = pipeline.process(vec![detection()], &mut store, 1000, &m);
    let _ = pipeline.process(vec![detection()], &mut store, 1005, &m);

    // Expected wire shape, compared as a parsed value so the assertion is
    // robust to JSON object key ordering (serde_json's `preserve_order`
    // feature flips map order under feature unification). The fingerprint is a
    // deterministic FNV digest, so it is pinned exactly.
    let expected = |state: &str| {
        serde_json::json!({
            "rule_title": "Malware execution",
            "rule_id": "rule-1",
            "level": "high",
            "tags": ["attack.t1059"],
            "enrichments": {
                "dedup_state": state,
                "dedup_fingerprint": "13bf5ab591909123",
                "dedup_fire_count": 2,
                "dedup_first_seen": 1000,
                "dedup_last_seen": 1005,
                "dedup_fields": {"rule": "rule-1", "match.CommandLine": "malware.exe"}
            },
            "matched_selections": ["selection"],
            "matched_fields": [{"field": "CommandLine", "value": "malware.exe"}]
        })
    };

    // A repeat re-emit is due at +11s with two fires accumulated.
    let repeat = pipeline.tick(&mut store, 1011, &m);
    assert_eq!(repeat.len(), 1);
    let repeat_json = serde_json::to_string(&repeat[0]).unwrap();
    let repeat_value: serde_json::Value = serde_json::from_str(&repeat_json).unwrap();
    assert_eq!(repeat_value, expected("repeat"));
    // The raw event payload is stripped from the summary record.
    assert!(repeat_value.get("event").is_none());

    // After resolve_timeout of no fires, the alert resolves and evicts.
    let resolved = pipeline.tick(&mut store, 1040, &m);
    assert_eq!(resolved.len(), 1);
    let resolved_json = serde_json::to_string(&resolved[0]).unwrap();
    let resolved_value: serde_json::Value = serde_json::from_str(&resolved_json).unwrap();
    assert_eq!(resolved_value, expected("resolved"));
    assert!(store.is_empty());
}
