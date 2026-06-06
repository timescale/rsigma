//! Golden NDJSON snapshot tests for the unified `EvaluationResult` wire shape.
//!
//! These tests pin the exact byte-for-byte serialization of one detection
//! result and one correlation result. They guarantee:
//!
//! 1. Both kinds serialize to a single flat top-level JSON object.
//! 2. Detection lines carry `matched_fields` / `matched_selections` and no
//!    `correlation_type` field; correlation lines carry `correlation_type`
//!    and no `matched_fields` field. Downstream NDJSON consumers
//!    disambiguate by these fields.
//! 3. `skip_serializing_if` behavior and field set match what every
//!    existing sink (file, stdout, NATS) has always emitted.
//!
//! If a future refactor changes the wire shape, these tests fail loudly.
//! Updating them is intentional, never automatic.

use std::collections::HashMap;
use std::sync::Arc;

use rsigma_eval::{
    CorrelationBody, DetectionBody, EvaluationResult, FieldMatch, MatcherKind, ResultBody,
    RuleHeader,
};
use rsigma_parser::{CorrelationType, Level};

fn header(title: &str) -> RuleHeader {
    RuleHeader {
        rule_title: title.to_string(),
        rule_id: Some(format!("{title}-id")),
        level: Some(Level::High),
        tags: vec![
            "attack.execution".to_string(),
            "attack.t1059.001".to_string(),
        ],
        custom_attributes: Arc::new(HashMap::new()),
        enrichments: None,
    }
}

#[test]
fn detection_golden_ndjson_line() {
    let result = EvaluationResult {
        header: header("Suspicious PowerShell Encoded Command"),
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection_image".to_string(), "selection_args".to_string()],
            matched_fields: vec![
                FieldMatch::new(
                    "Image",
                    serde_json::json!("C:\\Windows\\System32\\powershell.exe"),
                ),
                FieldMatch::new(
                    "CommandLine",
                    serde_json::json!("powershell -nop -w hidden -enc JAB..."),
                ),
            ],
            event: None,
        }),
    };

    let actual = serde_json::to_string(&result).unwrap();
    let expected = r#"{"rule_title":"Suspicious PowerShell Encoded Command","rule_id":"Suspicious PowerShell Encoded Command-id","level":"high","tags":["attack.execution","attack.t1059.001"],"matched_selections":["selection_image","selection_args"],"matched_fields":[{"field":"Image","value":"C:\\Windows\\System32\\powershell.exe"},{"field":"CommandLine","value":"powershell -nop -w hidden -enc JAB..."}]}"#;
    assert_eq!(
        actual, expected,
        "Detection NDJSON wire shape drift detected. If this change is intentional, update the golden string in this test and document it in the CHANGELOG."
    );

    // Downstream-disambiguation contract: a detection line carries
    // matched_fields and does NOT carry correlation_type.
    let parsed: serde_json::Value = serde_json::from_str(&actual).unwrap();
    assert!(parsed.get("matched_fields").is_some());
    assert!(parsed.get("correlation_type").is_none());
}

/// Wire-shape snapshot at `Summary`: enrichment fields appear after
/// `field`/`value`, the keyword entry has no `pattern`, and `None`
/// enrichment values are skipped.
#[test]
fn detection_summary_golden_ndjson_line() {
    let result = EvaluationResult {
        header: header("Suspicious PowerShell Encoded Command"),
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection_args".to_string(), "keywords".to_string()],
            matched_fields: vec![
                FieldMatch {
                    field: "CommandLine".to_string(),
                    value: serde_json::json!("powershell -nop -w hidden -enc JAB..."),
                    selection: Some("selection_args".to_string()),
                    matcher: Some(MatcherKind::Contains),
                    pattern: None,
                    case_sensitive: Some(false),
                    negated: false,
                },
                FieldMatch {
                    field: "keyword".to_string(),
                    value: serde_json::json!("powershell -nop -w hidden -enc JAB..."),
                    selection: Some("keywords".to_string()),
                    matcher: Some(MatcherKind::Keyword),
                    pattern: None,
                    case_sensitive: None,
                    negated: false,
                },
            ],
            event: None,
        }),
    };

    let actual = serde_json::to_string(&result).unwrap();
    let expected = r#"{"rule_title":"Suspicious PowerShell Encoded Command","rule_id":"Suspicious PowerShell Encoded Command-id","level":"high","tags":["attack.execution","attack.t1059.001"],"matched_selections":["selection_args","keywords"],"matched_fields":[{"field":"CommandLine","value":"powershell -nop -w hidden -enc JAB...","selection":"selection_args","matcher":"contains","case_sensitive":false},{"field":"keyword","value":"powershell -nop -w hidden -enc JAB...","selection":"keywords","matcher":"keyword"}]}"#;
    assert_eq!(
        actual, expected,
        "Summary detection wire shape drift. If intentional, update this golden and the CHANGELOG."
    );
}

/// Wire-shape snapshot at `Full`: same as `Summary` plus the `pattern` key,
/// and a negated entry emits `negated: true`.
#[test]
fn detection_full_golden_ndjson_line() {
    let result = EvaluationResult {
        header: header("Suspicious PowerShell Encoded Command"),
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection_args".to_string()],
            matched_fields: vec![
                FieldMatch {
                    field: "CommandLine".to_string(),
                    value: serde_json::json!("powershell -nop -w hidden -enc JAB..."),
                    selection: Some("selection_args".to_string()),
                    matcher: Some(MatcherKind::Contains),
                    pattern: Some("-enc".to_string()),
                    case_sensitive: Some(false),
                    negated: false,
                },
                FieldMatch {
                    field: "Image".to_string(),
                    value: serde_json::json!("C:\\Windows\\notepad.exe"),
                    selection: Some("selection_args".to_string()),
                    matcher: Some(MatcherKind::EndsWith),
                    pattern: Some("\\powershell.exe".to_string()),
                    case_sensitive: Some(false),
                    negated: true,
                },
            ],
            event: None,
        }),
    };

    let actual = serde_json::to_string(&result).unwrap();
    let expected = r#"{"rule_title":"Suspicious PowerShell Encoded Command","rule_id":"Suspicious PowerShell Encoded Command-id","level":"high","tags":["attack.execution","attack.t1059.001"],"matched_selections":["selection_args"],"matched_fields":[{"field":"CommandLine","value":"powershell -nop -w hidden -enc JAB...","selection":"selection_args","matcher":"contains","pattern":"-enc","case_sensitive":false},{"field":"Image","value":"C:\\Windows\\notepad.exe","selection":"selection_args","matcher":"endswith","pattern":"\\powershell.exe","case_sensitive":false,"negated":true}]}"#;
    assert_eq!(
        actual, expected,
        "Full detection wire shape drift. If intentional, update this golden and the CHANGELOG."
    );
}

#[test]
fn correlation_golden_ndjson_line() {
    let result = EvaluationResult {
        header: header("SSH brute force from single source"),
        body: ResultBody::Correlation(CorrelationBody {
            correlation_type: CorrelationType::EventCount,
            group_key: vec![
                ("SourceIP".to_string(), "203.0.113.4".to_string()),
                ("User".to_string(), "root".to_string()),
            ],
            aggregated_value: 73.0,
            timespan_secs: 300,
            events: None,
            event_refs: None,
        }),
    };

    let actual = serde_json::to_string(&result).unwrap();
    let expected = r#"{"rule_title":"SSH brute force from single source","rule_id":"SSH brute force from single source-id","level":"high","tags":["attack.execution","attack.t1059.001"],"correlation_type":"event_count","group_key":[["SourceIP","203.0.113.4"],["User","root"]],"aggregated_value":73.0,"timespan_secs":300}"#;
    assert_eq!(
        actual, expected,
        "Correlation NDJSON wire shape drift detected. If this change is intentional, update the golden string in this test and document it in the CHANGELOG."
    );

    // Downstream-disambiguation contract: a correlation line carries
    // correlation_type and does NOT carry matched_fields.
    let parsed: serde_json::Value = serde_json::from_str(&actual).unwrap();
    assert!(parsed.get("correlation_type").is_some());
    assert!(parsed.get("matched_fields").is_none());
}

/// `enrichments` is `None` by default and must be skipped from serialization.
#[test]
fn enrichments_none_is_skipped() {
    let result = EvaluationResult {
        header: header("Detection With No Enrichments"),
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![],
            event: None,
        }),
    };
    let json = serde_json::to_string(&result).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(
        parsed.get("enrichments").is_none(),
        "enrichments key must be omitted when None"
    );
}

/// When a downstream consumer populates the map, the field is emitted at
/// the top level (flattened from `RuleHeader`).
#[test]
fn enrichments_some_serializes_at_top_level() {
    let mut enrichments = serde_json::Map::new();
    enrichments.insert(
        "asset_info".to_string(),
        serde_json::json!({"hostname": "dc01", "owner": "IT-Ops"}),
    );
    enrichments.insert(
        "runbook_url".to_string(),
        serde_json::json!("https://wiki.internal/runbooks/abc123"),
    );

    let mut h = header("Detection With Enrichments");
    h.enrichments = Some(enrichments);
    let result = EvaluationResult {
        header: h,
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![],
            event: None,
        }),
    };
    let json = serde_json::to_string(&result).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let enr = parsed.get("enrichments").expect("enrichments at top level");
    assert_eq!(enr["asset_info"]["hostname"], "dc01");
    assert_eq!(
        enr["runbook_url"].as_str(),
        Some("https://wiki.internal/runbooks/abc123")
    );
}

/// With a non-empty `custom_attributes` map, the field flattens from
/// `RuleHeader` and is emitted between the rule-header fields and the
/// kind-specific body fields rather than at the end of the line.
///
/// JSON objects are unordered per spec, so compliant consumers do not
/// care; this test pins the actual byte ordering so any future change
/// is intentional, never silent.
#[test]
fn detection_with_custom_attributes_emits_after_tags_before_body() {
    let mut custom = HashMap::new();
    custom.insert("severity_score".to_string(), serde_json::json!(42));

    let mut h = header("Detection With Custom Attributes");
    h.custom_attributes = Arc::new(custom);

    let result = EvaluationResult {
        header: h,
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![FieldMatch::new("EventID", serde_json::json!(1))],
            event: None,
        }),
    };

    let actual = serde_json::to_string(&result).unwrap();
    let expected = r#"{"rule_title":"Detection With Custom Attributes","rule_id":"Detection With Custom Attributes-id","level":"high","tags":["attack.execution","attack.t1059.001"],"custom_attributes":{"severity_score":42},"matched_selections":["selection"],"matched_fields":[{"field":"EventID","value":1}]}"#;
    assert_eq!(
        actual, expected,
        "Custom-attributes detection ordering drift. If intentional, update this test."
    );
}
