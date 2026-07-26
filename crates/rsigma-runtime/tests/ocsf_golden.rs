//! Golden wire-shape and conformance tests for OCSF Detection Finding output.
//!
//! One golden per emitted shape lives in `tests/golden/ocsf/` and is compared
//! as pretty-printed JSON, so a field rename, an enum drift, or a changed
//! `unmapped` contract shows up as a reviewable diff. Every golden is then
//! validated against the committed minimal class-2004 schema in
//! `tests/fixtures/ocsf/class_2004.schema.json` (profiles off, no network).
//!
//! Time and the minted uids come from a fixed [`FindingSource`], so the
//! goldens are byte-stable.
//!
//! To regenerate after an intentional change, run with
//! `RSIGMA_UPDATE_GOLDEN=1`:
//!
//! ```sh
//! RSIGMA_UPDATE_GOLDEN=1 cargo test -p rsigma-runtime --test ocsf_golden
//! ```

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rsigma_eval::{
    CorrelationBody, DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader,
};
use rsigma_parser::{CorrelationType, Level};
use rsigma_runtime::ocsf::{
    self, FindingSource, detection_finding_with, incident_finding_with, risk_incident_finding_with,
};
use rsigma_runtime::{IncidentRef, IncidentResult, RiskIncidentResult, RiskRef};
use serde_json::{Value, json};

/// A fixed clock and a counted uid source, so a golden is the same bytes on
/// every run.
struct FixedSource {
    now_ms: i64,
    minted: Cell<u64>,
}

impl FixedSource {
    fn new() -> Self {
        FixedSource {
            now_ms: 1_767_225_600_000,
            minted: Cell::new(0),
        }
    }
}

impl FindingSource for FixedSource {
    fn now_ms(&self) -> i64 {
        self.now_ms
    }

    fn uid(&self) -> String {
        let n = self.minted.get() + 1;
        self.minted.set(n);
        format!("00000000-0000-4000-8000-{n:012}")
    }
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/ocsf")
}

/// Rebuild every object with its keys in sorted order.
///
/// `serde_json`'s `preserve_order` feature switches maps from sorted to
/// insertion order, and feature unification turns it on for some workspace
/// builds and not others. Canonicalizing keeps one golden valid under both.
fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .map(|key| (key.clone(), canonical(&map[key])))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

/// Compare a finding to its golden, then validate it against the class-2004
/// conformance schema.
fn check(name: &str, finding: &Value) {
    let path = golden_dir().join(format!("{name}.json"));
    let actual = format!(
        "{}\n",
        serde_json::to_string_pretty(&canonical(finding)).unwrap()
    );

    if std::env::var_os("RSIGMA_UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(golden_dir()).unwrap();
        fs::write(&path, &actual)
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
    } else {
        let expected = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
            .replace("\r\n", "\n");
        assert_eq!(actual, expected, "OCSF golden mismatch for '{name}'");
    }

    validate_class_2004(name, finding);
}

fn validate_class_2004(name: &str, finding: &Value) {
    let schema_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ocsf/class_2004.schema.json");
    let schema: Value = serde_json::from_str(&fs::read_to_string(&schema_path).unwrap()).unwrap();
    let validator = jsonschema::validator_for(&schema).expect("conformance schema must compile");

    let errors: Vec<String> = validator
        .iter_errors(finding)
        .map(|e| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "'{name}' is not a conformant class-2004 finding: {errors:#?}"
    );

    // The class/activity arithmetic OCSF requires, asserted directly because a
    // schema cannot express it without repeating every pair.
    let class_uid = finding["class_uid"].as_i64().unwrap();
    let activity_id = finding["activity_id"].as_i64().unwrap();
    assert_eq!(
        finding["type_uid"].as_i64().unwrap(),
        class_uid * 100 + activity_id,
        "'{name}': type_uid must be class_uid * 100 + activity_id",
    );
}

fn header(enrichments: Option<serde_json::Map<String, Value>>) -> RuleHeader {
    RuleHeader {
        rule_title: "Suspicious PowerShell".to_string(),
        rule_id: Some("rule-1".to_string()),
        level: Some(Level::High),
        tags: vec![
            "attack.t1059.001".to_string(),
            "attack.execution".to_string(),
            "cve.2023.1".to_string(),
        ],
        custom_attributes: Arc::new(HashMap::from([(
            "team".to_string(),
            json!("detection-eng"),
        )])),
        enrichments,
    }
}

#[test]
fn detection_with_matched_fields_and_risk_enrichments() {
    let enrichments = serde_json::Map::from_iter([
        ("risk.score".to_string(), json!(75)),
        (
            "risk.objects".to_string(),
            json!([
                {"type": "user", "value": "alice"},
                {"type": "host", "value": "ws-01"},
            ]),
        ),
        ("incident_id".to_string(), json!("f8bcd62a829b1126")),
    ]);
    let result = EvaluationResult {
        header: header(Some(enrichments)),
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![FieldMatch::new(
                "CommandLine",
                json!("powershell -enc ZQBjAGgAbwA="),
            )],
            event: Some(json!({"CommandLine": "powershell -enc ZQBjAGgAbwA=", "User": "alice"})),
        }),
    };

    check(
        "detection",
        &detection_finding_with(&result, &FixedSource::new()),
    );
}

#[test]
fn correlation_with_group_key() {
    let result = EvaluationResult {
        header: RuleHeader {
            rule_title: "SSH brute force".to_string(),
            rule_id: Some("corr-1".to_string()),
            level: Some(Level::Critical),
            tags: vec!["attack.credential_access".to_string()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
        },
        body: ResultBody::Correlation(CorrelationBody {
            correlation_type: CorrelationType::EventCount,
            group_key: vec![("SourceIP".to_string(), "203.0.113.4".to_string())],
            aggregated_value: 73.0,
            timespan_secs: 300,
            events: None,
            event_refs: None,
        }),
    };

    check(
        "correlation",
        &detection_finding_with(&result, &FixedSource::new()),
    );
}

fn incident(state: &'static str, trigger: &'static str) -> IncidentResult {
    IncidentResult {
        incident_id: "f8bcd62a829b1126".to_string(),
        state,
        trigger,
        first_seen: 1_767_225_000,
        last_seen: 1_767_225_600,
        max_level: Some("high".to_string()),
        result_count: 4,
        rule_counts: BTreeMap::from([("rule-1".to_string(), 3), ("rule-2".to_string(), 1)]),
        group_by: serde_json::Map::from_iter([("match.User".to_string(), json!("alice"))]),
        entities: serde_json::Map::new(),
        refs: Some(vec![IncidentRef {
            rule: "rule-1".to_string(),
            level: Some("high".to_string()),
        }]),
        results: None,
        sample_mode: None,
        bundle_ready: None,
    }
}

#[test]
fn incident_open_is_a_create_finding() {
    check(
        "incident_open",
        &incident_finding_with(&incident("open", "group_wait"), &FixedSource::new()),
    );
}

#[test]
fn incident_resolved_is_a_close_finding() {
    check(
        "incident_resolved",
        &incident_finding_with(&incident("resolved", "resolved"), &FixedSource::new()),
    );
}

#[test]
fn risk_incident_carries_score_and_entity() {
    let incident = RiskIncidentResult {
        risk_incident_id: "11111111-1111-4111-8111-111111111111".to_string(),
        entity_type: "user".to_string(),
        entity_value: "alice".to_string(),
        trigger: "score",
        score: 120,
        score_threshold: Some(100),
        tactic_count: 2,
        tactic_count_threshold: None,
        tactics: vec!["execution".to_string(), "credential-access".to_string()],
        sources: vec!["rule-1".to_string(), "rule-2".to_string()],
        source_count: 2,
        window_start: 1_767_222_000,
        window_end: 1_767_225_600,
        result_count: 5,
        refs: Some(vec![RiskRef {
            rule: "rule-1".to_string(),
            level: Some("high".to_string()),
            score: 75,
            timestamp: 1_767_225_600,
        }]),
        results: None,
    };

    check(
        "risk_incident",
        &risk_incident_finding_with(&incident, &FixedSource::new()),
    );
}

/// The default entry points mint a distinct `metadata.uid` per finding, so a
/// consumer can deduplicate a replayed batch.
#[test]
fn minted_uids_are_unique_across_a_batch() {
    let result = EvaluationResult {
        header: header(None),
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![],
            event: None,
        }),
    };

    let uids: Vec<String> = (0..8)
        .map(|_| {
            ocsf::detection_finding(&result)["metadata"]["uid"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    let distinct: std::collections::HashSet<&String> = uids.iter().collect();
    assert_eq!(distinct.len(), uids.len(), "metadata.uid must be unique");
}
