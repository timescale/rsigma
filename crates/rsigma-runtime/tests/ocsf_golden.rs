//! Golden wire-shape and conformance tests for OCSF Detection Finding and
//! Incident Finding output.
//!
//! One golden per emitted shape lives in `tests/golden/ocsf/` and is compared
//! as pretty-printed JSON, so a field rename, an enum drift, or a changed
//! `unmapped` contract shows up as a reviewable diff. Every golden is then
//! validated against the committed minimal schema for its class under
//! `tests/fixtures/ocsf/<version>/class_<uid>.schema.json` (profiles off, no
//! network).
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
use rsigma_runtime::RiskEvent;
use rsigma_runtime::ocsf::{
    self, FindingSource, OcsfOptions, OcsfVersion, dedup_summary_finding_with_opts,
    detection_finding_with_opts, incident_finding_2005, incident_finding_2005_with_opts,
    incident_finding_with_opts, risk_event_finding_with_opts, risk_incident_finding_2005,
    risk_incident_finding_2005_with_opts, risk_incident_finding_with_opts,
};
use rsigma_runtime::{
    AlertPipelineState, IncidentRef, IncidentResult, NoopMetrics, RiskIncidentResult, RiskRef,
    parse_alert_pipeline_config,
};
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

fn golden_path(version: OcsfVersion, name: &str) -> PathBuf {
    golden_dir()
        .join(version.as_str())
        .join(format!("{name}.json"))
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

/// Compare a finding to its golden, then validate it against the conformance
/// schema for its class.
fn check_version(version: OcsfVersion, name: &str, finding: &Value) {
    let path = golden_path(version, name);
    let actual = format!(
        "{}\n",
        serde_json::to_string_pretty(&canonical(finding)).unwrap()
    );

    if std::env::var_os("RSIGMA_UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &actual)
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
    } else {
        let expected = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
            .replace("\r\n", "\n");
        assert_eq!(
            actual,
            expected,
            "OCSF golden mismatch for '{name}' ({})",
            version.as_str()
        );
    }

    validate_class(name, finding, version);
}

fn check_both_versions(name: &str, build: impl Fn(OcsfOptions) -> Value) {
    check_version(OcsfVersion::V1_1_0, name, &build(OcsfOptions::default()));
    check_version(
        OcsfVersion::V1_3_0,
        name,
        &build(OcsfOptions::new(OcsfVersion::V1_3_0)),
    );
}

fn validate_class(name: &str, finding: &Value, version: OcsfVersion) {
    let class_uid = finding["class_uid"].as_i64().unwrap();
    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "tests/fixtures/ocsf/{}/class_{class_uid}.schema.json",
        version.as_str()
    ));
    let schema: Value = serde_json::from_str(&fs::read_to_string(&schema_path).unwrap()).unwrap();
    let validator = jsonschema::validator_for(&schema).expect("conformance schema must compile");

    let errors: Vec<String> = validator
        .iter_errors(finding)
        .map(|e| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "'{name}' is not a conformant class-{class_uid} finding: {errors:#?}"
    );

    // The class/activity arithmetic OCSF requires, asserted directly because a
    // schema cannot express it without repeating every pair.
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
        tenant_id: None,
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
        ruleset: None,
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

    check_both_versions("detection", |opts| {
        detection_finding_with_opts(&result, &FixedSource::new(), opts)
    });
}

#[test]
fn detection_from_a_named_ruleset_keeps_the_ruleset() {
    let mut header = header(None);
    header.ruleset = Some("win_a".into());
    let result = EvaluationResult {
        header,
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![FieldMatch::new("Image", json!("whoami"))],
            event: None,
        }),
    };

    check_both_versions("detection_ruleset", |opts| {
        detection_finding_with_opts(&result, &FixedSource::new(), opts)
    });
}

#[test]
fn correlation_with_group_key() {
    let result = EvaluationResult {
        header: RuleHeader {
            rule_title: "SSH brute force".to_string(),
            rule_id: Some("corr-1".to_string()),
            tenant_id: None,
            level: Some(Level::Critical),
            tags: vec!["attack.credential_access".to_string()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
            ruleset: None,
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

    check_both_versions("correlation", |opts| {
        detection_finding_with_opts(&result, &FixedSource::new(), opts)
    });
}

fn incident(state: &'static str, trigger: &'static str) -> IncidentResult {
    IncidentResult {
        incident_id: "f8bcd62a829b1126".to_string(),
        tenant_id: None,
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
    check_both_versions("incident_open", |opts| {
        incident_finding_with_opts(&incident("open", "group_wait"), &FixedSource::new(), opts)
    });
}

#[test]
fn incident_resolved_is_a_close_finding() {
    check_both_versions("incident_resolved", |opts| {
        incident_finding_with_opts(&incident("resolved", "resolved"), &FixedSource::new(), opts)
    });
}

/// Contributors whose Detection Finding uid the daemon minted are referenced
/// by that uid.
#[test]
fn incident_open_2005_references_its_detection_findings() {
    let mut open = incident("open", "group_wait");
    open.refs = Some(vec![
        IncidentRef {
            rule: "rule-1".to_string(),
            level: Some("high".to_string()),
        },
        IncidentRef {
            rule: "rule-2".to_string(),
            level: Some("medium".to_string()),
        },
    ]);
    let links = rsigma_runtime::FindingLinks {
        refs: vec![
            Some("msg_0123_0000_0".to_string()),
            Some("msg_4567_0001_0".to_string()),
        ],
        results: Vec::new(),
    };
    check_both_versions("incident_open_2005", |opts| {
        incident_finding_2005_with_opts(
            &open,
            &links,
            &FixedSource::new(),
            opts.with_incident_finding("soc").unwrap(),
        )
        .expect("assignee group")
    });
}

/// With no known contributor uid, each contributing rule gets one entry.
#[test]
fn incident_resolved_2005_falls_back_to_one_entry_per_rule() {
    check_both_versions("incident_resolved_2005", |opts| {
        incident_finding_2005_with_opts(
            &incident("resolved", "resolved"),
            &rsigma_runtime::FindingLinks::default(),
            &FixedSource::new(),
            opts.with_incident_finding("soc").unwrap(),
        )
        .expect("assignee group")
    });
}

#[test]
fn risk_incident_2005_references_its_detection_findings() {
    let incident = risk_incident();
    let links = rsigma_runtime::FindingLinks {
        refs: vec![Some("msg_89ab_0000_0".to_string())],
        results: Vec::new(),
    };
    check_both_versions("risk_incident_2005", |opts| {
        risk_incident_finding_2005_with_opts(
            &incident,
            &links,
            &FixedSource::new(),
            opts.with_incident_finding("soc").unwrap(),
        )
        .expect("assignee group")
    });
}

#[test]
fn class_2005_injected_builders_match_the_fixture_and_reject_a_missing_group() {
    let open = incident("open", "group_wait");
    let links = rsigma_runtime::FindingLinks::default();
    let src = FixedSource::new();
    assert!(incident_finding_2005(&open, " ").is_err());
    assert!(incident_finding_2005(&open, "").is_err());
    assert!(incident_finding_2005_with_opts(&open, &links, &src, OcsfOptions::default()).is_err());
    let finding = incident_finding_2005_with_opts(
        &open,
        &links,
        &src,
        OcsfOptions::default().with_incident_finding("soc").unwrap(),
    )
    .unwrap();
    validate_class("incident_2005_injected", &finding, OcsfVersion::V1_1_0);

    let risk = risk_incident();
    assert!(risk_incident_finding_2005(&risk, " ").is_err());
    assert!(
        risk_incident_finding_2005_with_opts(&risk, &links, &src, OcsfOptions::default()).is_err()
    );
    let finding = risk_incident_finding_2005_with_opts(
        &risk,
        &links,
        &src,
        OcsfOptions::default().with_incident_finding("soc").unwrap(),
    )
    .unwrap();
    validate_class("risk_2005_injected", &finding, OcsfVersion::V1_1_0);
}

fn risk_incident() -> RiskIncidentResult {
    RiskIncidentResult {
        risk_incident_id: "11111111-1111-4111-8111-111111111111".to_string(),
        tenant_id: None,
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
    }
}

#[test]
fn risk_incident_carries_score_and_entity() {
    let incident = risk_incident();
    check_both_versions("risk_incident", |opts| {
        risk_incident_finding_with_opts(&incident, &FixedSource::new(), opts)
    });
}

/// The default entry points mint a distinct `metadata.uid` per finding, so a
/// consumer can deduplicate a replayed batch.
#[test]
fn dedup_repeat_summary_is_an_update_finding() {
    let wire = serde_json::json!({
        "rule_title": "Malware execution",
        "rule_id": "rule-1",
        "level": "high",
        "tags": ["attack.t1059"],
        "enrichments": {
            "dedup_state": "repeat",
            "dedup_fingerprint": "13bf5ab591909123",
            "dedup_fire_count": 2,
            "dedup_first_seen": 1000,
            "dedup_last_seen": 1005,
            "dedup_fields": {"rule": "rule-1", "match.CommandLine": "malware.exe"}
        },
        "matched_selections": ["selection"],
        "matched_fields": [{"field": "CommandLine", "value": "malware.exe"}]
    });
    check_both_versions("dedup_repeat", |opts| {
        dedup_summary_finding_with_opts(&wire, &FixedSource::new(), opts)
    });
}

#[test]
fn dedup_summary_keeps_the_sample_ruleset() {
    let wire = serde_json::json!({
        "rule_title": "Malware execution",
        "rule_id": "rule-1",
        "level": "high",
        "ruleset": "win_a",
        "enrichments": {"dedup_state": "repeat", "dedup_fingerprint": "13bf5ab591909123"},
        "matched_selections": ["selection"],
        "matched_fields": []
    });
    let finding =
        dedup_summary_finding_with_opts(&wire, &FixedSource::new(), OcsfOptions::default());
    assert_eq!(finding["unmapped"]["ruleset"], "win_a");
}

#[test]
fn dedup_resolved_summary_is_a_close_finding() {
    let wire = serde_json::json!({
        "rule_title": "Malware execution",
        "rule_id": "rule-1",
        "level": "high",
        "tags": ["attack.t1059"],
        "enrichments": {
            "dedup_state": "resolved",
            "dedup_fingerprint": "13bf5ab591909123",
            "dedup_fire_count": 2,
            "dedup_first_seen": 1000,
            "dedup_last_seen": 1005,
            "dedup_fields": {"rule": "rule-1", "match.CommandLine": "malware.exe"}
        },
        "matched_selections": ["selection"],
        "matched_fields": [{"field": "CommandLine", "value": "malware.exe"}]
    });
    check_both_versions("dedup_resolved", |opts| {
        dedup_summary_finding_with_opts(&wire, &FixedSource::new(), opts)
    });
}

/// A repeat summary is the pipeline's stored sample plus `dedup_*` keys.
/// Enrichments the sample already carried (geo, incident id, risk) survive;
/// only the three keys lifted to `count` / `start_time` / `end_time` leave the map.
#[test]
fn dedup_repeat_from_a_pipeline_tick_keeps_sample_enrichments() {
    let pipeline = parse_alert_pipeline_config(
        "dedup:\n  fingerprint: [rule, match.CommandLine]\n  repeat_interval: 10s\n  resolve_timeout: 30s\n",
    )
    .unwrap();
    let mut state = AlertPipelineState::default();
    let metrics = NoopMetrics;
    let _ = pipeline.process(vec![enriched_detection()], &mut state, 1000, &metrics);
    let _ = pipeline.process(vec![enriched_detection()], &mut state, 1005, &metrics);
    let lines = pipeline.tick(&mut state, 1011, &metrics).dedup_lines;
    assert_eq!(lines.len(), 1, "one repeat summary is due");
    let wire = &lines[0];
    assert_eq!(wire["enrichments"]["geo"]["country"], "DE");
    assert_eq!(wire["enrichments"]["incident_id"], "inc-1");
    assert_eq!(wire["enrichments"]["risk.score"], 40);

    check_both_versions("dedup_repeat_enriched", |opts| {
        let finding = dedup_summary_finding_with_opts(wire, &FixedSource::new(), opts);
        let enrichments = &finding["unmapped"]["enrichments"];
        assert_eq!(enrichments["geo"]["country"], "DE");
        assert_eq!(enrichments["geo"]["city"], "Berlin");
        assert_eq!(enrichments["incident_id"], "inc-1");
        assert!(enrichments.get("risk.score").is_none());
        assert!(enrichments.get("risk.objects").is_none());
        assert!(enrichments.get("dedup_fire_count").is_none());
        assert!(enrichments.get("dedup_first_seen").is_none());
        assert!(enrichments.get("dedup_last_seen").is_none());
        assert_eq!(enrichments["dedup_state"], "repeat");
        assert_eq!(finding["risk_score"], 40);
        assert_eq!(finding["actor"]["user"]["name"], "alice");
        assert_eq!(finding["metadata"]["correlation_uid"], "inc-1");
        assert_eq!(finding["count"], 2);
        assert_eq!(finding["start_time"], 1_000_000);
        assert_eq!(finding["end_time"], 1_005_000);
        let profiles = finding["metadata"]["profiles"]
            .as_array()
            .expect("profiles");
        assert!(
            profiles
                .iter()
                .any(|p| p.as_str() == Some("security_control"))
        );
        assert!(profiles.iter().any(|p| p.as_str() == Some("host")));
        finding
    });
}

/// A correlation repeat summary is the pipeline sample, not a detection with
/// the correlation fields discarded. The pipeline strips event bodies before
/// it stores the sample; a line that still carries them keeps them too.
#[test]
fn dedup_repeat_from_a_correlation_keeps_the_correlation_body() {
    let pipeline = parse_alert_pipeline_config(
        "dedup:\n  fingerprint: [rule]\n  repeat_interval: 10s\n  resolve_timeout: 30s\n",
    )
    .unwrap();
    let mut state = AlertPipelineState::default();
    let metrics = NoopMetrics;
    let _ = pipeline.process(vec![correlation_detection()], &mut state, 1000, &metrics);
    let _ = pipeline.process(vec![correlation_detection()], &mut state, 1005, &metrics);
    let lines = pipeline.tick(&mut state, 1011, &metrics).dedup_lines;
    assert_eq!(lines.len(), 1, "one repeat summary is due");
    let wire = &lines[0];
    assert_eq!(wire["correlation_type"], "event_count");
    assert_eq!(wire["group_key"], json!([["SourceIP", "203.0.113.4"]]));
    assert_eq!(wire["aggregated_value"], json!(73.0));
    assert_eq!(wire["timespan_secs"], 300);
    assert_eq!(wire["custom_attributes"]["ticket"], "SOC-9");
    assert!(
        wire.get("events").is_none(),
        "the stored sample is event-stripped"
    );
    assert!(wire.get("matched_fields").is_none());

    let mut retained = wire.clone();
    retained["events"] = json!([{"User": "alice"}]);
    retained["event_refs"] = json!([{"id": "e-1"}]);
    let retained_finding =
        dedup_summary_finding_with_opts(&retained, &FixedSource::new(), OcsfOptions::default());
    assert_eq!(
        retained_finding["evidences"][0]["data"]["events"][0]["User"],
        "alice"
    );
    assert_eq!(
        retained_finding["evidences"][0]["data"]["event_refs"][0]["id"],
        "e-1"
    );
    assert_eq!(
        retained_finding["unmapped"]["correlation_type"],
        "event_count"
    );
    assert_eq!(
        retained_finding["unmapped"]["custom_attributes"]["ticket"],
        "SOC-9"
    );

    check_both_versions("dedup_repeat_correlation", |opts| {
        let finding = dedup_summary_finding_with_opts(wire, &FixedSource::new(), opts);
        assert_eq!(finding["unmapped"]["correlation_type"], "event_count");
        assert_eq!(
            finding["unmapped"]["group_key"],
            json!([["SourceIP", "203.0.113.4"]])
        );
        assert_eq!(finding["unmapped"]["aggregated_value"], json!(73.0));
        assert_eq!(finding["unmapped"]["timespan_secs"], 300);
        assert_eq!(finding["unmapped"]["custom_attributes"]["ticket"], "SOC-9");
        assert!(finding["unmapped"].get("matched_selections").is_none());
        assert!(finding.get("evidences").is_none());
        finding
    });
}

fn correlation_detection() -> EvaluationResult {
    let mut attributes = HashMap::new();
    attributes.insert("ticket".to_string(), json!("SOC-9"));
    EvaluationResult {
        header: RuleHeader {
            rule_title: "SSH brute force".to_string(),
            rule_id: Some("corr-1".to_string()),
            tenant_id: None,
            level: Some(Level::Critical),
            tags: vec!["attack.credential_access".to_string()],
            custom_attributes: Arc::new(attributes),
            enrichments: None,
            ruleset: None,
        },
        body: ResultBody::Correlation(CorrelationBody {
            correlation_type: CorrelationType::EventCount,
            group_key: vec![("SourceIP".to_string(), "203.0.113.4".to_string())],
            aggregated_value: 73.0,
            timespan_secs: 300,
            events: Some(vec![json!({"User": "alice"})]),
            event_refs: None,
        }),
    }
}

fn enriched_detection() -> EvaluationResult {
    let mut enrichments = serde_json::Map::new();
    enrichments.insert(
        "geo".to_string(),
        json!({"country": "DE", "city": "Berlin"}),
    );
    enrichments.insert("incident_id".to_string(), json!("inc-1"));
    enrichments.insert("risk.score".to_string(), json!(40));
    enrichments.insert(
        "risk.objects".to_string(),
        json!([
            {"type": "user", "value": "alice"},
            {"type": "src_ip", "value": "203.0.113.5"}
        ]),
    );
    EvaluationResult {
        header: RuleHeader {
            rule_title: "Malware execution".to_string(),
            rule_id: Some("rule-1".to_string()),
            tenant_id: None,
            level: Some(Level::High),
            tags: vec!["attack.t1059".to_string()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: Some(enrichments),
            ruleset: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![FieldMatch::new("CommandLine", json!("malware.exe"))],
            event: Some(json!({"CommandLine": "malware.exe"})),
        }),
    }
}

#[test]
fn risk_event_is_a_create_finding() {
    let event = RiskEvent {
        risk_event: true,
        timestamp: 1234,
        rule: "rule-1".to_string(),
        rule_title: "Brute force".to_string(),
        level: Some("high".to_string()),
        risk_score: 25,
        risk_object: rsigma_runtime::RiskObject {
            object_type: "src_ip".to_string(),
            value: "203.0.113.4".to_string(),
        },
        tenant_id: None,
    };
    check_both_versions("risk_event", |opts| {
        risk_event_finding_with_opts(&event, &FixedSource::new(), opts)
    });
}

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

fn schema_rejects(version: &str, class_uid: i64, finding: &Value) {
    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "tests/fixtures/ocsf/{version}/class_{class_uid}.schema.json"
    ));
    let schema: Value = serde_json::from_str(&fs::read_to_string(&schema_path).unwrap()).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(
        !validator.is_valid(finding),
        "class {class_uid} {version} accepted a finding it must reject: {finding}"
    );
}

fn golden_value(version: &str, name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/ocsf")
        .join(version)
        .join(format!("{name}.json"));
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn class_2005_without_assignee_group_fails_the_fixture() {
    for version in ["1.1.0", "1.3.0"] {
        let mut finding = golden_value(version, "incident_open_2005");
        finding.as_object_mut().unwrap().remove("assignee_group");
        schema_rejects(version, 2005, &finding);
    }
}

#[test]
fn class_2004_without_security_control_profile_fails_the_fixture() {
    for version in ["1.1.0", "1.3.0"] {
        let mut finding = golden_value(version, "detection");
        finding["metadata"]["profiles"]
            .as_array_mut()
            .unwrap()
            .clear();
        schema_rejects(version, 2004, &finding);
    }
}

#[test]
fn class_2004_actor_without_host_profile_fails_the_fixture() {
    for version in ["1.1.0", "1.3.0"] {
        let mut finding = golden_value(version, "detection");
        let profiles = finding["metadata"]["profiles"].as_array_mut().unwrap();
        profiles.retain(|p| p.as_str() != Some("host"));
        assert!(finding.get("actor").is_some());
        schema_rejects(version, 2004, &finding);
    }
}

#[test]
fn class_2005_rejects_detection_only_attributes() {
    for version in ["1.1.0", "1.3.0"] {
        let mut finding = golden_value(version, "incident_open_2005");
        finding["actor"] = json!({"user": {"name": "alice"}});
        schema_rejects(version, 2005, &finding);
    }
}
