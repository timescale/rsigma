//! Alert-pipeline identity across dedup, grouping, and capture.
//!
//! Results merge into one alert, one incident, or one capture generation only
//! when their tenant, rule, and selector values are equal. These tests drive
//! the public pipeline with inputs whose old delimiter-joined encodings were
//! identical (and so shared a 64-bit digest), with values that encoded alike,
//! and across tenants, then restore a version 2 snapshot written by the
//! previous release.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rsigma_eval::{
    DetectionBody, EvaluationResult, FieldMatch, ProcessResult, ResultBody, RuleHeader, TenantId,
};
use rsigma_parser::Level;
use rsigma_runtime::{
    AlertPipeline, AlertPipelineSnapshot, AlertPipelineState, CaptureConfig, CaptureRing,
    CaptureRingSink, IncludeMode, NoopMetrics, SNAPSHOT_VERSION, parse_alert_pipeline_config,
};
use serde_json::{Value, json};

const PIPELINE: &str = "dedup:\n  fingerprint: [match.A, match.B]\n  resolve_timeout: 1h\n\
                        group:\n  by: [match.A, match.B]\n  group_wait: 1h\n  resolve_timeout: 1h\n";

fn detection(rule: &str, fields: Vec<(&str, Value)>, level: Level) -> EvaluationResult {
    let event: serde_json::Map<String, Value> = fields
        .iter()
        .map(|(f, v)| (f.to_string(), v.clone()))
        .collect();
    EvaluationResult {
        header: RuleHeader {
            rule_title: "Brute force".to_string(),
            rule_id: Some(rule.to_string()),
            tenant_id: None,
            level: Some(level),
            tags: vec![],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
            ruleset: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec![],
            matched_fields: fields
                .into_iter()
                .map(|(f, v)| FieldMatch::new(f, v))
                .collect(),
            event: Some(Value::Object(event)),
        }),
    }
}

fn incident_id(result: &EvaluationResult) -> String {
    result.header.enrichments.as_ref().unwrap()["incident_id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Run `results` through `pipeline` one event at a time with a capture ring
/// attached, returning every kept result.
fn run(
    pipeline: &AlertPipeline,
    state: &mut AlertPipelineState,
    ring: &mut CaptureRing,
    results: Vec<EvaluationResult>,
) -> ProcessResult {
    let mut kept = Vec::new();
    for (now, result) in results.into_iter().enumerate() {
        let mut sink = CaptureRingSink {
            ring: &mut *ring,
            metrics: &NoopMetrics,
        };
        kept.extend(pipeline.process_with_capture(
            vec![result],
            state,
            now as i64,
            &NoopMetrics,
            Some(&mut sink),
        ));
    }
    kept
}

/// Assert every result opened its own alert, incident, and capture
/// generation.
fn assert_all_separate(results: Vec<EvaluationResult>) {
    let n = results.len();
    let pipeline = parse_alert_pipeline_config(PIPELINE).unwrap();
    let mut state = AlertPipelineState::default();
    let mut ring = CaptureRing::new(CaptureConfig::default());
    let tenants: Vec<Option<TenantId>> =
        results.iter().map(|r| r.header.tenant_id.clone()).collect();

    let kept = run(&pipeline, &mut state, &mut ring, results);
    assert_eq!(kept.len(), n, "no result folded into another's alert");
    assert_eq!(state.dedup.len(), n, "one active alert per result");
    assert_eq!(state.incidents.len(), n, "one incident per result");
    let ids: HashSet<String> = kept.iter().map(incident_id).collect();
    assert_eq!(ids.len(), n, "distinct incident ids");
    assert_eq!(
        ring.stats().incidents,
        n,
        "one capture generation per result"
    );
    for (result, tenant) in kept.iter().zip(&tenants) {
        let snap = ring
            .snapshot_incident(tenant.as_ref(), &incident_id(result))
            .unwrap();
        assert_eq!(
            snap.events.len(),
            1,
            "a generation holds only its own event"
        );
    }
}

#[test]
fn results_whose_old_encodings_matched_stay_apart() {
    // Both used to encode as `rule=r\x1fmatch.A=1\x1fmatch.B=2\x1fmatch.B=3`.
    assert_all_separate(vec![
        detection(
            "r",
            vec![("A", json!("1\u{1f}match.B=2")), ("B", json!("3"))],
            Level::High,
        ),
        detection(
            "r",
            vec![("A", json!("1")), ("B", json!("2\u{1f}match.B=3"))],
            Level::High,
        ),
    ]);
}

#[test]
fn values_that_encoded_alike_stay_apart() {
    let with_a = |a: Option<Value>| {
        let mut fields = vec![("B", json!("x"))];
        if let Some(a) = a {
            fields.push(("A", a));
        }
        detection("r", fields, Level::High)
    };
    assert_all_separate(vec![
        with_a(None),
        with_a(Some(Value::Null)),
        with_a(Some(json!("null"))),
        with_a(Some(json!("\u{0}null"))),
        with_a(Some(json!(123))),
        with_a(Some(json!("123"))),
        with_a(Some(json!("\u{1f}"))),
    ]);
}

#[test]
fn the_same_rule_and_values_in_two_tenants_never_merge() {
    let tenanted = |tenant: &str| {
        let mut r = detection(
            "r",
            vec![("A", json!("10.0.0.1")), ("B", json!("alice"))],
            Level::High,
        );
        r.header.tenant_id = Some(TenantId::new(tenant).unwrap());
        r
    };
    assert_all_separate(vec![tenanted("a"), tenanted("b")]);

    let pipeline = parse_alert_pipeline_config(PIPELINE).unwrap();
    let mut state = AlertPipelineState::default();
    let mut ring = CaptureRing::new(CaptureConfig::default());
    let kept = run(
        &pipeline,
        &mut state,
        &mut ring,
        vec![tenanted("a"), tenanted("b")],
    );
    let b_id = incident_id(&kept[1]);
    let a = TenantId::new("a").unwrap();
    assert!(ring.snapshot_incident(Some(&a), &b_id).is_none());
}

#[test]
fn equal_identities_still_fold_and_group() {
    let pipeline = parse_alert_pipeline_config(PIPELINE).unwrap();
    let mut state = AlertPipelineState::default();
    let mut ring = CaptureRing::new(CaptureConfig::default());
    let same = || {
        detection(
            "r",
            vec![("A", json!({"k": 1, "j": [2]})), ("B", json!(7))],
            Level::High,
        )
    };
    let kept = run(&pipeline, &mut state, &mut ring, vec![same(), same()]);
    assert_eq!(kept.len(), 1, "the duplicate folded");
    assert_eq!(state.dedup.len(), 1);
    let id = incident_id(&kept[0]);
    assert_eq!(id.len(), 32);
    let snap = ring.snapshot_incident(None, &id).unwrap();
    assert_eq!(
        snap.events.len(),
        2,
        "both admissions joined one generation"
    );
}

fn fixture_pipeline() -> AlertPipeline {
    parse_alert_pipeline_config(include_str!(
        "fixtures/alert_pipeline/snapshot_v2_pipeline.yml"
    ))
    .unwrap()
}

fn fixture_snapshot() -> AlertPipelineSnapshot {
    serde_json::from_str(include_str!("fixtures/alert_pipeline/snapshot_v2.json")).unwrap()
}

#[test]
fn a_version_2_snapshot_restores_with_its_ids() {
    let pipeline = fixture_pipeline();
    let snap = fixture_snapshot();
    assert_eq!(snap.version, 2);
    let mut state = AlertPipelineState::default();
    let stats = pipeline
        .restore_detailed(&mut state, snap, 1_010, false)
        .expect("version 2 restores");
    assert_eq!(
        stats.restored, 7,
        "3 alerts, 3 incidents, 1 inhibition source"
    );

    let mut ids: Vec<String> = state
        .incidents
        .snapshot(IncludeMode::Refs)
        .into_iter()
        .map(|inc| inc.incident_id)
        .collect();
    ids.sort();
    assert_eq!(
        ids,
        ["28eb97f73dc10a30", "4b73a8fad6e406ca", "b82bac56bc57e729"],
        "restored incidents keep their ids"
    );

    let m = &NoopMetrics;
    let ip = |ip: &str| ("SourceIp", json!(ip));
    // An absent User and a JSON null User fold into their own restored alerts.
    let absent = detection("rule-1", vec![ip("10.0.0.1")], Level::High);
    assert!(
        pipeline
            .process(vec![absent], &mut state, 1_011, m)
            .is_empty()
    );
    let null = detection(
        "rule-1",
        vec![ip("10.0.0.2"), ("User", Value::Null)],
        Level::High,
    );
    assert!(
        pipeline
            .process(vec![null], &mut state, 1_012, m)
            .is_empty()
    );
    assert_eq!(state.dedup.len(), 3, "no restored alert was reopened");

    // Another rule on the same group values joins the restored incident.
    let other_rule = detection("rule-2", vec![ip("10.0.0.1")], Level::Medium);
    let kept = pipeline.process(vec![other_rule], &mut state, 1_013, m);
    assert_eq!(incident_id(&kept[0]), "b82bac56bc57e729");
    assert_eq!(state.incidents.len(), 3);

    // The restored inhibition source still mutes its targets.
    let target = detection("rule-3", vec![ip("10.0.0.3")], Level::High);
    assert!(
        pipeline
            .process(vec![target], &mut state, 1_014, m)
            .is_empty()
    );
}

#[test]
fn a_restored_version_2_snapshot_saves_as_the_current_version() {
    let pipeline = fixture_pipeline();
    let mut state = AlertPipelineState::default();
    assert!(pipeline.restore(&mut state, fixture_snapshot(), 1_010, false));

    let json = serde_json::to_string(&pipeline.snapshot(&state)).unwrap();
    let resaved: AlertPipelineSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(resaved.version, SNAPSHOT_VERSION);

    let mut again = AlertPipelineState::default();
    assert!(pipeline.restore(&mut again, resaved, 1_020, false));
    let ids = |state: &AlertPipelineState| {
        let mut ids: Vec<String> = state
            .incidents
            .snapshot(IncludeMode::Refs)
            .into_iter()
            .map(|inc| inc.incident_id)
            .collect();
        ids.sort();
        ids
    };
    assert_eq!(ids(&again), ids(&state));
    let absent = detection("rule-1", vec![("SourceIp", json!("10.0.0.1"))], Level::High);
    assert!(
        pipeline
            .process(vec![absent], &mut again, 1_021, &NoopMetrics)
            .is_empty()
    );
}
