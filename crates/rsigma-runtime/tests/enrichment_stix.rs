//! STIX store enricher integration tests (`stix-enrich` feature).

#![cfg(feature = "stix-enrich")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rsigma_eval::pipeline::sources::ExtractExpr;
use rsigma_eval::{
    CorrelationBody, DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader,
};
use rsigma_parser::{CorrelationType, Level};
use rsigma_runtime::{
    EnrichErrorKind, Enricher, EnricherKind, EnricherResources, EnrichmentPipeline, NoopMetrics,
    OnError, Scope, StixEnricher, StixEnricherQuery, build_enrichers_full,
};
use rstix::core::StixObjectKind;
use rstix::store::{MemoryStore, StixStore};
use serde_json::json;

fn detection_with_hash(hash: &str) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "hash rule".into(),
            rule_id: Some("rule-hash".into()),
            tenant_id: None,
            level: Some(Level::High),
            tags: vec!["attack.t1059.001".into()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
            ruleset: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["sel".into()],
            matched_fields: vec![FieldMatch::new("Hash", json!(hash))],
            event: None,
        }),
    }
}

fn populated_store() -> Arc<MemoryStore> {
    let bundle = rstix::parse_bundle(include_str!(
        "../../rstix/tests/fixtures/store/multi-indicators.json"
    ))
    .expect("parse bundle");
    let store = Arc::new(MemoryStore::new());
    store.import_bundle(&bundle).expect("import");
    store
}

#[tokio::test(flavor = "multi_thread")]
async fn stix_text_search_injects_indicator_objects() {
    let store = populated_store();
    let enricher = StixEnricher::new(
        "hash_lookup".into(),
        EnricherKind::Detection,
        "stix_indicators".into(),
        StixEnricherQuery {
            stix_id: None,
            text_search: Some("${detection.fields.Hash}".into()),
            attack_technique: false,
            type_filter: vec![StixObjectKind::from_type_str("indicator").unwrap()],
            max_results: 2,
        },
        None,
        None,
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        store,
    );
    let pipeline = EnrichmentPipeline::new(vec![Box::new(enricher)], 4);
    let mut results = vec![detection_with_hash("644bf17e482f443f763b0b7355b14372")];
    pipeline.run(&mut results).await;
    let result = &results[0];
    let matches = result
        .header
        .enrichments
        .as_ref()
        .and_then(|m| m.get("stix_indicators"))
        .and_then(|v| v.as_array())
        .expect("stix_indicators array");
    assert_eq!(matches.len(), 1);
    assert_eq!(
        matches[0]["id"],
        "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stix_templates_read_unmatched_fields_from_the_event() {
    let store = populated_store();
    let by_text = StixEnricher::new(
        "hash_lookup".into(),
        EnricherKind::Detection,
        "by_text".into(),
        StixEnricherQuery {
            stix_id: None,
            text_search: Some("${detection.fields.Hash}".into()),
            attack_technique: false,
            type_filter: vec![StixObjectKind::from_type_str("indicator").unwrap()],
            max_results: 5,
        },
        Some(ExtractExpr::Jq(
            "[.[] | select(.id == \"${detection.fields.IndicatorId}\") | .id]".into(),
        )),
        None,
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        store.clone(),
    );
    let by_id = StixEnricher::new(
        "id_lookup".into(),
        EnricherKind::Detection,
        "by_id".into(),
        StixEnricherQuery {
            stix_id: Some("${detection.fields.IndicatorId}".into()),
            text_search: None,
            attack_technique: false,
            type_filter: vec![],
            max_results: 1,
        },
        Some(ExtractExpr::Jq(".[0].id".into())),
        None,
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        store,
    );
    let pipeline = EnrichmentPipeline::new(vec![Box::new(by_text), Box::new(by_id)], 4);
    let mut det = detection_with_hash("unused");
    let body = det.as_detection_mut().unwrap();
    body.matched_fields = vec![FieldMatch::new("EventType", json!("file_create"))];
    body.event = Some(json!({
        "Hash": "744bf17e482f443f763b0b7355b14373",
        "IndicatorId": "indicator--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    }));
    let mut results = vec![det];
    pipeline.run(&mut results).await;

    let enrichments = results[0].header.enrichments.as_ref().expect("enrichments");
    assert_eq!(
        enrichments.get("by_text"),
        Some(&json!(["indicator--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"])),
        "text_search and extract should render Hash and IndicatorId from the event"
    );
    assert_eq!(
        enrichments.get("by_id"),
        Some(&json!("indicator--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")),
        "stix_id should render IndicatorId from the event"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stix_attack_technique_finds_attack_pattern_by_external_id() {
    let bundle = rstix::parse_bundle(include_str!(
        "../../rstix/tests/fixtures/store/attack-pattern-powershell-t1059.json"
    ))
    .expect("parse bundle");
    let store = Arc::new(MemoryStore::new());
    store.import_bundle(&bundle).expect("import");
    let enricher = StixEnricher::new(
        "technique_lookup".into(),
        EnricherKind::Detection,
        "stix_technique".into(),
        StixEnricherQuery {
            stix_id: None,
            text_search: None,
            attack_technique: true,
            type_filter: vec![StixObjectKind::from_type_str("attack-pattern").unwrap()],
            max_results: 1,
        },
        Some(ExtractExpr::Jq(".[0].name".into())),
        None,
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        store,
    );
    let mut result = detection_with_hash("no-match-hash");
    enricher.enrich(&mut result).await.expect("enrich");
    let value = result
        .header
        .enrichments
        .as_ref()
        .and_then(|m| m.get("stix_technique"))
        .expect("stix_technique");
    assert_eq!(value, "PowerShell");
}

#[tokio::test(flavor = "multi_thread")]
async fn yaml_loader_builds_stix_enricher_pipeline() {
    let store = populated_store();
    let yaml = r#"
enrichers:
  - id: hash_lookup
    kind: detection
    type: stix
    inject_field: stix_indicators
    text_search: "${detection.fields.Hash}"
    type_filter: [indicator]
    max_results: 1
"#;
    let file: rsigma_runtime::EnrichersFile = yaml_serde::from_str(yaml).unwrap();
    let pipeline = build_enrichers_full(
        file,
        EnricherResources {
            stix_store: Some(store as Arc<dyn StixStore>),
            ..EnricherResources::default()
        },
        Arc::new(NoopMetrics),
    )
    .expect("build pipeline");
    assert_eq!(pipeline.len(), 1);
    let mut results = vec![detection_with_hash("844bf17e482f443f763b0b7355b14374")];
    pipeline.run(&mut results).await;
    let result = &results[0];
    let matches = result
        .header
        .enrichments
        .as_ref()
        .and_then(|m| m.get("stix_indicators"))
        .and_then(|v| v.as_array())
        .expect("matches");
    assert_eq!(matches.len(), 1);
    assert_eq!(
        matches[0]["id"],
        "indicator--cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stix_enricher_skips_correlation_results_for_detection_kind() {
    let store = populated_store();
    let enricher = StixEnricher::new(
        "hash_lookup".into(),
        EnricherKind::Detection,
        "stix_indicators".into(),
        StixEnricherQuery {
            stix_id: None,
            text_search: Some("644bf17e482f443f763b0b7355b14372".into()),
            attack_technique: false,
            type_filter: vec![],
            max_results: 1,
        },
        None,
        None,
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        store,
    );
    let pipeline = EnrichmentPipeline::new(vec![Box::new(enricher)], 4);
    let mut results = vec![EvaluationResult {
        header: RuleHeader {
            rule_title: "corr".into(),
            rule_id: Some("corr-1".into()),
            tenant_id: None,
            level: Some(Level::High),
            tags: vec![],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
            ruleset: None,
        },
        body: ResultBody::Correlation(CorrelationBody {
            correlation_type: CorrelationType::EventCount,
            group_key: vec![("Host".into(), "srv1".into())],
            aggregated_value: 3.0,
            timespan_secs: 60,
            events: None,
            event_refs: None,
            event_sources: None,
        }),
    }];
    pipeline.run(&mut results).await;
    assert!(results[0].header.enrichments.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn stix_query_with_no_objects_is_a_miss() {
    let enricher = StixEnricher::new(
        "hash_lookup".into(),
        EnricherKind::Detection,
        "stix_indicators".into(),
        StixEnricherQuery {
            stix_id: None,
            text_search: Some("${detection.fields.Hash}".into()),
            attack_technique: false,
            type_filter: vec![StixObjectKind::from_type_str("indicator").unwrap()],
            max_results: 1,
        },
        None,
        None,
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        populated_store(),
    );
    let mut result = detection_with_hash("no-such-hash");
    let err = enricher.enrich(&mut result).await.unwrap_err();
    assert!(
        matches!(&err.kind, EnrichErrorKind::Miss(m) if m.contains("returned no objects")),
        "got {err}"
    );
    assert!(result.header.enrichments.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn stix_extract_returning_null_is_a_miss() {
    let enricher = StixEnricher::new(
        "hash_lookup".into(),
        EnricherKind::Detection,
        "stix_indicators".into(),
        StixEnricherQuery {
            stix_id: None,
            text_search: Some("${detection.fields.Hash}".into()),
            attack_technique: false,
            type_filter: vec![StixObjectKind::from_type_str("indicator").unwrap()],
            max_results: 1,
        },
        Some(ExtractExpr::Jq(".[0].no_such_property".into())),
        None,
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        populated_store(),
    );
    let mut result = detection_with_hash("644bf17e482f443f763b0b7355b14372");
    let err = enricher.enrich(&mut result).await.unwrap_err();
    assert!(
        matches!(&err.kind, EnrichErrorKind::Miss(m) if m.contains("extract returned null")),
        "got {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_null_default_injects_null_when_the_store_has_no_objects() {
    let yaml = r#"
enrichers:
  - id: hash_lookup
    kind: detection
    type: stix
    inject_field: stix_indicators
    text_search: "${detection.fields.Hash}"
    type_filter: [indicator]
    default: null
    on_error: skip
"#;
    let file: rsigma_runtime::EnrichersFile = yaml_serde::from_str(yaml).unwrap();
    let pipeline = build_enrichers_full(
        file,
        EnricherResources {
            stix_store: Some(populated_store() as Arc<dyn StixStore>),
            ..EnricherResources::default()
        },
        Arc::new(NoopMetrics),
    )
    .expect("build pipeline");
    let mut results = vec![detection_with_hash("no-such-hash")];
    pipeline.run(&mut results).await;
    assert_eq!(
        results[0].header.enrichments.as_ref().unwrap()["stix_indicators"],
        serde_json::Value::Null
    );
}
