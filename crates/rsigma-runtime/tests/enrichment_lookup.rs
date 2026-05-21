//! Lookup enricher and scope-filter integration tests.
//!
//! Drives the [`LookupEnricher`](rsigma_runtime::LookupEnricher) end-to-end
//! against an [`Arc<SourceCache>`] populated by hand. Covers all three
//! extract languages, every cache-miss / no-extract-match cell of the
//! decision matrix, and both detection and correlation results.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rsigma_eval::pipeline::sources::ExtractExpr;
use rsigma_eval::{
    CorrelationBody, DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader,
};
use rsigma_parser::{CorrelationType, Level};
use rsigma_runtime::{
    EnricherKind, EnrichmentPipeline, LookupEnricher, OnError, Scope, SourceCache,
};
use serde_json::json;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn detection_with_field(field: &str, value: serde_json::Value) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "ip_seen".to_string(),
            rule_id: Some("rule-ip".to_string()),
            level: Some(Level::Medium),
            tags: vec!["attack.t1078".to_string()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![FieldMatch {
                field: field.to_string(),
                value,
            }],
            event: None,
        }),
    }
}

fn correlation_for_ip(ip: &str) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "ip_corr".to_string(),
            rule_id: Some("corr-ip".to_string()),
            level: Some(Level::High),
            tags: vec!["attack.t1110".to_string()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
        },
        body: ResultBody::Correlation(CorrelationBody {
            correlation_type: CorrelationType::EventCount,
            group_key: vec![("SourceIP".to_string(), ip.to_string())],
            aggregated_value: 42.0,
            timespan_secs: 60,
            events: None,
            event_refs: None,
        }),
    }
}

fn populated_employee_cache() -> Arc<SourceCache> {
    let cache = Arc::new(SourceCache::new());
    cache.store(
        "employee_directory",
        &json!([
            {"ip": "10.0.0.5", "user": "alice", "team": "Platform"},
            {"ip": "10.0.0.7", "user": "bob", "team": "IT-Ops"}
        ]),
    );
    cache
}

#[allow(clippy::too_many_arguments)]
fn lookup_enricher(
    id: &str,
    kind: EnricherKind,
    inject: &str,
    source: &str,
    extract: Option<ExtractExpr>,
    default: Option<serde_json::Value>,
    cache: Arc<SourceCache>,
    on_error: OnError,
) -> Box<dyn rsigma_runtime::Enricher> {
    Box::new(LookupEnricher::new(
        id.to_string(),
        kind,
        inject.to_string(),
        source.to_string(),
        extract,
        default,
        Duration::from_secs(5),
        on_error,
        Scope::default(),
        cache,
    )) as Box<dyn rsigma_runtime::Enricher>
}

// ---------------------------------------------------------------------------
// Cache hit + extract matches
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn lookup_cache_hit_extract_jq_returns_employee_record() {
    let cache = populated_employee_cache();
    let enricher = lookup_enricher(
        "enrich_ip_employee",
        EnricherKind::Detection,
        "employee",
        "employee_directory",
        Some(ExtractExpr::Jq(
            ".[] | select(.ip == \"${detection.fields.SourceIp}\")".to_string(),
        )),
        None,
        cache,
        OnError::Skip,
    );
    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![detection_with_field("SourceIp", json!("10.0.0.5"))];
    pipeline.run(&mut results).await;

    assert_eq!(
        results[0].header.enrichments.as_ref().unwrap()["employee"],
        json!({"ip": "10.0.0.5", "user": "alice", "team": "Platform"})
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lookup_cache_hit_extract_jsonpath_returns_record() {
    let cache = populated_employee_cache();
    let enricher = lookup_enricher(
        "enrich_ip_employee_jp",
        EnricherKind::Detection,
        "employee",
        "employee_directory",
        Some(ExtractExpr::JsonPath(
            "$[?(@.ip == '${detection.fields.SourceIp}')]".to_string(),
        )),
        None,
        cache,
        OnError::Skip,
    );
    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![detection_with_field("SourceIp", json!("10.0.0.7"))];
    pipeline.run(&mut results).await;

    let v = &results[0].header.enrichments.as_ref().unwrap()["employee"];
    let team = v
        .pointer("/team")
        .or_else(|| v.pointer("/0/team"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    assert_eq!(team, json!("IT-Ops"));
}

#[tokio::test(flavor = "multi_thread")]
async fn lookup_cache_hit_extract_cel_returns_filtered_list() {
    let cache = populated_employee_cache();
    // CEL `data.filter(x, x.ip == ...)` returns a list; the lookup
    // enricher injects whatever the extract produced.
    let enricher = lookup_enricher(
        "enrich_ip_employee_cel",
        EnricherKind::Detection,
        "employee",
        "employee_directory",
        Some(ExtractExpr::Cel(
            "data.filter(x, x.ip == '${detection.fields.SourceIp}')".to_string(),
        )),
        None,
        cache,
        OnError::Skip,
    );
    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![detection_with_field("SourceIp", json!("10.0.0.5"))];
    pipeline.run(&mut results).await;

    let v = &results[0].header.enrichments.as_ref().unwrap()["employee"];
    assert!(v.is_array(), "got: {v}");
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["user"], json!("alice"));
}

// ---------------------------------------------------------------------------
// Cache hit + no extract match
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn lookup_cache_hit_no_extract_match_uses_default() {
    let cache = populated_employee_cache();
    let enricher = lookup_enricher(
        "enrich_ip_employee_dflt",
        EnricherKind::Detection,
        "employee",
        "employee_directory",
        Some(ExtractExpr::Jq(
            ".[] | select(.ip == \"${detection.fields.SourceIp}\")".to_string(),
        )),
        Some(json!("unknown")),
        cache,
        OnError::Skip,
    );
    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![detection_with_field("SourceIp", json!("99.99.99.99"))];
    pipeline.run(&mut results).await;

    assert_eq!(
        results[0].header.enrichments.as_ref().unwrap()["employee"],
        json!("unknown")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lookup_cache_hit_no_extract_match_no_default_skips() {
    let cache = populated_employee_cache();
    let enricher = lookup_enricher(
        "enrich_ip_employee_skip",
        EnricherKind::Detection,
        "employee",
        "employee_directory",
        Some(ExtractExpr::Jq(
            ".[] | select(.ip == \"${detection.fields.SourceIp}\")".to_string(),
        )),
        None,
        cache,
        OnError::Skip,
    );
    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![detection_with_field("SourceIp", json!("99.99.99.99"))];
    pipeline.run(&mut results).await;

    // Skip leaves enrichments untouched.
    assert!(results[0].header.enrichments.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn lookup_cache_hit_no_extract_match_null_injects_null() {
    let cache = populated_employee_cache();
    let enricher = lookup_enricher(
        "enrich_ip_employee_null",
        EnricherKind::Detection,
        "employee",
        "employee_directory",
        Some(ExtractExpr::Jq(
            ".[] | select(.ip == \"${detection.fields.SourceIp}\")".to_string(),
        )),
        None,
        cache,
        OnError::Null,
    );
    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![detection_with_field("SourceIp", json!("99.99.99.99"))];
    pipeline.run(&mut results).await;
    assert_eq!(
        results[0].header.enrichments.as_ref().unwrap()["employee"],
        serde_json::Value::Null
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lookup_cache_hit_no_extract_match_drop_removes_result() {
    let cache = populated_employee_cache();
    let enricher = lookup_enricher(
        "enrich_drop",
        EnricherKind::Detection,
        "employee",
        "employee_directory",
        Some(ExtractExpr::Jq(
            ".[] | select(.ip == \"${detection.fields.SourceIp}\")".to_string(),
        )),
        None,
        cache,
        OnError::Drop,
    );
    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![
        detection_with_field("SourceIp", json!("99.99.99.99")),
        correlation_for_ip("10.0.0.5"),
    ];
    pipeline.run(&mut results).await;
    // Detection dropped (no match + drop), correlation untouched (kind mismatch).
    assert_eq!(results.len(), 1);
    assert!(results[0].is_correlation());
}

// ---------------------------------------------------------------------------
// Cache miss
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn lookup_cache_miss_uses_default() {
    let cache = Arc::new(SourceCache::new()); // empty
    let enricher = lookup_enricher(
        "enrich_missing_default",
        EnricherKind::Detection,
        "employee",
        "employee_directory",
        None,
        Some(json!({"name": "unknown"})),
        cache,
        OnError::Skip,
    );
    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![detection_with_field("SourceIp", json!("10.0.0.5"))];
    pipeline.run(&mut results).await;

    assert_eq!(
        results[0].header.enrichments.as_ref().unwrap()["employee"],
        json!({"name": "unknown"})
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn lookup_cache_miss_no_default_applies_on_error() {
    let cache = Arc::new(SourceCache::new());
    let enricher = lookup_enricher(
        "enrich_missing_null",
        EnricherKind::Detection,
        "employee",
        "employee_directory",
        None,
        None,
        cache,
        OnError::Null,
    );
    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![detection_with_field("SourceIp", json!("10.0.0.5"))];
    pipeline.run(&mut results).await;
    assert_eq!(
        results[0].header.enrichments.as_ref().unwrap()["employee"],
        serde_json::Value::Null
    );
}

// ---------------------------------------------------------------------------
// Scope filter integration with lookup
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn scope_excludes_low_severity_results() {
    let cache = populated_employee_cache();
    let scope = Scope::new(
        vec![],
        vec![],
        vec!["high".to_string(), "critical".to_string()],
    )
    .unwrap();
    let enricher = Box::new(LookupEnricher::new(
        "scoped".to_string(),
        EnricherKind::Detection,
        "employee".to_string(),
        "employee_directory".to_string(),
        Some(ExtractExpr::Jq(
            ".[] | select(.ip == \"${detection.fields.SourceIp}\")".to_string(),
        )),
        None,
        Duration::from_secs(5),
        OnError::Skip,
        scope,
        cache,
    )) as Box<dyn rsigma_runtime::Enricher>;
    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);

    let mut medium = detection_with_field("SourceIp", json!("10.0.0.5"));
    medium.header.level = Some(Level::Medium);
    let mut results = vec![medium];
    pipeline.run(&mut results).await;
    // Medium is below the high/critical scope; enricher is skipped.
    assert!(results[0].header.enrichments.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn scope_includes_matching_tag_only() {
    let cache = populated_employee_cache();
    let scope = Scope::new(vec![], vec!["attack.t1078".to_string()], vec![]).unwrap();
    let enricher = Box::new(LookupEnricher::new(
        "scoped_by_tag".to_string(),
        EnricherKind::Detection,
        "employee".to_string(),
        "employee_directory".to_string(),
        Some(ExtractExpr::Jq(
            ".[] | select(.ip == \"${detection.fields.SourceIp}\")".to_string(),
        )),
        None,
        Duration::from_secs(5),
        OnError::Skip,
        scope,
        cache,
    )) as Box<dyn rsigma_runtime::Enricher>;
    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);

    let hit = detection_with_field("SourceIp", json!("10.0.0.5"));
    let mut miss = detection_with_field("SourceIp", json!("10.0.0.5"));
    miss.header.tags = vec!["unrelated.tag".to_string()];
    let mut results = vec![hit, miss];
    pipeline.run(&mut results).await;

    assert!(results[0].header.enrichments.is_some());
    assert!(results[1].header.enrichments.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn scope_rule_id_exact_match() {
    let cache = populated_employee_cache();
    let scope = Scope::new(vec!["rule-ip".to_string()], vec![], vec![]).unwrap();
    let enricher = Box::new(LookupEnricher::new(
        "scoped_rule".to_string(),
        EnricherKind::Detection,
        "employee".to_string(),
        "employee_directory".to_string(),
        Some(ExtractExpr::Jq(
            ".[] | select(.ip == \"${detection.fields.SourceIp}\")".to_string(),
        )),
        None,
        Duration::from_secs(5),
        OnError::Skip,
        scope,
        cache,
    )) as Box<dyn rsigma_runtime::Enricher>;
    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);

    let hit = detection_with_field("SourceIp", json!("10.0.0.5"));
    let mut miss = detection_with_field("SourceIp", json!("10.0.0.5"));
    miss.header.rule_id = Some("other-rule".to_string());
    let mut results = vec![hit, miss];
    pipeline.run(&mut results).await;

    assert!(results[0].header.enrichments.is_some());
    assert!(results[1].header.enrichments.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn scope_rule_title_glob_match() {
    let cache = populated_employee_cache();
    let scope = Scope::new(vec!["ip_*".to_string()], vec![], vec![]).unwrap();
    let enricher = Box::new(LookupEnricher::new(
        "scoped_glob".to_string(),
        EnricherKind::Detection,
        "employee".to_string(),
        "employee_directory".to_string(),
        Some(ExtractExpr::Jq(
            ".[] | select(.ip == \"${detection.fields.SourceIp}\")".to_string(),
        )),
        None,
        Duration::from_secs(5),
        OnError::Skip,
        scope,
        cache,
    )) as Box<dyn rsigma_runtime::Enricher>;
    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);

    // `ip_seen` rule_title matches `ip_*`.
    let mut results = vec![detection_with_field("SourceIp", json!("10.0.0.5"))];
    pipeline.run(&mut results).await;
    assert!(results[0].header.enrichments.is_some());
}
