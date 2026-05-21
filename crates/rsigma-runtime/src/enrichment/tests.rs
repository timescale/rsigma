//! Unit tests for the enrichment foundation.
//!
//! Tests sit at `super::tests` so they share visibility with `mod.rs`'s
//! crate-private hooks (`clear_builtin_registry`, `EnrichOutcome`, …).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rsigma_eval::{
    CorrelationBody, DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader,
};
use rsigma_parser::{CorrelationType, Level};

use super::{
    EnrichError, EnrichErrorKind, Enricher, EnricherKind, EnrichmentPipeline, OnError, Scope,
    TemplateEnricher, register_builtin, validate_template_namespace,
};

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

fn detection_result() -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "Suspicious PowerShell".to_string(),
            rule_id: Some("rule-pwsh".to_string()),
            level: Some(Level::High),
            tags: vec![
                "attack.t1059.001".to_string(),
                "attack.execution".to_string(),
            ],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![FieldMatch {
                field: "CommandLine".to_string(),
                value: serde_json::json!("powershell -enc QQA="),
            }],
            event: Some(serde_json::json!({"User": "alice", "Host": "dc01"})),
        }),
    }
}

fn correlation_result() -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "SSH brute force".to_string(),
            rule_id: Some("corr-ssh".to_string()),
            level: Some(Level::High),
            tags: vec!["attack.t1110".to_string()],
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
    }
}

fn template_enricher(
    id: &str,
    kind: EnricherKind,
    inject: &str,
    template: &str,
) -> TemplateEnricher {
    TemplateEnricher::new(
        id.to_string(),
        kind,
        inject.to_string(),
        template.to_string(),
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
    )
}

// ---------------------------------------------------------------------------
// Template variable expansion tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn template_expands_detection_rule_fields() {
    let mut r = detection_result();
    let e = template_enricher(
        "runbook_det",
        EnricherKind::Detection,
        "runbook_url",
        "https://wiki/runbooks/${detection.rule.id}",
    );
    e.enrich(&mut r).await.unwrap();
    let map = r.header.enrichments.unwrap();
    assert_eq!(
        map.get("runbook_url").unwrap(),
        &serde_json::json!("https://wiki/runbooks/rule-pwsh")
    );
}

#[tokio::test]
async fn template_expands_detection_field_value() {
    let mut r = detection_result();
    let e = template_enricher(
        "echo_cmd",
        EnricherKind::Detection,
        "command_summary",
        "saw: ${detection.fields.CommandLine}",
    );
    e.enrich(&mut r).await.unwrap();
    let v = r.header.enrichments.unwrap();
    assert_eq!(
        v.get("command_summary").unwrap(),
        &serde_json::json!("saw: powershell -enc QQA=")
    );
}

#[tokio::test]
async fn template_expands_detection_event_jsonpath() {
    let mut r = detection_result();
    let e = template_enricher(
        "user",
        EnricherKind::Detection,
        "by",
        "user=${detection.event.User} host=${detection.event.Host}",
    );
    e.enrich(&mut r).await.unwrap();
    let v = r.header.enrichments.unwrap();
    assert_eq!(
        v.get("by").unwrap(),
        &serde_json::json!("user=alice host=dc01")
    );
}

#[tokio::test]
async fn template_expands_detection_tags_joined() {
    let mut r = detection_result();
    let e = template_enricher(
        "tags",
        EnricherKind::Detection,
        "all_tags",
        "${detection.tags}",
    );
    e.enrich(&mut r).await.unwrap();
    let v = r.header.enrichments.unwrap();
    assert_eq!(
        v.get("all_tags").unwrap(),
        &serde_json::json!("attack.t1059.001,attack.execution")
    );
}

#[tokio::test]
async fn template_expands_correlation_aggregate_and_group_key() {
    let mut r = correlation_result();
    let e = template_enricher(
        "burst",
        EnricherKind::Correlation,
        "summary",
        "Burst of ${correlation.aggregated_value} from ${correlation.group_key.SourceIP} over ${correlation.timespan_secs}s",
    );
    e.enrich(&mut r).await.unwrap();
    let v = r.header.enrichments.unwrap();
    assert_eq!(
        v.get("summary").unwrap(),
        &serde_json::json!("Burst of 73 from 203.0.113.4 over 300s")
    );
}

#[tokio::test]
async fn template_expands_correlation_type_and_group_key_joined() {
    let mut r = correlation_result();
    let e = template_enricher(
        "ct",
        EnricherKind::Correlation,
        "key",
        "${correlation.type}|${correlation.group_key}",
    );
    e.enrich(&mut r).await.unwrap();
    let v = r.header.enrichments.unwrap();
    assert_eq!(
        v.get("key").unwrap(),
        &serde_json::json!("event_count|SourceIP=203.0.113.4")
    );
}

#[tokio::test]
async fn template_missing_field_renders_empty() {
    let mut r = detection_result();
    let e = template_enricher(
        "x",
        EnricherKind::Detection,
        "out",
        "[${detection.fields.NotThere}]",
    );
    e.enrich(&mut r).await.unwrap();
    let v = r.header.enrichments.unwrap();
    assert_eq!(v.get("out").unwrap(), &serde_json::json!("[]"));
}

#[tokio::test]
async fn template_env_var_expansion() {
    // SAFETY: tests run on a single thread per test function and we set a
    // process-wide env var; the value is unique enough not to collide.
    unsafe {
        std::env::set_var("RSIGMA_TEST_ENRICH_ENV", "hello");
    }
    let mut r = detection_result();
    let e = template_enricher(
        "envprobe",
        EnricherKind::Detection,
        "out",
        "v=${RSIGMA_TEST_ENRICH_ENV}",
    );
    e.enrich(&mut r).await.unwrap();
    let v = r.header.enrichments.unwrap();
    assert_eq!(v.get("out").unwrap(), &serde_json::json!("v=hello"));
    unsafe {
        std::env::remove_var("RSIGMA_TEST_ENRICH_ENV");
    }
}

// ---------------------------------------------------------------------------
// Config-load-time namespace validation
// ---------------------------------------------------------------------------

#[test]
fn validator_rejects_correlation_ref_in_detection_enricher() {
    let err = validate_template_namespace(
        "https://wiki/${correlation.rule.id}",
        EnricherKind::Detection,
        "runbook_det",
        "template",
    )
    .unwrap_err();
    assert!(format!("{err}").contains("wrong namespace"));
}

#[test]
fn validator_rejects_detection_ref_in_correlation_enricher() {
    let err = validate_template_namespace(
        "${detection.fields.User}",
        EnricherKind::Correlation,
        "x",
        "url",
    )
    .unwrap_err();
    assert!(format!("{err}").contains("wrong namespace"));
}

#[test]
fn validator_accepts_matching_namespace_and_env_var() {
    validate_template_namespace(
        "https://wiki/${detection.rule.id}/${HOME}",
        EnricherKind::Detection,
        "x",
        "template",
    )
    .unwrap();
    validate_template_namespace(
        "${correlation.aggregated_value}/${HOME}",
        EnricherKind::Correlation,
        "x",
        "template",
    )
    .unwrap();
}

#[test]
fn validator_rejects_malformed_dotted_reference() {
    let err = validate_template_namespace(
        "${something.weird}",
        EnricherKind::Detection,
        "x",
        "template",
    )
    .unwrap_err();
    assert!(format!("{err}").contains("malformed"));
}

// Note: `${}` (empty inner) does not match the `\$\{([^}]+)\}` regex at
// all, so it is not classified as a reference and renders literally. The
// validator therefore accepts strings like `${}` as plain text. Operators
// who type that almost certainly meant `${something}`, but the cost of
// the extra regex pass to flag literal `${}` is not worth it.

// ---------------------------------------------------------------------------
// EnrichmentPipeline: kind filter and multi-enricher ordering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pipeline_skips_enricher_when_kind_does_not_match_body() {
    let mut results = vec![correlation_result()];
    let det_enricher = Box::new(template_enricher(
        "det",
        EnricherKind::Detection,
        "should_not_appear",
        "static-value",
    )) as Box<dyn Enricher>;
    let corr_enricher = Box::new(template_enricher(
        "corr",
        EnricherKind::Correlation,
        "should_appear",
        "yes",
    )) as Box<dyn Enricher>;
    let pipeline = EnrichmentPipeline::new(vec![det_enricher, corr_enricher], 4);

    pipeline.run(&mut results).await;

    let map = results[0].header.enrichments.as_ref().unwrap();
    assert!(map.get("should_not_appear").is_none());
    assert_eq!(map.get("should_appear").unwrap(), &serde_json::json!("yes"));
}

#[tokio::test]
async fn pipeline_applies_multiple_enrichers_in_order() {
    let mut results = vec![detection_result()];
    let a = Box::new(template_enricher(
        "a",
        EnricherKind::Detection,
        "field_a",
        "first",
    )) as Box<dyn Enricher>;
    let b = Box::new(template_enricher(
        "b",
        EnricherKind::Detection,
        "field_b",
        "second",
    )) as Box<dyn Enricher>;
    let pipeline = EnrichmentPipeline::new(vec![a, b], 2);
    pipeline.run(&mut results).await;
    let map = results[0].header.enrichments.as_ref().unwrap();
    assert_eq!(map.get("field_a").unwrap(), &serde_json::json!("first"));
    assert_eq!(map.get("field_b").unwrap(), &serde_json::json!("second"));
}

#[tokio::test]
async fn pipeline_with_no_enrichers_is_noop() {
    let mut results = vec![detection_result(), correlation_result()];
    let pipeline = EnrichmentPipeline::default();
    pipeline.run(&mut results).await;
    assert!(results[0].header.enrichments.is_none());
    assert!(results[1].header.enrichments.is_none());
}

#[tokio::test]
async fn pipeline_does_not_create_empty_enrichments_map() {
    // A correlation result with only detection-kind enrichers should keep
    // enrichments=None so the `skip_serializing_if` contract is preserved.
    let mut results = vec![correlation_result()];
    let det_only =
        Box::new(template_enricher("det", EnricherKind::Detection, "x", "y")) as Box<dyn Enricher>;
    let pipeline = EnrichmentPipeline::new(vec![det_only], 4);
    pipeline.run(&mut results).await;
    assert!(results[0].header.enrichments.is_none());
}

// ---------------------------------------------------------------------------
// On-error policy
// ---------------------------------------------------------------------------

/// Test-only enricher that always errors. Used to drive the `on_error`
/// branches without spinning up an HTTP server.
struct ErroringEnricher {
    id: String,
    kind: EnricherKind,
    inject_field: String,
    on_error: OnError,
    scope: Scope,
}

#[async_trait::async_trait]
impl Enricher for ErroringEnricher {
    fn kind(&self) -> EnricherKind {
        self.kind
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn inject_field(&self) -> &str {
        &self.inject_field
    }
    fn timeout(&self) -> Duration {
        Duration::from_secs(1)
    }
    fn scope(&self) -> &Scope {
        &self.scope
    }
    fn on_error(&self) -> OnError {
        self.on_error
    }
    async fn enrich(&self, _: &mut EvaluationResult) -> Result<(), EnrichError> {
        Err(EnrichError {
            enricher_id: self.id.clone(),
            kind: EnrichErrorKind::Fetch("synthetic".to_string()),
        })
    }
}

#[tokio::test]
async fn on_error_skip_leaves_enrichments_alone() {
    let mut results = vec![detection_result()];
    let e = Box::new(ErroringEnricher {
        id: "boom".to_string(),
        kind: EnricherKind::Detection,
        inject_field: "out".to_string(),
        on_error: OnError::Skip,
        scope: Scope::default(),
    }) as Box<dyn Enricher>;
    EnrichmentPipeline::new(vec![e], 1).run(&mut results).await;
    assert!(results[0].header.enrichments.is_none());
}

#[tokio::test]
async fn on_error_null_injects_null() {
    let mut results = vec![detection_result()];
    let e = Box::new(ErroringEnricher {
        id: "boom".to_string(),
        kind: EnricherKind::Detection,
        inject_field: "out".to_string(),
        on_error: OnError::Null,
        scope: Scope::default(),
    }) as Box<dyn Enricher>;
    EnrichmentPipeline::new(vec![e], 1).run(&mut results).await;
    let map = results[0].header.enrichments.as_ref().unwrap();
    assert_eq!(map.get("out").unwrap(), &serde_json::Value::Null);
}

#[tokio::test]
async fn on_error_drop_removes_result_from_vec() {
    let mut results = vec![detection_result(), correlation_result()];
    let e = Box::new(ErroringEnricher {
        id: "boom".to_string(),
        kind: EnricherKind::Detection,
        inject_field: "out".to_string(),
        on_error: OnError::Drop,
        scope: Scope::default(),
    }) as Box<dyn Enricher>;
    EnrichmentPipeline::new(vec![e], 1).run(&mut results).await;
    // Detection got dropped, correlation survived.
    assert_eq!(results.len(), 1);
    assert!(results[0].is_correlation());
}

// ---------------------------------------------------------------------------
// Timeout
// ---------------------------------------------------------------------------

struct SleepingEnricher {
    id: String,
    sleep_for: Duration,
    timeout: Duration,
    on_error: OnError,
    scope: Scope,
}

#[async_trait::async_trait]
impl Enricher for SleepingEnricher {
    fn kind(&self) -> EnricherKind {
        EnricherKind::Detection
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn inject_field(&self) -> &str {
        "_"
    }
    fn timeout(&self) -> Duration {
        self.timeout
    }
    fn scope(&self) -> &Scope {
        &self.scope
    }
    fn on_error(&self) -> OnError {
        self.on_error
    }
    async fn enrich(&self, _: &mut EvaluationResult) -> Result<(), EnrichError> {
        tokio::time::sleep(self.sleep_for).await;
        Ok(())
    }
}

#[tokio::test]
async fn timeout_triggers_on_error_policy() {
    let mut results = vec![detection_result()];
    let e = Box::new(SleepingEnricher {
        id: "slow".to_string(),
        sleep_for: Duration::from_millis(200),
        timeout: Duration::from_millis(20),
        on_error: OnError::Null,
        scope: Scope::default(),
    }) as Box<dyn Enricher>;
    EnrichmentPipeline::new(vec![e], 1).run(&mut results).await;
    let map = results[0].header.enrichments.as_ref().unwrap();
    assert_eq!(map.get("_").unwrap(), &serde_json::Value::Null);
}

// ---------------------------------------------------------------------------
// register_builtin / lookup_builtin
// ---------------------------------------------------------------------------
//
// The bespoke-enricher registry is process-global, so these tests must
// not race each other. We serialize them under a `Mutex` and clear the
// registry at the start of each.

fn registry_test_lock() -> &'static std::sync::Mutex<()> {
    use std::sync::OnceLock;
    static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[test]
fn register_builtin_rejects_reserved_names() {
    let _guard = registry_test_lock().lock().unwrap();
    super::clear_builtin_registry();
    for reserved in ["template", "lookup", "http", "command"] {
        let err = register_builtin(
            reserved,
            std::sync::Arc::new(|_| Err::<Box<dyn Enricher>, _>("unused".to_string())),
        )
        .unwrap_err();
        assert!(err.contains("reserved"));
    }
}

#[test]
fn register_builtin_rejects_duplicate_name() {
    let _guard = registry_test_lock().lock().unwrap();
    super::clear_builtin_registry();
    let factory: super::EnricherFactory =
        std::sync::Arc::new(|_| Err::<Box<dyn Enricher>, _>("not-buildable".to_string()));
    register_builtin("enrich_dup", factory.clone()).unwrap();
    let err = register_builtin("enrich_dup", factory).unwrap_err();
    assert!(err.contains("already registered"));
}

// ---------------------------------------------------------------------------
// Metrics hook
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CollectingMetrics {
    completed: std::sync::Mutex<Vec<(String, String, String)>>,
    queue_changes: std::sync::Mutex<Vec<i64>>,
    cache_hits: std::sync::Mutex<Vec<String>>,
    cache_misses: std::sync::Mutex<Vec<String>>,
    cache_expirations: std::sync::Mutex<Vec<String>>,
}

impl crate::MetricsHook for CollectingMetrics {
    fn on_parse_error(&self) {}
    fn on_events_processed(&self, _: u64) {}
    fn on_detection_matches(&self, _: u64) {}
    fn on_correlation_matches(&self, _: u64) {}
    fn observe_processing_latency(&self, _: f64) {}
    fn on_input_queue_depth_change(&self, _: i64) {}
    fn on_back_pressure(&self) {}
    fn observe_batch_size(&self, _: u64) {}
    fn on_output_queue_depth_change(&self, _: i64) {}
    fn observe_pipeline_latency(&self, _: f64) {}
    fn set_correlation_state_entries(&self, _: u64) {}
    fn on_enrichment_completed(
        &self,
        enricher_id: &str,
        kind: &str,
        status: &str,
        _duration_seconds: f64,
    ) {
        self.completed.lock().unwrap().push((
            enricher_id.to_string(),
            kind.to_string(),
            status.to_string(),
        ));
    }
    fn on_enrichment_queue_depth_change(&self, delta: i64) {
        self.queue_changes.lock().unwrap().push(delta);
    }
    fn on_enrichment_http_cache_hit(&self, enricher_id: &str) {
        self.cache_hits
            .lock()
            .unwrap()
            .push(enricher_id.to_string());
    }
    fn on_enrichment_http_cache_miss(&self, enricher_id: &str) {
        self.cache_misses
            .lock()
            .unwrap()
            .push(enricher_id.to_string());
    }
    fn on_enrichment_http_cache_expiration(&self, enricher_id: &str) {
        self.cache_expirations
            .lock()
            .unwrap()
            .push(enricher_id.to_string());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_records_success_and_queue_depth() {
    let m = std::sync::Arc::new(CollectingMetrics::default());
    let enricher = Box::new(template_enricher(
        "ok_one",
        EnricherKind::Detection,
        "out",
        "static-${detection.rule.id}",
    )) as Box<dyn Enricher>;
    let pipeline = EnrichmentPipeline::new(vec![enricher], 4)
        .with_metrics(m.clone() as std::sync::Arc<dyn crate::MetricsHook>);
    let mut results = vec![detection_result()];
    pipeline.run(&mut results).await;

    let completed = m.completed.lock().unwrap().clone();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].0, "ok_one");
    assert_eq!(completed[0].1, "detection");
    assert_eq!(completed[0].2, "success");

    let qc = m.queue_changes.lock().unwrap().clone();
    assert_eq!(qc, vec![1, -1], "queue depth must rise then fall by 1");
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_records_skip_status_on_error() {
    let m = std::sync::Arc::new(CollectingMetrics::default());
    let e = Box::new(ErroringEnricher {
        id: "boom".to_string(),
        kind: EnricherKind::Detection,
        inject_field: "out".to_string(),
        on_error: OnError::Skip,
        scope: Scope::default(),
    }) as Box<dyn Enricher>;
    let pipeline = EnrichmentPipeline::new(vec![e], 1)
        .with_metrics(m.clone() as std::sync::Arc<dyn crate::MetricsHook>);
    let mut results = vec![detection_result()];
    pipeline.run(&mut results).await;
    let completed = m.completed.lock().unwrap().clone();
    assert_eq!(completed[0].2, "skip");
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_records_drop_status() {
    let m = std::sync::Arc::new(CollectingMetrics::default());
    let e = Box::new(ErroringEnricher {
        id: "drop_me".to_string(),
        kind: EnricherKind::Detection,
        inject_field: "out".to_string(),
        on_error: OnError::Drop,
        scope: Scope::default(),
    }) as Box<dyn Enricher>;
    let pipeline = EnrichmentPipeline::new(vec![e], 1)
        .with_metrics(m.clone() as std::sync::Arc<dyn crate::MetricsHook>);
    let mut results = vec![detection_result()];
    pipeline.run(&mut results).await;
    let completed = m.completed.lock().unwrap().clone();
    assert_eq!(completed[0].2, "drop");
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_records_timeout_status() {
    let m = std::sync::Arc::new(CollectingMetrics::default());
    let e = Box::new(SleepingEnricher {
        id: "slow".to_string(),
        sleep_for: Duration::from_millis(200),
        timeout: Duration::from_millis(20),
        on_error: OnError::Skip,
        scope: Scope::default(),
    }) as Box<dyn Enricher>;
    let pipeline = EnrichmentPipeline::new(vec![e], 1)
        .with_metrics(m.clone() as std::sync::Arc<dyn crate::MetricsHook>);
    let mut results = vec![detection_result()];
    pipeline.run(&mut results).await;
    let completed = m.completed.lock().unwrap().clone();
    assert_eq!(completed[0].2, "timeout");
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_skips_filtered_results() {
    // A correlation result hitting a detection-only enricher should not
    // record anything (kind filter skips before metrics fire).
    let m = std::sync::Arc::new(CollectingMetrics::default());
    let e =
        Box::new(template_enricher("det", EnricherKind::Detection, "x", "y")) as Box<dyn Enricher>;
    let pipeline = EnrichmentPipeline::new(vec![e], 1)
        .with_metrics(m.clone() as std::sync::Arc<dyn crate::MetricsHook>);
    let mut results = vec![correlation_result()];
    pipeline.run(&mut results).await;
    assert!(m.completed.lock().unwrap().is_empty());
    assert!(m.queue_changes.lock().unwrap().is_empty());
}

#[test]
fn lookup_builtin_returns_registered_factory() {
    let _guard = registry_test_lock().lock().unwrap();
    super::clear_builtin_registry();
    let factory: super::EnricherFactory =
        std::sync::Arc::new(|_| Err::<Box<dyn Enricher>, _>("not-buildable".to_string()));
    register_builtin("enrich_test_thing", factory).unwrap();
    assert!(super::lookup_builtin("enrich_test_thing").is_some());
    assert!(super::lookup_builtin("missing").is_none());
}
