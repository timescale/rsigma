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
    TemplateEnricher, TemplateError, empty_key_message, register_builtin, render_enricher_template,
    render_template, render_webhook_body, validate_template_namespace,
};
use crate::{EnricherResources, EnrichersFile, NoopMetrics, SourceCache, build_enrichers_full};

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

fn detection_result() -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "Suspicious PowerShell".to_string(),
            rule_id: Some("rule-pwsh".to_string()),
            tenant_id: None,
            level: Some(Level::High),
            tags: vec![
                "attack.t1059.001".to_string(),
                "attack.execution".to_string(),
            ],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
            ruleset: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![FieldMatch::new(
                "CommandLine",
                serde_json::json!("powershell -enc QQA="),
            )],
            event: Some(serde_json::json!({"User": "alice", "Host": "dc01"})),
        }),
    }
}

fn correlation_result() -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "SSH brute force".to_string(),
            rule_id: Some("corr-ssh".to_string()),
            tenant_id: None,
            level: Some(Level::High),
            tags: vec!["attack.t1110".to_string()],
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
            event_sources: None,
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
async fn template_reads_an_unmatched_field_from_the_event() {
    let mut r = detection_result();
    let e = template_enricher(
        "user",
        EnricherKind::Detection,
        "by",
        "user=${detection.fields.User}",
    );
    e.enrich(&mut r).await.unwrap();
    let v = r.header.enrichments.unwrap();
    assert_eq!(v.get("by").unwrap(), &serde_json::json!("user=alice"));
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
// Enrichment event fallback
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fallback_prefers_a_matched_field_over_the_event() {
    let mut r = detection_result();
    r.body = ResultBody::Detection(DetectionBody {
        matched_selections: vec!["selection".to_string()],
        matched_fields: vec![FieldMatch::new("User", serde_json::json!("bob"))],
        event: Some(serde_json::json!({"User": "alice"})),
    });
    assert_eq!(
        render_enricher_template("${detection.fields.User}", &r),
        "bob"
    );
}

#[test]
fn enrichment_fallback_keeps_a_matched_null() {
    let mut r = detection_result();
    r.body = ResultBody::Detection(DetectionBody {
        matched_selections: vec!["selection".to_string()],
        matched_fields: vec![FieldMatch::new("User", serde_json::Value::Null)],
        event: Some(serde_json::json!({"User": "alice"})),
    });
    assert_eq!(render_enricher_template("${detection.fields.User}", &r), "");
}

#[test]
fn enrichment_fallback_reads_an_unmatched_field_from_the_event() {
    let mut r = detection_result();
    r.body = ResultBody::Detection(DetectionBody {
        matched_selections: vec!["selection".to_string()],
        matched_fields: vec![],
        event: Some(serde_json::json!({
            "SourceIp": "203.0.113.7",
            "a.b": "flat",
            "nested": {"x": "deep"},
            "arr": [10, 20],
        })),
    });
    assert_eq!(
        render_enricher_template("${detection.fields.SourceIp}", &r),
        "203.0.113.7"
    );
    assert_eq!(
        render_enricher_template("${detection.fields.a.b}", &r),
        "flat",
        "a whole-name top-level key wins over dotted navigation"
    );
    assert_eq!(
        render_enricher_template("${detection.fields.nested.x}", &r),
        "deep"
    );
    assert_eq!(
        render_enricher_template("${detection.fields.arr.1}", &r),
        "20"
    );
}

#[test]
fn enrichment_fallback_renders_empty_without_an_event() {
    let mut r = detection_result();
    r.body = ResultBody::Detection(DetectionBody {
        matched_selections: vec!["selection".to_string()],
        matched_fields: vec![],
        event: None,
    });
    assert_eq!(
        render_enricher_template("${detection.fields.SourceIp}", &r),
        ""
    );
}

#[test]
fn public_renderers_do_not_fall_back_to_the_event() {
    let mut r = detection_result();
    r.body = ResultBody::Detection(DetectionBody {
        matched_selections: vec!["selection".to_string()],
        matched_fields: vec![],
        event: Some(serde_json::json!({"SourceIp": "203.0.113.7"})),
    });
    assert_eq!(render_template("${detection.fields.SourceIp}", &r), "");
    assert_eq!(
        render_enricher_template("${detection.fields.SourceIp}", &r),
        "203.0.113.7"
    );
}

#[test]
fn empty_key_hint_names_the_event_fallback_only_for_detection_payloads() {
    let hint = "key rendered empty; the field is neither a matched field nor present in the event";
    assert_eq!(empty_key_message("${detection.fields.SourceIp}"), hint);
    assert_eq!(empty_key_message("${detection.event.SourceIp}"), hint);
    assert_eq!(empty_key_message("${detection.event}"), hint);
    assert_eq!(
        empty_key_message("${detection.rule.id}"),
        "key rendered empty"
    );
    assert_eq!(
        empty_key_message("${correlation.group_key.SourceIp}"),
        "key rendered empty"
    );
    assert_eq!(empty_key_message("${HOME}"), "key rendered empty");
}

fn pipeline_needs_event(yaml: &str) -> bool {
    let file: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
    let resources = EnricherResources {
        source_cache: Some(std::sync::Arc::new(SourceCache::new())),
        #[cfg(feature = "stix-enrich")]
        stix_store: Some(std::sync::Arc::new(rstix::store::MemoryStore::new())),
    };
    build_enrichers_full(file, resources, std::sync::Arc::new(NoopMetrics))
        .unwrap()
        .needs_event()
}

#[test]
fn needs_event_covers_every_rendered_enrichment_field() {
    for yaml in [
        r#"
enrichers:
  - id: e
    kind: detection
    type: template
    inject_field: out
    template: "${detection.fields.SourceIp}"
"#,
        r#"
enrichers:
  - id: e
    kind: detection
    type: template
    inject_field: out
    template: "${detection.event.SourceIp}"
"#,
        r#"
enrichers:
  - id: e
    kind: detection
    type: template
    inject_field: out
    template: "${detection.event}"
"#,
        r#"
enrichers:
  - id: e
    kind: detection
    type: lookup
    inject_field: out
    source: feed
    extract: '."${detection.fields.SourceIp}"'
"#,
        r#"
enrichers:
  - id: e
    kind: detection
    type: http
    inject_field: out
    url: "https://example.test/${detection.fields.SourceIp}"
"#,
        r#"
enrichers:
  - id: e
    kind: detection
    type: http
    inject_field: out
    url: "https://example.test/static"
    body: '{"ip": "${detection.fields.SourceIp}"}'
"#,
        r#"
enrichers:
  - id: e
    kind: detection
    type: http
    inject_field: out
    url: "https://example.test/static"
    headers:
      X-Ip: "${detection.fields.SourceIp}"
"#,
        r#"
enrichers:
  - id: e
    kind: detection
    type: command
    inject_field: out
    command: ["/bin/echo", "${detection.fields.SourceIp}"]
"#,
        r#"
enrichers:
  - id: e
    kind: detection
    type: command
    inject_field: out
    command: ["/bin/echo"]
    env:
      IP: "${detection.fields.SourceIp}"
"#,
    ] {
        assert!(pipeline_needs_event(yaml), "{yaml}");
    }
}

#[cfg(feature = "stix-enrich")]
#[test]
fn needs_event_covers_stix_templates() {
    for yaml in [
        r#"
enrichers:
  - id: e
    kind: detection
    type: stix
    inject_field: out
    stix_id: "indicator--aaaaaaaa-aaaa-4aaa-8aaa-${detection.fields.SourceIp}"
"#,
        r#"
enrichers:
  - id: e
    kind: detection
    type: stix
    inject_field: out
    text_search: "${detection.fields.SourceIp}"
"#,
        r#"
enrichers:
  - id: e
    kind: detection
    type: stix
    inject_field: out
    text_search: "static"
    extract: '."${detection.fields.SourceIp}"'
"#,
    ] {
        assert!(pipeline_needs_event(yaml), "{yaml}");
    }
}

#[cfg(feature = "mmdb-enrich")]
#[test]
fn needs_event_covers_mmdb_keys() {
    let yaml = format!(
        r#"
enrichers:
  - id: e
    kind: detection
    type: mmdb
    inject_field: out
    db_path: {}/tests/fixtures/mmdb/city-test.mmdb
    key: "${{detection.fields.SourceIp}}"
"#,
        env!("CARGO_MANIFEST_DIR")
    );
    assert!(pipeline_needs_event(&yaml));
}

#[cfg(feature = "dns-enrich")]
#[test]
fn needs_event_covers_dns_keys() {
    let yaml = r#"
enrichers:
  - id: e
    kind: detection
    type: dns
    inject_field: out
    record_type: A
    key: "${detection.fields.Domain}"
"#;
    assert!(pipeline_needs_event(yaml));
}

#[test]
fn needs_event_ignores_unrendered_extracts_and_correlation_templates() {
    for yaml in [
        r#"
enrichers:
  - id: e
    kind: detection
    type: http
    inject_field: out
    url: "https://example.test/static"
    extract: '."${detection.fields.SourceIp}"'
"#,
        r#"
enrichers:
  - id: e
    kind: correlation
    type: template
    inject_field: out
    template: "${correlation.rule.id}"
"#,
        r#"
enrichers:
  - id: e
    kind: detection
    type: template
    inject_field: out
    template: "${detection.rule.id} ${detection.tags}"
"#,
    ] {
        assert!(!pipeline_needs_event(yaml), "{yaml}");
    }
}

#[cfg(feature = "dns-enrich")]
#[test]
fn needs_event_ignores_a_dns_extract() {
    let yaml = r#"
enrichers:
  - id: e
    kind: detection
    type: dns
    inject_field: out
    record_type: A
    key: "example.test"
    extract: '.[0] | "${detection.fields.SourceIp}"'
"#;
    assert!(!pipeline_needs_event(yaml));
}

#[test]
fn needs_event_is_false_for_a_pipeline_built_by_hand() {
    let enricher = template_enricher(
        "e",
        EnricherKind::Detection,
        "out",
        "${detection.fields.SourceIp}",
    );
    let pipeline = EnrichmentPipeline::new(vec![Box::new(enricher)], 1);
    assert!(!pipeline.needs_event());
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

#[test]
fn validator_rejects_ocsf_references_outside_a_webhook_body() {
    for (text, kind) in [
        ("${detection.ocsf}", EnricherKind::Detection),
        ("https://x/${correlation.ocsf}", EnricherKind::Correlation),
    ] {
        let err = validate_template_namespace(text, kind, "x", "template").unwrap_err();
        assert!(
            matches!(err, TemplateError::MisplacedOcsf { .. }),
            "{text}: {err}"
        );
        assert!(format!("{err}").contains("webhook body"), "{err}");
    }
}

#[test]
fn webhook_body_accepts_ocsf_as_a_whole_json_value() {
    for body in [
        "${detection.ocsf}",
        r#"{"finding": ${detection.ocsf}}"#,
        r#"{"title": "${detection.rule.title}", "findings": [${detection.ocsf}, ${detection.ocsf}]}"#,
        r#"{"count": ${detection.fields.count}, "finding": ${detection.ocsf}}"#,
    ] {
        super::validate_webhook_body_template(body, EnricherKind::Detection, "x")
            .unwrap_or_else(|e| panic!("{body}: {e}"));
    }
    // A body without an OCSF reference is not required to be JSON.
    super::validate_webhook_body_template(
        "plain ${detection.rule.title}",
        EnricherKind::Detection,
        "x",
    )
    .unwrap();
}

#[test]
fn webhook_body_rejects_ocsf_that_is_not_a_whole_json_value() {
    for body in [
        r#"{"finding": "${detection.ocsf}"}"#,
        r#"{"finding": "prefix ${detection.ocsf} suffix"}"#,
        r#"{${detection.ocsf}: 1}"#,
        r#"{"finding": ${detection.ocsf}x}"#,
        "text ${detection.ocsf}",
    ] {
        let err =
            super::validate_webhook_body_template(body, EnricherKind::Detection, "x").unwrap_err();
        assert!(
            matches!(err, TemplateError::MisplacedOcsf { field: "body", .. }),
            "{body}: {err}"
        );
    }
}

#[test]
fn webhook_body_ocsf_reference_keeps_namespace_rules() {
    let err = super::validate_webhook_body_template(
        r#"{"finding": ${correlation.ocsf}}"#,
        EnricherKind::Detection,
        "x",
    )
    .unwrap_err();
    assert!(matches!(err, TemplateError::CrossNamespace { .. }), "{err}");
}

#[test]
fn ocsf_reference_renders_raw_json_only_through_the_webhook_renderer() {
    let result = detection_result();
    let body = r#"{"t": "${detection.rule.title}", "finding": ${detection.ocsf}}"#;
    let rendered =
        super::render_template_json_with_ocsf(body, &result, || r#"{"class_uid":2004}"#.into());
    let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(parsed["finding"]["class_uid"], 2004);
    assert_eq!(
        render_template("${detection.ocsf}", &result),
        "",
        "the plain renderer has no finding to insert",
    );
    let via_webhook = render_webhook_body(body, EnricherKind::Detection, "hook", &result, || {
        r#"{"class_uid":2004}"#.into()
    })
    .expect("whole-value reference");
    assert_eq!(via_webhook, rendered);
    let misplaced = render_webhook_body(
        r#"{"finding": "${detection.ocsf}"}"#,
        EnricherKind::Detection,
        "hook",
        &result,
        || "{}".into(),
    );
    assert!(matches!(
        misplaced,
        Err(TemplateError::MisplacedOcsf { .. })
    ));
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
    error: EnrichErrorKind,
}

fn erroring(on_error: OnError, error: EnrichErrorKind) -> Box<dyn Enricher> {
    Box::new(ErroringEnricher {
        id: "boom".to_string(),
        kind: EnricherKind::Detection,
        inject_field: "out".to_string(),
        on_error,
        scope: Scope::default(),
        error,
    })
}

fn fetch_error() -> EnrichErrorKind {
    EnrichErrorKind::Fetch("synthetic".to_string())
}

fn miss_error() -> EnrichErrorKind {
    EnrichErrorKind::Miss("synthetic".to_string())
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
            kind: self.error.clone(),
        })
    }
}

#[tokio::test]
async fn on_error_skip_leaves_enrichments_alone() {
    let mut results = vec![detection_result()];
    let e = erroring(OnError::Skip, fetch_error());
    EnrichmentPipeline::new(vec![e], 1).run(&mut results).await;
    assert!(results[0].header.enrichments.is_none());
}

#[tokio::test]
async fn on_error_null_injects_null() {
    let mut results = vec![detection_result()];
    let e = erroring(OnError::Null, fetch_error());
    EnrichmentPipeline::new(vec![e], 1).run(&mut results).await;
    let map = results[0].header.enrichments.as_ref().unwrap();
    assert_eq!(map.get("out").unwrap(), &serde_json::Value::Null);
}

#[tokio::test]
async fn on_error_drop_removes_result_from_vec() {
    let mut results = vec![detection_result(), correlation_result()];
    let e = erroring(OnError::Drop, fetch_error());
    EnrichmentPipeline::new(vec![e], 1).run(&mut results).await;
    // Detection got dropped, correlation survived.
    assert_eq!(results.len(), 1);
    assert!(results[0].is_correlation());
}

#[tokio::test]
async fn miss_applies_on_error_like_a_failure() {
    let mut skipped = vec![detection_result()];
    EnrichmentPipeline::new(vec![erroring(OnError::Skip, miss_error())], 1)
        .run(&mut skipped)
        .await;
    assert!(skipped[0].header.enrichments.is_none());

    let mut nulled = vec![detection_result()];
    EnrichmentPipeline::new(vec![erroring(OnError::Null, miss_error())], 1)
        .run(&mut nulled)
        .await;
    assert_eq!(
        nulled[0].header.enrichments.as_ref().unwrap()["out"],
        serde_json::Value::Null
    );

    let mut dropped = vec![detection_result(), correlation_result()];
    EnrichmentPipeline::new(vec![erroring(OnError::Drop, miss_error())], 1)
        .run(&mut dropped)
        .await;
    assert_eq!(dropped.len(), 1);
    assert!(dropped[0].is_correlation());
}

#[tokio::test]
async fn throttled_failure_warnings_still_apply_on_error() {
    let pipeline = EnrichmentPipeline::new(vec![erroring(OnError::Null, fetch_error())], 1);
    let mut first = vec![detection_result()];
    pipeline.run(&mut first).await;
    let mut second = vec![detection_result()];
    pipeline.run(&mut second).await;
    for results in [&first, &second] {
        assert_eq!(
            results[0].header.enrichments.as_ref().unwrap()["out"],
            serde_json::Value::Null
        );
    }

    let pipeline = EnrichmentPipeline::new(vec![erroring(OnError::Drop, fetch_error())], 1);
    let mut results = vec![detection_result(), detection_result()];
    pipeline.run(&mut results).await;
    assert!(results.is_empty());
}

#[test]
fn failure_logs_throttle_per_enricher_id() {
    let logs = super::FailureLogs::default();
    let now = std::time::Instant::now();
    assert_eq!(logs.record("a", now), Some(1));
    assert_eq!(logs.record("a", now), None);
    assert_eq!(logs.record("b", now), Some(1));
    assert_eq!(
        logs.record(
            "a",
            now + crate::log_throttle::WarnThrottle::DEFAULT_INTERVAL
        ),
        Some(2)
    );
}

#[test]
fn cloned_pipelines_share_failure_logs() {
    let pipeline = EnrichmentPipeline::default();
    let clone = pipeline.clone();
    let now = std::time::Instant::now();
    assert_eq!(pipeline.failure_logs.record("a", now), Some(1));
    assert_eq!(clone.failure_logs.record("a", now), None);
}

/// Test-only enricher that misses for results whose rule id is `miss` and
/// fails for every other result.
struct MissOrFail {
    on_error: OnError,
    on_miss: OnError,
    scope: Scope,
}

fn miss_or_fail(on_error: OnError, on_miss: OnError) -> Box<dyn Enricher> {
    Box::new(MissOrFail {
        on_error,
        on_miss,
        scope: Scope::default(),
    })
}

#[async_trait::async_trait]
impl Enricher for MissOrFail {
    fn kind(&self) -> EnricherKind {
        EnricherKind::Detection
    }
    fn id(&self) -> &str {
        "miss_or_fail"
    }
    fn inject_field(&self) -> &str {
        "out"
    }
    fn scope(&self) -> &Scope {
        &self.scope
    }
    fn on_error(&self) -> OnError {
        self.on_error
    }
    fn on_miss(&self) -> OnError {
        self.on_miss
    }
    async fn enrich(&self, result: &mut EvaluationResult) -> Result<(), EnrichError> {
        let kind = if result.header.rule_id.as_deref() == Some("miss") {
            miss_error()
        } else {
            fetch_error()
        };
        Err(EnrichError {
            enricher_id: "miss_or_fail".to_string(),
            kind,
        })
    }
}

fn result_with_rule_id(rule_id: &str) -> EvaluationResult {
    let mut result = detection_result();
    result.header.rule_id = Some(rule_id.to_string());
    result
}

#[tokio::test]
async fn on_miss_skip_keeps_missed_results_when_on_error_drops() {
    let mut results = vec![result_with_rule_id("miss"), result_with_rule_id("fail")];
    EnrichmentPipeline::new(vec![miss_or_fail(OnError::Drop, OnError::Skip)], 1)
        .run(&mut results)
        .await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].header.rule_id.as_deref(), Some("miss"));
    assert!(results[0].header.enrichments.is_none());
}

#[tokio::test]
async fn on_miss_null_injects_null_only_for_misses() {
    let mut results = vec![result_with_rule_id("miss"), result_with_rule_id("fail")];
    EnrichmentPipeline::new(vec![miss_or_fail(OnError::Skip, OnError::Null)], 1)
        .run(&mut results)
        .await;
    assert_eq!(
        results[0].header.enrichments.as_ref().unwrap()["out"],
        serde_json::Value::Null
    );
    assert!(results[1].header.enrichments.is_none());
}

#[tokio::test]
async fn on_miss_drop_removes_missed_results_only() {
    let mut results = vec![result_with_rule_id("miss"), result_with_rule_id("fail")];
    EnrichmentPipeline::new(vec![miss_or_fail(OnError::Null, OnError::Drop)], 1)
        .run(&mut results)
        .await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].header.rule_id.as_deref(), Some("fail"));
    assert_eq!(
        results[0].header.enrichments.as_ref().unwrap()["out"],
        serde_json::Value::Null
    );
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
    for reserved in [
        "template", "lookup", "http", "command", "stix", "mmdb", "dns",
    ] {
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
    let e = erroring(OnError::Skip, fetch_error());
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
        error: fetch_error(),
    }) as Box<dyn Enricher>;
    let pipeline = EnrichmentPipeline::new(vec![e], 1)
        .with_metrics(m.clone() as std::sync::Arc<dyn crate::MetricsHook>);
    let mut results = vec![detection_result()];
    pipeline.run(&mut results).await;
    let completed = m.completed.lock().unwrap().clone();
    assert_eq!(completed[0].2, "drop");
}

#[tokio::test(flavor = "multi_thread")]
async fn miss_covered_by_null_default_reports_success() {
    let m = std::sync::Arc::new(CollectingMetrics::default());
    let yaml = r#"
enrichers:
  - id: owner
    kind: detection
    type: lookup
    inject_field: owner
    source: missing_source
    default: null
"#;
    let file: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
    let pipeline = build_enrichers_full(
        file,
        EnricherResources {
            source_cache: Some(Arc::new(SourceCache::new())),
            #[cfg(feature = "stix-enrich")]
            stix_store: None,
        },
        m.clone() as std::sync::Arc<dyn crate::MetricsHook>,
    )
    .unwrap();
    let mut results = vec![detection_result()];
    pipeline.run(&mut results).await;
    assert_eq!(
        results[0].header.enrichments.as_ref().unwrap()["owner"],
        serde_json::Value::Null
    );
    let completed = m.completed.lock().unwrap().clone();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].2, "success");
}

#[tokio::test(flavor = "multi_thread")]
async fn cached_miss_status_counts_as_an_http_cache_hit() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;
    let m = std::sync::Arc::new(CollectingMetrics::default());
    let enricher = super::HttpEnricher::new(
        "vt".to_string(),
        EnricherKind::Detection,
        "vt".to_string(),
        "GET".to_string(),
        server.uri(),
        Vec::new(),
        None,
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        None,
        crate::build_default_http_client().unwrap(),
        crate::HttpResponseCache::new(Duration::from_secs(60)),
    )
    .with_default(Some(serde_json::json!("unknown")))
    .with_miss_status(vec![404])
    .with_metrics(m.clone() as std::sync::Arc<dyn crate::MetricsHook>);
    let pipeline = EnrichmentPipeline::new(vec![Box::new(enricher)], 1);
    let mut results = vec![detection_result(), detection_result()];
    pipeline.run(&mut results).await;
    assert_eq!(m.cache_misses.lock().unwrap().len(), 1);
    assert_eq!(m.cache_hits.lock().unwrap().len(), 1);
    for result in &results {
        assert_eq!(result.header.enrichments.as_ref().unwrap()["vt"], "unknown");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn http_null_result_is_a_success_not_a_miss() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::Value::Null))
        .expect(1)
        .mount(&server)
        .await;
    let m = std::sync::Arc::new(CollectingMetrics::default());
    let enricher = super::HttpEnricher::new(
        "vt".to_string(),
        EnricherKind::Detection,
        "vt".to_string(),
        "GET".to_string(),
        server.uri(),
        Vec::new(),
        None,
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        None,
        crate::build_default_http_client().unwrap(),
        crate::HttpResponseCache::new(Duration::ZERO),
    )
    .with_on_miss(OnError::Drop);
    let pipeline = EnrichmentPipeline::new(vec![Box::new(enricher)], 1)
        .with_metrics(m.clone() as std::sync::Arc<dyn crate::MetricsHook>);
    let mut results = vec![detection_result()];
    pipeline.run(&mut results).await;
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].header.enrichments.as_ref().unwrap()["vt"],
        serde_json::Value::Null
    );
    let completed = m.completed.lock().unwrap().clone();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].2, "success");
}

async fn statuses_for(enricher: Box<dyn Enricher>, rule_ids: &[&str]) -> Vec<String> {
    let m = std::sync::Arc::new(CollectingMetrics::default());
    let pipeline = EnrichmentPipeline::new(vec![enricher], 1)
        .with_metrics(m.clone() as std::sync::Arc<dyn crate::MetricsHook>);
    let mut results: Vec<_> = rule_ids.iter().map(|id| result_with_rule_id(id)).collect();
    pipeline.run(&mut results).await;
    let completed = m.completed.lock().unwrap().clone();
    completed.into_iter().map(|(_, _, status)| status).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_report_misses_as_miss_unless_dropped() {
    // Without an `on_miss` override, the policy falls back to `on_error`.
    for (on_error, expected) in [
        (OnError::Skip, "miss"),
        (OnError::Null, "miss"),
        (OnError::Drop, "drop"),
    ] {
        assert_eq!(
            statuses_for(erroring(on_error, miss_error()), &["r"]).await,
            vec![expected],
            "on_error {on_error:?}"
        );
    }
    for (on_miss, expected) in [
        (OnError::Skip, "miss"),
        (OnError::Null, "miss"),
        (OnError::Drop, "drop"),
    ] {
        assert_eq!(
            statuses_for(miss_or_fail(OnError::Null, on_miss), &["miss", "fail"]).await,
            vec![expected, "error"],
            "on_miss {on_miss:?}"
        );
    }
    assert_eq!(
        statuses_for(miss_or_fail(OnError::Skip, OnError::Null), &["fail"]).await,
        vec!["skip"]
    );
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

#[test]
fn bespoke_factory_receives_custom_keys() {
    let _guard = registry_test_lock().lock().unwrap();
    super::clear_builtin_registry();
    let seen = Arc::new(std::sync::Mutex::new(None::<serde_json::Value>));
    let seen_in_factory = Arc::clone(&seen);
    let factory: super::EnricherFactory = Arc::new(move |raw| {
        *seen_in_factory.lock().unwrap() = Some(raw.clone());
        Ok(Box::new(template_enricher(
            raw["id"].as_str().unwrap(),
            EnricherKind::Detection,
            raw["inject_field"].as_str().unwrap(),
            "static",
        )) as Box<dyn Enricher>)
    });
    register_builtin("passive_dns", factory).unwrap();

    let file: crate::EnrichersFile = yaml_serde::from_str(
        r#"
enrichers:
  - id: pdns
    kind: detection
    type: passive_dns
    inject_field: pdns
    timeout: 3s
    api_key_env: PASSIVEDNS_API_KEY
    key_field: SourceIp
"#,
    )
    .unwrap();
    let pipeline = crate::build_enrichers(file).unwrap();
    assert_eq!(pipeline.len(), 1);

    let raw = seen.lock().unwrap().take().expect("factory was called");
    assert_eq!(raw["api_key_env"], "PASSIVEDNS_API_KEY");
    assert_eq!(raw["key_field"], "SourceIp");
    assert_eq!(raw["type"], "passive_dns");
    assert_eq!(raw["timeout_ms"], 3000);
    assert!(raw.get("timeout").is_none());
}
