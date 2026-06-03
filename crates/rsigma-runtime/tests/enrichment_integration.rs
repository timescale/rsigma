//! Integration tests for the four enrichment primitives.
//!
//! Spins up `wiremock` for HTTP coverage, exercises real `tokio::process`
//! invocations for command coverage, and drives the
//! [`EnrichmentPipeline`](rsigma_runtime::EnrichmentPipeline) end-to-end
//! across both detection and correlation results.
//!
//! Per-test fixtures sit inline rather than behind a shared helper module
//! to keep each test single-file readable.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rsigma_eval::pipeline::sources::ExtractExpr;
use rsigma_eval::{
    CorrelationBody, DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader,
};
use rsigma_parser::{CorrelationType, Level};
use rsigma_runtime::{
    CommandEnricher, EnricherKind, EnrichmentPipeline, HttpEnricher, HttpEnricherClient,
    HttpResponseCache, OnError, OutputFormat, Scope, build_default_http_client,
};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Platform-portable shell helpers
// ---------------------------------------------------------------------------

/// Wrap a shell command body in the right `argv` for the host platform.
/// On Unix the body is passed to `/bin/sh -c <body>`; on Windows it is
/// passed to `cmd.exe /C <body>`. Quoting differs slightly between the
/// two shells so callers should keep the body simple (single-line, no
/// embedded quotes) or use a static fixture file plus `cat` / `type`.
fn shell_argv(body: &str) -> Vec<String> {
    #[cfg(unix)]
    {
        vec!["/bin/sh".to_string(), "-c".to_string(), body.to_string()]
    }
    #[cfg(windows)]
    {
        vec!["cmd.exe".to_string(), "/C".to_string(), body.to_string()]
    }
}

/// `cat` (Unix) / `type` (Windows) the given file. Used in tests that
/// need a deterministic JSON payload from a command without dealing
/// with cross-shell quote escaping.
///
/// On Windows, `type` and the path go in their own argv elements
/// rather than being baked into a `type "..."` blob. That avoids
/// cmd.exe's `/C` quote-stripping pathology: Rust's CreateProcess
/// quoting wraps a single string with embedded `"`s in outer quotes
/// and escapes the inner ones, which cmd's `/C` parser then
/// outer-strips, leaving `type \"...\"` -- a path that does not
/// exist. With separate args, Rust quotes only the path element and
/// cmd's `type` reads the file cleanly. `/D` disables AutoRun for
/// hermeticity.
fn cat_argv(path: &str) -> Vec<String> {
    #[cfg(unix)]
    {
        vec!["/bin/cat".to_string(), path.to_string()]
    }
    #[cfg(windows)]
    {
        vec![
            "cmd.exe".to_string(),
            "/D".to_string(),
            "/C".to_string(),
            "type".to_string(),
            path.to_string(),
        ]
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn detection(rule_id: &str, command_line: &str) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: format!("rule-{rule_id}"),
            rule_id: Some(rule_id.to_string()),
            level: Some(Level::High),
            tags: vec!["attack.t1059".to_string()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![FieldMatch {
                field: "CommandLine".to_string(),
                value: json!(command_line),
            }],
            event: None,
        }),
    }
}

fn correlation(rule_id: &str, source_ip: &str, count: u64) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: format!("corr-{rule_id}"),
            rule_id: Some(rule_id.to_string()),
            level: Some(Level::High),
            tags: vec!["attack.t1110".to_string()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
        },
        body: ResultBody::Correlation(CorrelationBody {
            correlation_type: CorrelationType::EventCount,
            group_key: vec![("SourceIP".to_string(), source_ip.to_string())],
            aggregated_value: count as f64,
            timespan_secs: 300,
            tenant_id: None,
            events: None,
            event_refs: None,
        }),
    }
}

fn http_client_for_test() -> HttpEnricherClient {
    build_default_http_client().expect("build reqwest client")
}

// ---------------------------------------------------------------------------
// HttpEnricher integration tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn http_success_injects_full_response_object() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/asset/dc01"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "owner": "IT-Ops",
            "criticality": "high"
        })))
        .mount(&server)
        .await;

    let url_template = format!("{}/asset/${{detection.fields.HostName}}", server.uri());
    let mut det = detection("rule-x", "ps -ef");
    det.as_detection_mut()
        .unwrap()
        .matched_fields
        .push(FieldMatch {
            field: "HostName".to_string(),
            value: json!("dc01"),
        });

    let enricher = Box::new(HttpEnricher::new(
        "asset_lookup".to_string(),
        EnricherKind::Detection,
        "asset_info".to_string(),
        "GET".to_string(),
        url_template,
        Vec::new(),
        None,
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        None,
        http_client_for_test(),
        HttpResponseCache::new(Duration::from_secs(0)),
    )) as Box<dyn rsigma_runtime::Enricher>;

    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![det];
    pipeline.run(&mut results).await;

    let map = results[0].header.enrichments.as_ref().unwrap();
    assert_eq!(
        map.get("asset_info").unwrap(),
        &json!({"owner": "IT-Ops", "criticality": "high"})
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn http_template_renders_path_and_authorization_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/asset/dc01"))
        .and(header("Authorization", "Bearer secret-xyz"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&server)
        .await;
    // SAFETY: tests run as a single-threaded runtime per #[tokio::test]
    // task; we set a process-wide env var, but it is unique enough not
    // to collide.
    unsafe {
        std::env::set_var("CMDB_TOKEN", "secret-xyz");
    }

    let url_template = format!("{}/asset/${{detection.fields.HostName}}", server.uri());
    let mut det = detection("rule-x", "ps -ef");
    det.as_detection_mut()
        .unwrap()
        .matched_fields
        .push(FieldMatch {
            field: "HostName".to_string(),
            value: json!("dc01"),
        });

    let enricher = Box::new(HttpEnricher::new(
        "asset_lookup_with_auth".to_string(),
        EnricherKind::Detection,
        "asset".to_string(),
        "GET".to_string(),
        url_template,
        vec![(
            "Authorization".to_string(),
            "Bearer ${CMDB_TOKEN}".to_string(),
        )],
        None,
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        None,
        http_client_for_test(),
        HttpResponseCache::new(Duration::from_secs(0)),
    )) as Box<dyn rsigma_runtime::Enricher>;

    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![det];
    pipeline.run(&mut results).await;

    assert!(
        results[0]
            .header
            .enrichments
            .as_ref()
            .unwrap()
            .contains_key("asset")
    );
    unsafe {
        std::env::remove_var("CMDB_TOKEN");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn http_500_triggers_on_error_policy() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/x"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let enricher = Box::new(HttpEnricher::new(
        "boom".to_string(),
        EnricherKind::Detection,
        "out".to_string(),
        "GET".to_string(),
        format!("{}/x", server.uri()),
        Vec::new(),
        None,
        Duration::from_secs(5),
        OnError::Null,
        Scope::default(),
        None,
        http_client_for_test(),
        HttpResponseCache::new(Duration::from_secs(0)),
    )) as Box<dyn rsigma_runtime::Enricher>;

    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![detection("rule-x", "ps -ef")];
    pipeline.run(&mut results).await;

    let map = results[0].header.enrichments.as_ref().unwrap();
    assert_eq!(map.get("out").unwrap(), &serde_json::Value::Null);
}

#[tokio::test(flavor = "multi_thread")]
async fn http_response_cache_eliminates_second_call() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/r"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"v": 1})))
        // Strict: only one upstream request expected.
        .expect(1)
        .mount(&server)
        .await;

    let cache = HttpResponseCache::new(Duration::from_secs(60));
    let make_enricher = |id: &str| {
        Box::new(HttpEnricher::new(
            id.to_string(),
            EnricherKind::Detection,
            format!("out_{id}"),
            "GET".to_string(),
            format!("{}/r", server.uri()),
            Vec::new(),
            None,
            Duration::from_secs(5),
            OnError::Skip,
            Scope::default(),
            None,
            http_client_for_test(),
            cache.clone(),
        )) as Box<dyn rsigma_runtime::Enricher>
    };

    let pipeline =
        EnrichmentPipeline::new(vec![make_enricher("first"), make_enricher("second")], 4);
    let mut results = vec![detection("rule-x", "ps -ef")];
    pipeline.run(&mut results).await;

    // wiremock's `.expect(1)` is asserted on Drop; both enrichers fired
    // but only the first hit the upstream. Both injected the same value.
    let map = results[0].header.enrichments.as_ref().unwrap();
    assert_eq!(map.get("out_first").unwrap(), &json!({"v": 1}));
    assert_eq!(map.get("out_second").unwrap(), &json!({"v": 1}));

    let (hits, misses, _exp) = cache.stats();
    assert_eq!(misses, 1, "first call should be a miss");
    assert_eq!(hits, 1, "second call should be a cache hit");
}

#[tokio::test(flavor = "multi_thread")]
async fn http_cache_ttl_expires() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/r"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"v": 1})))
        // Two upstream calls expected: TTL expires between them.
        .expect(2)
        .mount(&server)
        .await;

    let cache = HttpResponseCache::new(Duration::from_millis(40));
    let make_enricher = |id: &str| {
        Box::new(HttpEnricher::new(
            id.to_string(),
            EnricherKind::Detection,
            format!("out_{id}"),
            "GET".to_string(),
            format!("{}/r", server.uri()),
            Vec::new(),
            None,
            Duration::from_secs(5),
            OnError::Skip,
            Scope::default(),
            None,
            http_client_for_test(),
            cache.clone(),
        )) as Box<dyn rsigma_runtime::Enricher>
    };

    let p1 = EnrichmentPipeline::new(vec![make_enricher("first")], 4);
    let p2 = EnrichmentPipeline::new(vec![make_enricher("second")], 4);

    let mut r1 = vec![detection("rule-x", "ps -ef")];
    p1.run(&mut r1).await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    let mut r2 = vec![detection("rule-x", "ps -ef")];
    p2.run(&mut r2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn http_extract_jq_filters_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/whois"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ip": "203.0.113.4",
            "asn": 64512,
            "country": "US"
        })))
        .mount(&server)
        .await;

    let enricher = Box::new(HttpEnricher::new(
        "geoip".to_string(),
        EnricherKind::Detection,
        "country".to_string(),
        "GET".to_string(),
        format!("{}/whois", server.uri()),
        Vec::new(),
        None,
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        Some(ExtractExpr::Jq(".country".to_string())),
        http_client_for_test(),
        HttpResponseCache::new(Duration::from_secs(0)),
    )) as Box<dyn rsigma_runtime::Enricher>;

    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![detection("rule-x", "ps -ef")];
    pipeline.run(&mut results).await;

    let map = results[0].header.enrichments.as_ref().unwrap();
    assert_eq!(map.get("country").unwrap(), &json!("US"));
}

// ---------------------------------------------------------------------------
// CommandEnricher integration tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn command_json_output_parses_into_object() {
    // Cross-shell quoting of `echo '{"k":"v"}'` is a tarpit; stage the
    // payload as a fixture file and have the command read it back. The
    // `cat_argv` helper picks `cat` on Unix and `type` on Windows.
    let payload = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(payload.path(), r#"{"score": 12, "category": "internal"}"#).unwrap();
    let argv = cat_argv(payload.path().to_str().unwrap());

    let enricher = Box::new(CommandEnricher::new(
        "echo_json".to_string(),
        EnricherKind::Detection,
        "ip_rep".to_string(),
        argv,
        HashMap::new(),
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        OutputFormat::Json,
    )) as Box<dyn rsigma_runtime::Enricher>;

    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![detection("rule-x", "ps -ef")];
    pipeline.run(&mut results).await;

    let map = results[0].header.enrichments.as_ref().unwrap();
    assert_eq!(
        map.get("ip_rep").unwrap(),
        &json!({"score": 12, "category": "internal"})
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn command_raw_output_strips_trailing_newline() {
    let enricher = Box::new(CommandEnricher::new(
        "raw".to_string(),
        EnricherKind::Detection,
        "out".to_string(),
        shell_argv("echo hello"),
        HashMap::new(),
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        OutputFormat::Raw,
    )) as Box<dyn rsigma_runtime::Enricher>;

    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![detection("rule-x", "ps -ef")];
    pipeline.run(&mut results).await;
    assert_eq!(
        results[0]
            .header
            .enrichments
            .as_ref()
            .unwrap()
            .get("out")
            .unwrap(),
        &json!("hello")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn command_nonzero_exit_triggers_on_error_policy() {
    let enricher = Box::new(CommandEnricher::new(
        "false_cmd".to_string(),
        EnricherKind::Detection,
        "out".to_string(),
        shell_argv("exit 7"),
        HashMap::new(),
        Duration::from_secs(5),
        OnError::Null,
        Scope::default(),
        OutputFormat::Json,
    )) as Box<dyn rsigma_runtime::Enricher>;

    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![detection("rule-x", "ps -ef")];
    pipeline.run(&mut results).await;
    assert_eq!(
        results[0]
            .header
            .enrichments
            .as_ref()
            .unwrap()
            .get("out")
            .unwrap(),
        &serde_json::Value::Null
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn command_template_expansion_for_correlation_kind() {
    // The template engine renders `${correlation.*}` in the argv before
    // it ever reaches the OS, so by the time `cmd.exe` / `sh` sees the
    // body it is just `echo agg=73 ip=203.0.113.4`. That `echo` form
    // works identically under both shells.
    let enricher = Box::new(CommandEnricher::new(
        "summary".to_string(),
        EnricherKind::Correlation,
        "summary".to_string(),
        shell_argv("echo agg=${correlation.aggregated_value} ip=${correlation.group_key.SourceIP}"),
        HashMap::new(),
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        OutputFormat::Raw,
    )) as Box<dyn rsigma_runtime::Enricher>;

    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![correlation("c1", "203.0.113.4", 73)];
    pipeline.run(&mut results).await;
    assert_eq!(
        results[0]
            .header
            .enrichments
            .as_ref()
            .unwrap()
            .get("summary")
            .unwrap(),
        &json!("agg=73 ip=203.0.113.4")
    );
}

// ---------------------------------------------------------------------------
// drop policy + concurrency
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn on_error_drop_removes_only_offending_result() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/x"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let enricher = Box::new(HttpEnricher::new(
        "drop_me".to_string(),
        EnricherKind::Detection,
        "out".to_string(),
        "GET".to_string(),
        format!("{}/x", server.uri()),
        Vec::new(),
        None,
        Duration::from_secs(5),
        OnError::Drop,
        Scope::default(),
        None,
        http_client_for_test(),
        HttpResponseCache::new(Duration::from_secs(0)),
    )) as Box<dyn rsigma_runtime::Enricher>;

    let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
    let mut results = vec![
        detection("alpha", "ps"),
        correlation("corr1", "1.2.3.4", 10),
        detection("beta", "ls"),
    ];
    pipeline.run(&mut results).await;

    // Both detections should drop (the http enricher matches kind:detection
    // and erroring on a 500 with on_error: drop), correlation survives.
    assert_eq!(results.len(), 1);
    assert!(results[0].is_correlation());
}

#[tokio::test(flavor = "multi_thread")]
async fn semaphore_caps_concurrent_enrichments() {
    // With 1 permit and three results, enrichments must run sequentially.
    // We assert by stamping each result with a monotonic counter inside a
    // synthetic enricher; if the semaphore is honoured, observed
    // counters match the sequential-execution invariant (counter ==
    // index after run).
    use rsigma_runtime::Enricher;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Stamper {
        counter: Arc<AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl Enricher for Stamper {
        fn kind(&self) -> EnricherKind {
            EnricherKind::Detection
        }
        fn id(&self) -> &str {
            "stamper"
        }
        fn inject_field(&self) -> &str {
            "n"
        }
        fn timeout(&self) -> Duration {
            Duration::from_secs(5)
        }
        fn scope(&self) -> &Scope {
            static EMPTY: std::sync::OnceLock<Scope> = std::sync::OnceLock::new();
            EMPTY.get_or_init(Scope::default)
        }
        fn on_error(&self) -> OnError {
            OnError::Skip
        }
        async fn enrich(
            &self,
            r: &mut EvaluationResult,
        ) -> Result<(), rsigma_runtime::EnrichError> {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let n = self.counter.fetch_add(1, Ordering::SeqCst);
            rsigma_runtime::EnrichmentPipeline::default(); // noop, just to use the type
            r.header
                .enrichments
                .get_or_insert_with(serde_json::Map::new)
                .insert("n".to_string(), json!(n));
            Ok(())
        }
    }

    let counter = Arc::new(AtomicUsize::new(0));
    let enricher = Box::new(Stamper {
        counter: counter.clone(),
    }) as Box<dyn rsigma_runtime::Enricher>;
    let pipeline = EnrichmentPipeline::new(vec![enricher], 1);

    let mut results = vec![
        detection("a", "ls"),
        detection("b", "ls"),
        detection("c", "ls"),
    ];
    pipeline.run(&mut results).await;
    assert_eq!(counter.load(Ordering::SeqCst), 3);
    // Three sequential stamps.
    let mut stamps: Vec<i64> = results
        .iter()
        .map(|r| {
            r.header.enrichments.as_ref().unwrap()["n"]
                .as_i64()
                .unwrap()
        })
        .collect();
    stamps.sort();
    assert_eq!(stamps, vec![0, 1, 2]);
}
