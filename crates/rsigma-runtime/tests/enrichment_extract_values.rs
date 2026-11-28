//! Event values reach `lookup` extract programs as data.
//!
//! Every hostile value below is looked up through jq, JSONPath, and CEL
//! programs that reference it from a string literal, a key position, and
//! (where the language allows it) outside a literal. A value that is in the
//! source must find exactly its own record; a value that is not must be a
//! miss. Neither may produce an extract error, a different output shape,
//! or the source's `secret`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rsigma_eval::pipeline::sources::ExtractExpr;
use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
use rsigma_parser::Level;
use rsigma_runtime::{
    EnrichErrorKind, Enricher, EnricherKind, EnricherResources, EnrichersFile, EnrichmentPipeline,
    LookupEnricher, NoopMetrics, OnError, Scope, SourceCache, build_enrichers_full,
    parse_enrichers_config,
};
use serde_json::{Value, json};

/// Values that change a program's meaning when pasted into its text.
const HOSTILE: &[&str] = &[
    "\"",
    "\\",
    "|",
    "]",
    ")",
    "or",
    "true",
    "env",
    "'",
    "a\" or true or \"",
    "\") | .secret | (\"",
    "\"] | .secret | .[\"",
    "'] | $..secret | ['",
    "' || true || '",
    "x') || true || ('",
    "\\\" or 1 == 1 //",
    "$ENV.HOME",
    "env.HOME",
    "\\(env)",
    "\\(.secret)",
    "$__v0",
    "__v0",
    "${detection.rule.title}",
    ".[]",
    "a\nb\r\tc",
    "nul\u{0}byte",
    "ünïcødé 名前 🚀",
    "' + data.secret + '",
    "\" + data.secret + \"",
    "#",
    "// comment",
    "@.name",
    "$",
];

fn source() -> Value {
    let mut by_key = serde_json::Map::new();
    let mut records = Vec::new();
    for (i, value) in HOSTILE.iter().enumerate() {
        by_key.insert((*value).to_string(), json!({ "hit": i }));
        records.push(json!({ "name": value, "hit": i }));
    }
    json!({ "by_key": by_key, "records": records, "secret": "do-not-leak" })
}

fn cache() -> Arc<SourceCache> {
    let cache = Arc::new(SourceCache::new());
    cache.store("intel", &source());
    cache
}

fn detection(value: &str) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "hostile".to_string(),
            rule_id: Some("rule-hostile".to_string()),
            tenant_id: None,
            level: Some(Level::High),
            tags: vec![],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
            ruleset: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![FieldMatch::new("Value", json!(value))],
            event: None,
        }),
    }
}

fn enricher(extract: ExtractExpr) -> LookupEnricher {
    LookupEnricher::new(
        "hostile".to_string(),
        EnricherKind::Detection,
        "out".to_string(),
        "intel".to_string(),
        Some(extract),
        None,
        Duration::from_secs(5),
        OnError::Skip,
        Scope::default(),
        cache(),
    )
}

/// Programs that look up `${detection.fields.Value}` and return its `hit`.
fn programs() -> Vec<ExtractExpr> {
    vec![
        ExtractExpr::Jq(
            r#".records[] | select(.name == "${detection.fields.Value}") | .hit"#.into(),
        ),
        ExtractExpr::Jq(r#".by_key["${detection.fields.Value}"].hit"#.into()),
        ExtractExpr::Jq(r#".by_key."${detection.fields.Value}".hit"#.into()),
        ExtractExpr::Jq(r#".by_key[${detection.fields.Value}].hit"#.into()),
        ExtractExpr::Jq(r#".records[] | select(.name == ${detection.fields.Value}) | .hit"#.into()),
        ExtractExpr::Jq(
            r#".records[] | select(.name == "\("${detection.fields.Value}")") | .hit"#.into(),
        ),
        ExtractExpr::JsonPath("$.records[?@.name == '${detection.fields.Value}'].hit".into()),
        ExtractExpr::JsonPath(r#"$.records[?@.name == "${detection.fields.Value}"].hit"#.into()),
        ExtractExpr::JsonPath("$.records[?@.name == ${detection.fields.Value}].hit".into()),
        ExtractExpr::JsonPath("$.by_key['${detection.fields.Value}'].hit".into()),
        ExtractExpr::JsonPath(r#"$.by_key["${detection.fields.Value}"].hit"#.into()),
        ExtractExpr::JsonPath("$.by_key[${detection.fields.Value}].hit".into()),
        ExtractExpr::Cel(
            "data.records.filter(r, r.name == '${detection.fields.Value}').map(r, r.hit)".into(),
        ),
        ExtractExpr::Cel(
            r#"data.records.filter(r, r.name == "${detection.fields.Value}").map(r, r.hit)"#.into(),
        ),
        ExtractExpr::Cel(
            r#"data.records.filter(r, r.name == """${detection.fields.Value}""").map(r, r.hit)"#
                .into(),
        ),
        ExtractExpr::Cel(
            "data.records.filter(r, r.name == ${detection.fields.Value}).map(r, r.hit)".into(),
        ),
        ExtractExpr::Cel(
            "data.records.filter(r, r.name == r'${detection.fields.Value}').map(r, r.hit)".into(),
        ),
    ]
}

/// The `hit` a program returns, unwrapping the one-element list CEL's
/// `filter` produces.
fn hit(value: Value) -> Value {
    match value {
        Value::Array(mut items) if items.len() == 1 => items.remove(0),
        other => other,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hostile_value_finds_exactly_its_own_record() {
    for program in programs() {
        let enricher = enricher(program.clone());
        for (i, value) in HOSTILE.iter().enumerate() {
            let mut result = detection(value);
            let outcome = enricher.enrich(&mut result).await;
            assert!(outcome.is_ok(), "{program:?} with {value:?}: {outcome:?}");
            let injected = result.header.enrichments.unwrap()["out"].clone();
            assert_eq!(hit(injected), json!(i), "{program:?} with {value:?}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hostile_value_that_is_not_in_the_source_is_a_miss() {
    let absent = [
        "nope\" or true or \"",
        "nope\") | .secret | (\"",
        "nope' || true || '",
        "nope'] | $..secret | ['",
        "nope' + data.secret + '",
        "nope\\",
        "nope\n",
        "nopé 🚀",
        "",
    ];
    for program in programs() {
        let enricher = enricher(program.clone());
        for value in absent {
            let mut result = detection(value);
            match enricher.enrich(&mut result).await {
                Err(e) if matches!(e.kind, EnrichErrorKind::Miss(_)) => {}
                Ok(()) => {
                    let injected = &result.header.enrichments.as_ref().unwrap()["out"];
                    assert_eq!(injected, &json!([]), "{program:?} with {value:?}");
                }
                other => panic!("{program:?} with {value:?}: {other:?}"),
            }
            assert!(
                !format!("{:?}", result.header.enrichments).contains("do-not-leak"),
                "{program:?} with {value:?} leaked the secret"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hostile_values_never_reach_the_drop_path() {
    let yaml = r#"
enrichers:
  - id: jq
    kind: detection
    type: lookup
    inject_field: jq
    source: intel
    extract: '.records[] | select(.name == "${detection.fields.Value}") | .hit'
    on_error: drop
    on_miss: skip
  - id: jsonpath
    kind: detection
    type: lookup
    inject_field: jsonpath
    source: intel
    extract: "$.records[?@.name == '${detection.fields.Value}'].hit"
    extract_type: jsonpath
    on_error: drop
    on_miss: skip
  - id: cel
    kind: detection
    type: lookup
    inject_field: cel
    source: intel
    extract: "data.records.filter(r, r.name == '${detection.fields.Value}').map(r, r.hit)"
    extract_type: cel
    on_error: drop
    on_miss: skip
"#;
    let file: EnrichersFile = parse_enrichers_config(yaml).unwrap();
    let pipeline = build_enrichers_full(
        file,
        EnricherResources {
            source_cache: Some(cache()),
            #[cfg(feature = "stix-enrich")]
            stix_store: None,
        },
        Arc::new(NoopMetrics),
    )
    .unwrap();
    let mut results: Vec<EvaluationResult> = HOSTILE.iter().map(|v| detection(v)).collect();
    results.push(detection("nope\" or true or \""));
    pipeline.run(&mut results).await;
    assert_eq!(
        results.len(),
        HOSTILE.len() + 1,
        "a hostile value dropped a result"
    );
    for (i, result) in results.iter().take(HOSTILE.len()).enumerate() {
        let enrichments = result.header.enrichments.as_ref().unwrap();
        assert_eq!(enrichments["jq"], json!(i));
        assert_eq!(enrichments["jsonpath"], json!(i));
        assert_eq!(enrichments["cel"], json!([i]));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn documented_extract_shapes_keep_working() {
    let cache = Arc::new(SourceCache::new());
    cache.store(
        "assets",
        &json!({
            "dc01": {"owner": "IT-Ops"},
            "assets": [{"hostname": "dc01", "owner": "IT-Ops"}]
        }),
    );
    let shapes = [
        ExtractExpr::Jq(r#"."${detection.fields.HostName}""#.into()),
        ExtractExpr::Jq(
            r#".assets[] | select(.hostname == "${detection.fields.HostName}")"#.into(),
        ),
        ExtractExpr::JsonPath("$.assets[?(@.hostname == '${detection.fields.HostName}')]".into()),
        ExtractExpr::Cel(
            "data.assets.filter(x, x.hostname == '${detection.fields.HostName}')".into(),
        ),
        ExtractExpr::Cel(r#"data["${detection.fields.HostName}"]"#.into()),
    ];
    for extract in shapes {
        let enricher = LookupEnricher::new(
            "asset".to_string(),
            EnricherKind::Detection,
            "asset".to_string(),
            "assets".to_string(),
            Some(extract.clone()),
            None,
            Duration::from_secs(5),
            OnError::Skip,
            Scope::default(),
            Arc::clone(&cache),
        );
        let mut result = EvaluationResult {
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: vec![FieldMatch::new("HostName", json!("dc01"))],
                event: None,
            }),
            ..detection("")
        };
        enricher.enrich(&mut result).await.unwrap();
        let owner = hit(result.header.enrichments.unwrap()["asset"].clone());
        assert_eq!(owner["owner"], json!("IT-Ops"), "{extract:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn env_is_not_readable_from_an_extract() {
    for extract in ["env", "$ENV", "env.PATH", "[env[]] | length"] {
        let yaml = format!(
            "enrichers:\n  - id: e\n    kind: detection\n    type: lookup\n    inject_field: out\n    source: intel\n    extract: '{extract}'\n"
        );
        let err = parse_enrichers_config(&yaml).unwrap_err().to_string();
        assert!(err.contains("extract"), "{extract}: {err}");
    }
}

#[test]
fn an_extract_that_does_not_compile_is_rejected_at_load() {
    for (extract, extract_type) in [
        (".[", "jq"),
        ("def f: f; f", "jq"),
        ("$[", "jsonpath"),
        ("$.${detection.fields.Name}", "jsonpath"),
        ("data.${detection.fields.Name}", "cel"),
        ("data +", "cel"),
    ] {
        let yaml = format!(
            "enrichers:\n  - id: e\n    kind: detection\n    type: lookup\n    inject_field: out\n    source: intel\n    extract: '{extract}'\n    extract_type: {extract_type}\n"
        );
        let err = parse_enrichers_config(&yaml).unwrap_err().to_string();
        assert!(err.contains("invalid 'extract'"), "{extract}: {err}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unbounded_program_stops_within_the_timeout() {
    for extract in [
        "last(range(1e18))",
        "[repeat(1)] | length",
        "1 | until(false; .)",
    ] {
        let enricher = Box::new(LookupEnricher::new(
            "runaway".to_string(),
            EnricherKind::Detection,
            "out".to_string(),
            "intel".to_string(),
            Some(ExtractExpr::Jq(extract.into())),
            None,
            Duration::from_millis(200),
            OnError::Skip,
            Scope::default(),
            cache(),
        )) as Box<dyn Enricher>;
        let pipeline = EnrichmentPipeline::new(vec![enricher], 4);
        let mut results = vec![detection("x")];
        let started = Instant::now();
        pipeline.run(&mut results).await;
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{extract} ran for {:?}",
            started.elapsed()
        );
        assert!(results[0].header.enrichments.is_none(), "{extract}");
    }

    // The runaway programs gave their slots back.
    let enricher = enricher(ExtractExpr::Jq(".records[0].hit".into()));
    let mut result = detection("x");
    enricher.enrich(&mut result).await.unwrap();
    assert_eq!(result.header.enrichments.unwrap()["out"], json!(0));
}
