//! Enrichment-pipeline throughput benchmarks.
//!
//! Measures the sink-path overhead of the post-evaluation enrichment stage
//! for the CPU-only `template` primitive (no I/O, the cheapest enricher and
//! the floor cost of running the pipeline at all): template interpolation,
//! kind/scope filtering, semaphore acquisition, and the enrichments-map
//! injection, over a 1,000-result batch with one and four enrichers.
//!
//! `enrichment_lookup_extract` measures a `lookup` enricher whose extract
//! reads an event field, in jq, JSONPath, and CEL, over a 100-result batch.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rsigma_eval::pipeline::sources::ExtractExpr;
use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
use rsigma_parser::Level;
use rsigma_runtime::{
    EnricherKind, EnrichersFile, EnrichmentPipeline, LookupEnricher, OnError, Scope, SourceCache,
    build_enrichers,
};

const BATCH: usize = 1_000;

fn detection(i: usize) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "Suspicious activity".to_string(),
            rule_id: Some(format!("rule-{}", i % 10)),
            tenant_id: None,
            level: Some(Level::High),
            tags: vec!["attack.execution".to_string()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
            ruleset: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![FieldMatch::new(
                "SourceIp",
                serde_json::json!(format!("10.0.0.{}", i % 256)),
            )],
            event: None,
        }),
    }
}

fn pipeline_yaml(n_enrichers: usize) -> String {
    let mut yaml = String::from("enrichers:\n");
    for i in 0..n_enrichers {
        yaml.push_str(&format!(
            "  - id: tpl_{i}\n\
             \x20   kind: detection\n\
             \x20   type: template\n\
             \x20   inject_field: field_{i}\n\
             \x20   template: \"https://wiki.internal/${{detection.rule.id}}/${{detection.fields.SourceIp}}/{i}\"\n"
        ));
    }
    yaml
}

fn bench_enrichment(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("enrichment_template");
    for &n_enrichers in &[1usize, 4] {
        let file: EnrichersFile = yaml_serde::from_str(&pipeline_yaml(n_enrichers)).unwrap();
        let pipeline = build_enrichers(file).unwrap();
        let batch: Vec<EvaluationResult> = (0..BATCH).map(detection).collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(n_enrichers),
            &pipeline,
            |b, pipeline| {
                b.iter(|| {
                    let mut results = batch.clone();
                    rt.block_on(pipeline.run(&mut results));
                    black_box(&results);
                });
            },
        );
    }
    group.finish();
}

fn asset_cache() -> Arc<SourceCache> {
    let assets: Vec<serde_json::Value> = (0..256)
        .map(|i| {
            serde_json::json!({
                "ip": format!("10.0.0.{i}"),
                "host": format!("host-{i}"),
                "owner": "IT-Ops",
            })
        })
        .collect();
    let cache = Arc::new(SourceCache::new());
    cache.store("assets", &serde_json::Value::Array(assets));
    cache
}

/// A `lookup` enricher whose extract reads the detection's `SourceIp`, in
/// each extract language, over a 256-record source.
fn bench_lookup_extract(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let cases = [
        (
            "jq",
            ExtractExpr::Jq(r#".[] | select(.ip == "${detection.fields.SourceIp}")"#.to_string()),
        ),
        (
            "jsonpath",
            ExtractExpr::JsonPath("$[?@.ip == '${detection.fields.SourceIp}']".to_string()),
        ),
        (
            "cel",
            ExtractExpr::Cel("data.filter(x, x.ip == '${detection.fields.SourceIp}')".to_string()),
        ),
    ];

    let mut group = c.benchmark_group("enrichment_lookup_extract");
    group.sample_size(20);
    for (name, extract) in cases {
        let enricher = LookupEnricher::new(
            format!("lookup_{name}"),
            EnricherKind::Detection,
            "asset".to_string(),
            "assets".to_string(),
            Some(extract),
            None,
            Duration::from_secs(5),
            OnError::Skip,
            Scope::default(),
            asset_cache(),
        );
        let pipeline = EnrichmentPipeline::new(vec![Box::new(enricher)], 16);
        let batch: Vec<EvaluationResult> = (0..BATCH / 10).map(detection).collect();
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &pipeline,
            |b, pipeline| {
                b.iter(|| {
                    let mut results = batch.clone();
                    rt.block_on(pipeline.run(&mut results));
                    black_box(&results);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_enrichment, bench_lookup_extract);
criterion_main!(benches);
