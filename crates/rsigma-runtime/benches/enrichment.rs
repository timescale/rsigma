//! Enrichment-pipeline throughput benchmarks.
//!
//! Measures the sink-path overhead of the post-evaluation enrichment stage
//! for the CPU-only `template` primitive (no I/O, the cheapest enricher and
//! the floor cost of running the pipeline at all): template interpolation,
//! kind/scope filtering, semaphore acquisition, and the enrichments-map
//! injection, over a 1,000-result batch with one and four enrichers.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
use rsigma_parser::Level;
use rsigma_runtime::{EnrichersFile, build_enrichers};

const BATCH: usize = 1_000;

fn detection(i: usize) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "Suspicious activity".to_string(),
            rule_id: Some(format!("rule-{}", i % 10)),
            level: Some(Level::High),
            tags: vec!["attack.execution".to_string()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
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

criterion_group!(benches, bench_enrichment);
criterion_main!(benches);
