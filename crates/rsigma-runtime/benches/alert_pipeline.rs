//! Alert-pipeline throughput benchmarks.
//!
//! Measures the sink-path overhead of the post-engine layer: dedup folding plus
//! incident grouping over a batch of synthetic detections at varying entity
//! cardinalities (how many distinct fingerprint/group values appear in the
//! batch). Low cardinality is the heavy-fold / single-incident case; high
//! cardinality is the many-distinct-alerts case.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rsigma_eval::{
    DetectionBody, EvaluationResult, FieldMatch, ProcessResult, ResultBody, RuleHeader,
};
use rsigma_parser::Level;
use rsigma_runtime::{AlertPipelineState, NoopMetrics, parse_alert_pipeline_config};

const BATCH: usize = 1_000;

fn detection(ip: &str) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "Brute force".to_string(),
            rule_id: Some("rule-1".to_string()),
            tenant_id: None,
            level: Some(Level::High),
            tags: vec![],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
            ruleset: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec![],
            matched_fields: vec![FieldMatch::new("SourceIp", serde_json::json!(ip))],
            event: None,
        }),
    }
}

/// One result batch (one ProcessResult per synthetic event) cycling through
/// `cardinality` distinct source IPs.
fn batch(cardinality: usize) -> Vec<ProcessResult> {
    (0..BATCH)
        .map(|i| {
            vec![detection(&format!(
                "10.0.{}.{}",
                i % cardinality / 256,
                i % cardinality % 256
            ))]
        })
        .collect()
}

fn bench_alert_pipeline(c: &mut Criterion) {
    let pipeline = parse_alert_pipeline_config(
        "dedup:\n  fingerprint: [rule, match.SourceIp]\n  resolve_timeout: 1h\n\
         group:\n  by: [match.SourceIp]\n  group_wait: 30s\n  resolve_timeout: 1h\n",
    )
    .unwrap();
    let metrics = NoopMetrics;

    let mut group = c.benchmark_group("alert_pipeline_process");
    for &cardinality in &[1usize, 10, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(cardinality),
            &cardinality,
            |b, &cardinality| {
                let batches = batch(cardinality);
                b.iter(|| {
                    // Fresh state per iteration so dedup/grouping does not
                    // accumulate across iterations.
                    let mut state = AlertPipelineState::default();
                    let mut now = 0i64;
                    for b in &batches {
                        now += 1;
                        let kept = pipeline.process(b.clone(), &mut state, now, &metrics);
                        black_box(kept);
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_alert_pipeline);
criterion_main!(benches);
