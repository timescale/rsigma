//! Risk-layer throughput benchmarks.
//!
//! Measures the sink-path overhead of the post-engine risk layer: annotation
//! plus per-entity accumulation over a batch of synthetic detections at varying
//! entity cardinalities (how many distinct entity values appear in the batch).
//! Low cardinality is the hot, single-entity accumulation case; high
//! cardinality exercises the many-distinct-entities store path.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rsigma_eval::{
    DetectionBody, EvaluationResult, FieldMatch, ProcessResult, ResultBody, RuleHeader,
};
use rsigma_parser::Level;
use rsigma_runtime::{NoopMetrics, RiskState, parse_risk_config};

const BATCH: usize = 1_000;

fn detection(ip: &str) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "Suspicious activity".to_string(),
            rule_id: Some("rule-1".to_string()),
            level: Some(Level::High),
            tags: vec!["attack.execution".to_string()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
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

fn bench_risk(c: &mut Criterion) {
    let layer = parse_risk_config(
        "score:\n  level_scores:\n    high: 40\n\
         objects:\n  - type: src_ip\n    selector: match.SourceIp\n\
         incident:\n  score_threshold: 100\n  tactic_count_threshold: 3\n  window: 1h\n",
    )
    .unwrap();
    let metrics = NoopMetrics;

    let mut group = c.benchmark_group("risk_process");
    for &cardinality in &[1usize, 10, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(cardinality),
            &cardinality,
            |b, &cardinality| {
                let batches = batch(cardinality);
                b.iter(|| {
                    // Fresh state per iteration so accumulation does not carry
                    // across iterations.
                    let mut state = RiskState::default();
                    let mut now = 0i64;
                    for b in &batches {
                        now += 1;
                        let out = layer.process(b.clone(), &mut state, now, &metrics);
                        black_box(out);
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_risk);
criterion_main!(benches);
