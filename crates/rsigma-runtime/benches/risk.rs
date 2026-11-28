//! Risk-layer throughput benchmarks.
//!
//! Measures the sink-path overhead of the post-engine risk layer: annotation
//! plus per-entity accumulation over a batch of synthetic detections at varying
//! entity cardinalities (how many distinct entity values appear in the batch).
//! Low cardinality is the hot, single-entity accumulation case; high
//! cardinality exercises the many-distinct-entities store path. The capped
//! groups measure a full entity store taking new entities and one entity
//! taking more contributions than it keeps samples for.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};

use rsigma_eval::{
    DetectionBody, EvaluationResult, FieldMatch, ProcessResult, ResultBody, RuleHeader,
};
use rsigma_parser::Level;
use rsigma_runtime::{NoopMetrics, RiskLayer, RiskState, parse_risk_config};

const BATCH: usize = 1_000;

fn detection(ip: &str, level: Level) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "Suspicious activity".to_string(),
            rule_id: Some("rule-1".to_string()),
            tenant_id: None,
            level: Some(level),
            tags: vec!["attack.execution".to_string()],
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

fn ip(i: usize) -> String {
    format!("10.{}.{}.{}", i / 65_536 % 256, i / 256 % 256, i % 256)
}

/// One result batch (one ProcessResult per synthetic event) cycling through
/// `cardinality` distinct source IPs.
fn batch(cardinality: usize) -> Vec<ProcessResult> {
    (0..BATCH)
        .map(|i| vec![detection(&ip(i % cardinality), Level::High)])
        .collect()
}

fn run(layer: &RiskLayer, state: &mut RiskState, batches: &[ProcessResult], start: i64) {
    let metrics = NoopMetrics;
    let mut now = start;
    for b in batches {
        now += 1;
        let out = layer.process(b.clone(), state, now, &metrics);
        black_box(out);
    }
}

fn bench_risk(c: &mut Criterion) {
    let layer = parse_risk_config(
        "score:\n  level_scores:\n    high: 40\n\
         objects:\n  - type: src_ip\n    selector: match.SourceIp\n\
         incident:\n  score_threshold: 100\n  tactic_count_threshold: 3\n  window: 1h\n",
    )
    .unwrap();

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
                    run(&layer, &mut state, &batches, 0);
                });
            },
        );
    }
    group.finish();
}

fn bench_risk_caps(c: &mut Criterion) {
    let mut group = c.benchmark_group("risk_caps");

    // A store full of low-score entities taking a batch of new ones.
    let capped = parse_risk_config(
        "score:\n  level_scores:\n    low: 1\n    high: 40\n\
         objects:\n  - type: src_ip\n    selector: match.SourceIp\n\
         incident:\n  score_threshold: 100\n  window: 1h\n  caps:\n    max_open_entities: 10000\n",
    )
    .unwrap();
    let fill: Vec<ProcessResult> = (0..10_000)
        .map(|i| vec![detection(&ip(i), Level::Low)])
        .collect();
    let fresh: Vec<ProcessResult> = (0..BATCH)
        .map(|i| vec![detection(&ip(100_000 + i), Level::High)])
        .collect();
    group.bench_function("new_entities_at_cap", |b| {
        b.iter_batched(
            || {
                let mut state = RiskState::default();
                run(&capped, &mut state, &fill, 0);
                state
            },
            |mut state| run(&capped, &mut state, &fresh, 20_000),
            BatchSize::LargeInput,
        );
    });

    // One entity taking ten times more contributions than it keeps samples.
    let deep = parse_risk_config(
        "score:\n  level_scores:\n    low: 1\n    high: 40\n\
         objects:\n  - type: src_ip\n    selector: match.SourceIp\n\
         incident:\n  score_threshold: 1000000000\n  window: 1h\n  caps:\n    max_results_per_incident: 100\n",
    )
    .unwrap();
    let mixed: Vec<ProcessResult> = (0..BATCH)
        .map(|i| {
            let level = if i % 10 == 0 { Level::High } else { Level::Low };
            vec![detection("10.0.0.1", level)]
        })
        .collect();
    group.bench_function("sample_eviction_one_entity", |b| {
        b.iter(|| {
            let mut state = RiskState::default();
            run(&deep, &mut state, &mixed, 0);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_risk, bench_risk_caps);
criterion_main!(benches);
