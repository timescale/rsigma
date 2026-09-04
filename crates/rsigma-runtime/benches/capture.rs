//! Capture-ring overhead on the alert-pipeline sink path.
//!
//! Measures `process_with_capture` at 1/100/1000 open-incident cardinalities
//! so the clone-and-key cost is visible before release.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rsigma_eval::{
    DetectionBody, EvaluationResult, FieldMatch, ProcessResult, ResultBody, RuleHeader,
};
use rsigma_parser::Level;
use rsigma_runtime::{
    AlertPipelineState, CaptureConfig, CaptureRing, CaptureRingSink, NoopMetrics,
    parse_alert_pipeline_config,
};

const BATCH: usize = 200;

fn detection(ip: &str) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "Brute force".to_string(),
            rule_id: Some("rule-1".to_string()),
            level: Some(Level::High),
            tags: vec![],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec![],
            matched_fields: vec![FieldMatch::new("SourceIp", serde_json::json!(ip))],
            event: Some(serde_json::json!({"SourceIp": ip, "raw": "event"})),
        }),
    }
}

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

fn bench_capture(c: &mut Criterion) {
    let pipeline = parse_alert_pipeline_config(
        "dedup:\n  fingerprint: [rule, match.SourceIp]\n  resolve_timeout: 1h\n\
         group:\n  by: [match.SourceIp]\n  group_wait: 30s\n  resolve_timeout: 1h\n",
    )
    .unwrap();
    let metrics = NoopMetrics;

    let mut group = c.benchmark_group("capture_process");
    for &cardinality in &[1usize, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(cardinality),
            &cardinality,
            |b, &cardinality| {
                let batches = batch(cardinality);
                b.iter(|| {
                    let mut state = AlertPipelineState::default();
                    let mut ring = CaptureRing::new(CaptureConfig {
                        max_captured_incidents: 2_000,
                        ..CaptureConfig::default()
                    });
                    let mut now = 0i64;
                    for batch in &batches {
                        now += 1;
                        let mut sink = CaptureRingSink {
                            ring: &mut ring,
                            metrics: &metrics,
                        };
                        let kept = pipeline.process_with_capture(
                            batch.clone(),
                            &mut state,
                            now,
                            &metrics,
                            Some(&mut sink),
                        );
                        black_box(kept);
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_capture);
criterion_main!(benches);
