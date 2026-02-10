//! Correlation engine benchmarks for rsigma-eval.
//!
//! Measures event_count and temporal correlation performance, end-to-end
//! throughput with mixed detection + correlation, and state map pressure
//! from many unique group keys.

mod datagen;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main, black_box};
use rand::Rng;
use rsigma_eval::{CorrelationConfig, CorrelationEngine, Event};
use rsigma_parser::parse_sigma_yaml;

// ---------------------------------------------------------------------------
// Benchmark: event_count correlations
// ---------------------------------------------------------------------------

fn bench_correlation_event_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_event_count");
    group.sample_size(20);

    for n_corr in [5, 10, 20] {
        let yaml = datagen::gen_rules_with_event_count_correlations(20, n_corr);
        let collection = parse_sigma_yaml(&yaml).unwrap();
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.add_collection(&collection).unwrap();

        let event_values = datagen::gen_event_values(1_000);
        let events: Vec<Event> = event_values.iter().map(Event::from_value).collect();

        group.throughput(criterion::Throughput::Elements(1_000));

        group.bench_with_input(
            BenchmarkId::new("corr_rules", n_corr),
            &events,
            |b, events| {
                b.iter_with_setup(
                    || {
                        // Reset engine state each iteration
                        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
                        engine.add_collection(&collection).unwrap();
                        engine
                    },
                    |mut engine| {
                        let base_ts = 1_000_000i64;
                        for (i, event) in events.iter().enumerate() {
                            let result = engine.process_event_at(
                                black_box(event),
                                base_ts + i as i64,
                            );
                            black_box(&result);
                        }
                    },
                );
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: temporal correlations
// ---------------------------------------------------------------------------

fn bench_correlation_temporal(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_temporal");
    group.sample_size(20);

    for n_corr in [3, 5, 10] {
        let yaml = datagen::gen_rules_with_temporal_correlations(10, n_corr);
        let collection = parse_sigma_yaml(&yaml).unwrap();

        let event_values = datagen::gen_event_values(1_000);
        let events: Vec<Event> = event_values.iter().map(Event::from_value).collect();

        group.throughput(criterion::Throughput::Elements(1_000));

        group.bench_with_input(
            BenchmarkId::new("corr_rules", n_corr),
            &events,
            |b, events| {
                b.iter_with_setup(
                    || {
                        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
                        engine.add_collection(&collection).unwrap();
                        engine
                    },
                    |mut engine| {
                        let base_ts = 1_000_000i64;
                        for (i, event) in events.iter().enumerate() {
                            let result = engine.process_event_at(
                                black_box(event),
                                base_ts + i as i64,
                            );
                            black_box(&result);
                        }
                    },
                );
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: end-to-end throughput (detection + correlation)
// ---------------------------------------------------------------------------

fn bench_correlation_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_throughput");
    group.sample_size(10);

    let yaml = datagen::gen_rules_with_event_count_correlations(50, 10);
    let collection = parse_sigma_yaml(&yaml).unwrap();

    for n_events in [10_000, 100_000] {
        let event_values = datagen::gen_event_values(n_events);
        let events: Vec<Event> = event_values.iter().map(Event::from_value).collect();

        group.throughput(criterion::Throughput::Elements(n_events as u64));

        group.bench_with_input(
            BenchmarkId::new("events", n_events),
            &events,
            |b, events| {
                b.iter_with_setup(
                    || {
                        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
                        engine.add_collection(&collection).unwrap();
                        engine
                    },
                    |mut engine| {
                        let base_ts = 1_000_000i64;
                        let mut det_total = 0usize;
                        let mut corr_total = 0usize;
                        for (i, event) in events.iter().enumerate() {
                            let result = engine.process_event_at(
                                black_box(event),
                                base_ts + i as i64,
                            );
                            det_total += result.detections.len();
                            corr_total += result.correlations.len();
                        }
                        black_box((det_total, corr_total));
                    },
                );
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: state pressure (many unique group keys)
// ---------------------------------------------------------------------------

fn bench_correlation_state_pressure(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_state_pressure");
    group.sample_size(10);

    // Use a single event_count correlation with group-by User
    // but generate events with many unique user names.
    let yaml = r#"
title: Base Rule
id: bench-base-001
logsource:
    product: windows
detection:
    selection:
        EventType: 'process_create'
    condition: selection
level: low
---
title: State Pressure Corr
id: corr-pressure-001
correlation:
    type: event_count
    rules:
        - bench-base-001
    group-by:
        - User
    timespan: 3600s
    condition:
        gte: 3
level: high
"#;
    let collection = parse_sigma_yaml(yaml).unwrap();

    for n_unique_keys in [1_000, 10_000, 50_000] {
        // Generate events with unique user names to create many group keys
        let mut rng = datagen::rng();
        let event_values: Vec<serde_json::Value> = (0..n_unique_keys)
            .map(|i| {
                serde_json::json!({
                    "EventType": "process_create",
                    "User": format!("user_{:06}", i),
                    "CommandLine": "whoami",
                    "Image": datagen::IMAGE_PATHS[rng.random_range(0..datagen::IMAGE_PATHS.len())],
                })
            })
            .collect();
        let events: Vec<Event> = event_values.iter().map(Event::from_value).collect();

        group.throughput(criterion::Throughput::Elements(n_unique_keys as u64));

        group.bench_with_input(
            BenchmarkId::new("unique_keys", n_unique_keys),
            &events,
            |b, events| {
                b.iter_with_setup(
                    || {
                        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
                        engine.add_collection(&collection).unwrap();
                        engine
                    },
                    |mut engine| {
                        let base_ts = 1_000_000i64;
                        for (i, event) in events.iter().enumerate() {
                            let result = engine.process_event_at(
                                black_box(event),
                                base_ts + i as i64,
                            );
                            black_box(&result);
                        }
                        black_box(engine.state_count());
                    },
                );
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_correlation_event_count,
    bench_correlation_temporal,
    bench_correlation_throughput,
    bench_correlation_state_pressure,
);
criterion_main!(benches);
