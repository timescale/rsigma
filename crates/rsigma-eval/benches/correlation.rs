//! Correlation engine benchmarks for rsigma-eval.
//!
//! Measures event_count and temporal correlation performance, end-to-end
//! throughput with mixed detection + correlation, state map pressure from
//! many unique group keys, percentile/median checks over large windows, and
//! chained correlations that carry events up the chain.

mod datagen;

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::RngExt;
use rsigma_eval::{
    CorrelationConfig, CorrelationEngine, CorrelationEventMode, JsonEvent, ProcessResultExt,
};
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
        let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

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
                            let result =
                                engine.process_event_at(black_box(event), base_ts + i as i64);
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
        let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

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
                            let result =
                                engine.process_event_at(black_box(event), base_ts + i as i64);
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
        let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

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
                            let result =
                                engine.process_event_at(black_box(event), base_ts + i as i64);
                            det_total += result.detection_count();
                            corr_total += result.correlation_count();
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
// Benchmark: batch correlation (process_batch vs sequential process_event_at)
// ---------------------------------------------------------------------------

fn bench_correlation_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_batch");
    group.sample_size(10);

    let yaml = datagen::gen_rules_with_event_count_correlations(50, 10);
    let collection = parse_sigma_yaml(&yaml).unwrap();

    let n_events = 10_000;
    let event_values = datagen::gen_event_values(n_events);
    let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

    group.throughput(criterion::Throughput::Elements(n_events as u64));

    // Sequential: loop calling process_event_at per event
    group.bench_with_input(
        BenchmarkId::new("mode", "sequential"),
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
                        let result = engine.process_event_at(black_box(event), base_ts + i as i64);
                        black_box(&result);
                    }
                },
            );
        },
    );

    // Batch: process_batch (parallel detection + sequential correlation)
    group.bench_with_input(BenchmarkId::new("mode", "batch"), &events, |b, events| {
        b.iter_with_setup(
            || {
                let mut engine = CorrelationEngine::new(CorrelationConfig::default());
                engine.add_collection(&collection).unwrap();
                engine
            },
            |mut engine| {
                let refs: Vec<&JsonEvent> = events.iter().collect();
                let results = engine.process_batch(black_box(&refs));
                black_box(results);
            },
        );
    });

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
        let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

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
                            let result =
                                engine.process_event_at(black_box(event), base_ts + i as i64);
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
// Benchmark: window modes (sliding vs tumbling vs session)
// ---------------------------------------------------------------------------

fn bench_correlation_window_modes(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_window_modes");
    group.sample_size(20);

    // Identical workload for all three modes: 10k events spread over 1k
    // group keys, one event per group per 10s tick, 1h window. The session
    // gap (10m) exceeds the tick interval so sessions stay open until the
    // timespan cap, matching the sliding window's retention.
    let yaml_for = |window_block: &str| {
        format!(
            r#"
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
title: Window Mode Corr
id: corr-window-001
correlation:
    type: event_count
    rules:
        - bench-base-001
    group-by:
        - User
    timespan: 3600s
{window_block}    condition:
        gte: 1000000
level: high
"#
        )
    };

    let n_events = 10_000usize;
    let n_groups = 1_000usize;
    let event_values: Vec<serde_json::Value> = (0..n_groups)
        .map(|g| {
            serde_json::json!({
                "EventType": "process_create",
                "User": format!("user_{g:04}"),
                "CommandLine": "whoami",
            })
        })
        .collect();
    let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

    for (mode, window_block) in [
        ("sliding", ""),
        ("tumbling", "    window: tumbling\n"),
        ("session", "    window: session\n    gap: 600s\n"),
    ] {
        let yaml = yaml_for(window_block);
        let collection = parse_sigma_yaml(&yaml).unwrap();

        group.throughput(criterion::Throughput::Elements(n_events as u64));

        group.bench_with_input(BenchmarkId::new("mode", mode), &events, |b, events| {
            b.iter_with_setup(
                || {
                    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
                    engine.add_collection(&collection).unwrap();
                    engine
                },
                |mut engine| {
                    let base_ts = 1_000_000i64;
                    for i in 0..n_events {
                        let event = &events[i % n_groups];
                        // One event per group per 10s tick.
                        let ts = base_ts + (i / n_groups) as i64 * 10;
                        let result = engine.process_event_at(black_box(event), ts);
                        black_box(&result);
                    }
                },
            );
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: percentile and median over large windows
// ---------------------------------------------------------------------------

fn bench_correlation_numeric_window(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_numeric_window");
    group.sample_size(20);

    // One group fed one event per second into a sliding window of `size`
    // seconds, so after the warm-up every measured event is checked against
    // a full window of `size` values.
    let yaml_for = |corr_type: &str, size: usize| {
        format!(
            r#"
title: Latency Sample
id: bench-latency-001
logsource:
    product: web
detection:
    selection:
        EventType: 'request'
    condition: selection
level: low
---
title: Latency Window
id: corr-latency-001
correlation:
    type: {corr_type}
    rules:
        - bench-latency-001
    group-by:
        - Host
    timespan: {size}s
    condition:
        field: latency
        percentile: 95
        gte: 1000000000
level: high
"#
        )
    };

    let n_events = 1_000usize;
    let mut rng = datagen::rng();
    let event_values: Vec<serde_json::Value> = (0..n_events)
        .map(|_| {
            serde_json::json!({
                "EventType": "request",
                "Host": "web-01",
                "latency": rng.random_range(0.0..5_000.0),
            })
        })
        .collect();
    let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

    for corr_type in ["value_percentile", "value_median"] {
        for size in [1_000usize, 5_000] {
            let collection = parse_sigma_yaml(&yaml_for(corr_type, size)).unwrap();
            let mut engine = CorrelationEngine::new(CorrelationConfig::default());
            engine.add_collection(&collection).unwrap();
            let mut ts = 1_000_000i64;
            for i in 0..size {
                let _ = engine.process_event_at(&events[i % n_events], ts);
                ts += 1;
            }

            group.throughput(criterion::Throughput::Elements(n_events as u64));
            group.bench_with_input(BenchmarkId::new(corr_type, size), &events, |b, events| {
                b.iter(|| {
                    for event in events {
                        let result = engine.process_event_at(black_box(event), ts);
                        black_box(&result);
                        ts += 1;
                    }
                });
            });
        }
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: tenant-keyed correlation state
// ---------------------------------------------------------------------------

fn bench_correlation_tenants(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_tenants");
    group.sample_size(10);

    let yaml = datagen::gen_rules_with_event_count_correlations(20, 5);
    let collection = parse_sigma_yaml(&yaml).unwrap();
    let event_values = datagen::gen_event_values(1_000);
    let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

    for n_tenants in [1usize, 100, 1_000] {
        let tenants: Vec<Option<rsigma_eval::TenantId>> = (0..events.len())
            .map(|i| Some(rsigma_eval::TenantId::new(&format!("t{}", i % n_tenants)).unwrap()))
            .collect();
        group.throughput(criterion::Throughput::Elements(events.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("tenants", n_tenants),
            &tenants,
            |b, tenants| {
                b.iter_with_setup(
                    || {
                        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
                        engine.add_collection(&collection).unwrap();
                        engine
                    },
                    |mut engine| {
                        let refs: Vec<&JsonEvent> = events.iter().collect();
                        let results =
                            engine.process_batch_for_tenants(black_box(&refs), black_box(tenants));
                        black_box(results);
                    },
                );
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: chained correlations with event retention
// ---------------------------------------------------------------------------

fn bench_correlation_chained_events(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_chained_events");
    group.sample_size(20);

    let yaml = datagen::gen_rules_with_chained_correlations(10);
    let collection = parse_sigma_yaml(&yaml).unwrap();

    let event_values = datagen::gen_event_values(1_000);
    let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

    group.throughput(criterion::Throughput::Elements(1_000));

    for (label, mode) in [
        ("none", CorrelationEventMode::None),
        ("refs", CorrelationEventMode::Refs),
        ("full", CorrelationEventMode::Full),
    ] {
        let config = CorrelationConfig {
            correlation_event_mode: mode,
            ..CorrelationConfig::default()
        };

        group.bench_with_input(BenchmarkId::new("mode", label), &events, |b, events| {
            b.iter_with_setup(
                || {
                    let mut engine = CorrelationEngine::new(config.clone());
                    engine.add_collection(&collection).unwrap();
                    engine
                },
                |mut engine| {
                    let base_ts = 1_000_000i64;
                    for (i, event) in events.iter().enumerate() {
                        let result = engine.process_event_at(black_box(event), base_ts + i as i64);
                        black_box(&result);
                    }
                },
            );
        });
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
    bench_correlation_batch,
    bench_correlation_state_pressure,
    bench_correlation_window_modes,
    bench_correlation_numeric_window,
    bench_correlation_tenants,
    bench_correlation_chained_events,
);
criterion_main!(benches);
