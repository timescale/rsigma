//! Detection engine benchmarks for rsigma-eval.
//!
//! Measures compilation time, single-event evaluation at various rule counts,
//! throughput with many events, and the cost of different matching strategies.

mod datagen;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main, black_box};
use rsigma_eval::{Engine, Event};
use rsigma_parser::parse_sigma_yaml;

// ---------------------------------------------------------------------------
// Benchmark: compile N rules into an Engine
// ---------------------------------------------------------------------------

fn bench_compile_rules(c: &mut Criterion) {
    let mut group = c.benchmark_group("compile_rules");

    for n in [100, 500, 1000, 5000] {
        let yaml = datagen::gen_n_rules(n);
        let collection = parse_sigma_yaml(&yaml).unwrap();

        group.bench_with_input(
            BenchmarkId::new("count", n),
            &collection,
            |b, collection| {
                b.iter(|| {
                    let mut engine = Engine::new();
                    engine.add_collection(black_box(collection)).unwrap();
                    black_box(&engine);
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: evaluate 1 event against N rules
// ---------------------------------------------------------------------------

fn bench_eval_single_event(c: &mut Criterion) {
    let mut group = c.benchmark_group("eval_single_event");

    let events = datagen::gen_event_values(1);
    let event_val = &events[0];
    let event = Event::from_value(event_val);

    for n in [100, 500, 1000, 5000] {
        let yaml = datagen::gen_n_rules(n);
        let collection = parse_sigma_yaml(&yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();

        group.bench_with_input(
            BenchmarkId::new("rules", n),
            &engine,
            |b, engine| {
                b.iter(|| {
                    let matches = engine.evaluate(black_box(&event));
                    black_box(matches);
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: throughput — many events against a fixed rule set
// ---------------------------------------------------------------------------

fn bench_eval_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("eval_throughput");
    // Reduce sample size since each iteration processes many events
    group.sample_size(20);

    let yaml = datagen::gen_n_rules(100);
    let collection = parse_sigma_yaml(&yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();

    for n_events in [1_000, 10_000, 100_000] {
        let event_values = datagen::gen_event_values(n_events);
        let events: Vec<Event> = event_values.iter().map(Event::from_value).collect();

        group.throughput(criterion::Throughput::Elements(n_events as u64));

        group.bench_with_input(
            BenchmarkId::new("events", n_events),
            &events,
            |b, events| {
                b.iter(|| {
                    let mut total = 0usize;
                    for event in events {
                        total += engine.evaluate(black_box(event)).len();
                    }
                    black_box(total);
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: wildcard-heavy rules
// ---------------------------------------------------------------------------

fn bench_eval_wildcard_heavy(c: &mut Criterion) {
    let mut group = c.benchmark_group("eval_wildcard");

    for n in [100, 500, 1000] {
        let yaml = datagen::gen_n_wildcard_rules(n);
        let collection = parse_sigma_yaml(&yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();

        let event_values = datagen::gen_event_values(100);
        let events: Vec<Event> = event_values.iter().map(Event::from_value).collect();

        group.bench_with_input(
            BenchmarkId::new("rules", n),
            &(&engine, &events),
            |b, (engine, events)| {
                b.iter(|| {
                    let mut total = 0usize;
                    for event in *events {
                        total += engine.evaluate(black_box(event)).len();
                    }
                    black_box(total);
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: regex-heavy rules
// ---------------------------------------------------------------------------

fn bench_eval_regex_heavy(c: &mut Criterion) {
    let mut group = c.benchmark_group("eval_regex");

    for n in [100, 500, 1000] {
        let yaml = datagen::gen_n_regex_rules(n);
        let collection = parse_sigma_yaml(&yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();

        let event_values = datagen::gen_event_values(100);
        let events: Vec<Event> = event_values.iter().map(Event::from_value).collect();

        group.bench_with_input(
            BenchmarkId::new("rules", n),
            &(&engine, &events),
            |b, (engine, events)| {
                b.iter(|| {
                    let mut total = 0usize;
                    for event in *events {
                        total += engine.evaluate(black_box(event)).len();
                    }
                    black_box(total);
                });
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
    bench_compile_rules,
    bench_eval_single_event,
    bench_eval_throughput,
    bench_eval_wildcard_heavy,
    bench_eval_regex_heavy,
);
criterion_main!(benches);
