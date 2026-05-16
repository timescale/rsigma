//! Detection engine benchmarks for rsigma-eval.
//!
//! Measures compilation time, single-event evaluation at various rule counts,
//! throughput with many events, and the cost of different matching strategies.

mod datagen;

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rsigma_eval::{Engine, JsonEvent};
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
// Benchmark: rule load paths at large N
//
// Compares the three engine entry points used by validate / daemon /
// library callers. All three should scale linearly in the rule count;
// `add_collection` and `add_rules` rebuild the inverted and bloom
// indexes once at the end of the batch, while `add_rule` in a loop
// folds each rule incrementally with an amortized-doubling bloom
// rebuild.
// ---------------------------------------------------------------------------

fn bench_rule_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_load");
    // Each iteration builds an engine from scratch, so keep the sample
    // count modest to bound wall-clock time at 100K rules.
    group.sample_size(10);

    for n in [1_000, 10_000, 100_000] {
        let yaml = datagen::gen_n_rules(n);
        let collection = parse_sigma_yaml(&yaml).unwrap();

        group.bench_with_input(
            BenchmarkId::new("add_collection", n),
            &collection,
            |b, collection| {
                b.iter(|| {
                    let mut engine = Engine::new();
                    engine.add_collection(black_box(collection)).unwrap();
                    black_box(&engine);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("add_rules", n),
            &collection,
            |b, collection| {
                b.iter(|| {
                    let mut engine = Engine::new();
                    let errs = engine.add_rules(black_box(&collection.rules));
                    debug_assert!(errs.is_empty());
                    black_box(&engine);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("add_rule_loop", n),
            &collection,
            |b, collection| {
                b.iter(|| {
                    let mut engine = Engine::new();
                    for rule in black_box(&collection.rules) {
                        engine.add_rule(rule).unwrap();
                    }
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
    let event = JsonEvent::borrow(event_val);

    for n in [100, 500, 1000, 5000] {
        let yaml = datagen::gen_n_rules(n);
        let collection = parse_sigma_yaml(&yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();

        group.bench_with_input(BenchmarkId::new("rules", n), &engine, |b, engine| {
            b.iter(|| {
                let matches = engine.evaluate(black_box(&event));
                black_box(matches);
            });
        });
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
        let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

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
        let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

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
// Benchmark: batch parallel evaluation vs sequential
// ---------------------------------------------------------------------------

fn bench_eval_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("eval_batch");
    group.sample_size(20);

    for (n_rules, n_events) in [(100, 1_000), (1000, 1_000), (5000, 1_000)] {
        let yaml = datagen::gen_n_rules(n_rules);
        let collection = parse_sigma_yaml(&yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();

        let event_values = datagen::gen_event_values(n_events);
        let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

        group.throughput(criterion::Throughput::Elements(n_events as u64));

        // Sequential: loop calling evaluate() per event
        let label = format!("{n_rules}r_seq");
        group.bench_with_input(
            BenchmarkId::new("sequential", &label),
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

        // Batch: evaluate_batch() (parallel when feature enabled)
        let label = format!("{n_rules}r_batch");
        group.bench_with_input(BenchmarkId::new("batch", &label), &events, |b, events| {
            b.iter(|| {
                let refs: Vec<&JsonEvent> = events.iter().collect();
                let results = engine.evaluate_batch(black_box(&refs));
                black_box(results);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: contains-heavy rules — N plain |contains needles on CommandLine
// ---------------------------------------------------------------------------

fn bench_eval_contains_heavy(c: &mut Criterion) {
    let mut group = c.benchmark_group("eval_contains_heavy");
    group.sample_size(40);

    let event_values = datagen::gen_event_values(1000);
    let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

    for n_patterns in [5, 10, 20, 50, 100, 200] {
        let yaml = datagen::gen_n_contains_heavy_rules(1, n_patterns);
        let collection = parse_sigma_yaml(&yaml).unwrap();
        let mut engine = rsigma_eval::Engine::new();
        engine.add_collection(&collection).unwrap();

        group.throughput(criterion::Throughput::Elements(events.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("patterns", n_patterns),
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
// Benchmark: AC threshold sweep — find the cross-over between
// AnyOf(Contains) and AhoCorasickSet across haystack lengths.
// ---------------------------------------------------------------------------

fn bench_eval_ac_threshold_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("eval_ac_threshold_sweep");
    group.sample_size(30);

    let mut rng = datagen::rng();
    // Pre-generate one event per haystack length so each pattern-count run
    // sees the same haystack distribution.
    let events_per_len: Vec<(usize, Vec<JsonEvent<'_>>)> = [100usize, 1024, 8 * 1024, 64 * 1024]
        .into_iter()
        .map(|len| {
            let values: Vec<serde_json::Value> = (0..50)
                .map(|_| datagen::gen_event_with_cmdline_len(&mut rng, len))
                .collect();
            (len, values)
        })
        .map(|(len, values)| {
            let leaked: &'static [serde_json::Value] = Box::leak(values.into_boxed_slice());
            let events: Vec<JsonEvent<'_>> = leaked.iter().map(JsonEvent::borrow).collect();
            (len, events)
        })
        .collect();

    for n_patterns in [1usize, 2, 4, 8, 16, 32] {
        let yaml = datagen::gen_n_contains_heavy_rules(1, n_patterns);
        let collection = parse_sigma_yaml(&yaml).unwrap();
        let mut engine = rsigma_eval::Engine::new();
        engine.add_collection(&collection).unwrap();

        for (len, events) in &events_per_len {
            let label = format!("p{n_patterns}_h{len}");
            group.throughput(criterion::Throughput::Elements(events.len() as u64));
            group.bench_with_input(
                BenchmarkId::new("sweep", &label),
                &(&engine, events),
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
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: many wildcard `|contains` patterns on a single field — exercises
// the RegexSet batching path.
// ---------------------------------------------------------------------------

fn bench_eval_regex_set_heavy(c: &mut Criterion) {
    let mut group = c.benchmark_group("eval_regex_set_heavy");
    group.sample_size(40);

    let event_values = datagen::gen_event_values(1000);
    let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

    for n_patterns in [3, 5, 10, 20, 50] {
        let yaml = datagen::gen_n_regex_set_heavy_rules(1, n_patterns);
        let collection = parse_sigma_yaml(&yaml).unwrap();
        let mut engine = rsigma_eval::Engine::new();
        engine.add_collection(&collection).unwrap();

        group.throughput(criterion::Throughput::Elements(events.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("patterns", n_patterns),
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
// Benchmark: bloom rejection — many substring-only rules vs events that
// guaranteed-do-not-match any pattern. Measures the fast-reject path.
// ---------------------------------------------------------------------------

fn bench_eval_bloom_rejection(c: &mut Criterion) {
    let mut group = c.benchmark_group("eval_bloom_rejection");
    group.sample_size(20);

    // 1000 events that contain only digits — guaranteed not to share any
    // trigram with the alphabetical needles in `STRING_VALUES`.
    let event_values = datagen::gen_non_matching_events(1000);
    let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

    for n_rules in [100, 500, 1000, 5000] {
        let yaml = datagen::gen_n_substring_only_rules(n_rules);
        let collection = parse_sigma_yaml(&yaml).unwrap();

        // Default engine: bloom pre-filter off.
        let mut off_engine = rsigma_eval::Engine::new();
        off_engine.add_collection(&collection).unwrap();
        // Bloom-enabled engine: same rules.
        let mut on_engine = rsigma_eval::Engine::new();
        on_engine.add_collection(&collection).unwrap();
        on_engine.set_bloom_prefilter(true);

        group.throughput(criterion::Throughput::Elements(events.len() as u64));

        let off_label = format!("{n_rules}r_bloom_off");
        group.bench_with_input(
            BenchmarkId::new("default", &off_label),
            &(&off_engine, &events),
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

        let on_label = format!("{n_rules}r_bloom_on");
        group.bench_with_input(
            BenchmarkId::new("bloom_prefilter", &on_label),
            &(&on_engine, &events),
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
// Benchmark: cross-rule Aho-Corasick prefilter (daachorse-index feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "daachorse-index")]
fn bench_eval_cross_rule_ac(c: &mut Criterion) {
    let mut group = c.benchmark_group("eval_cross_rule_ac");
    group.sample_size(20);

    // Pure-substring rules amplify the cross-rule index's win because every
    // rule is AC-prunable and shares the same field. Mix non-matching
    // events with a small fraction of matches to model a typical
    // threat-intel deployment where most events are benign.
    let event_values = datagen::gen_non_matching_events(200);
    let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

    for n_rules in [1_000usize, 5_000, 10_000] {
        let yaml = datagen::gen_n_substring_only_rules(n_rules);
        let collection = parse_sigma_yaml(&yaml).unwrap();

        let mut off_engine = Engine::new();
        off_engine.add_collection(&collection).unwrap();

        let mut on_engine = Engine::new();
        on_engine.set_cross_rule_ac(true);
        on_engine.add_collection(&collection).unwrap();

        group.throughput(criterion::Throughput::Elements(events.len() as u64));

        let off_label = format!("{n_rules}r_off");
        group.bench_with_input(
            BenchmarkId::new("default", &off_label),
            &(&off_engine, &events),
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

        let on_label = format!("{n_rules}r_on");
        group.bench_with_input(
            BenchmarkId::new("cross_rule_ac", &on_label),
            &(&on_engine, &events),
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
        let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

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

#[cfg(feature = "daachorse-index")]
criterion_group!(
    benches,
    bench_compile_rules,
    bench_rule_load,
    bench_eval_single_event,
    bench_eval_throughput,
    bench_eval_batch,
    bench_eval_contains_heavy,
    bench_eval_ac_threshold_sweep,
    bench_eval_regex_set_heavy,
    bench_eval_bloom_rejection,
    bench_eval_cross_rule_ac,
    bench_eval_wildcard_heavy,
    bench_eval_regex_heavy,
);

#[cfg(not(feature = "daachorse-index"))]
criterion_group!(
    benches,
    bench_compile_rules,
    bench_rule_load,
    bench_eval_single_event,
    bench_eval_throughput,
    bench_eval_batch,
    bench_eval_contains_heavy,
    bench_eval_ac_threshold_sweep,
    bench_eval_regex_set_heavy,
    bench_eval_bloom_rejection,
    bench_eval_wildcard_heavy,
    bench_eval_regex_heavy,
);
criterion_main!(benches);
