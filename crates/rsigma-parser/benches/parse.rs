//! Parser benchmarks for rsigma-parser.
//!
//! Measures parsing throughput at various rule counts and condition complexity.

mod datagen;

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use rsigma_parser::parse_sigma_yaml;

// ---------------------------------------------------------------------------
// Benchmark: parse single rule
// ---------------------------------------------------------------------------

fn bench_parse_single_rule(c: &mut Criterion) {
    let yaml = datagen::gen_n_rules(1);

    c.bench_function("parse_single_rule", |b| {
        b.iter(|| {
            let result = parse_sigma_yaml(black_box(&yaml)).unwrap();
            black_box(result);
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: parse N rules (scaling)
// ---------------------------------------------------------------------------

fn bench_parse_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_rules");

    for n in [10, 100, 500, 1000] {
        let yaml = datagen::gen_n_rules(n);
        let yaml_len = yaml.len();

        group.bench_with_input(BenchmarkId::new("count", n), &yaml, |b, yaml| {
            b.iter(|| {
                let result = parse_sigma_yaml(black_box(yaml)).unwrap();
                black_box(result);
            });
        });

        // Also report throughput in bytes
        group.throughput(criterion::Throughput::Bytes(yaml_len as u64));
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: parse complex condition expression
// ---------------------------------------------------------------------------

fn bench_parse_complex_condition(c: &mut Criterion) {
    let yaml = datagen::gen_complex_condition_rule();

    c.bench_function("parse_complex_condition", |b| {
        b.iter(|| {
            let result = parse_sigma_yaml(black_box(&yaml)).unwrap();
            black_box(result);
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: parse wildcard-heavy rules
// ---------------------------------------------------------------------------

fn bench_parse_wildcard_rules(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_wildcard_rules");

    for n in [100, 500, 1000] {
        let yaml = datagen::gen_n_wildcard_rules(n);

        group.bench_with_input(BenchmarkId::new("count", n), &yaml, |b, yaml| {
            b.iter(|| {
                let result = parse_sigma_yaml(black_box(yaml)).unwrap();
                black_box(result);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: parse regex-heavy rules
// ---------------------------------------------------------------------------

fn bench_parse_regex_rules(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_regex_rules");

    for n in [100, 500, 1000] {
        let yaml = datagen::gen_n_regex_rules(n);

        group.bench_with_input(BenchmarkId::new("count", n), &yaml, |b, yaml| {
            b.iter(|| {
                let result = parse_sigma_yaml(black_box(yaml)).unwrap();
                black_box(result);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_parse_single_rule,
    bench_parse_scaling,
    bench_parse_complex_condition,
    bench_parse_wildcard_rules,
    bench_parse_regex_rules,
);
criterion_main!(benches);
