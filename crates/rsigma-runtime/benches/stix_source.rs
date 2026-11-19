//! Parse, lifecycle, and value build for STIX indicator bundles.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rsigma_eval::pipeline::sources::StixOptions;
use rsigma_runtime::sources::stix::build;
use rstix::core::StixTimestamp;

fn bundle(count: usize) -> String {
    let mut objects = String::new();
    for n in 0..count {
        if n > 0 {
            objects.push(',');
        }
        objects.push_str(&format!(
            r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--00000000-0000-4000-8000-{n:012x}","created":"2020-01-01T00:00:00.000Z","modified":"2024-01-01T00:00:00.000Z","pattern":"[domain-name:value = 'n{n}.example']","pattern_type":"stix","valid_from":"2020-01-01T00:00:00.000Z"}}"#
        ));
    }
    format!(
        r#"{{"type":"bundle","id":"bundle--11111111-1111-4111-8111-111111111111","objects":[{objects}]}}"#
    )
}

fn bench_builds(c: &mut Criterion) {
    let now = StixTimestamp::parse("2026-06-01T00:00:00.000Z").unwrap();
    let options = StixOptions::all();
    let mut group = c.benchmark_group("stix_source");
    for count in [10_000, 100_000] {
        let raw = bundle(count);
        group.bench_with_input(BenchmarkId::from_parameter(count), &raw, |b, raw| {
            b.iter(|| {
                let built = build(black_box(raw), &options, &now).expect("bundle");
                black_box(built.value);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_builds);
criterion_main!(benches);
