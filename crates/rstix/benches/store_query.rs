//! `MemoryStore::query` text search over a store of indicators.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rstix::model::Bundle;
use rstix::store::{MemoryStore, StixQuery, StixStore};

fn indicator_bundle(count: usize) -> Bundle {
    let objects: Vec<String> = (0..count)
        .map(|n| {
            format!(
                r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--00000000-0000-4000-8000-{n:012x}","created":"2024-01-01T00:00:00.000Z","modified":"2024-01-01T00:00:00.000Z","name":"indicator {n}","pattern":"[ipv4-addr:value = '10.{}.{}.{}']","pattern_type":"stix","valid_from":"2024-01-01T00:00:00.000Z"}}"#,
                (n >> 16) & 0xff,
                (n >> 8) & 0xff,
                n & 0xff
            )
        })
        .collect();
    Bundle::parse(&format!(
        r#"{{"type":"bundle","id":"bundle--00000000-0000-4000-8000-000000000001","objects":[{}]}}"#,
        objects.join(",")
    ))
    .expect("indicator bundle")
}

fn bench_text_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("store_text_search");
    group.sample_size(20);
    for count in [1_000usize, 10_000] {
        let store = MemoryStore::new();
        store
            .import_objects(indicator_bundle(count).objects())
            .expect("import");
        let match_all = StixQuery::new().text_search("indicator").max_results(1);
        group.bench_with_input(
            BenchmarkId::new("match_all_first_page", count),
            &match_all,
            |b, query| b.iter(|| black_box(store.query(black_box(query)).expect("query"))),
        );
        let one = StixQuery::new().text_search("10.0.0.7'").max_results(1);
        group.bench_with_input(BenchmarkId::new("one_match", count), &one, |b, query| {
            b.iter(|| black_box(store.query(black_box(query)).expect("query")))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_text_search);
criterion_main!(benches);
