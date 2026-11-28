//! Bundle parse with many `language-content` objects pointing at one large object.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rstix::model::Bundle;

const TARGET_ID: &str = "identity--00000000-0000-4000-8000-000000000001";

fn language_content_bundle(description_bytes: usize, contents: usize) -> String {
    let mut objects = vec![format!(
        r#"{{"type":"identity","spec_version":"2.1","id":"{TARGET_ID}","created":"2024-01-01T00:00:00.000Z","modified":"2024-01-01T00:00:00.000Z","name":"Large","identity_class":"organization","description":"{}"}}"#,
        "d".repeat(description_bytes)
    )];
    for n in 0..contents {
        objects.push(format!(
            r#"{{"type":"language-content","spec_version":"2.1","id":"language-content--00000000-0000-4000-8000-{n:012x}","created":"2024-01-01T00:00:00.000Z","modified":"2024-01-01T00:00:00.000Z","object_ref":"{TARGET_ID}","contents":{{"de":{{"name":"Gross","description":"Beschreibung"}}}}}}"#
        ));
    }
    format!(
        r#"{{"type":"bundle","id":"bundle--00000000-0000-4000-8000-000000000001","objects":[{}]}}"#,
        objects.join(",")
    )
}

fn bench_language_content(c: &mut Criterion) {
    let mut group = c.benchmark_group("bundle_language_content");
    group.sample_size(10);
    for contents in [10usize, 1_000] {
        let raw = language_content_bundle(1 << 20, contents);
        group.bench_with_input(BenchmarkId::new("1MiB", contents), &raw, |b, raw| {
            b.iter(|| black_box(Bundle::parse(black_box(raw)).expect("bundle")));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_language_content);
criterion_main!(benches);
