//! STIX pattern evaluation: `_refs[*]` chains and observation-level `AND`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rstix::Pattern;
use rstix::core::{StixId, StixTimestamp};
use rstix::model::sco::ScoObject;
use rstix::model::{Bundle, StixObject};
use rstix::pattern::{ObservationContext, TimestampedObservation};

fn directory_id(n: usize) -> String {
    format!("directory--00000000-0000-4000-8000-{n:012x}")
}

/// `count` directories, each listing every directory in `contains_refs`.
fn mesh_bundle(count: usize) -> Bundle {
    let refs: Vec<String> = (0..count)
        .map(|n| format!("\"{}\"", directory_id(n)))
        .collect();
    let objects: Vec<String> = (0..count)
        .map(|n| {
            format!(
                r#"{{"type":"directory","spec_version":"2.1","id":"{}","path":"/d{n}","contains_refs":[{}]}}"#,
                directory_id(n),
                refs.join(",")
            )
        })
        .collect();
    Bundle::parse(&format!(
        r#"{{"type":"bundle","id":"bundle--00000000-0000-4000-8000-000000000001","objects":[{}]}}"#,
        objects.join(",")
    ))
    .expect("mesh bundle")
}

fn chained_refs_pattern(depth: usize) -> Pattern {
    let chain = vec!["contains_refs[*]"; depth].join(".");
    Pattern::parse(&format!("[directory:{chain}.path = '/missing']")).expect("chain pattern")
}

fn bench_ref_chains(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_ref_chain");
    group.sample_size(10);
    let bundle = mesh_bundle(4);
    let root_id = StixId::parse(&directory_id(0)).expect("id");
    let Some(StixObject::Sco(root)) = bundle.get(&root_id) else {
        panic!("root directory");
    };
    for depth in [4usize, 8] {
        let pattern = chained_refs_pattern(depth);
        group.bench_with_input(BenchmarkId::new("mesh4", depth), &pattern, |b, pattern| {
            b.iter(|| {
                let matched = pattern
                    .matches_single_with_bundle(black_box(root), Some(&bundle))
                    .expect("eval");
                black_box(matched);
            });
        });
    }
    group.finish();
}

fn ipv4(value: &str, n: usize) -> ScoObject {
    ScoObject::parse_str(&format!(
        r#"{{"type":"ipv4-addr","spec_version":"2.1","id":"ipv4-addr--00000000-0000-4000-8000-{n:012x}","value":"{value}"}}"#
    ))
    .expect("ipv4")
}

/// Left-deep `AND` of `terms` observations whose first term never matches.
fn and_chain(terms: usize) -> Pattern {
    let mut source = String::from("[ipv4-addr:value = '203.0.113.1']");
    for _ in 1..terms {
        source.push_str(" AND [ipv4-addr:value = '198.51.100.3']");
    }
    Pattern::parse(&source).expect("and chain")
}

fn bench_observation_and(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_observation_and");
    group.sample_size(10);
    let at = StixTimestamp::parse("2024-01-01T00:00:00.000Z").expect("ts");
    let scos: Vec<ScoObject> = (0..256).map(|n| ipv4("198.51.100.3", n)).collect();
    for (terms, observations) in [(2usize, 256usize), (6, 6), (8, 6), (256, 256)] {
        let pattern = and_chain(terms);
        let observed: Vec<TimestampedObservation<'_>> = scos[..observations]
            .iter()
            .map(|sco| TimestampedObservation {
                sco,
                at: Some(at.clone()),
            })
            .collect();
        group.bench_with_input(
            BenchmarkId::new(format!("terms{terms}"), observations),
            &observed,
            |b, observed| {
                b.iter(|| {
                    let ctx = ObservationContext::from_scos(observed);
                    black_box(pattern.evaluate(&ctx).expect("eval"));
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_ref_chains, bench_observation_and);
criterion_main!(benches);
