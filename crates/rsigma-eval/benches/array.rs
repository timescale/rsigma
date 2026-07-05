//! Array-matching benchmarks (`sigma-version: 3`).
//!
//! Measures the per-event cost of the array evaluation paths against a flat
//! field baseline: implicit any-member matching through arrays of objects,
//! `[any]`/`[all]` object-scope blocks (same-element correlation) at varying
//! array lengths and match positions, and positional indexing. Array-scope
//! bodies are evaluated per member rather than through the batched flat-field
//! matchers, so the cost model (O(members x predicates) per event) is worth
//! pinning down.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rsigma_eval::{Engine, JsonEvent};
use rsigma_parser::parse_sigma_yaml;
use serde_json::{Value, json};

fn make_engine(rule_yaml: &str) -> Engine {
    let collection = parse_sigma_yaml(rule_yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();
    engine
}

/// A `connections` array of `len` members. The member at `match_at` (when in
/// range) is the only one that is both TCP and inside 123.1.0.0/16; every
/// other member fails both predicates.
fn connections_event(len: usize, match_at: Option<usize>) -> Value {
    let members: Vec<Value> = (0..len)
        .map(|i| {
            if Some(i) == match_at {
                json!({"protocol": "TCP", "ip": "123.1.9.9", "port": 443})
            } else {
                json!({"protocol": "UDP", "ip": format!("10.0.{}.{}", i / 256, i % 256), "port": 53})
            }
        })
        .collect();
    json!({"connections": members})
}

const IMPLICIT_ANY_RULE: &str = r#"
title: Implicit any-member
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections.ip: '123.1.9.9'
    condition: selection
"#;

const SCOPE_ANY_RULE: &str = r#"
title: Any-scope same-element
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[any]:
            protocol: 'TCP'
            ip|cidr: '123.1.0.0/16'
    condition: selection
"#;

const SCOPE_ALL_RULE: &str = r#"
title: All-scope
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[all]:
            protocol: 'UDP'
    condition: selection
"#;

/// Flat single-field equivalent of the implicit-any rule, as the baseline the
/// array paths are compared against.
const FLAT_BASELINE_RULE: &str = r#"
title: Flat baseline
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        dst_ip: '123.1.9.9'
    condition: selection
"#;

fn bench_array_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("array_matching");

    // Baseline: one flat field lookup, no arrays anywhere.
    {
        let engine = make_engine(FLAT_BASELINE_RULE);
        let ev = json!({"dst_ip": "123.1.9.9"});
        let event = JsonEvent::borrow(&ev);
        group.bench_function("flat_baseline", |b| {
            b.iter(|| black_box(engine.evaluate(black_box(&event))));
        });
    }

    // Implicit any-member matching through an object array: the matching
    // member is last (full fan-out), or absent (full scan, worst case).
    {
        let engine = make_engine(IMPLICIT_ANY_RULE);
        for len in [10usize, 100, 1000] {
            let hit = connections_event(len, Some(len - 1));
            let miss = connections_event(len, None);
            let hit_event = JsonEvent::borrow(&hit);
            let miss_event = JsonEvent::borrow(&miss);
            group.bench_with_input(
                BenchmarkId::new("implicit_any_hit_last", len),
                &len,
                |b, _| b.iter(|| black_box(engine.evaluate(black_box(&hit_event)))),
            );
            group.bench_with_input(BenchmarkId::new("implicit_any_miss", len), &len, |b, _| {
                b.iter(|| black_box(engine.evaluate(black_box(&miss_event))))
            });
        }
    }

    // [any] object scope (same-element correlation): satisfying member first
    // (early exit), last (full scan), or absent (worst case).
    {
        let engine = make_engine(SCOPE_ANY_RULE);
        for len in [10usize, 100, 1000] {
            for (name, match_at) in [
                ("scope_any_hit_first", Some(0)),
                ("scope_any_hit_last", Some(len - 1)),
                ("scope_any_miss", None),
            ] {
                let ev = connections_event(len, match_at);
                let event = JsonEvent::borrow(&ev);
                group.bench_with_input(BenchmarkId::new(name, len), &len, |b, _| {
                    b.iter(|| black_box(engine.evaluate(black_box(&event))))
                });
            }
        }
    }

    // [all] object scope: every member satisfies (full scan), or the first
    // member already fails (early exit).
    {
        let engine = make_engine(SCOPE_ALL_RULE);
        for len in [10usize, 100, 1000] {
            // All UDP -> every member satisfies the all-scope.
            let all_match = connections_event(len, None);
            // First member TCP -> early mismatch.
            let early_mismatch = connections_event(len, Some(0));
            let all_event = JsonEvent::borrow(&all_match);
            let early_event = JsonEvent::borrow(&early_mismatch);
            group.bench_with_input(BenchmarkId::new("scope_all_match", len), &len, |b, _| {
                b.iter(|| black_box(engine.evaluate(black_box(&all_event))))
            });
            group.bench_with_input(
                BenchmarkId::new("scope_all_early_mismatch", len),
                &len,
                |b, _| b.iter(|| black_box(engine.evaluate(black_box(&early_event)))),
            );
        }
    }

    // Positional indexing: exact index into a long args array. Should be
    // O(1) in the array length.
    {
        let first = make_engine(
            r#"
title: Positional first
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        args[0]: 'powershell.exe'
    condition: selection
"#,
        );
        let last = make_engine(
            r#"
title: Positional last
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        args[-1]: '-enc'
    condition: selection
"#,
        );
        let args: Vec<Value> = std::iter::once(json!("powershell.exe"))
            .chain((0..998).map(|i| json!(format!("-flag{i}"))))
            .chain(std::iter::once(json!("-enc")))
            .collect();
        let ev = json!({"args": args});
        let event = JsonEvent::borrow(&ev);
        group.bench_function("positional_index_0_len1000", |b| {
            b.iter(|| black_box(first.evaluate(black_box(&event))))
        });
        group.bench_function("positional_index_neg1_len1000", |b| {
            b.iter(|| black_box(last.evaluate(black_box(&event))))
        });
    }

    group.finish();
}

criterion_group!(benches, bench_array_matching);
criterion_main!(benches);
