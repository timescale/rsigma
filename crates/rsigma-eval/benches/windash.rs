//! `|windash` benchmarks: compiling rules whose values carry several dash
//! characters, and matching events against a set of typical windash rules.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rsigma_eval::{Engine, JsonEvent};
use rsigma_parser::parse_sigma_yaml;
use serde_json::{Value, json};

const DASHES: [char; 5] = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];

/// A command-line fragment with `dashes` flags, each introduced by a
/// different kind of dash.
fn flags(seed: usize, dashes: usize) -> String {
    (0..dashes)
        .map(|i| format!("{}opt{seed}x{i}", DASHES[(seed + i) % DASHES.len()]))
        .collect::<Vec<_>>()
        .join(" ")
}

/// One rule with four `|windash|contains` items of one value each, every
/// value carrying `dashes` dash characters, and a wildcard when asked.
fn heavy_rule(dashes: usize, wildcard: bool) -> String {
    let mut yaml = String::from(
        "title: Heavy Windash\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n",
    );
    for item in 0..4 {
        let value = if wildcard {
            format!("tool{item} * {}", flags(item, dashes))
        } else {
            format!("tool{item} {}", flags(item, dashes))
        };
        yaml.push_str(&format!(
            "    sel{item}:\n        CommandLine|windash|contains: '{value}'\n"
        ));
    }
    yaml.push_str("    condition: 1 of sel*\n");
    yaml
}

/// `n` rules shaped like the windash rules in SigmaHQ: an image suffix and a
/// few command-line flags with one or two dashes each.
fn typical_rules(n: usize) -> String {
    let mut yaml = String::new();
    for i in 0..n {
        if i > 0 {
            yaml.push_str("---\n");
        }
        yaml.push_str(&format!(
            "title: Typical Windash {i}\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    image:\n        Image|endswith: '\\tool{i}.exe'\n    flags:\n        CommandLine|windash|contains:\n            - ' -enc{i} '\n            - ' -ep bypass{i}'\n            - ' -w hidden -nop{i}'\n            - ' /c run{i}'\n    condition: image and flags\n"
        ));
    }
    yaml
}

fn typical_events(n_rules: usize, n_events: usize) -> Vec<Value> {
    (0..n_events)
        .map(|i| {
            let rule = i % n_rules;
            let dash = DASHES[i % DASHES.len()];
            match i % 4 {
                0 => json!({
                    "Image": format!("C:\\Windows\\tool{rule}.exe"),
                    "CommandLine": format!("tool{rule}.exe {dash}w hidden {dash}nop{rule} payload"),
                }),
                1 => json!({
                    "Image": format!("C:\\Windows\\tool{rule}.exe"),
                    "CommandLine": format!("tool{rule}.exe +enc{rule} quiet"),
                }),
                2 => json!({
                    "Image": "C:\\Windows\\System32\\svchost.exe",
                    "CommandLine": format!("svchost.exe {dash}k netsvcs {dash}p"),
                }),
                _ => json!({
                    "Image": format!("C:\\Windows\\tool{rule}.exe"),
                    "CommandLine": format!("cmd.exe {dash}c run{rule} --verbose"),
                }),
            }
        })
        .collect()
}

fn bench_compile(c: &mut Criterion) {
    let mut group = c.benchmark_group("windash_compile");
    group.sample_size(10);
    for wildcard in [false, true] {
        let kind = if wildcard { "wildcard" } else { "plain" };
        for dashes in [1, 2, 3, 4, 5] {
            let collection = parse_sigma_yaml(&heavy_rule(dashes, wildcard)).unwrap();
            assert!(collection.errors().next().is_none());
            group.bench_with_input(
                BenchmarkId::new(kind, format!("dashes={dashes}")),
                &collection,
                |b, collection| {
                    b.iter(|| {
                        let mut engine = Engine::new();
                        engine.add_collection(black_box(collection)).unwrap();
                        black_box(engine);
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_match_heavy(c: &mut Criterion) {
    let mut group = c.benchmark_group("windash_match_heavy");
    for wildcard in [false, true] {
        let kind = if wildcard { "wildcard" } else { "plain" };
        for dashes in [2, 5] {
            let collection = parse_sigma_yaml(&heavy_rule(dashes, wildcard)).unwrap();
            let mut engine = Engine::new();
            engine.add_collection(&collection).unwrap();
            let hit_text = if wildcard {
                format!("run TOOL3 x {} end", flags(3, dashes))
            } else {
                format!("run TOOL3 {} end", flags(3, dashes))
            };
            let hit = json!({ "CommandLine": hit_text });
            let miss = json!({ "CommandLine": hit_text.replace(DASHES, "+") });
            assert_eq!(engine.evaluate(&JsonEvent::borrow(&hit)).len(), 1);
            assert!(engine.evaluate(&JsonEvent::borrow(&miss)).is_empty());
            group.bench_function(BenchmarkId::new(kind, format!("dashes={dashes}")), |b| {
                b.iter(|| {
                    black_box(engine.evaluate(&JsonEvent::borrow(black_box(&hit))));
                    black_box(engine.evaluate(&JsonEvent::borrow(black_box(&miss))));
                });
            });
        }
    }
    group.finish();
}

fn bench_match_typical(c: &mut Criterion) {
    let mut group = c.benchmark_group("windash_match_typical");
    for n_rules in [10, 100] {
        let collection = parse_sigma_yaml(&typical_rules(n_rules)).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();
        let events = typical_events(n_rules, 1_000);
        group.throughput(Throughput::Elements(events.len() as u64));
        group.bench_function(BenchmarkId::new("rules", n_rules), |b| {
            b.iter(|| {
                for event in &events {
                    black_box(engine.evaluate(&JsonEvent::borrow(event)));
                }
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_compile,
    bench_match_heavy,
    bench_match_typical
);
criterion_main!(benches);
