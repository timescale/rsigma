//! Logsource-pruning benchmark.
//!
//! Compares single-event evaluation throughput with the conflict-based
//! logsource extractor off vs on, over an always-evaluated ruleset split
//! evenly across two products. A product-tagged event prunes the
//! conflicting-product half before matching, so the win grows with the
//! fraction of rules that cannot apply.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rsigma_eval::{Engine, JsonEvent, LogSourceExtractor};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

/// Build `n` always-evaluated (`contains`-only) rules, alternating product
/// `windows`/`linux`, each keyed on a distinct non-matching needle so every
/// rule is iterated but none fires.
fn gen_split_product_rules(n: usize) -> String {
    let mut yaml = String::new();
    for i in 0..n {
        let product = if i % 2 == 0 { "windows" } else { "linux" };
        if i > 0 {
            yaml.push_str("---\n");
        }
        yaml.push_str(&format!(
            "title: Rule {i}\n\
             id: bench-ls-{i:06}\n\
             logsource:\n\
             \x20   product: {product}\n\
             detection:\n\
             \x20   selection:\n\
             \x20       CommandLine|contains: 'needle_{i}_zzzz'\n\
             \x20   condition: selection\n\
             level: low\n"
        ));
    }
    yaml
}

fn bench_logsource_pruning(c: &mut Criterion) {
    let mut group = c.benchmark_group("logsource_pruning");

    for n in [1_000, 10_000] {
        let yaml = gen_split_product_rules(n);
        let collection = parse_sigma_yaml(&yaml).unwrap();

        let mut engine_off = Engine::new();
        engine_off.add_collection(&collection).unwrap();

        let mut engine_on = Engine::new();
        engine_on.add_collection(&collection).unwrap();
        engine_on.set_logsource_extractor(Some(LogSourceExtractor::new()));

        // A windows-tagged event matching none of the needles: with pruning
        // on, the linux half of the ruleset is never iterated.
        let ev = json!({"CommandLine": "benign user activity", "product": "windows"});
        let event = JsonEvent::borrow(&ev);

        group.bench_with_input(BenchmarkId::new("off", n), &engine_off, |b, engine| {
            b.iter(|| black_box(engine.evaluate(black_box(&event))));
        });
        group.bench_with_input(BenchmarkId::new("on", n), &engine_on, |b, engine| {
            b.iter(|| black_box(engine.evaluate(black_box(&event))));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_logsource_pruning);
criterion_main!(benches);
