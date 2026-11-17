//! Ruleset fan-out throughput benchmarks.

use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rsigma_eval::{
    Engine, JsonEvent, RuleFieldSet, RulesetEngines, RulesetUnit, SchemaClassifier,
    SchemaPredicate, SchemaSignature, UnitEngine,
};
use rsigma_parser::parse_sigma_yaml;

mod datagen;

fn detection_unit(name: &str, yaml: &str, when: Vec<String>) -> RulesetUnit {
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();
    RulesetUnit {
        name: Arc::from(name),
        when_schemas: when,
        engine: UnitEngine::Detection(Box::new(engine)),
        field_set: RuleFieldSet::collect(&collection, &[], true),
    }
}

fn bench_rulesets(c: &mut Criterion) {
    let mut group = c.benchmark_group("rulesets");
    let rules = datagen::gen_n_rules(1_000);
    let events = datagen::gen_event_values(10_000);
    let refs: Vec<JsonEvent> = events.iter().map(JsonEvent::borrow).collect();
    let event_refs: Vec<&JsonEvent> = refs.iter().collect();

    let mut one =
        RulesetEngines::new(vec![detection_unit("all", &rules, Vec::new())], None).unwrap();
    group.bench_with_input(
        BenchmarkId::new("one_unit", 10_000),
        &event_refs,
        |b, events| b.iter(|| black_box(one.process_batch(events))),
    );

    let mut split = RulesetEngines::new(
        vec![
            detection_unit("a", &datagen::gen_n_rules(334), Vec::new()),
            detection_unit("b", &datagen::gen_n_rules(333), Vec::new()),
            detection_unit("c", &datagen::gen_n_rules(333), Vec::new()),
        ],
        None,
    )
    .unwrap();
    group.bench_with_input(
        BenchmarkId::new("three_units_split", 10_000),
        &event_refs,
        |b, events| b.iter(|| black_box(split.process_batch(events))),
    );

    let mut full = RulesetEngines::new(
        vec![
            detection_unit("a", &rules, Vec::new()),
            detection_unit("b", &rules, Vec::new()),
            detection_unit("c", &rules, Vec::new()),
        ],
        None,
    )
    .unwrap();
    group.bench_with_input(
        BenchmarkId::new("three_units_full", 10_000),
        &event_refs,
        |b, events| b.iter(|| black_box(full.process_batch(events))),
    );

    let classifier = Arc::new(SchemaClassifier::new(vec![SchemaSignature {
        name: "aws_cloudtrail".to_string(),
        predicates: vec![SchemaPredicate::FieldPresent("eventVersion".to_string())],
        specificity: 80,
    }]));
    let mut bound = RulesetEngines::new(
        vec![
            detection_unit("a", &rules, Vec::new()),
            detection_unit("b", &rules, Vec::new()),
            detection_unit("c", &rules, vec!["aws_cloudtrail".to_string()]),
        ],
        Some(classifier),
    )
    .unwrap();
    group.bench_with_input(
        BenchmarkId::new("three_units_when", 10_000),
        &event_refs,
        |b, events| b.iter(|| black_box(bound.process_batch(events))),
    );

    group.finish();
}

criterion_group!(benches, bench_rulesets);
criterion_main!(benches);
