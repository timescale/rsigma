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
        tenants: Vec::new(),
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

    let collection = parse_sigma_yaml(&rules).unwrap();
    let mut plain = Engine::new();
    plain.add_collection(&collection).unwrap();
    group.bench_with_input(
        BenchmarkId::new("plain_engine", 10_000),
        &event_refs,
        |b, events| b.iter(|| black_box(plain.evaluate_batch(events))),
    );

    let mut one =
        RulesetEngines::new(vec![detection_unit("all", &rules, Vec::new())], None).unwrap();
    group.bench_with_input(
        BenchmarkId::new("one_unit", 10_000),
        &event_refs,
        |b, events| b.iter(|| black_box(one.process_batch(events))),
    );

    let docs: Vec<&str> = rules.split("---\n").collect();
    assert_eq!(docs.len(), 1_000);
    let mut split = RulesetEngines::new(
        vec![
            detection_unit("a", &docs[..334].join("---\n"), Vec::new()),
            detection_unit("b", &docs[334..667].join("---\n"), Vec::new()),
            detection_unit("c", &docs[667..].join("---\n"), Vec::new()),
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

    // Every fourth event carries the CloudTrail marker, so the bound unit
    // evaluates a quarter of the stream and skips the rest.
    let mut cloud_events = events.clone();
    for event in cloud_events.iter_mut().step_by(4) {
        event["eventVersion"] = serde_json::json!("1.08");
    }
    let cloud_refs: Vec<JsonEvent> = cloud_events.iter().map(JsonEvent::borrow).collect();
    let cloud_event_refs: Vec<&JsonEvent> = cloud_refs.iter().collect();
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
    bound.process_batch(&cloud_event_refs);
    assert_eq!(bound.skipped_totals()[2].1, 7_500);
    group.bench_with_input(
        BenchmarkId::new("three_units_when", 10_000),
        &cloud_event_refs,
        |b, events| b.iter(|| black_box(bound.process_batch(events))),
    );

    group.finish();
}

criterion_group!(benches, bench_rulesets);
criterion_main!(benches);
