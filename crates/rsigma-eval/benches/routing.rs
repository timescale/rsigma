//! Schema-routing dispatch benchmarks.
//!
//! Measures the end-to-end per-event overhead of `--schema-routing` beyond
//! bare classification (covered by the `schema` bench): classify, route to
//! the per-schema engine, and evaluate, compared against a single unrouted
//! engine over the same mixed-schema event stream. Pipelines transform rules
//! at engine build time, so the steady-state routing overhead is the
//! classify-plus-dispatch step measured here.

use std::collections::HashMap;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use rsigma_eval::pipeline::builtin::resolve_builtin;
use rsigma_eval::{
    CorrelationConfig, Engine, JsonEvent, MatchDetailLevel, RoutingConfig, RoutingPlan,
    SchemaBinding, SchemaClassifier, SchemaRouter,
};
use rsigma_parser::parse_sigma_yaml;
use serde_json::{Value, json};

const N_RULES: usize = 100;
const N_EVENTS: usize = 1_000;

/// Non-matching detection rules over the fields the events carry.
fn gen_rules(n: usize) -> String {
    let mut docs = Vec::with_capacity(n);
    for i in 0..n {
        docs.push(format!(
            "title: Routing Bench Rule {i}\n\
             id: bench-routing-{i:06}\n\
             logsource:\n\
             \x20   product: windows\n\
             \x20   category: process_creation\n\
             detection:\n\
             \x20   selection:\n\
             \x20       CommandLine|contains: 'needle_{i}_zzzz'\n\
             \x20   condition: selection\n\
             level: low\n"
        ));
    }
    docs.join("---\n")
}

/// Mixed-schema stream: one third ECS, one third flat Sysmon, one third
/// unrecognized, all with benign non-matching command lines.
fn gen_events(n: usize) -> Vec<Value> {
    (0..n)
        .map(|i| match i % 3 {
            0 => json!({
                "ecs.version": "8.11.0",
                "process.command_line": format!("benign activity {i}"),
                "event.category": "process"
            }),
            1 => json!({
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "EventID": 1,
                "CommandLine": format!("benign activity {i}")
            }),
            _ => json!({
                "zz_custom_source": "appliance",
                "zz_message": format!("benign activity {i}")
            }),
        })
        .collect()
}

fn bench_routing(c: &mut Criterion) {
    let collection = parse_sigma_yaml(&gen_rules(N_RULES)).unwrap();
    let values = gen_events(N_EVENTS);
    let events: Vec<JsonEvent> = values.iter().map(JsonEvent::borrow).collect();
    let event_refs: Vec<&JsonEvent> = events.iter().collect();

    let mut group = c.benchmark_group("schema_routing");
    group.throughput(criterion::Throughput::Elements(N_EVENTS as u64));

    // Baseline: one unrouted engine over the whole mixed stream.
    {
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();
        group.bench_function("single_engine", |b| {
            b.iter(|| {
                let mut total = 0usize;
                for event in &events {
                    total += engine.evaluate(black_box(event)).len();
                }
                black_box(total);
            });
        });
    }

    // Routed: classify each event and dispatch to its per-schema engine
    // (ecs and sysmon bound to the corresponding builtin pipelines, unknown
    // events falling through to the pipeline-less default set).
    {
        let config = RoutingConfig {
            on_unknown: Default::default(),
            default_pipelines: vec![],
            aliases: HashMap::new(),
            bindings: vec![
                SchemaBinding {
                    schema: "ecs".to_string(),
                    pipelines: vec!["ecs_windows".to_string()],
                    logsource: None,
                },
                SchemaBinding {
                    schema: "sysmon".to_string(),
                    pipelines: vec!["sysmon".to_string()],
                    logsource: None,
                },
            ],
        };
        let plan = RoutingPlan::from_config(&config);
        let pipeline_sets = plan
            .pipeline_sets()
            .iter()
            .map(|names| {
                names
                    .iter()
                    .map(|name| resolve_builtin(name).expect("builtin pipeline").unwrap())
                    .collect()
            })
            .collect();
        let mut router = SchemaRouter::build(
            &collection,
            SchemaClassifier::builtin(),
            plan,
            pipeline_sets,
            CorrelationConfig::default(),
            false,
            MatchDetailLevel::Off,
            None,
            false,
        )
        .unwrap();

        group.bench_function("routed_per_event", |b| {
            b.iter(|| {
                let mut total = 0usize;
                for event in &events {
                    total += router.route(black_box(event)).results.len();
                }
                black_box(total);
            });
        });

        group.bench_function("routed_batch", |b| {
            b.iter(|| black_box(router.process_batch(black_box(&event_refs))));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_routing);
criterion_main!(benches);
