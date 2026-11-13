//! MMDB enricher throughput benchmarks.
//!
//! Measures the cost of looking up and injecting records for a 1,000-result
//! batch whose `SourceIp` cycles through IPv4 and IPv6 hit networks in the
//! synthetic City fixture, plus a batch where every lookup misses and the
//! configured `default` is injected instead. The database is loaded once and
//! shared by the pipeline, so the measurement covers lookup, projection, and
//! injection rather than file I/O.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
use rsigma_parser::Level;
use rsigma_runtime::{EnrichersFile, build_enrichers};

const BATCH: usize = 1_000;

fn detection(ip: String) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "Suspicious activity".to_string(),
            rule_id: Some("rule-1".to_string()),
            level: Some(Level::High),
            tags: vec!["attack.execution".to_string()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![FieldMatch::new("SourceIp", serde_json::json!(ip))],
            event: None,
        }),
    }
}

fn hit_ip(i: usize) -> String {
    let octet = i % 256;
    match i % 4 {
        0 => format!("192.0.2.{octet}"),
        1 => format!("198.51.100.{octet}"),
        2 => format!("2001:db8::{octet:x}"),
        _ => format!("203.0.113.{octet}"),
    }
}

fn miss_ip(i: usize) -> String {
    format!("203.0.113.{}", i % 256)
}

fn fixture_path() -> String {
    format!(
        "{}/tests/fixtures/mmdb/city-test.mmdb",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn pipeline_yaml(fields: &str, default: bool) -> String {
    format!(
        r#"
enrichers:
  - id: geo
    kind: detection
    type: mmdb
    inject_field: geo
    db_path: {}
    key: "${{detection.fields.SourceIp}}"
{fields}{default}"#,
        fixture_path(),
        fields = fields,
        default = if default {
            "    default:\n      country_code: unknown\n"
        } else {
            ""
        }
    )
}

fn bench_mmdb(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let cases = [
        (
            "full_record",
            pipeline_yaml("", false),
            (0..BATCH).map(hit_ip).collect::<Vec<_>>(),
        ),
        (
            "four_field_projection",
            pipeline_yaml(
                "    fields:\n      country: country.iso_code\n      subdivision: subdivisions.0.iso_code\n      latitude: location.latitude\n      city: city.names.en\n",
                false,
            ),
            (0..BATCH).map(hit_ip).collect(),
        ),
        (
            "all_miss_default",
            pipeline_yaml("", true),
            (0..BATCH).map(miss_ip).collect(),
        ),
    ];

    let mut group = c.benchmark_group("mmdb_enrichment");
    for (name, yaml, ips) in cases {
        let file: EnrichersFile = yaml_serde::from_str(&yaml).unwrap();
        let pipeline = build_enrichers(file).unwrap();
        let batch: Vec<EvaluationResult> = ips.into_iter().map(detection).collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &pipeline,
            |b, pipeline| {
                b.iter(|| {
                    let mut results = batch.clone();
                    rt.block_on(pipeline.run(&mut results));
                    black_box(&results);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_mmdb);
criterion_main!(benches);
