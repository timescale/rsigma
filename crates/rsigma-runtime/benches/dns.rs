//! DNS enricher throughput benchmarks.
//!
//! Measures the cost of resolving and injecting answers for a 1,000-result
//! batch against the in-process stub nameserver in `tests/common/dns.rs`. Three
//! cases are covered: a warm positive cache, caching disabled so every result
//! queries the stub over loopback, and NXDOMAIN answers served from a warm
//! negative cache with a configured `default`.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
use rsigma_parser::Level;
use rsigma_runtime::{EnrichersFile, build_enrichers};

#[path = "../tests/common/dns.rs"]
mod dns_stub;

use dns_stub::StubDnsServer;

const BATCH: usize = 1_000;

fn detection(host: String) -> EvaluationResult {
    EvaluationResult {
        header: RuleHeader {
            rule_title: "Suspicious activity".to_string(),
            rule_id: Some("rule-1".to_string()),
            tenant_id: None,
            level: Some(Level::High),
            tags: vec!["attack.execution".to_string()],
            custom_attributes: Arc::new(HashMap::new()),
            enrichments: None,
            ruleset: None,
        },
        body: ResultBody::Detection(DetectionBody {
            matched_selections: vec!["selection".to_string()],
            matched_fields: vec![FieldMatch::new("Host", serde_json::json!(host))],
            event: None,
        }),
    }
}

fn zone_host(i: usize) -> String {
    match i % 3 {
        0 => "host.example.com".to_string(),
        1 => "alias.example.com".to_string(),
        _ => "v4only.example.com".to_string(),
    }
}

fn pipeline_yaml(addr: std::net::SocketAddr, extra: &str) -> String {
    format!(
        r#"
enrichers:
  - id: resolved
    kind: detection
    type: dns
    inject_field: resolved
    record_type: A
    key: "${{detection.fields.Host}}"
    nameservers: ["{addr}"]
{extra}"#
    )
}

fn bench_dns(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let stub = rt.block_on(StubDnsServer::start());
    let addr = stub.addr();

    let hosts: Vec<String> = (0..BATCH).map(zone_host).collect();
    let missing = vec!["missing.example.com".to_string(); BATCH];
    let cases = [
        ("warm_cache", pipeline_yaml(addr, ""), hosts),
        (
            "cache_disabled",
            pipeline_yaml(addr, "    cache_ttl: 0s\n    negative_cache_ttl: 0s\n"),
            (0..BATCH).map(zone_host).collect(),
        ),
        (
            "negative_warm_cache",
            pipeline_yaml(addr, "    default: []\n"),
            missing,
        ),
    ];

    let mut group = c.benchmark_group("dns_enrichment");
    for (name, yaml, hosts) in cases {
        let file: EnrichersFile = yaml_serde::from_str(&yaml).unwrap();
        let pipeline = build_enrichers(file).unwrap();
        let batch: Vec<EvaluationResult> = hosts.into_iter().map(detection).collect();

        if name != "cache_disabled" {
            let mut warm = batch.clone();
            rt.block_on(pipeline.run(&mut warm));
        }

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

criterion_group!(benches, bench_dns);
criterion_main!(benches);
