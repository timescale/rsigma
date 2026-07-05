//! OTLP log-decode benchmarks.
//!
//! Measures `logs_request_to_raw_events`, the per-record cost of flattening
//! an OTLP `ExportLogsServiceRequest` (resource attributes, scope metadata,
//! log attributes, body, trace context) into the JSON events the engine
//! evaluates. This is the ingest-side hot path of `--input http` OTLP and
//! gRPC ingestion, downstream of transport and protobuf decoding.
//!
//! Requires `--features otlp`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use opentelemetry_proto::tonic::{
    collector::logs::v1::ExportLogsServiceRequest,
    common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    resource::v1::Resource,
};
use rsigma_runtime::io::otlp::logs_request_to_raw_events;

fn kv(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_string())),
        }),
        ..Default::default()
    }
}

/// A request shaped like a typical collector export: one resource, one scope,
/// `n` log records with a string body, eight log attributes, and trace
/// context.
fn gen_request(n: usize) -> ExportLogsServiceRequest {
    let log_records: Vec<LogRecord> = (0..n)
        .map(|i| LogRecord {
            time_unix_nano: 1_751_712_000_000_000_000 + i as u64,
            observed_time_unix_nano: 1_751_712_000_000_000_100 + i as u64,
            severity_number: 9,
            severity_text: "INFO".to_string(),
            body: Some(AnyValue {
                value: Some(any_value::Value::StringValue(format!(
                    "user user_{} executed process {}",
                    i % 100,
                    i % 7
                ))),
            }),
            attributes: vec![
                kv("event.category", "process"),
                kv("process.command_line", "systeminfo"),
                kv("process.executable", "/usr/bin/systeminfo"),
                kv("user.name", "alice"),
                kv("source.ip", "10.0.0.1"),
                kv("destination.port", "443"),
                kv("host.name", "web01"),
                kv("log.source", "bench"),
            ],
            trace_id: vec![0xab; 16],
            span_id: vec![0xcd; 8],
            ..Default::default()
        })
        .collect();

    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![
                    kv("service.name", "bench-service"),
                    kv("service.version", "1.2.3"),
                    kv("deployment.environment", "prod"),
                    kv("cloud.region", "eu-west-1"),
                ],
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                scope: Some(InstrumentationScope {
                    name: "bench-scope".to_string(),
                    version: "0.1.0".to_string(),
                    ..Default::default()
                }),
                log_records,
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

fn bench_otlp_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("otlp_decode");
    for n_records in [100usize, 1_000, 10_000] {
        let request = gen_request(n_records);
        group.throughput(criterion::Throughput::Elements(n_records as u64));
        group.bench_with_input(
            BenchmarkId::new("records", n_records),
            &request,
            |b, request| {
                b.iter(|| black_box(logs_request_to_raw_events(black_box(request))));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_otlp_decode);
criterion_main!(benches);
