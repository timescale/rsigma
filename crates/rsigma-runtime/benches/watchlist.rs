//! Cost of pushing a large watchlist and rebuilding rules from it.
//!
//! Addresses are synthetic RFC 5737 strings (`192.0.2.<n>`). Placeholder
//! expansion refuses a list longer than 4096 values, so the 10k and 100k
//! rebuilds measure that refusal as well as the successful 1k rebuild.

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use chrono::{TimeZone, Utc};
use criterion::{Criterion, criterion_group, criterion_main};
use rsigma_eval::pipeline::sources::{DynamicSource, ErrorPolicy, RefreshPolicy, SourceType};
use rsigma_eval::{CorrelationConfig, parse_pipeline};
use rsigma_runtime::{
    DefaultSourceResolver, LogProcessor, NoopMetrics, RuntimeEngine, SourceResolver, WatchlistItem,
    WatchlistRegistry,
};

fn address(index: usize) -> String {
    format!("192.0.2.{index}")
}

fn items(count: usize) -> Vec<WatchlistItem> {
    (0..count)
        .map(|index| WatchlistItem::Bare(address(index)))
        .collect()
}

fn registry(max: usize) -> WatchlistRegistry {
    WatchlistRegistry::from_sources(&[DynamicSource {
        id: "c2_ips".into(),
        source_type: SourceType::Watchlist {
            max_indicators: max,
            max_value_length: 64,
            default_ttl: None,
        },
        refresh: RefreshPolicy::Once,
        timeout: None,
        on_error: ErrorPolicy::Fail,
        required: true,
        default: None,
    }])
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
}

fn bench_add(c: &mut Criterion) {
    let batch = items(10_000);
    c.bench_function("watchlist_add_10k", |b| {
        b.iter(|| {
            let set = registry(200_000);
            black_box(set.add("c2_ips", &batch, None, now()).unwrap());
        });
    });
}

fn loaded(count: usize) -> LogProcessor {
    let set = Arc::new(registry(200_000));
    set.add("c2_ips", &items(count), None, now()).unwrap();
    let resolver = DefaultSourceResolver::new().with_watchlists(set);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let source = DynamicSource {
            id: "c2_ips".into(),
            source_type: SourceType::Watchlist {
                max_indicators: 200_000,
                max_value_length: 64,
                default_ttl: None,
            },
            refresh: RefreshPolicy::Once,
            timeout: None,
            on_error: ErrorPolicy::Fail,
            required: true,
            default: None,
        };
        resolver.resolve(&source).await.unwrap();

        let pipeline_yaml = r#"
name: bench-watchlist
priority: 10
vars:
  c2_ips:
    - "${source.c2_ips}"
transformations:
  - type: value_placeholders
"#;
        let rule_yaml = r#"
title: Bench Watchlist
id: 00000000-0000-0000-0000-0000000000b1
logsource:
    product: test
    category: test
detection:
    selection:
        DestinationIp|expand: "%c2_ips%"
    condition: selection
level: high
"#;
        let dir = tempfile::tempdir().unwrap();
        let rule_path = dir.path().join("rule.yml");
        std::fs::write(&rule_path, rule_yaml).unwrap();
        let pipeline = parse_pipeline(pipeline_yaml).unwrap();
        let mut engine = RuntimeEngine::new(
            rule_path,
            vec![pipeline],
            CorrelationConfig::default(),
            false,
        );
        engine.set_source_resolver(Arc::new(resolver));
        engine.set_external_sources(vec![source]);
        engine.load_rules().unwrap();
        std::mem::forget(dir);
        LogProcessor::new(engine, Arc::new(NoopMetrics))
    })
}

fn bench_rebuild(c: &mut Criterion) {
    let mut group = c.benchmark_group("watchlist_rebuild");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(10));
    for count in [1_000, 10_000, 100_000] {
        let processor = loaded(count);
        group.bench_function(format!("{count}"), |b| {
            b.iter(|| black_box(processor.rebuild_from_sources()));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_add, bench_rebuild);
criterion_main!(benches);
