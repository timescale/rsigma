//! Schema-classification benchmarks.
//!
//! Measures the per-event cost of [`SchemaClassifier::classify`] against the
//! built-in signature set, which is the hot-path overhead added by
//! `--schema-routing` and `--observe-schemas`. Covers the early-match case
//! (high-specificity ECS), a mid-list match (flat Sysmon), the worst case
//! (an unknown event that fails every signature), and the ambiguity-aware
//! variant used by the daemon observer.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use rsigma_eval::{JsonEvent, SchemaClassifier};
use serde_json::json;

fn bench_schema_classify(c: &mut Criterion) {
    let classifier = SchemaClassifier::builtin();

    let ecs = json!({
        "ecs.version": "8.11.0",
        "host.os.type": "windows",
        "winlog.event_id": 4624,
        "event.category": "authentication",
        "user.name": "alice",
        "source.ip": "10.0.0.1"
    });
    let sysmon = json!({
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd /c whoami",
        "User": "CORP\\alice"
    });
    let ocsf = json!({
        "class_uid": 1001,
        "metadata.version": "1.1.0",
        "activity_id": 1,
        "severity_id": 2
    });
    // Fails every built-in predicate except the generic_json fallback probes,
    // so the classifier scans the whole signature list.
    let unknown = json!({
        "zz_custom_a": "x",
        "zz_custom_b": 7,
        "zz_custom_c": ["y"],
        "zz_custom_d": {"nested": true}
    });

    let mut group = c.benchmark_group("schema_classify");
    for (name, value) in [
        ("ecs_windows", &ecs),
        ("sysmon_flat", &sysmon),
        ("ocsf", &ocsf),
        ("unknown_full_scan", &unknown),
    ] {
        let event = JsonEvent::borrow(value);
        group.bench_function(name, |b| {
            b.iter(|| black_box(classifier.classify(black_box(&event))));
        });
    }

    let event = JsonEvent::borrow(&ecs);
    group.bench_function("ecs_windows_with_ambiguity", |b| {
        b.iter(|| black_box(classifier.classify_with_ambiguity(black_box(&event))));
    });
    group.finish();
}

criterion_group!(benches, bench_schema_classify);
criterion_main!(benches);
