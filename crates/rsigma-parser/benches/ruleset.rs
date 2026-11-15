//! Ruleset resolution benchmarks.
//!
//! Measures selection, dependency closure, and overlays over in-memory
//! sources at 1,000 and 10,000 detection rules.

#[allow(dead_code)]
mod datagen;

use std::hint::black_box;
use std::path::PathBuf;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use rsigma_parser::ruleset::{
    Candidate, CandidateDoc, InlineOnlyOverlayLoader, LoadedSources, OverlayEntry, OverlayPatch,
    RuleOrigin, RuleSelector, RulesetSpec, resolve_loaded,
};
use rsigma_parser::{Status, parse_sigma_yaml};

fn origin(file: &str, ordinal: usize) -> RuleOrigin {
    RuleOrigin {
        source: 0,
        root: PathBuf::from("."),
        file: PathBuf::from(file),
        ordinal,
    }
}

fn correlation_yaml(index: usize, first: usize, second: usize) -> String {
    format!(
        "title: Bench Correlation {index}\n\
         id: bench-corr-{index:06}\n\
         correlation:\n\
         \x20   type: event_count\n\
         \x20   rules:\n\
         \x20       - bench-rule-{first:06}\n\
         \x20       - bench-rule-{second:06}\n\
         \x20   timespan: 5m\n\
         \x20   condition:\n\
         \x20       gte: 2\n\
         tags:\n\
         \x20   - attack.discovery\n"
    )
}

fn filter_yaml(index: usize, target: usize) -> String {
    format!(
        "title: Bench Filter {index}\n\
         id: bench-filter-{index:06}\n\
         logsource:\n\
         \x20   product: windows\n\
         filter:\n\
         \x20   rules:\n\
         \x20       - bench-rule-{target:06}\n\
         \x20   selection:\n\
         \x20       User: SYSTEM\n\
         \x20   condition: selection\n"
    )
}

fn sources(n: usize) -> LoadedSources {
    let yaml = datagen::gen_n_rules(n);
    let collection = parse_sigma_yaml(&yaml).unwrap();
    let mut candidates = Vec::with_capacity(n + 70);

    for (ordinal, mut rule) in collection.rules.into_iter().enumerate() {
        rule.status = Some(if ordinal % 10 == 0 {
            Status::Deprecated
        } else {
            Status::Stable
        });
        rule.tags.push(if ordinal % 3 == 0 {
            format!("attack.t1059.{:03}", ordinal % 10)
        } else {
            "attack.t1000".to_string()
        });
        candidates.push(Candidate {
            doc: CandidateDoc::Detection(rule),
            origin: origin("rules.yml", ordinal),
        });
    }

    for index in 0..50 {
        let first = index % n;
        let second = (index + 1) % n;
        let yaml = correlation_yaml(index, first, second);
        let rule = parse_sigma_yaml(&yaml)
            .unwrap()
            .correlations
            .into_iter()
            .next()
            .unwrap();
        candidates.push(Candidate {
            doc: CandidateDoc::Correlation(rule),
            origin: origin("correlations.yml", index),
        });
    }

    for index in 0..20 {
        let yaml = filter_yaml(index, index % n);
        let rule = parse_sigma_yaml(&yaml)
            .unwrap()
            .filters
            .into_iter()
            .next()
            .unwrap();
        candidates.push(Candidate {
            doc: CandidateDoc::Filter(rule),
            origin: origin("filters.yml", index),
        });
    }

    LoadedSources {
        candidates,
        ..Default::default()
    }
}

fn no_selectors() -> RulesetSpec {
    RulesetSpec {
        sources: vec![PathBuf::from(".")],
        ..Default::default()
    }
}

fn tag_and_status() -> RulesetSpec {
    RulesetSpec {
        sources: vec![PathBuf::from(".")],
        include: vec![RuleSelector {
            tags: vec!["attack.t1059*".into()],
            ..Default::default()
        }],
        exclude: vec![RuleSelector {
            status: vec!["deprecated".into()],
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// Selects the `attack.t1059*` rules (every third ordinal) and the
/// correlations, pulls in the correlation references the selector misses, and
/// overlays `n` selected rules.
fn overlays(n: usize) -> RulesetSpec {
    let overlays = (0..n)
        .map(|index| OverlayEntry {
            id: Some(format!("bench-rule-{:06}", index * 3)),
            set: Some(OverlayPatch {
                level: Some("high".into()),
                ..Default::default()
            }),
            ..Default::default()
        })
        .collect();
    RulesetSpec {
        sources: vec![PathBuf::from(".")],
        include: vec![RuleSelector {
            tags: vec!["attack.t1059*".into(), "attack.discovery".into()],
            ..Default::default()
        }],
        dependencies: Some("include".into()),
        overlays,
        ..Default::default()
    }
}

type SpecBuilder = fn(usize) -> RulesetSpec;

fn bench_resolution(c: &mut Criterion) {
    let loader = InlineOnlyOverlayLoader;
    let specs: [(&str, SpecBuilder); 3] = [
        ("no_selectors", |_| no_selectors()),
        ("tag_and_status", |_| tag_and_status()),
        ("overlays", |_| overlays(200)),
    ];

    for size in [1_000, 10_000] {
        let loaded = sources(size);
        for (name, build) in specs {
            let spec = build(size);
            c.bench_with_input(
                BenchmarkId::new(name, size),
                &(spec, loaded.clone()),
                |b, (spec, loaded)| {
                    b.iter_batched(
                        || loaded.clone(),
                        |loaded| {
                            let resolved =
                                resolve_loaded("bench", black_box(spec), loaded, &loader).unwrap();
                            black_box(resolved);
                        },
                        BatchSize::LargeInput,
                    );
                },
            );
        }
    }
}

criterion_group!(benches, bench_resolution);
criterion_main!(benches);
