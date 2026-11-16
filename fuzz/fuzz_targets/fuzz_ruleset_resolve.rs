#![no_main]

use std::path::PathBuf;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rsigma_parser::parse_sigma_yaml;
use rsigma_parser::ruleset::{
    Candidate, CandidateDoc, InlineOnlyOverlayLoader, LoadedSources, OverlayEntry, RuleOrigin,
    RuleSelector, RulesetSpec, resolve_loaded, validate_spec,
};

const WINDOWS: &str = include_str!(
    "../../crates/rsigma-parser/tests/fixtures/ruleset/vendor/windows/proc_creation.yml"
);
const LINUX: &str =
    include_str!("../../crates/rsigma-parser/tests/fixtures/ruleset/vendor/linux/auth.yml");
const CORRELATION: &str =
    include_str!("../../crates/rsigma-parser/tests/fixtures/ruleset/vendor/correlation.yml");
const FILTER: &str =
    include_str!("../../crates/rsigma-parser/tests/fixtures/ruleset/vendor/filter.yml");

fn embedded_sources() -> &'static LoadedSources {
    static SOURCES: OnceLock<LoadedSources> = OnceLock::new();
    SOURCES.get_or_init(|| {
        let mut loaded = LoadedSources::default();
        for (file, text) in [
            ("windows/proc_creation.yml", WINDOWS),
            ("linux/auth.yml", LINUX),
            ("correlation.yml", CORRELATION),
            ("filter.yml", FILTER),
        ] {
            let collection = parse_sigma_yaml(text).expect("embedded fixture parses");
            for (ordinal, rule) in collection.rules.into_iter().enumerate() {
                loaded.candidates.push(Candidate {
                    doc: CandidateDoc::Detection(rule),
                    origin: RuleOrigin {
                        source: 0,
                        root: PathBuf::from("embedded"),
                        file: PathBuf::from(file),
                        ordinal,
                    },
                });
            }
            for (ordinal, rule) in collection.correlations.into_iter().enumerate() {
                loaded.candidates.push(Candidate {
                    doc: CandidateDoc::Correlation(rule),
                    origin: RuleOrigin {
                        source: 0,
                        root: PathBuf::from("embedded"),
                        file: PathBuf::from(file),
                        ordinal,
                    },
                });
            }
            for (ordinal, rule) in collection.filters.into_iter().enumerate() {
                loaded.candidates.push(Candidate {
                    doc: CandidateDoc::Filter(rule),
                    origin: RuleOrigin {
                        source: 0,
                        root: PathBuf::from("embedded"),
                        file: PathBuf::from(file),
                        ordinal,
                    },
                });
            }
        }
        loaded
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };

    let base = RulesetSpec {
        sources: vec![PathBuf::from("embedded")],
        ..Default::default()
    };
    let spec = match mode % 3 {
        0 => match yaml_serde::from_str::<RulesetSpec>(text) {
            Ok(spec) if spec.sources.is_empty() => RulesetSpec {
                sources: base.sources.clone(),
                ..spec
            },
            Ok(spec) => spec,
            Err(_) => return,
        },
        1 => match yaml_serde::from_str::<Vec<OverlayEntry>>(text) {
            Ok(overlays) => RulesetSpec { overlays, ..base },
            Err(_) => return,
        },
        _ => match yaml_serde::from_str::<RuleSelector>(text) {
            Ok(selector) => RulesetSpec {
                include: vec![selector],
                ..base
            },
            Err(_) => return,
        },
    };

    let _ = validate_spec("fuzz", &spec);
    let _ = resolve_loaded(
        "fuzz",
        &spec,
        embedded_sources().clone(),
        &InlineOnlyOverlayLoader,
    );
});
