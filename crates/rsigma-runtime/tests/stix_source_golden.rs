//! Golden values for `format: stix` file sources.
//!
//! Regenerate after an intentional change:
//!
//! ```sh
//! RSIGMA_UPDATE_GOLDEN=1 cargo test -p rsigma-runtime --features stix-source --test stix_source_golden
//! ```

#![cfg(feature = "stix-source")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rsigma_eval::pipeline::sources::{
    DataFormat, DynamicSource, ErrorPolicy, RefreshPolicy, SourceType, StixOptions,
};
use rsigma_runtime::SourceResolver;
use rsigma_runtime::sources::DefaultSourceResolver;
use rstix::core::StixTimestamp;
use serde_json::Value;

use common::canonical;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/stix-source")
        .join(format!("{name}.json"))
}

fn golden_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/stix-source")
        .join(format!("{name}.json"))
}

fn clock() -> StixTimestamp {
    StixTimestamp::parse("2026-06-01T00:00:00.000Z").unwrap()
}

fn options_for(name: &str) -> StixOptions {
    if name == "selected" {
        StixOptions {
            min_confidence: Some(50),
            observables: vec!["ipv4".to_owned(), "domain".to_owned()],
            max_indicators: 100_000,
        }
    } else if name == "escaped" {
        StixOptions {
            min_confidence: None,
            observables: vec![
                "url".to_owned(),
                "domain".to_owned(),
                "file_name".to_owned(),
            ],
            max_indicators: 100_000,
        }
    } else if name == "mixed" {
        StixOptions {
            min_confidence: None,
            observables: ["ipv4", "ipv4_cidr", "domain", "url", "sha256", "ipv6"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            max_indicators: 100_000,
        }
    } else {
        StixOptions {
            min_confidence: None,
            observables: vec!["ipv4".to_owned(), "domain".to_owned()],
            max_indicators: 100_000,
        }
    }
}

fn check(name: &str, value: &Value) {
    let path = golden_path(name);
    // `preserve_order` is on for some workspace builds and off for others.
    let actual = format!(
        "{}\n",
        serde_json::to_string_pretty(&canonical(value)).unwrap()
    );
    if std::env::var_os("RSIGMA_UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &actual)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
    } else {
        let expected = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
            .replace("\r\n", "\n");
        assert_eq!(actual, expected, "STIX source golden mismatch for '{name}'");
    }
}

async fn resolve(name: &str) -> Value {
    let path = fixture(name);
    let source = DynamicSource {
        id: name.to_owned(),
        source_type: SourceType::File {
            path,
            format: DataFormat::Stix,
            extract: None,
            stix: Some(options_for(name)),
        },
        refresh: RefreshPolicy::OnDemand,
        timeout: Some(Duration::from_secs(5)),
        on_error: ErrorPolicy::Fail,
        required: true,
        default: None,
    };
    DefaultSourceResolver::new()
        .with_stix_clock(clock())
        .resolve(&source)
        .await
        .unwrap_or_else(|err| panic!("resolve {name}: {err}"))
        .data
}

#[tokio::test]
async fn golden_values_match_the_fixed_clock() {
    for name in ["mixed", "lifecycle", "unsupported", "selected", "escaped"] {
        let value = resolve(name).await;
        check(name, &value);
    }
}
