//! E2E test: daemon `--stix-store` + enrichers `type: stix`.

#![cfg(all(feature = "daemon", feature = "stix-enrich"))]

use crate::common;

use common::{DaemonProcess, http_post, poll_until, temp_file};
use rstix::store::{FsStore, StixStore};
use std::time::Duration;
use tempfile::tempdir;

const HASH_RULE: &str = r#"
title: Suspicious hash
id: 00000000-0000-0000-0000-0000000000bb
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Hash|contains: "644bf17e"
    condition: selection
level: high
tags:
    - attack.t1059.001
"#;

const ENRICHERS_YAML: &str = r#"
enrichers:
  - id: stix_hash
    kind: detection
    type: stix
    inject_field: stix_indicators
    text_search: "${detection.fields.Hash}"
    type_filter: [indicator]
    max_results: 1
"#;

fn seed_store(root: &std::path::Path) {
    let bundle = rstix::parse_bundle(include_str!(
        "../../rstix/tests/fixtures/store/multi-indicators.json"
    ))
    .expect("parse bundle");
    let store = FsStore::open(root).expect("open store");
    store.import_bundle(&bundle).expect("import");
}

#[test]
fn stix_store_enricher_injects_indicator_from_local_fs_store() {
    let store_dir = tempdir().expect("tempdir");
    seed_store(store_dir.path());
    assert_store_enriches(store_dir.path());
}

#[test]
fn stix_store_with_a_corrupt_file_still_starts_and_enriches() {
    let store_dir = tempdir().expect("tempdir");
    seed_store(store_dir.path());
    std::fs::write(
        store_dir.path().join("objects").join("corrupt.json"),
        "{not json",
    )
    .expect("write corrupt file");
    assert_store_enriches(store_dir.path());
}

fn assert_store_enriches(store_dir: &std::path::Path) {
    let rule = temp_file(".yml", HASH_RULE);
    let enrichers = temp_file(".yml", ENRICHERS_YAML);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let output_path = output_file.path().to_str().unwrap().to_string();

    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--stix-store",
        store_dir.to_str().unwrap(),
        "--enrichers",
        enrichers.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--output",
        &format!("file://{output_path}"),
    ]);

    let body = serde_json::json!({
        "Hash": "644bf17e482f443f763b0b7355b14372"
    });
    let (status, _) = http_post(
        &daemon.url("/api/v1/events"),
        &serde_json::to_string(&body).unwrap(),
    );
    assert_eq!(status, 200, "POST /api/v1/events did not accept the event");

    let line = poll_until(Duration::from_secs(5), || {
        let bytes = std::fs::read_to_string(&output_path).ok()?;
        bytes.lines().find(|l| !l.is_empty()).map(str::to_string)
    })
    .expect("enriched detection never landed in the file sink within 5s");

    let parsed: serde_json::Value = serde_json::from_str(&line).expect("invalid NDJSON");
    let matches = parsed
        .pointer("/enrichments/stix_indicators")
        .and_then(|v| v.as_array())
        .expect("stix_indicators enrichment");
    assert_eq!(matches.len(), 1);
    assert_eq!(
        matches[0]["id"],
        "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    );
}
