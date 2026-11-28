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

const TOKEN_ENRICHERS_YAML: &str = r#"
enrichers:
  - id: stix_hash
    kind: detection
    type: stix
    inject_field: stix_indicators
    text_search: "${detection.fields.Hash}"
    text_match: token
    type_filter: [indicator]
    max_results: 5
"#;

/// A prefix of the stored indicator hash `644bf17e482f443f763b0b7355b14372`.
const NEW_HASH: &str = "644bf17e482f";
const NEW_INDICATOR_ID: &str = "indicator--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

/// An indicator written to the store after start-up is found once the
/// daemon reloads, and `text_match: token` does not match the stored
/// indicator whose hash only starts with the event's.
#[test]
fn stix_store_reload_picks_up_new_indicators_for_token_searches() {
    let store_dir = tempdir().expect("tempdir");
    seed_store(store_dir.path());
    let rule = temp_file(".yml", HASH_RULE);
    let enrichers = temp_file(".yml", TOKEN_ENRICHERS_YAML);
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let output_path = output_file.path().to_str().unwrap().to_string();
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--stix-store",
        store_dir.path().to_str().unwrap(),
        "--enrichers",
        enrichers.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--output",
        &format!("file://{output_path}"),
    ]);
    let event = serde_json::json!({ "Hash": NEW_HASH }).to_string();
    let lines = || {
        std::fs::read_to_string(&output_path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("NDJSON"))
            .collect::<Vec<_>>()
    };

    let (status, _) = http_post(&daemon.url("/api/v1/events"), &event);
    assert_eq!(status, 200);
    let first = poll_until(Duration::from_secs(5), || lines().into_iter().next())
        .expect("detection never landed in the file sink");
    assert!(
        first.pointer("/enrichments/stix_indicators").is_none(),
        "a token search must not match inside a longer hash: {first}"
    );

    let indicator = rstix::parse_object(&format!(
        r#"{{"type":"indicator","spec_version":"2.1","id":"{NEW_INDICATOR_ID}","created":"2024-01-01T00:00:00.000Z","modified":"2024-01-01T00:00:00.000Z","pattern":"[file:hashes.MD5 = '{NEW_HASH}']","pattern_type":"stix","valid_from":"2024-01-01T00:00:00.000Z"}}"#
    ))
    .expect("indicator");
    FsStore::open(store_dir.path())
        .expect("open store")
        .upsert(&indicator)
        .expect("upsert");
    // 429 means a reload is already pending, which reloads the store too.
    let reload = || {
        let (status, _) = http_post(&daemon.url("/api/v1/reload"), "");
        assert!(matches!(status, 200 | 429), "reload returned {status}");
    };
    reload();

    let enriched = poll_until(Duration::from_secs(10), || {
        reload();
        let (status, _) = http_post(&daemon.url("/api/v1/events"), &event);
        assert_eq!(status, 200);
        lines().into_iter().find_map(|line| {
            let matches = line.pointer("/enrichments/stix_indicators")?.as_array()?;
            Some(matches.iter().map(|m| m["id"].clone()).collect::<Vec<_>>())
        })
    })
    .expect("the reloaded indicator never enriched a detection");
    assert_eq!(enriched, vec![serde_json::json!(NEW_INDICATOR_ID)]);
}
