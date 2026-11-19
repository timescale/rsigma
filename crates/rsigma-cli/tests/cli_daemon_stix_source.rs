//! STIX file sources in the daemon: lifecycle values, rebuild on edit, lookup, metrics.

#![cfg(feature = "daemon")]

mod common;

#[cfg(not(feature = "stix-source"))]
use std::process::{Command, Stdio};
#[cfg(feature = "stix-source")]
use std::time::Duration;

#[cfg(feature = "stix-source")]
use common::{DaemonProcess, http_get, http_post, poll_until, temp_file};
#[cfg(not(feature = "stix-source"))]
use common::{rsigma_bin, temp_file};

const RULE: &str = r#"
title: STIX Destination
id: 00000000-0000-0000-0000-0000000000b1
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        DestinationIp|expand: '%ti_ips%'
    condition: selection
level: high
"#;

const PIPELINE: &str = r#"
name: stix-test
priority: 10
vars:
  ti_ips:
    - "${source.ti_file.ipv4}"
transformations:
  - type: value_placeholders
"#;

#[cfg(feature = "stix-source")]
const ENRICHERS: &str = r#"
enrichers:
  - id: ti_hit
    kind: detection
    type: lookup
    inject_field: ti
    source: ti_file
    extract: '.indicators."${detection.fields.DestinationIp}"'
    extract_type: jq
    default: absent
"#;

fn bundle(ips: &[(&str, u8)]) -> String {
    let objects: Vec<String> = ips
        .iter()
        .map(|(ip, n)| {
            format!(
                r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--00000000-0000-4000-8000-{n:012x}","created":"2020-01-01T00:00:00.000Z","modified":"2024-01-01T00:00:00.000Z","name":"n{n}","pattern":"[ipv4-addr:value = '{ip}']","pattern_type":"stix","valid_from":"2020-01-01T00:00:00.000Z","indicator_types":["malicious-activity"]}}"#
            )
        })
        .collect();
    format!(
        r#"{{"type":"bundle","id":"bundle--11111111-1111-4111-8111-111111111111","objects":[{}]}}"#,
        objects.join(",")
    )
}

#[cfg(feature = "stix-source")]
fn status(daemon: &DaemonProcess) -> serde_json::Value {
    serde_json::from_str(&http_get(&daemon.url("/api/v1/status")).1).expect("status json")
}

#[cfg(all(feature = "daemon", not(feature = "stix-source")))]
#[test]
fn stix_sources_require_the_feature() {
    let bundle_file = temp_file(".json", &bundle(&[("198.51.100.8", 1)]));
    let sources = temp_file(
        ".yml",
        &format!(
            r#"
sources:
  - id: ti_file
    type: file
    path: {}
    format: stix
    refresh: on_demand
"#,
            bundle_file.path().display()
        ),
    );
    let rule = temp_file(".yml", RULE);
    let pipeline = temp_file(".yml", PIPELINE);
    assert_feature_rejection(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "-p",
        pipeline.path().to_str().unwrap(),
        "--source",
        sources.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);

    let taxii = temp_file(
        ".yml",
        r#"
sources:
  - id: ti
    type: taxii
    url: https://taxii.example/api1/
    collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116
    refresh: once
"#,
    );
    assert_feature_rejection(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--source",
        taxii.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
    ]);
}

#[cfg(all(feature = "daemon", not(feature = "stix-source")))]
fn assert_feature_rejection(args: &[&str]) {
    let output = Command::new(rsigma_bin())
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawn rsigma");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(
        stderr.contains("stix-source"),
        "startup error should name the feature: {stderr}"
    );
}

#[cfg(feature = "stix-source")]
#[test]
fn file_source_rebuilds_and_exports_metrics() {
    let bundle_path = temp_file(".json", &bundle(&[("198.51.100.8", 1)]));
    let sources = temp_file(
        ".yml",
        &format!(
            r#"
sources:
  - id: ti_file
    type: file
    path: {}
    format: stix
    refresh: watch
    stix:
      observables: [ipv4]
"#,
            bundle_path.path().display()
        ),
    );
    let rule = temp_file(".yml", RULE);
    let pipeline = temp_file(".yml", PIPELINE);
    let enrichers = temp_file(".yml", ENRICHERS);
    let output = temp_file(".jsonl", "");
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "-p",
        pipeline.path().to_str().unwrap(),
        "--source",
        sources.path().to_str().unwrap(),
        "--enrichers",
        enrichers.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--output",
        &format!("file://{}", output.path().display()),
    ]);

    let event = r#"{"DestinationIp":"198.51.100.7"}"#;
    http_post(&daemon.url("/api/v1/events"), event);
    let before = poll_until(Duration::from_secs(10), || {
        let value = status(&daemon);
        (value["events_processed"].as_u64().unwrap_or(0) >= 1).then_some(value)
    });
    let before = before.expect("event was not processed");
    assert_eq!(before["detection_matches"].as_u64().unwrap_or(0), 0);

    std::fs::write(
        bundle_path.path(),
        bundle(&[("198.51.100.8", 1), ("198.51.100.7", 2)]),
    )
    .unwrap();
    let found = poll_until(Duration::from_secs(15), || {
        let _ = http_post(&daemon.url("/api/v1/events"), event);
        let text = std::fs::read_to_string(output.path()).ok()?;
        text.lines().find_map(|line| {
            let parsed: serde_json::Value = serde_json::from_str(line).ok()?;
            let metadata = &parsed["enrichments"]["ti"];
            metadata
                .as_array()
                .is_some_and(|items| {
                    items
                        .iter()
                        .any(|item| item["id"] == "indicator--00000000-0000-4000-8000-000000000002")
                })
                .then_some(true)
        })
    });
    assert!(
        found.is_some(),
        "lookup did not inject the new indicator:\n{}",
        std::fs::read_to_string(output.path()).unwrap_or_default()
    );

    let metrics = http_get(&daemon.url("/metrics")).1;
    assert!(
        metrics.contains("rsigma_stix_source_indicators{source_id=\"ti_file\"}"),
        "{metrics}"
    );
    assert!(
        metrics.contains("rsigma_stix_source_objects_total{source_id=\"ti_file\"}"),
        "{metrics}"
    );
    assert!(
        metrics
            .contains("rsigma_stix_source_skipped_total{reason=\"revoked\",source_id=\"ti_file\"}"),
        "{metrics}"
    );
}
