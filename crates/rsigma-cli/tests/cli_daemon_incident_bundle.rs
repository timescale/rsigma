//! E2E tests for `GET /api/v1/incidents/{id}` and `.../bundle`.
//!
//! Spawns a daemon with a grouping alert pipeline, drives a detection through
//! `--input http` until an incident opens, and then exercises the per-incident
//! routes: the raw view, both bundle renderings, and every error path the
//! routes distinguish.

#![cfg(feature = "daemon")]

mod common;

use common::{DaemonProcess, http_get, http_post, poll_until, temp_file};
use std::time::Duration;

/// A documented rule, so the bundle has a full ADS document to carry.
const DOCUMENTED_RULE: &str = r#"
title: Malware sample execution
id: 00000000-0000-0000-0000-0000000000ad
status: test
description: Detects the malware sample marker on a command line.
logsource:
    category: test
    product: test
detection:
    selection:
        CommandLine|contains: "malware"
    condition: selection
level: high
falsepositives:
    - A researcher replaying a sample in a lab
tags:
    - attack.execution
custom_attributes:
    rsigma.ads.strategy: Match the sample marker on process command lines.
    rsigma.ads.technical_context: Requires command-line telemetry.
    rsigma.ads.blind_spots:
        - An obfuscated command line evades the substring match.
    rsigma.ads.validation: Replay the sample and confirm the rule fires.
    rsigma.ads.priority: High because execution is mid-kill-chain.
    rsigma.ads.response:
        - Isolate the host.
"#;

const GROUPING: &str = r#"
group:
  by:
    - match.CommandLine
  group_wait: 0s
  resolve_timeout: 1h
"#;

/// A long `group_wait`, so an incident stays batching for the whole test.
const SLOW_GROUPING: &str = r#"
group:
  by:
    - match.CommandLine
  group_wait: 1h
  resolve_timeout: 2h
"#;

const DEDUP_ONLY: &str = r#"
dedup:
  fingerprint:
    - rule
  repeat_interval: 0
  resolve_timeout: 1h
"#;

/// A spawned daemon plus the temporary files it reads and writes, which must
/// outlive it.
struct Fixture {
    daemon: DaemonProcess,
    _rule: tempfile::NamedTempFile,
    _pipeline: tempfile::NamedTempFile,
    _output: tempfile::NamedTempFile,
}

/// Spawn a daemon with the given alert pipeline.
fn daemon_with(alert_pipeline: &str) -> Fixture {
    let rule = temp_file(".yml", DOCUMENTED_RULE);
    let pipeline = temp_file(".yml", alert_pipeline);
    let output = tempfile::NamedTempFile::new().unwrap();
    let daemon = DaemonProcess::spawn(&[
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--alert-pipeline",
        pipeline.path().to_str().unwrap(),
        "--input",
        "http",
        "--api-addr",
        "127.0.0.1:0",
        "--output",
        &format!("file://{}", output.path().to_str().unwrap()),
    ]);
    Fixture {
        daemon,
        _rule: rule,
        _pipeline: pipeline,
        _output: output,
    }
}

/// Drive one detection and wait for its incident to open.
fn open_incident(daemon: &DaemonProcess) -> String {
    let body = serde_json::to_string(&serde_json::json!({"CommandLine": "malware x"})).unwrap();
    let (status, _) = http_post(&daemon.url("/api/v1/events"), &body);
    assert_eq!(status, 200);

    poll_until(Duration::from_secs(10), || {
        let (status, body) = http_get(&daemon.url("/api/v1/incidents"));
        if status != 200 {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        let incident = v["incidents"].as_array()?.first()?;
        // Only usable once the incident has cleared `group_wait`.
        if incident["bundle_ready"] != serde_json::json!(true) {
            return None;
        }
        Some(incident["incident_id"].as_str()?.to_string())
    })
    .expect("no incident opened within 10s")
}

#[test]
fn the_detail_route_returns_one_incident() {
    let fixture = daemon_with(GROUPING);
    let id = open_incident(&fixture.daemon);

    let (status, body) = http_get(&fixture.daemon.url(&format!("/api/v1/incidents/{id}")));
    assert_eq!(status, 200, "{body}");
    let incident: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(incident["incident_id"], serde_json::json!(id));
    assert_eq!(incident["bundle_ready"], serde_json::json!(true));
    assert_eq!(incident["sample_mode"], serde_json::json!("refs"));
}

#[test]
fn an_unknown_incident_is_not_found() {
    let fixture = daemon_with(GROUPING);
    open_incident(&fixture.daemon);

    for path in ["/api/v1/incidents/nope", "/api/v1/incidents/nope/bundle"] {
        let (status, body) = http_get(&fixture.daemon.url(path));
        assert_eq!(status, 404, "{path}: {body}");
        let error: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(error["incident_id"], serde_json::json!("nope"));
        assert!(error["hint"].as_str().unwrap().contains("resolved"));
    }
}

#[test]
fn the_routes_report_grouping_as_unavailable_rather_than_missing() {
    // Dedup only: the daemon has an alert pipeline but no grouping stage, so
    // there are no incidents to address at all.
    let fixture = daemon_with(DEDUP_ONLY);
    let body = serde_json::to_string(&serde_json::json!({"CommandLine": "malware x"})).unwrap();
    http_post(&fixture.daemon.url("/api/v1/events"), &body);

    for path in ["/api/v1/incidents/any", "/api/v1/incidents/any/bundle"] {
        let (status, body) = http_get(&fixture.daemon.url(path));
        assert_eq!(status, 503, "{path}: {body}");
        let error: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            error["error"],
            serde_json::json!("incident grouping disabled")
        );
    }
}

#[test]
fn the_json_bundle_documents_every_contributing_rule() {
    let fixture = daemon_with(GROUPING);
    let id = open_incident(&fixture.daemon);

    let (status, body) = http_get(
        &fixture
            .daemon
            .url(&format!("/api/v1/incidents/{id}/bundle")),
    );
    assert_eq!(status, 200, "{body}");
    let bundle: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(bundle["schema_version"], serde_json::json!(1));
    assert_eq!(bundle["incident"]["incident_id"], serde_json::json!(id));
    assert!(bundle["generated_at"].as_str().unwrap().ends_with('Z'));

    let rules = bundle["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["resolution"], serde_json::json!("unique"));
    assert_eq!(
        rules[0]["documents"][0]["identity"]["title"],
        serde_json::json!("Malware sample execution")
    );

    // Every ADS section the rule declares is present in the bundle.
    let sections = rules[0]["documents"][0]["ads"]["sections"]
        .as_array()
        .unwrap();
    assert_eq!(sections.len(), 9);
    assert!(
        sections
            .iter()
            .all(|s| s["present"] == serde_json::json!(true)),
        "an ADS section was lost between the rule file and the bundle: {sections:#?}"
    );

    // No risk accumulator is configured, so the bundle says so rather than
    // reporting an empty overlap.
    assert_eq!(bundle["sources"]["risk"], serde_json::json!(false));
    assert!(bundle.get("risk").is_none());
}

#[test]
fn the_markdown_bundle_is_served_as_markdown() {
    let fixture = daemon_with(GROUPING);
    let id = open_incident(&fixture.daemon);

    let url = fixture
        .daemon
        .url(&format!("/api/v1/incidents/{id}/bundle?format=markdown"));
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let response = agent.get(&url).call().unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/markdown; charset=utf-8")
    );

    let body = response.into_body().read_to_string().unwrap();
    assert!(body.starts_with(&format!("# Incident {id}\n")));
    assert!(body.contains("## Contributing rules"));
    assert!(body.contains("Isolate the host."));
}

#[test]
fn a_batching_incident_is_readable_but_not_yet_bundleable() {
    // Inside `group_wait` an incident can still absorb more results, so a
    // bundle taken now could disagree with the one taken after it is first
    // reported. The raw view stays available; only the bundle is withheld.
    let fixture = daemon_with(SLOW_GROUPING);
    let body = serde_json::to_string(&serde_json::json!({"CommandLine": "malware x"})).unwrap();
    assert_eq!(
        http_post(&fixture.daemon.url("/api/v1/events"), &body).0,
        200
    );

    let id = poll_until(Duration::from_secs(10), || {
        let (status, body) = http_get(&fixture.daemon.url("/api/v1/incidents"));
        if status != 200 {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        Some(
            v["incidents"].as_array()?.first()?["incident_id"]
                .as_str()?
                .to_string(),
        )
    })
    .expect("no incident was created within 10s");

    let (status, body) = http_get(&fixture.daemon.url(&format!("/api/v1/incidents/{id}")));
    assert_eq!(status, 200, "{body}");
    let incident: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(incident["bundle_ready"], serde_json::json!(false));

    let (status, body) = http_get(
        &fixture
            .daemon
            .url(&format!("/api/v1/incidents/{id}/bundle")),
    );
    assert_eq!(status, 409, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(error["hint"].as_str().unwrap().contains("group_wait"));
}

#[test]
fn an_unknown_format_is_rejected() {
    let fixture = daemon_with(GROUPING);
    let id = open_incident(&fixture.daemon);

    let (status, body) = http_get(
        &fixture
            .daemon
            .url(&format!("/api/v1/incidents/{id}/bundle?format=pdf")),
    );
    assert_eq!(status, 400, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(error["error"].as_str().unwrap().contains("pdf"));
}
