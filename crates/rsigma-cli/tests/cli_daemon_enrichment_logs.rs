//! Enrichment miss and failure handling as seen from a running daemon: how
//! misses and failures are logged, and which `rsigma_enrichment_total`
//! status they report.

#![cfg(feature = "mmdb-enrich")]

mod common;

use std::time::Duration;

use common::{DaemonProcess, http_get, http_post, poll_until, temp_file};

const PROBE_RULE: &str = r#"
title: Probe
id: 00000000-0000-0000-0000-0000000000cc
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        EventType: probe
    condition: selection
level: high
"#;

const EVENTS: usize = 200;

fn geo_enrichers_yaml(extra: &str) -> String {
    let db = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rsigma-runtime/tests/fixtures/mmdb/city-test.mmdb");
    format!(
        r#"
enrichers:
  - id: geo
    kind: detection
    type: mmdb
    inject_field: geo
    db_path: {}
    key: "${{detection.fields.SourceIp}}"
{extra}"#,
        db.display()
    )
}

fn spawn(
    rule: &tempfile::NamedTempFile,
    enrichers: &tempfile::NamedTempFile,
    output_path: &str,
) -> DaemonProcess {
    let output = format!("file://{output_path}");
    DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--enrichers",
            enrichers.path().to_str().unwrap(),
            "--output",
            &output,
        ],
    )
}

/// Post `EVENTS` probe events with `source_ip` in one NDJSON request.
fn post_events(daemon: &DaemonProcess, source_ip: &str) {
    let line = serde_json::json!({"EventType": "probe", "SourceIp": source_ip}).to_string();
    let body = vec![line; EVENTS].join("\n");
    let (status, _) = http_post(&daemon.url("/api/v1/events"), &body);
    assert_eq!(status, 200, "POST /api/v1/events did not accept the events");
}

fn wait_for_metric(daemon: &DaemonProcess, line: &str) -> String {
    poll_until(Duration::from_secs(15), || {
        let (_, body) = http_get(&daemon.url("/metrics"));
        body.lines().any(|l| l == line).then_some(body)
    })
    .unwrap_or_else(|| {
        let (_, body) = http_get(&daemon.url("/metrics"));
        panic!("/metrics never reported `{line}`:\n{body}")
    })
}

fn enrichment_total(status: &str, count: usize) -> String {
    format!(
        r#"rsigma_enrichment_total{{enricher_id="geo",kind="detection",status="{status}"}} {count}"#
    )
}

fn failure_warnings(daemon: &DaemonProcess) -> Vec<String> {
    daemon
        .stderr_lines()
        .into_iter()
        .filter(|l| l.contains("Enricher failed"))
        .collect()
}

#[test]
fn misses_are_quiet_and_report_miss() {
    let rule = temp_file(".yml", PROBE_RULE);
    let enrichers = temp_file(".yml", &geo_enrichers_yaml(""));
    let output = tempfile::NamedTempFile::new().unwrap();
    let daemon = spawn(&rule, &enrichers, output.path().to_str().unwrap());

    wait_for_metric(&daemon, &enrichment_total("miss", 0));
    post_events(&daemon, "203.0.113.5");

    wait_for_metric(
        &daemon,
        &format!(r#"rsigma_enrichment_mmdb_misses_total{{enricher_id="geo"}} {EVENTS}"#),
    );
    wait_for_metric(&daemon, &enrichment_total("miss", EVENTS));
    let metrics = wait_for_metric(&daemon, &enrichment_total("skip", 0));
    assert!(
        metrics.lines().any(|l| l == enrichment_total("error", 0)),
        "{metrics}"
    );
    assert_eq!(
        failure_warnings(&daemon),
        Vec::<String>::new(),
        "a miss must not log a warning"
    );
}

#[test]
fn failure_warnings_are_rate_limited() {
    let rule = temp_file(".yml", PROBE_RULE);
    let enrichers = temp_file(".yml", &geo_enrichers_yaml(""));
    let output = tempfile::NamedTempFile::new().unwrap();
    let daemon = spawn(&rule, &enrichers, output.path().to_str().unwrap());

    post_events(&daemon, "not-an-ip");
    wait_for_metric(&daemon, &enrichment_total("skip", EVENTS));

    let warnings = poll_until(Duration::from_secs(5), || {
        let lines = failure_warnings(&daemon);
        (!lines.is_empty()).then_some(lines)
    })
    .expect("a failed enrichment must log a warning");
    assert_eq!(
        warnings.len(),
        1,
        "later failures within the interval fold into the next warning: {warnings:?}"
    );
    let warning: serde_json::Value = serde_json::from_str(&warnings[0]).unwrap();
    assert_eq!(warning["level"], "WARN");
    assert_eq!(warning["fields"]["message"], "Enricher failed, skipping");
    assert_eq!(warning["fields"]["enricher_id"], "geo");
    assert_eq!(warning["fields"]["suppressed"], 0);
    assert!(
        warning["fields"]["error"]
            .as_str()
            .is_some_and(|e| e.contains("is not an IP address")),
        "{warning}"
    );
}

#[test]
fn null_default_covers_a_miss_as_a_success() {
    let rule = temp_file(".yml", PROBE_RULE);
    let enrichers = temp_file(".yml", &geo_enrichers_yaml("    default: null\n"));
    let output = tempfile::NamedTempFile::new().unwrap();
    let output_path = output.path().to_str().unwrap().to_string();
    let daemon = spawn(&rule, &enrichers, &output_path);

    post_events(&daemon, "203.0.113.5");
    wait_for_metric(&daemon, &enrichment_total("success", EVENTS));
    wait_for_metric(&daemon, &enrichment_total("miss", 0));

    let lines = poll_until(Duration::from_secs(5), || {
        let text = std::fs::read_to_string(&output_path).ok()?;
        let lines: Vec<String> = text
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        (lines.len() == EVENTS).then_some(lines)
    })
    .expect("every detection should reach the file sink");
    for line in &lines {
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(
            parsed["enrichments"]
                .as_object()
                .is_some_and(|m| m.get("geo") == Some(&serde_json::Value::Null)),
            "{parsed}"
        );
    }
    assert_eq!(failure_warnings(&daemon), Vec::<String>::new());
}
