//! Integration tests for the per-sink `?format=` parameter: the channels that
//! accept it, the specs that reject it at startup, the byte-for-byte
//! neutrality of the default NDJSON path, and OCSF output end to end through
//! the daemon.

#![cfg(feature = "daemon")]

mod common;

use std::time::Duration;

use common::{
    DaemonProcess, SIMPLE_RULE, http_post, poll_until, rsigma, temp_file, validate_ocsf_finding,
};
use predicates::str::contains;
use serde_json::Value;

const MATCHING_EVENT: &str = "{\"CommandLine\":\"run malware.exe\"}\n";
const EVENT_BODY: &str = r#"{"CommandLine":"run malware.exe"}"#;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

/// Every parseable JSON line currently in `path`.
fn lines(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

/// Wait for a line in `path` matching `predicate`.
fn wait_for_line(path: &std::path::Path, predicate: impl Fn(&Value) -> bool) -> Option<Value> {
    poll_until(Duration::from_secs(10), || {
        lines(path).into_iter().find(|line| predicate(line))
    })
}

/// Run a stdin-fed daemon with the given extra args and return the assertion.
fn daemon_with(args: &[&str], stdin: &str) -> assert_cmd::assert::Assert {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let mut cmd = rsigma();
    cmd.args([
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--api-addr",
        "127.0.0.1:0",
    ])
    .args(args)
    .timeout(COMMAND_TIMEOUT)
    .write_stdin(stdin.to_string())
    .assert()
}

/// Run a daemon expected to reject its configuration before reading events.
fn daemon_startup_failure(args: &[&str]) -> assert_cmd::assert::Assert {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let mut cmd = rsigma();
    cmd.args([
        "engine",
        "daemon",
        "-r",
        rule.path().to_str().unwrap(),
        "--api-addr",
        "127.0.0.1:0",
    ])
    .args(args)
    .timeout(COMMAND_TIMEOUT)
    .assert()
}

#[test]
fn explicit_ndjson_format_is_accepted_on_a_findings_sink() {
    let out = temp_file(".ndjson", "");
    let spec = format!("file://{}?format=ndjson", out.path().display());
    daemon_with(&["--output", &spec], MATCHING_EVENT).success();

    let written = std::fs::read_to_string(out.path()).unwrap();
    assert!(
        written.contains("Test Rule"),
        "an explicit ndjson sink must still deliver detections: {written}",
    );
}

/// Naming the default must not change it: a spec with no `format` parameter and
/// a spec that names `ndjson` must produce the same bytes.
#[test]
fn explicit_ndjson_matches_the_default_byte_for_byte() {
    let implicit = temp_file(".ndjson", "");
    let explicit = temp_file(".ndjson", "");
    let implicit_spec = format!("file://{}", implicit.path().display());
    let explicit_spec = format!("file://{}?format=ndjson", explicit.path().display());

    daemon_with(&["--output", &implicit_spec], MATCHING_EVENT).success();
    daemon_with(&["--output", &explicit_spec], MATCHING_EVENT).success();

    let implicit = std::fs::read_to_string(implicit.path()).unwrap();
    let explicit = std::fs::read_to_string(explicit.path()).unwrap();
    assert_eq!(
        implicit, explicit,
        "?format=ndjson must be the default path"
    );
    assert!(
        !implicit.is_empty(),
        "the run should have emitted a finding"
    );
}

#[test]
fn unknown_format_value_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!("file://{}?format=bogus", out.path().display());
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("Unknown sink format"));
}

#[test]
fn bare_format_parameter_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!("file://{}?format", out.path().display());
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("Unknown sink format"));
}

#[test]
fn duplicate_format_parameter_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!("file://{}?format=ndjson&format=ocsf", out.path().display());
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("may be specified only once"));
}

#[test]
fn unknown_ocsf_version_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!(
        "file://{}?format=ocsf&ocsf_version=9.9.9",
        out.path().display()
    );
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("Invalid ocsf_version"));
}

#[test]
fn ocsf_version_without_ocsf_format_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!(
        "file://{}?format=ndjson&ocsf_version=1.3.0",
        out.path().display()
    );
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("only valid with format=ocsf"));
}

#[test]
fn duplicate_ocsf_version_parameter_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!(
        "file://{}?format=ocsf&ocsf_version=1.1.0&ocsf_version=1.3.0",
        out.path().display()
    );
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("ocsf_version= may be specified only once"));
}

#[test]
fn unknown_ocsf_incident_class_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!(
        "file://{}?format=ocsf&ocsf_incident_class=2003",
        out.path().display()
    );
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("Invalid ocsf_incident_class"));
}

#[test]
fn ocsf_incident_class_without_ocsf_format_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!("file://{}?ocsf_incident_class=2005", out.path().display());
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains(
            "ocsf_incident_class= is only valid with format=ocsf",
        ));
}

#[test]
fn duplicate_ocsf_incident_class_parameter_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!(
        "file://{}?format=ocsf&ocsf_incident_class=2004&ocsf_incident_class=2005",
        out.path().display()
    );
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("ocsf_incident_class= may be specified only once"));
}

#[test]
fn class_2005_without_assignee_group_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!(
        "file://{}?format=ocsf&ocsf_incident_class=2005",
        out.path().display()
    );
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains(
            "ocsf_incident_class=2005 requires ocsf_assignee_group=<name>",
        ));
}

#[test]
fn assignee_group_without_class_2005_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!(
        "file://{}?format=ocsf&ocsf_assignee_group=soc",
        out.path().display()
    );
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains(
            "ocsf_assignee_group= is only valid with ocsf_incident_class=2005",
        ));
}

#[test]
fn empty_assignee_group_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let spec = format!(
        "file://{}?format=ocsf&ocsf_incident_class=2005&ocsf_assignee_group=   ",
        out.path().display()
    );
    daemon_startup_failure(&["--output", &spec])
        .failure()
        .stderr(contains("ocsf_assignee_group= must not be empty"));
}

#[cfg(feature = "daemon-otlp")]
#[test]
fn unknown_format_on_an_otlp_sink_is_a_startup_error() {
    daemon_startup_failure(&["--output", "otlphttp://127.0.0.1:1?format=cef"])
        .failure()
        .stderr(contains("Unknown sink format"));
}

#[cfg(feature = "daemon-otlp")]
#[test]
fn ocsf_incident_class_on_an_otlp_sink_is_a_startup_error() {
    daemon_startup_failure(&[
        "--output",
        "otlphttp://127.0.0.1:1?format=ocsf&ocsf_incident_class=2005",
    ])
    .failure()
    .stderr(contains(
        "ocsf_incident_class= and ocsf_assignee_group= are not supported on OTLP sinks",
    ));
}

#[cfg(feature = "daemon-otlp")]
#[test]
fn ocsf_assignee_group_on_an_otlp_sink_is_a_startup_error() {
    daemon_startup_failure(&[
        "--output",
        "otlphttp://127.0.0.1:1?format=ocsf&ocsf_assignee_group=soc",
    ])
    .failure()
    .stderr(contains(
        "ocsf_incident_class= and ocsf_assignee_group= are not supported on OTLP sinks",
    ));
}

#[cfg(feature = "daemon-otlp")]
#[test]
fn ocsf_version_on_an_ndjson_otlp_sink_is_a_startup_error() {
    daemon_startup_failure(&[
        "--output",
        "otlphttp://127.0.0.1:1?format=ndjson&ocsf_version=1.3.0",
    ])
    .failure()
    .stderr(contains("ocsf_version= is only valid with format=ocsf"));
}

#[test]
fn format_on_the_dlq_spec_is_a_startup_error() {
    let out = temp_file(".ndjson", "");
    let dlq = temp_file(".ndjson", "");
    let out_spec = format!("file://{}", out.path().display());
    let dlq_spec = format!("file://{}?format=ndjson", dlq.path().display());
    daemon_startup_failure(&["--output", &out_spec, "--dlq", &dlq_spec])
        .failure()
        .stderr(contains("only supported on findings sinks"));
}

#[test]
fn format_on_the_audit_sink_spec_is_a_startup_error() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");
    let audit_out = dir.path().join("audit.ndjson");
    let audit_spec = format!("file://{}?format=ndjson", audit_out.display());
    let audit_spec = format!("'{}'", audit_spec.replace('\'', "''"));
    let config = temp_file(
        ".yaml",
        &format!("daemon:\n  api:\n    audit:\n      enabled: true\n      sink: {audit_spec}\n"),
    );

    daemon_startup_failure(&[
        "--config",
        config.path().to_str().unwrap(),
        "--state-db",
        db.to_str().unwrap(),
    ])
    .failure()
    .stderr(contains("only supported on findings sinks"));
}

/// Lower an OTLP `AnyValue` back to JSON, the inverse of the sink's encoding.
#[cfg(feature = "daemon-otlp")]
fn any_value_json(value: &opentelemetry_proto::tonic::common::v1::AnyValue) -> Value {
    use opentelemetry_proto::tonic::common::v1::any_value::Value as V;
    match &value.value {
        Some(V::StringValue(s)) => Value::from(s.clone()),
        Some(V::BoolValue(b)) => Value::from(*b),
        Some(V::IntValue(i)) => Value::from(*i),
        Some(V::DoubleValue(d)) => Value::from(*d),
        Some(V::ArrayValue(a)) => Value::Array(a.values.iter().map(any_value_json).collect()),
        Some(V::KvlistValue(kv)) => Value::Object(
            kv.values
                .iter()
                .filter_map(|kv| Some((kv.key.clone(), any_value_json(kv.value.as_ref()?))))
                .collect(),
        ),
        _ => Value::Null,
    }
}

/// An OTLP sink with `format=ocsf` exports the OCSF finding as a JSON string
/// in the log-record body, with the same identity an OCSF line sink gets for
/// the same detection.
#[cfg(feature = "daemon-otlp")]
#[test]
fn ocsf_otlp_sink_exports_the_finding_as_the_log_body() {
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use prost::Message;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let collector = rt.block_on(async {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/logs"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        server
    });

    let rule = temp_file(".yml", SIMPLE_RULE);
    let ocsf = temp_file(".ndjson", "");
    let ocsf_spec = format!("file://{}?format=ocsf", ocsf.path().display());
    let otlp_spec = format!(
        "otlphttp://{}?format=ocsf&ocsf_version=1.3.0",
        collector.address()
    );
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--output", &ocsf_spec, "--output", &otlp_spec],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), EVENT_BODY);
    assert_eq!(status, 200);

    let line = wait_for_line(ocsf.path(), |line| line["class_uid"] == 2004)
        .expect("the OCSF line sink never received the finding");
    let request = poll_until(Duration::from_secs(10), || {
        let received = rt.block_on(collector.received_requests())?;
        let body = &received.first()?.body;
        Some(ExportLogsServiceRequest::decode(body.as_slice()).unwrap())
    })
    .expect("the collector never received an export");

    let record = &request.resource_logs[0].scope_logs[0].log_records[0];
    assert_eq!(
        record.severity_text, "ERROR",
        "severity still follows the level"
    );
    assert!(
        record.attributes.iter().any(|kv| kv.key == "rule_title"),
        "native attributes stay on the OCSF record: {:?}",
        record.attributes,
    );
    let encoded = any_value_json(record.body.as_ref().expect("a log body"));
    let raw = encoded
        .as_str()
        .expect("the OCSF body is a JSON string, not a kvlist");
    let finding: Value = serde_json::from_str(raw).expect("the OCSF body parses");
    validate_ocsf_finding(&finding);
    assert_eq!(finding["class_uid"], 2004);
    assert_eq!(finding["metadata"]["version"], "1.3.0");
    assert_eq!(finding["finding_info"]["analytic"]["uid"], SIMPLE_RULE_ID);
    assert_eq!(
        finding["finding_info"]["uid"], line["finding_info"]["uid"],
        "OTLP and line sinks share the finding identity",
    );
    assert_eq!(finding["time"], line["time"]);
}

/// Two sinks on one daemon, one OCSF and one default: each gets its own
/// serialization of the same detection.
#[test]
fn mixed_format_fan_out_serializes_per_sink() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let native = temp_file(".ndjson", "");
    let ocsf = temp_file(".ndjson", "");
    let native_spec = format!("file://{}", native.path().display());
    let ocsf_spec = format!("file://{}?format=ocsf", ocsf.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--output", &native_spec, "--output", &ocsf_spec],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), EVENT_BODY);
    assert_eq!(status, 200);

    let finding = wait_for_line(ocsf.path(), |line| line["class_uid"] == 2004)
        .expect("the OCSF sink never received a class-2004 finding");
    assert_eq!(finding["action_id"], 0);
    assert_eq!(finding["type_uid"], 200401);
    assert_eq!(finding["finding_info"]["title"], "Test Rule");
    assert_eq!(finding["finding_info"]["analytic"]["uid"], SIMPLE_RULE_ID);
    assert_eq!(finding["severity"], "High");
    assert_eq!(finding["metadata"]["version"], "1.1.0");
    assert_eq!(
        finding["unmapped"]["matched_selections"],
        serde_json::json!(["selection"])
    );

    let native = wait_for_line(native.path(), |line| line["rule_title"] == "Test Rule")
        .expect("the default sink never received the native line");
    assert!(
        native.get("class_uid").is_none(),
        "the default sink must be untouched by the OCSF sibling: {native}",
    );
}

#[test]
fn ocsf_fan_out_preserves_finding_identity_and_time() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let first = temp_file(".ndjson", "");
    let second = temp_file(".ndjson", "");
    let first_spec = format!("file://{}?format=ocsf", first.path().display());
    let second_spec = format!("file://{}?format=ocsf", second.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--output", &first_spec, "--output", &second_spec],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), EVENT_BODY);
    assert_eq!(status, 200);

    let first = wait_for_line(first.path(), |line| line["class_uid"] == 2004)
        .expect("the first OCSF sink never received the finding");
    let second = wait_for_line(second.path(), |line| line["class_uid"] == 2004)
        .expect("the second OCSF sink never received the finding");
    assert_eq!(first["finding_info"]["uid"], second["finding_info"]["uid"]);
    assert_eq!(first["metadata"]["uid"], second["metadata"]["uid"]);
    assert_eq!(first["time"], second["time"]);
}

const SIMPLE_RULE_ID: &str = "00000000-0000-0000-0000-000000000001";

const GROUP_AND_DEDUP_PIPELINE: &str = r#"
dedup:
  fingerprint:
    - rule
  repeat_interval: 1s
  resolve_timeout: 1h
group:
  by:
    - match.CommandLine
  group_wait: 0s
  resolve_timeout: 2s
"#;

/// Incidents and dedup sidecar lines reach an OCSF sink as class-2004 findings.
#[test]
fn incidents_and_dedup_lines_are_ocsf_findings_on_ocsf_sink() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let pipeline = temp_file(".yml", GROUP_AND_DEDUP_PIPELINE);
    let native = temp_file(".ndjson", "");
    let native_spec = format!("file://{}", native.path().display());
    let ocsf = temp_file(".ndjson", "");
    let ocsf_spec = format!("file://{}?format=ocsf", ocsf.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--alert-pipeline",
            pipeline.path().to_str().unwrap(),
            "--output",
            &native_spec,
            "--output",
            &ocsf_spec,
        ],
    );

    // Three identical events: the first opens the incident, the rest fold into
    // the dedup alert so a `repeat` sidecar record is due on the next tick.
    for _ in 0..3 {
        let (status, _) = http_post(&daemon.url("/api/v1/events"), EVENT_BODY);
        assert_eq!(status, 200);
    }

    let created = wait_for_line(ocsf.path(), |line| {
        line["class_uid"] == 2004 && line["unmapped"]["state"] == "open"
    })
    .expect("an open incident never reached the OCSF sink as a finding");
    assert_eq!(created["activity_name"], "Create");
    assert_eq!(created["status"], "New");
    assert_eq!(created["count"], 1);
    assert_eq!(
        created["finding_info"]["related_analytics"][0]["name"],
        SIMPLE_RULE_ID
    );

    let dedup_ocsf = wait_for_line(ocsf.path(), |line| line["activity_name"] == "Update")
        .expect("a dedup repeat finding never reached the OCSF sink");
    assert_eq!(dedup_ocsf["class_uid"], 2004);
    assert_eq!(
        dedup_ocsf["unmapped"]["enrichments"]["dedup_state"],
        "repeat",
    );

    let dedup_native = wait_for_line(native.path(), |line| {
        line.pointer("/enrichments/dedup_state").is_some()
    })
    .expect("a dedup sidecar line never reached the native sink");
    assert!(
        dedup_native.get("class_uid").is_none(),
        "native sink keeps the flat summary wire: {dedup_native}",
    );

    // Once `resolve_timeout` elapses with no further results, the incident
    // resolves and closes the finding.
    let closed = wait_for_line(ocsf.path(), |line| {
        line["class_uid"] == 2004 && line["unmapped"]["state"] == "resolved"
    })
    .expect("the resolved incident never reached the OCSF sink");
    assert_eq!(closed["activity_name"], "Close");
    assert_eq!(closed["activity_id"], 3);
    assert_eq!(closed["type_uid"], 200403);
    assert_eq!(closed["status"], "Resolved");
    assert_eq!(closed["status_id"], 4);
    assert_eq!(
        closed["finding_info"]["uid"], created["finding_info"]["uid"],
        "both emissions describe the same incident",
    );
}

/// With `ocsf_incident_class=2005` an incident is an Incident Finding whose
/// `finding_info_list` points at the Detection Finding the same sink emitted
/// for its contributor, while the native sibling keeps the flat incident wire.
#[test]
fn incident_finding_references_the_emitted_detection_finding() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let pipeline = temp_file(".yml", GROUP_AND_DEDUP_PIPELINE);
    let native = temp_file(".ndjson", "");
    let native_spec = format!("file://{}", native.path().display());
    let ocsf = temp_file(".ndjson", "");
    let ocsf_spec = format!(
        "file://{}?format=ocsf&ocsf_incident_class=2005&ocsf_assignee_group=soc",
        ocsf.path().display()
    );
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--alert-pipeline",
            pipeline.path().to_str().unwrap(),
            "--output",
            &native_spec,
            "--output",
            &ocsf_spec,
        ],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), EVENT_BODY);
    assert_eq!(status, 200);

    let detection = wait_for_line(ocsf.path(), |line| line["class_uid"] == 2004)
        .expect("the detection never reached the OCSF sink as a Detection Finding");
    let incident = wait_for_line(ocsf.path(), |line| line["class_uid"] == 2005)
        .expect("the incident never reached the OCSF sink as an Incident Finding");
    assert_eq!(incident["activity_name"], "Create");
    assert_eq!(incident["type_uid"], 200501);
    assert_eq!(incident["status"], "New");
    assert!(incident.get("action_id").is_none(), "{incident}");
    assert!(incident.get("finding_info").is_none(), "{incident}");
    assert_eq!(incident["assignee_group"]["name"], "soc");
    assert_eq!(
        incident["finding_info_list"][0]["uid"], detection["finding_info"]["uid"],
        "the incident references the Detection Finding of its contributor",
    );
    assert_eq!(incident["finding_info_list"][0]["title"], SIMPLE_RULE_ID);

    let native_incident = wait_for_line(native.path(), |line| line["state"] == "open")
        .expect("the incident never reached the native sink");
    assert!(
        native_incident.get("class_uid").is_none(),
        "the native sink keeps the flat incident wire: {native_incident}",
    );
    assert_eq!(
        incident["metadata"]["correlation_uid"],
        native_incident["incident_id"],
    );
    assert!(
        !native_incident.to_string().contains("finding_uid"),
        "finding uids never reach the native wire: {native_incident}",
    );
}

/// A webhook body with `${detection.ocsf}` posts the same finding an OCSF line
/// sink writes for the detection.
#[test]
fn webhook_ocsf_body_carries_the_dispatched_finding() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let server = rt.block_on(async {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        server
    });
    let webhook = temp_file(
        ".yml",
        &format!(
            "webhooks:\n  - id: siem\n    kind: detection\n    url: {}/hook\n    body: '{{\"source\": \"rsigma\", \"finding\": ${{detection.ocsf}}}}'\n",
            server.uri()
        ),
    );
    let rule = temp_file(".yml", SIMPLE_RULE);
    let ocsf = temp_file(".ndjson", "");
    let ocsf_spec = format!("file://{}?format=ocsf", ocsf.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--webhook",
            webhook.path().to_str().unwrap(),
            "--output",
            &ocsf_spec,
        ],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), EVENT_BODY);
    assert_eq!(status, 200);

    let line = wait_for_line(ocsf.path(), |line| line["class_uid"] == 2004)
        .expect("the OCSF line sink never received the finding");
    let request = poll_until(Duration::from_secs(10), || {
        rt.block_on(server.received_requests())?.into_iter().next()
    })
    .expect("the webhook never made a request");
    let body: Value = serde_json::from_slice(&request.body).expect("the body is JSON");
    assert_eq!(body["source"], "rsigma");
    validate_ocsf_finding(&body["finding"]);
    assert_eq!(
        body["finding"], line,
        "the webhook finding is the finding the line sink wrote",
    );
}

#[test]
fn webhook_ocsf_reference_inside_a_string_is_a_startup_error() {
    let webhook = temp_file(
        ".yml",
        "webhooks:\n  - id: siem\n    kind: detection\n    url: http://127.0.0.1:1/hook\n    body: '{\"finding\": \"${detection.ocsf}\"}'\n",
    );
    daemon_startup_failure(&["--webhook", webhook.path().to_str().unwrap()])
        .failure()
        .stderr(contains("only valid in body, as a whole JSON value"));
}
