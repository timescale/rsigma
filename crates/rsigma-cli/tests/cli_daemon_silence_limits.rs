//! E2E tests for the limits on API silences (`max_silence_duration`,
//! `allow_broad_silences`) and for `POST /api/v1/silences` without an alert
//! pipeline.

#![cfg(feature = "daemon")]

mod common;

use common::{DaemonProcess, SIMPLE_RULE, SIMPLE_RULE_ID, bounded_silence, http_post, temp_file};

fn spawn_with_pipeline(pipeline_yaml: &str) -> (DaemonProcess, [tempfile::NamedTempFile; 2]) {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let pipeline = temp_file(".yml", pipeline_yaml);
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--alert-pipeline", pipeline.path().to_str().unwrap()],
    );
    (daemon, [rule, pipeline])
}

/// POST a silence and return the status with the JSON body, including the
/// body of a 4xx response.
fn post_silence(daemon: &DaemonProcess, body: serde_json::Value) -> (u16, serde_json::Value) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let resp = agent
        .post(daemon.url("/api/v1/silences"))
        .send(body.to_string())
        .expect("POST /api/v1/silences failed");
    let status = resp.status().as_u16();
    let text = resp.into_body().read_to_string().unwrap();
    let value = serde_json::from_str(&text).unwrap_or_else(|_| panic!("non-JSON body: {text}"));
    (status, value)
}

fn in_one_hour() -> String {
    (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()
}

fn scoped() -> serde_json::Value {
    serde_json::json!([{ "selector": "rule", "op": "=", "value": SIMPLE_RULE_ID }])
}

#[test]
fn default_limits_refuse_catch_all_and_unbounded_silences() {
    let (daemon, _files) = spawn_with_pipeline("{}\n");

    let (status, body) = post_silence(
        &daemon,
        serde_json::json!({
            "matchers": [{ "selector": "rule", "op": "=~", "value": ".*" }],
            "ends_at": in_one_hour(),
        }),
    );
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("`=` matcher"),
        "{body}"
    );
    assert!(
        body["hint"]
            .as_str()
            .unwrap()
            .contains("allow_broad_silences"),
        "{body}"
    );

    let (status, body) = post_silence(
        &daemon,
        serde_json::json!({ "matchers": scoped(), "ends_at": "9999-12-31T23:59:59Z" }),
    );
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("max_silence_duration"),
        "{body}"
    );

    let (status, body) = post_silence(&daemon, serde_json::json!({ "matchers": scoped() }));
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("needs ends_at"),
        "{body}"
    );
}

#[test]
fn default_limits_accept_a_scoped_bounded_silence() {
    let (daemon, _files) = spawn_with_pipeline("{}\n");
    let (status, text) = http_post(
        &daemon.url("/api/v1/silences"),
        &bounded_silence("maintenance"),
    );
    assert_eq!(status, 201, "{text}");
}

#[test]
fn limits_can_be_lifted_in_the_alert_pipeline_config() {
    let (daemon, _files) =
        spawn_with_pipeline("max_silence_duration: 0\nallow_broad_silences: true\n");
    let (status, body) = post_silence(
        &daemon,
        serde_json::json!({ "matchers": [{ "selector": "rule", "op": "=~", "value": ".*" }] }),
    );
    assert_eq!(status, 201, "{body}");
}

#[test]
fn silences_without_an_alert_pipeline_are_refused() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());
    let (status, body) = post_silence(
        &daemon,
        serde_json::json!({ "matchers": scoped(), "ends_at": in_one_hour() }),
    );
    assert_eq!(status, 409, "{body}");
    assert!(
        body["hint"].as_str().unwrap().contains("--alert-pipeline"),
        "{body}"
    );
}
