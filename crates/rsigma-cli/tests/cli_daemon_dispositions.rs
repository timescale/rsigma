//! E2E limits on `POST /api/v1/dispositions`: unknown rules, the batch size,
//! and future timestamps.

#![cfg(feature = "daemon")]

use crate::common;

use common::{DaemonProcess, SIMPLE_RULE, SIMPLE_RULE_ID, http_get, temp_file};

fn spawn() -> (DaemonProcess, tempfile::NamedTempFile) {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--enable-dispositions"],
    );
    (daemon, rule)
}

fn post(daemon: &DaemonProcess, body: &str) -> (u16, serde_json::Value) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let resp = agent
        .post(daemon.url("/api/v1/dispositions"))
        .send(body)
        .expect("POST /api/v1/dispositions failed");
    let status = resp.status().as_u16();
    let text = resp.into_body().read_to_string().unwrap();
    let value = serde_json::from_str(&text).unwrap_or_else(|_| panic!("non-JSON body: {text}"));
    (status, value)
}

fn tracked_rules(daemon: &DaemonProcess) -> u64 {
    let (_, metrics) = http_get(&daemon.url("/metrics"));
    metrics
        .lines()
        .find(|line| line.starts_with("rsigma_disposition_tracked_rules "))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .expect("tracked rules gauge")
}

#[test]
fn unknown_rule_ids_create_no_entries() {
    let (daemon, _rule) = spawn();
    for batch in 0..100 {
        let body: String = (0..1000)
            .map(|i| {
                format!("{{\"rule_id\":\"bogus-{batch}-{i}\",\"verdict\":\"false_positive\"}}\n")
            })
            .collect();
        let (status, summary) = post(&daemon, &body);
        assert_eq!(status, 200, "{summary}");
        assert_eq!(summary["rejected"], 1000, "{summary}");
    }
    assert_eq!(tracked_rules(&daemon), 0);
    let (_, view) = http_get(&daemon.url("/api/v1/dispositions"));
    assert!(view.contains("\"rules\":[]"), "{view}");

    let (status, summary) = post(
        &daemon,
        &format!(r#"{{"rule_id":"{SIMPLE_RULE_ID}","verdict":"false_positive"}}"#),
    );
    assert_eq!(status, 200, "{summary}");
    assert_eq!(
        summary["accepted"], 1,
        "a loaded rule is accepted: {summary}"
    );
    assert_eq!(tracked_rules(&daemon), 1);
}

#[test]
fn a_batch_over_the_record_limit_is_refused_whole() {
    let (daemon, _rule) = spawn();
    let one = format!(r#"{{"rule_id":"{SIMPLE_RULE_ID}","verdict":"true_positive"}}"#);
    let body = vec![one; 1001].join("\n");
    let (status, body) = post(&daemon, &body);
    assert_eq!(status, 413, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("at most 1000"),
        "{body}"
    );
    assert_eq!(tracked_rules(&daemon), 0);
}

#[test]
fn a_future_timestamp_is_refused() {
    let (daemon, _rule) = spawn();
    let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let (status, summary) = post(
        &daemon,
        &format!(
            r#"{{"rule_id":"{SIMPLE_RULE_ID}","verdict":"true_positive","timestamp":"{future}"}}"#
        ),
    );
    assert_eq!(status, 200, "{summary}");
    assert_eq!(summary["rejected"], 1, "{summary}");
    assert!(
        summary["errors"][0].as_str().unwrap().contains("future"),
        "{summary}"
    );
}
