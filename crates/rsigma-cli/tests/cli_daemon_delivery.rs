//! Integration tests for the async sink delivery layer: per-sink `?on_full`
//! policy parsing, multi-sink fan-out, and the per-sink / input-source
//! delivery metrics. Runs under the default `daemon` feature (HTTP input,
//! file output) so no external broker is needed.

mod common;

use std::time::Duration;

use common::{DaemonProcess, SIMPLE_RULE, http_get, http_post, poll_until, temp_file};

const MATCHING_EVENT: &str = r#"{"CommandLine":"run malware.exe"}"#;

fn file_contains(path: &std::path::Path, needle: &str) -> bool {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .contains(needle)
}

#[test]
fn on_full_drop_sink_is_accepted_and_delivers() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = temp_file(".ndjson", "");
    let out_spec = format!("file://{}?on_full=drop", out.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--output", &out_spec],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), MATCHING_EVENT);
    assert_eq!(status, 200, "event ingestion should be accepted");

    let delivered = poll_until(Duration::from_secs(5), || {
        file_contains(out.path(), "Test Rule").then_some(())
    });
    assert!(
        delivered.is_some(),
        "detection should reach an ?on_full=drop sink under normal (non-saturated) load",
    );
}

#[test]
fn fan_out_delivers_to_every_sink() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let a = temp_file(".ndjson", "");
    let b = temp_file(".ndjson", "");
    let a_spec = format!("file://{}", a.path().display());
    let b_spec = format!("file://{}", b.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--output", &a_spec, "--output", &b_spec],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), MATCHING_EVENT);
    assert_eq!(status, 200);

    let both = poll_until(Duration::from_secs(5), || {
        (file_contains(a.path(), "Test Rule") && file_contains(b.path(), "Test Rule")).then_some(())
    });
    assert!(
        both.is_some(),
        "fan-out must deliver the detection to every leaf sink",
    );
}

#[test]
fn sink_and_input_metrics_are_exposed() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let out = temp_file(".ndjson", "");
    let out_spec = format!("file://{}", out.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--output", &out_spec],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), MATCHING_EVENT);
    assert_eq!(status, 200);
    poll_until(Duration::from_secs(5), || {
        file_contains(out.path(), "Test Rule").then_some(())
    });

    let (status, body) = http_get(&daemon.url("/metrics"));
    assert_eq!(status, 200);
    // The per-sink delivery metric is pre-registered with the sink kind
    // label when the worker starts, so it is present even before saturation.
    assert!(
        body.contains("rsigma_sink_queue_depth"),
        "per-sink delivery gauge must be exposed",
    );
    assert!(
        body.contains(r#"sink="file""#),
        "the file sink's label must be present: {body}",
    );
    // Input-source metric parity: the HTTP push receiver feeds the same
    // gauge the pull sources do.
    assert!(
        body.contains("rsigma_input_queue_depth"),
        "input-queue-depth gauge must be exposed",
    );
}

/// An OTLP output sink pointed at an unreachable collector should, after
/// exhausting retries, route the failed result to the DLQ. With
/// `--sink-retry-max 0` the first failure is terminal, keeping the test fast
/// and deterministic. Exercises the `otlphttp://` grammar, OTLP sink
/// construction, the delivery layer, and the DLQ bridge end to end.
#[cfg(feature = "daemon-otlp")]
#[test]
fn otlp_sink_unreachable_endpoint_routes_to_dlq() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let dlq = temp_file(".ndjson", "");
    let dlq_spec = format!("file://{}", dlq.path().display());
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &[
            "--output",
            "otlphttp://127.0.0.1:1",
            "--dlq",
            &dlq_spec,
            "--sink-retry-max",
            "0",
        ],
    );

    let (status, _) = http_post(&daemon.url("/api/v1/events"), MATCHING_EVENT);
    assert_eq!(status, 200);

    let dlqd = poll_until(Duration::from_secs(10), || {
        file_contains(dlq.path(), "sink delivery failure").then_some(())
    });
    assert!(
        dlqd.is_some(),
        "an unreachable OTLP sink should route the failed result to the DLQ",
    );
}
