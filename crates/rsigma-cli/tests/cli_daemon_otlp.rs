//! E2E tests for OTLP log ingestion endpoints.
//!
//! Each test spawns the daemon with `--input http`, discovers the actual
//! API port from the structured log output, and sends OTLP
//! ExportLogsServiceRequests over HTTP (protobuf, JSON, gzip).

#![cfg(feature = "daemon-otlp")]

mod common;

use common::{SIMPLE_RULE, temp_file};
use opentelemetry_proto::tonic::{
    collector::logs::v1::ExportLogsServiceRequest,
    common::v1::{AnyValue, KeyValue, KeyValueList, any_value},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    resource::v1::Resource,
};
use prost::Message;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

fn rsigma_bin() -> String {
    assert_cmd::cargo::cargo_bin("rsigma")
        .to_str()
        .unwrap()
        .to_string()
}

struct DaemonProcess {
    child: std::process::Child,
    api_addr: String,
}

impl DaemonProcess {
    fn spawn(rule_path: &str) -> Self {
        let mut child = Command::new(rsigma_bin())
            .args([
                "daemon",
                "-r",
                rule_path,
                "--input",
                "http",
                "--api-addr",
                "127.0.0.1:0",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn rsigma daemon");

        let stderr = child.stderr.take().unwrap();
        let reader = BufReader::new(stderr);
        let mut api_addr = String::new();

        for line in reader.lines() {
            let line = line.unwrap();
            if line.contains("API server listening")
                && let Some(addr) = extract_addr(&line)
            {
                api_addr = addr;
            }
            if line.contains("Sink started") {
                break;
            }
        }

        assert!(
            !api_addr.is_empty(),
            "failed to discover API address from daemon stderr"
        );

        Self { child, api_addr }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.api_addr)
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn extract_addr(line: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v["fields"]["addr"].as_str().map(|s| s.to_string()))
}

fn string_val(s: &str) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::StringValue(s.to_string())),
    }
}

fn kv(key: &str, value: AnyValue) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(value),
    }
}

fn make_otlp_request(fields: Vec<KeyValue>) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![kv("service.name", string_val("test-service"))],
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    severity_text: "INFO".to_string(),
                    body: Some(AnyValue {
                        value: Some(any_value::Value::KvlistValue(KeyValueList {
                            values: fields,
                        })),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

fn http_get(url: &str) -> (u16, String) {
    let resp = ureq::get(url).call().expect("HTTP GET failed");
    let status = resp.status().as_u16();
    let body = resp.into_body().read_to_string().unwrap();
    (status, body)
}

// ---------------------------------------------------------------------------
// OTLP/HTTP protobuf tests
// ---------------------------------------------------------------------------

#[test]
fn otlp_http_protobuf_accepted() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(rule.path().to_str().unwrap());

    let request = make_otlp_request(vec![kv("CommandLine", string_val("something benign"))]);
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();

    let resp = ureq::post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/x-protobuf")
        .send(&buf[..])
        .expect("OTLP POST failed");

    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value =
        serde_json::from_str(&resp.into_body().read_to_string().unwrap()).unwrap();
    assert_eq!(body["partialSuccess"]["rejectedLogRecords"], 0);
}

#[test]
fn otlp_http_protobuf_triggers_detection() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(rule.path().to_str().unwrap());

    let request = make_otlp_request(vec![kv("CommandLine", string_val("run malware.exe now"))]);
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();

    let resp = ureq::post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/x-protobuf")
        .send(&buf[..])
        .expect("OTLP POST failed");
    assert_eq!(resp.status().as_u16(), 200);

    std::thread::sleep(Duration::from_millis(500));

    let (_, status_body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&status_body).unwrap();
    assert!(
        v["events_processed"].as_u64().unwrap() >= 1,
        "events_processed should be >= 1 after OTLP ingestion"
    );
    assert!(
        v["detection_matches"].as_u64().unwrap() >= 1,
        "detection_matches should be >= 1 for matching OTLP event"
    );
}

// ---------------------------------------------------------------------------
// OTLP/HTTP JSON tests
// ---------------------------------------------------------------------------

#[test]
fn otlp_http_json_accepted() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(rule.path().to_str().unwrap());

    let request = make_otlp_request(vec![kv("CommandLine", string_val("benign process"))]);
    let json_body = serde_json::to_string(&request).unwrap();

    let resp = ureq::post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/json")
        .send(json_body.as_bytes())
        .expect("OTLP JSON POST failed");

    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value =
        serde_json::from_str(&resp.into_body().read_to_string().unwrap()).unwrap();
    assert_eq!(body["partialSuccess"]["rejectedLogRecords"], 0);
}

#[test]
fn otlp_http_json_triggers_detection() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(rule.path().to_str().unwrap());

    let request = make_otlp_request(vec![kv("CommandLine", string_val("launch malware.exe"))]);
    let json_body = serde_json::to_string(&request).unwrap();

    let resp = ureq::post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/json")
        .send(json_body.as_bytes())
        .expect("OTLP JSON POST failed");
    assert_eq!(resp.status().as_u16(), 200);

    std::thread::sleep(Duration::from_millis(500));

    let (_, status_body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&status_body).unwrap();
    assert!(
        v["detection_matches"].as_u64().unwrap() >= 1,
        "detection_matches should be >= 1 for matching OTLP JSON event"
    );
}

// ---------------------------------------------------------------------------
// OTLP/HTTP gzip tests
// ---------------------------------------------------------------------------

#[test]
fn otlp_http_gzip_protobuf_accepted() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(rule.path().to_str().unwrap());

    let request = make_otlp_request(vec![kv("CommandLine", string_val("malware.exe gzip test"))]);
    let mut proto_buf = Vec::new();
    request.encode(&mut proto_buf).unwrap();

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&proto_buf).unwrap();
    let compressed = encoder.finish().unwrap();

    let resp = ureq::post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/x-protobuf")
        .header("Content-Encoding", "gzip")
        .send(&compressed[..])
        .expect("OTLP gzip POST failed");

    assert_eq!(resp.status().as_u16(), 200);

    std::thread::sleep(Duration::from_millis(500));

    let (_, status_body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&status_body).unwrap();
    assert!(
        v["detection_matches"].as_u64().unwrap() >= 1,
        "detection_matches should be >= 1 for gzip-compressed OTLP event"
    );
}

// ---------------------------------------------------------------------------
// OTLP/HTTP error cases
// ---------------------------------------------------------------------------

#[test]
fn otlp_http_unsupported_content_type_returns_415() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(rule.path().to_str().unwrap());

    let result = ureq::post(&daemon.url("/v1/logs"))
        .header("Content-Type", "text/plain")
        .send("not otlp");

    match result {
        Err(ureq::Error::StatusCode(415)) => {}
        other => panic!("expected 415 Unsupported Media Type, got {other:?}"),
    }
}

#[test]
fn otlp_http_malformed_protobuf_returns_400() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(rule.path().to_str().unwrap());

    let result = ureq::post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/x-protobuf")
        .send(&b"not valid protobuf"[..]);

    match result {
        Err(ureq::Error::StatusCode(400)) => {}
        other => panic!("expected 400 Bad Request, got {other:?}"),
    }
}

#[test]
fn otlp_http_malformed_json_returns_400() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(rule.path().to_str().unwrap());

    let result = ureq::post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/json")
        .send("{not valid json".as_bytes());

    match result {
        Err(ureq::Error::StatusCode(400)) => {}
        other => panic!("expected 400 Bad Request, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// OTLP metrics
// ---------------------------------------------------------------------------

#[test]
fn otlp_metrics_exposed_after_request() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn(rule.path().to_str().unwrap());

    let request = make_otlp_request(vec![kv("CommandLine", string_val("test"))]);
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();

    ureq::post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/x-protobuf")
        .send(&buf[..])
        .expect("OTLP POST failed");

    std::thread::sleep(Duration::from_millis(200));

    let (status, body) = http_get(&daemon.url("/metrics"));
    assert_eq!(status, 200);
    assert!(
        body.contains("rsigma_otlp_requests_total"),
        "metrics should contain rsigma_otlp_requests_total"
    );
    assert!(
        body.contains("rsigma_otlp_log_records_total"),
        "metrics should contain rsigma_otlp_log_records_total"
    );
}
