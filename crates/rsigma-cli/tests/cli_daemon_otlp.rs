//! E2E tests for OTLP log ingestion endpoints.
//!
//! Each test spawns the daemon with `--input http`, discovers the actual
//! API port from the structured log output, and sends OTLP
//! ExportLogsServiceRequests over HTTP (protobuf, JSON, gzip).

#![cfg(feature = "daemon-otlp")]

use crate::common;

use common::{DaemonProcess, SIMPLE_RULE, http_get, poll_until, temp_file};
use opentelemetry_proto::tonic::{
    collector::logs::v1::{ExportLogsServiceRequest, ExportLogsServiceResponse},
    common::v1::{AnyValue, KeyValue, KeyValueList, any_value},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    resource::v1::Resource,
};
use prost::Message;
use std::time::Duration;

fn string_val(s: &str) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::StringValue(s.to_string())),
    }
}

fn kv(key: &str, value: AnyValue) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(value),
        ..Default::default()
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

/// Wait until `/api/v1/status` reports `detection_matches >= 1`.
/// Panics with a clear message on timeout.
fn wait_for_detection_match(daemon: &DaemonProcess) {
    poll_until(Duration::from_secs(5), || {
        let (_, body) = http_get(&daemon.url("/api/v1/status"));
        let v: serde_json::Value = serde_json::from_str(&body).ok()?;
        (v["detection_matches"].as_u64()? >= 1).then_some(())
    })
    .expect("detection_matches never reached 1 within 5s");
}

// ---------------------------------------------------------------------------
// OTLP/HTTP protobuf tests
// ---------------------------------------------------------------------------

#[test]
fn otlp_http_protobuf_accepted() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let request = make_otlp_request(vec![kv("CommandLine", string_val("something benign"))]);
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();

    let resp = ureq::post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/x-protobuf")
        .send(&buf[..])
        .expect("OTLP POST failed");

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/x-protobuf",
        "a protobuf request gets a protobuf response"
    );
    let body = resp.into_body().read_to_vec().unwrap();
    let response = ExportLogsServiceResponse::decode(body.as_slice()).unwrap();
    assert_eq!(response.partial_success, None);
}

#[test]
fn otlp_http_protobuf_triggers_detection() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let request = make_otlp_request(vec![kv("CommandLine", string_val("run malware.exe now"))]);
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();

    let resp = ureq::post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/x-protobuf")
        .send(&buf[..])
        .expect("OTLP POST failed");
    assert_eq!(resp.status().as_u16(), 200);

    wait_for_detection_match(&daemon);

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
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

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
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let request = make_otlp_request(vec![kv("CommandLine", string_val("launch malware.exe"))]);
    let json_body = serde_json::to_string(&request).unwrap();

    let resp = ureq::post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/json")
        .send(json_body.as_bytes())
        .expect("OTLP JSON POST failed");
    assert_eq!(resp.status().as_u16(), 200);

    wait_for_detection_match(&daemon);

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
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

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

    wait_for_detection_match(&daemon);

    let (_, status_body) = http_get(&daemon.url("/api/v1/status"));
    let v: serde_json::Value = serde_json::from_str(&status_body).unwrap();
    assert!(
        v["detection_matches"].as_u64().unwrap() >= 1,
        "detection_matches should be >= 1 for gzip-compressed OTLP event"
    );
}

/// The OTLP/HTTP decompressed-body limit, mirrored from the daemon.
const OTLP_HTTP_MAX_DECOMPRESSED_BYTES: usize = 4 * 1024 * 1024;

fn gzip(data: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn otlp_http_gzip_over_limit_returns_413() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let compressed = gzip(&vec![0u8; 2 * OTLP_HTTP_MAX_DECOMPRESSED_BYTES]);
    assert!(compressed.len() < 64 * 1024);

    let result = ureq::post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/x-protobuf")
        .header("Content-Encoding", "gzip")
        .send(&compressed[..]);

    match result {
        Err(ureq::Error::StatusCode(413)) => {}
        other => panic!("expected 413 Payload Too Large, got {other:?}"),
    }

    let (_, metrics) = http_get(&daemon.url("/metrics"));
    assert!(
        metrics
            .lines()
            .any(|l| l.starts_with("rsigma_otlp_errors_total{")
                && l.contains(r#"reason="body_too_large""#)
                && l.contains(r#"transport="http""#)
                && l.ends_with(" 1")),
        "body_too_large error not counted:\n{metrics}"
    );

    let (status, _) = http_get(&daemon.url("/healthz"));
    assert_eq!(status, 200, "daemon must stay up after a rejected bomb");
}

#[test]
fn otlp_http_gzip_under_limit_is_accepted() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let request = make_otlp_request(vec![kv(
        "CommandLine",
        string_val(&"a".repeat(OTLP_HTTP_MAX_DECOMPRESSED_BYTES - 1024)),
    )]);
    let mut proto_buf = Vec::new();
    request.encode(&mut proto_buf).unwrap();
    assert!(proto_buf.len() <= OTLP_HTTP_MAX_DECOMPRESSED_BYTES);

    let resp = ureq::post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/x-protobuf")
        .header("Content-Encoding", "gzip")
        .send(&gzip(&proto_buf)[..])
        .expect("OTLP gzip POST under the limit failed");

    assert_eq!(resp.status().as_u16(), 200);
}

// ---------------------------------------------------------------------------
// OTLP/HTTP error cases
// ---------------------------------------------------------------------------

#[test]
fn otlp_http_unsupported_content_type_returns_415() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

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
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

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
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

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
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());

    let request = make_otlp_request(vec![kv("CommandLine", string_val("test"))]);
    let mut buf = Vec::new();
    request.encode(&mut buf).unwrap();

    ureq::post(&daemon.url("/v1/logs"))
        .header("Content-Type", "application/x-protobuf")
        .send(&buf[..])
        .expect("OTLP POST failed");

    let body = poll_until(Duration::from_secs(5), || {
        let (status, body) = http_get(&daemon.url("/metrics"));
        (status == 200
            && body.contains("rsigma_otlp_requests_total")
            && body.contains("rsigma_otlp_log_records_total"))
        .then_some(body)
    })
    .expect("OTLP metrics never appeared within 5s");

    assert!(
        body.contains("rsigma_otlp_requests_total"),
        "metrics should contain rsigma_otlp_requests_total"
    );
    assert!(
        body.contains("rsigma_otlp_log_records_total"),
        "metrics should contain rsigma_otlp_log_records_total"
    );
}

// ---------------------------------------------------------------------------
// OTLP expansion limits
// ---------------------------------------------------------------------------

/// One resource with a 512 KiB attribute over `n` small log records.
fn large_resource_request(n: usize) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![kv("service.blob", string_val(&"r".repeat(512 * 1024)))],
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                log_records: (0..n)
                    .map(|i| LogRecord {
                        body: Some(string_val(&format!("e{i}"))),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

fn metric_value(metrics: &str, line_prefix: &str) -> Option<u64> {
    metrics
        .lines()
        .find(|l| l.starts_with(line_prefix))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
}

/// Send `body` to `/v1/logs` and return the number of rejected records the
/// response reports.
fn post_otlp(daemon: &DaemonProcess, body: &[u8], content_type: &str, gzip: bool) -> i64 {
    let mut request = ureq::post(&daemon.url("/v1/logs")).header("Content-Type", content_type);
    if gzip {
        request = request.header("Content-Encoding", "gzip");
    }
    let resp = request.send(body).expect("OTLP POST failed");
    assert_eq!(resp.status().as_u16(), 200);
    if content_type == "application/json" {
        let v: serde_json::Value =
            serde_json::from_str(&resp.into_body().read_to_string().unwrap()).unwrap();
        v["partialSuccess"]["rejectedLogRecords"].as_i64().unwrap()
    } else {
        let bytes = resp.into_body().read_to_vec().unwrap();
        ExportLogsServiceResponse::decode(bytes.as_slice())
            .unwrap()
            .partial_success
            .map_or(0, |p| p.rejected_log_records)
    }
}

#[test]
fn otlp_http_a_large_resource_over_many_records_is_bounded() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());
    let proto = large_resource_request(10_000).encode_to_vec();
    // OTLP/JSON spells out every default field, so fewer records fit the body
    // limit.
    let json = serde_json::to_vec(&large_resource_request(4_000)).unwrap();

    let mut rejected_total = 0;
    for (body, content_type, gzip, records) in [
        (proto.clone(), "application/x-protobuf", false, 10_000),
        (gzip(&proto), "application/x-protobuf", true, 10_000),
        (json, "application/json", false, 4_000),
    ] {
        let rejected = post_otlp(&daemon, &body, content_type, gzip);
        assert!(
            rejected > records - 1_000,
            "{content_type} gzip={gzip}: most records are past the request budget, got {rejected}"
        );
        rejected_total += rejected as u64;
    }

    let (_, metrics) = http_get(&daemon.url("/metrics"));
    assert_eq!(
        metric_value(
            &metrics,
            r#"rsigma_otlp_rejected_log_records_total{reason="over_budget",transport="http"}"#
        ),
        Some(rejected_total),
        "{metrics}"
    );
    let accepted = metric_value(&metrics, "rsigma_otlp_log_records_total").unwrap();
    assert_eq!(accepted + rejected_total, 24_000);
    let (status, _) = http_get(&daemon.url("/healthz"));
    assert_eq!(status, 200);
}

#[test]
fn otlp_http_too_many_records_are_refused_before_decoding() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http_with_args(
        rule.path().to_str().unwrap(),
        &["--otlp-max-records", "100"],
    );
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord::default(); 101],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    for (body, content_type) in [
        (request.encode_to_vec(), "application/x-protobuf"),
        (serde_json::to_vec(&request).unwrap(), "application/json"),
    ] {
        match ureq::post(&daemon.url("/v1/logs"))
            .header("Content-Type", content_type)
            .send(&body[..])
        {
            Err(ureq::Error::StatusCode(413)) => {}
            other => panic!("{content_type}: expected 413, got {other:?}"),
        }
    }
    let (_, metrics) = http_get(&daemon.url("/metrics"));
    assert_eq!(
        metric_value(
            &metrics,
            r#"rsigma_otlp_errors_total{reason="too_many_records",transport="http"}"#
        ),
        Some(2),
        "{metrics}"
    );
}

// ---------------------------------------------------------------------------
// OTLP/gRPC
// ---------------------------------------------------------------------------

use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;

const INGEST_AUTH_CONFIG: &str = r#"
daemon:
  api:
    auth:
      tokens:
        - name: shipper
          role: ingest
          token_env: TEST_TOKEN_INGEST
        - name: viewer
          role: reader
          token_env: TEST_TOKEN_READER
"#;

fn grpc_request(
    request: ExportLogsServiceRequest,
    token: Option<&str>,
) -> tonic::Request<ExportLogsServiceRequest> {
    let mut request = tonic::Request::new(request);
    if let Some(token) = token {
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
    }
    request
}

#[test]
fn otlp_grpc_checks_credentials_and_limits() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let config = temp_file(".yaml", INGEST_AUTH_CONFIG);
    let daemon = DaemonProcess::spawn_http_with_args_env(
        rule.path().to_str().unwrap(),
        &[
            "--config",
            config.path().to_str().unwrap(),
            "--otlp-max-records",
            "50",
        ],
        &[
            ("TEST_TOKEN_INGEST", "tok-ingest"),
            ("TEST_TOKEN_READER", "tok-reader"),
        ],
    );
    let url = daemon.url("");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async move {
        let mut client = LogsServiceClient::connect(url)
            .await
            .unwrap()
            .send_compressed(tonic::codec::CompressionEncoding::Gzip);
        let benign = || make_otlp_request(vec![kv("CommandLine", string_val("run malware.exe"))]);

        let status = client
            .export(grpc_request(benign(), None))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);

        let status = client
            .export(grpc_request(benign(), Some("tok-reader")))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);

        let mut too_many = benign();
        too_many.resource_logs[0].scope_logs[0].log_records = vec![LogRecord::default(); 51];
        let status = client
            .export(grpc_request(too_many, Some("tok-ingest")))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);

        let response = client
            .export(grpc_request(benign(), Some("tok-ingest")))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.partial_success, None);

        let response = client
            .export(grpc_request(
                large_resource_request(5_000).clone(),
                Some("tok-ingest"),
            ))
            .await;
        let status = response.unwrap_err();
        assert_eq!(
            status.code(),
            tonic::Code::ResourceExhausted,
            "5,000 records exceed the limit of 50"
        );
    });
}

#[test]
fn otlp_grpc_a_large_resource_over_many_records_is_bounded() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let daemon = DaemonProcess::spawn_http(rule.path().to_str().unwrap());
    let url = daemon.url("");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let rejected = runtime.block_on(async move {
        let mut client = LogsServiceClient::connect(url)
            .await
            .unwrap()
            .send_compressed(tonic::codec::CompressionEncoding::Gzip);
        client
            .export(grpc_request(large_resource_request(10_000), None))
            .await
            .unwrap()
            .into_inner()
            .partial_success
            .expect("a partial success")
            .rejected_log_records
    });
    assert!(rejected > 9_000, "got {rejected}");
    let (_, metrics) = http_get(&daemon.url("/metrics"));
    assert_eq!(
        metric_value(
            &metrics,
            r#"rsigma_otlp_rejected_log_records_total{reason="over_budget",transport="grpc"}"#
        ),
        Some(rejected as u64),
        "{metrics}"
    );
}
