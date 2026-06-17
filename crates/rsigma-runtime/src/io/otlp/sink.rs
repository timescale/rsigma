//! OTLP output sink: export evaluation results to an OpenTelemetry collector
//! over OTLP/HTTP (protobuf) or OTLP/gRPC.

use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
};
use prost::Message;
use tonic::codec::CompressionEncoding;
use tonic::transport::Channel;

use rsigma_eval::ProcessResult;

use super::convert::evaluation_results_to_logs_request;
use crate::error::RuntimeError;

/// OTLP transport, selected by the sink URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtlpProtocol {
    /// OTLP/gRPC. Default OTLP port 4317.
    Grpc,
    /// OTLP/HTTP with protobuf encoding. Default OTLP port 4318, path `/v1/logs`.
    Http,
}

enum Transport {
    Http {
        client: reqwest::Client,
        url: String,
        gzip: bool,
    },
    Grpc {
        client: LogsServiceClient<Channel>,
    },
}

/// Exports detection and correlation results to an OTLP collector.
///
/// The gRPC channel connects lazily, so a collector that is not yet reachable
/// does not fail daemon startup; delivery failures are surfaced to the
/// delivery layer, which retries and ultimately routes to the DLQ.
pub struct OtlpSink {
    transport: Transport,
}

impl OtlpSink {
    /// Build an OTLP sink targeting `endpoint` (`host:port`). `gzip` enables
    /// payload compression on the wire.
    pub fn new(protocol: OtlpProtocol, endpoint: &str, gzip: bool) -> Result<Self, RuntimeError> {
        let transport = match protocol {
            OtlpProtocol::Http => Transport::Http {
                client: reqwest::Client::new(),
                url: format!("http://{}/v1/logs", endpoint.trim_end_matches('/')),
                gzip,
            },
            OtlpProtocol::Grpc => {
                let channel = Channel::from_shared(format!("http://{endpoint}"))
                    .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?
                    .connect_lazy();
                let mut client = LogsServiceClient::new(channel);
                if gzip {
                    client = client
                        .send_compressed(CompressionEncoding::Gzip)
                        .accept_compressed(CompressionEncoding::Gzip);
                }
                Transport::Grpc { client }
            }
        };
        Ok(OtlpSink { transport })
    }

    /// Serialize and export a batch of results to the collector.
    pub async fn send(&mut self, result: &ProcessResult) -> Result<(), RuntimeError> {
        if result.is_empty() {
            return Ok(());
        }
        self.export(evaluation_results_to_logs_request(result))
            .await
    }

    /// Export a pre-serialized line as a single OTLP log-record body. Used when
    /// an OTLP sink is configured as a DLQ target.
    pub async fn send_raw(&mut self, json: &str) -> Result<(), RuntimeError> {
        use opentelemetry_proto::tonic::{
            common::v1::{AnyValue, any_value},
            logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
        };
        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                scope_logs: vec![ScopeLogs {
                    log_records: vec![LogRecord {
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue(json.to_string())),
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        self.export(request).await
    }

    async fn export(&mut self, request: ExportLogsServiceRequest) -> Result<(), RuntimeError> {
        match &mut self.transport {
            Transport::Http { client, url, gzip } => {
                let mut builder = client
                    .post(url.as_str())
                    .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf");
                let body = if *gzip {
                    builder = builder.header(reqwest::header::CONTENT_ENCODING, "gzip");
                    gzip_compress(&request.encode_to_vec())?
                } else {
                    request.encode_to_vec()
                };
                let response = builder
                    .body(body)
                    .send()
                    .await
                    .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?;
                if !response.status().is_success() {
                    return Err(RuntimeError::Io(std::io::Error::other(format!(
                        "OTLP/HTTP export returned status {}",
                        response.status()
                    ))));
                }
                Ok(())
            }
            Transport::Grpc { client } => {
                client
                    .export(request)
                    .await
                    .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?;
                Ok(())
            }
        }
    }
}

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use rsigma_eval::result::{
        DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader,
    };
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn one_detection() -> Vec<EvaluationResult> {
        vec![EvaluationResult {
            header: RuleHeader {
                rule_title: "Test Rule".to_string(),
                rule_id: Some("rule-1".to_string()),
                level: Some(rsigma_parser::Level::High),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec!["selection".to_string()],
                matched_fields: vec![FieldMatch::new("CommandLine", serde_json::json!("malware"))],
                event: None,
            }),
        }]
    }

    #[tokio::test]
    async fn http_export_posts_protobuf_to_v1_logs() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/logs"))
            .and(header("content-type", "application/x-protobuf"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let endpoint = server.address().to_string();
        let mut sink = OtlpSink::new(OtlpProtocol::Http, &endpoint, false).unwrap();
        sink.send(&one_detection()).await.unwrap();
        // `expect(1)` is verified when the server drops.
    }

    #[tokio::test]
    async fn http_export_surfaces_non_2xx_as_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/logs"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let endpoint = server.address().to_string();
        let mut sink = OtlpSink::new(OtlpProtocol::Http, &endpoint, false).unwrap();
        let err = sink.send(&one_detection()).await.unwrap_err();
        assert!(
            err.to_string().contains("503"),
            "non-2xx must surface as a retryable error: {err}",
        );
    }

    #[tokio::test]
    async fn empty_batch_is_a_noop() {
        // No server: an empty batch must not attempt any network call.
        let mut sink = OtlpSink::new(OtlpProtocol::Http, "127.0.0.1:1", false).unwrap();
        let empty: Vec<EvaluationResult> = Vec::new();
        sink.send(&empty).await.unwrap();
    }

    #[tokio::test]
    async fn http_export_gzip_sets_content_encoding() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/logs"))
            .and(header("content-encoding", "gzip"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let endpoint = server.address().to_string();
        let mut sink = OtlpSink::new(OtlpProtocol::Http, &endpoint, true).unwrap();
        sink.send(&one_detection()).await.unwrap();
    }

    #[tokio::test]
    async fn grpc_export_reaches_the_collector() {
        use std::time::Duration;

        use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceResponse;

        use crate::io::otlp::{LogsService, LogsServiceServer};

        #[derive(Clone)]
        struct Recording {
            received: Arc<tokio::sync::Mutex<Vec<ExportLogsServiceRequest>>>,
        }

        #[tonic::async_trait]
        impl LogsService for Recording {
            async fn export(
                &self,
                request: tonic::Request<ExportLogsServiceRequest>,
            ) -> Result<tonic::Response<ExportLogsServiceResponse>, tonic::Status> {
                self.received.lock().await.push(request.into_inner());
                Ok(tonic::Response::new(ExportLogsServiceResponse::default()))
            }
        }

        // Reserve an ephemeral port, then let the tonic server bind it.
        let addr = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            drop(listener);
            addr
        };
        let received = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let service = Recording {
            received: received.clone(),
        };
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(LogsServiceServer::new(service))
                .serve(addr)
                .await
                .unwrap();
        });

        // Wait until the server is accepting connections before exporting.
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let mut sink = OtlpSink::new(OtlpProtocol::Grpc, &addr.to_string(), false).unwrap();
        sink.send(&one_detection()).await.unwrap();

        let got = received.lock().await;
        assert_eq!(got.len(), 1, "collector should receive exactly one export");
        let record = &got[0].resource_logs[0].scope_logs[0].log_records[0];
        assert_eq!(record.severity_text, "ERROR");
        server.abort();
    }
}
