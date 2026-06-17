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

/// Client TLS material for an OTLP sink. `Some(OtlpClientTls::default())`
/// enables TLS and verifies the collector against the bundled webpki roots;
/// fields add a custom CA, a client identity (mutual TLS), or an SNI override.
#[derive(Debug, Clone, Default)]
pub struct OtlpClientTls {
    /// Custom CA bundle (PEM) to verify the collector against, instead of the
    /// bundled public roots.
    pub ca_pem: Option<Vec<u8>>,
    /// Client certificate (PEM) for mutual TLS.
    pub client_cert_pem: Option<Vec<u8>>,
    /// Client private key (PEM) for mutual TLS.
    pub client_key_pem: Option<Vec<u8>>,
    /// Optional SNI / domain-name override, useful when dialing by IP.
    pub domain: Option<String>,
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
    /// payload compression; `tls` enables TLS (`Some`, with optional custom CA
    /// and client identity) or plaintext (`None`).
    pub fn new(
        protocol: OtlpProtocol,
        endpoint: &str,
        gzip: bool,
        tls: Option<OtlpClientTls>,
    ) -> Result<Self, RuntimeError> {
        if tls.is_some() {
            install_crypto_provider();
        }
        let scheme = if tls.is_some() { "https" } else { "http" };
        let transport = match protocol {
            OtlpProtocol::Http => Transport::Http {
                client: build_http_client(tls.as_ref())?,
                url: format!("{scheme}://{}/v1/logs", endpoint.trim_end_matches('/')),
                gzip,
            },
            OtlpProtocol::Grpc => {
                let mut endpoint = Channel::from_shared(format!("{scheme}://{endpoint}"))
                    .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?;
                if let Some(tls) = &tls {
                    endpoint = endpoint
                        .tls_config(grpc_tls_config(tls))
                        .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?;
                }
                let mut client = LogsServiceClient::new(endpoint.connect_lazy());
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

/// Pin the process-default rustls `CryptoProvider` to aws-lc-rs.
///
/// Both aws-lc-rs (via tonic) and ring (via reqwest) rustls providers are in
/// the dependency tree, so rustls cannot auto-select a default and any TLS
/// config build would panic. We pin aws-lc-rs to match the daemon's
/// server-side TLS. First call wins; later calls are a no-op.
fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Build the OTLP/HTTP `reqwest` client, applying TLS material when present.
fn build_http_client(tls: Option<&OtlpClientTls>) -> Result<reqwest::Client, RuntimeError> {
    let Some(tls) = tls else {
        return Ok(reqwest::Client::new());
    };
    let mut builder = reqwest::Client::builder();
    if let Some(ca) = &tls.ca_pem {
        let cert = reqwest::Certificate::from_pem(ca)
            .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?;
        builder = builder.add_root_certificate(cert);
    }
    if let (Some(cert), Some(key)) = (&tls.client_cert_pem, &tls.client_key_pem) {
        // reqwest's rustls identity wants a single PEM buffer of cert + key.
        let mut pem = cert.clone();
        pem.push(b'\n');
        pem.extend_from_slice(key);
        let identity = reqwest::Identity::from_pem(&pem)
            .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?;
        builder = builder.identity(identity);
    }
    builder
        .build()
        .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))
}

/// Build the OTLP/gRPC client TLS config: custom CA (or bundled webpki roots),
/// optional client identity, optional SNI override.
fn grpc_tls_config(tls: &OtlpClientTls) -> tonic::transport::ClientTlsConfig {
    use tonic::transport::{Certificate, ClientTlsConfig, Identity};
    let mut config = match &tls.ca_pem {
        Some(ca) => ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca)),
        None => ClientTlsConfig::new().with_webpki_roots(),
    };
    if let (Some(cert), Some(key)) = (&tls.client_cert_pem, &tls.client_key_pem) {
        config = config.identity(Identity::from_pem(cert, key));
    }
    if let Some(domain) = &tls.domain {
        config = config.domain_name(domain.clone());
    }
    config
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
        let mut sink = OtlpSink::new(OtlpProtocol::Http, &endpoint, false, None).unwrap();
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
        let mut sink = OtlpSink::new(OtlpProtocol::Http, &endpoint, false, None).unwrap();
        let err = sink.send(&one_detection()).await.unwrap_err();
        assert!(
            err.to_string().contains("503"),
            "non-2xx must surface as a retryable error: {err}",
        );
    }

    #[tokio::test]
    async fn empty_batch_is_a_noop() {
        // No server: an empty batch must not attempt any network call.
        let mut sink = OtlpSink::new(OtlpProtocol::Http, "127.0.0.1:1", false, None).unwrap();
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
        let mut sink = OtlpSink::new(OtlpProtocol::Http, &endpoint, true, None).unwrap();
        sink.send(&one_detection()).await.unwrap();
    }

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

    /// Reserve an ephemeral loopback port (closed before the caller binds it).
    fn free_port() -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    async fn wait_reachable(addr: std::net::SocketAddr) {
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("server at {addr} never became reachable");
    }

    #[tokio::test]
    async fn grpc_export_reaches_the_collector() {
        let addr = free_port();
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
        wait_reachable(addr).await;

        let mut sink = OtlpSink::new(OtlpProtocol::Grpc, &addr.to_string(), false, None).unwrap();
        sink.send(&one_detection()).await.unwrap();

        let got = received.lock().await;
        assert_eq!(got.len(), 1, "collector should receive exactly one export");
        let record = &got[0].resource_logs[0].scope_logs[0].log_records[0];
        assert_eq!(record.severity_text, "ERROR");
        server.abort();
    }

    /// A CA, a server leaf (SAN `127.0.0.1` + `localhost`), and a client leaf,
    /// all PEM, for the TLS roundtrip tests.
    struct Certs {
        ca_pem: Vec<u8>,
        server_cert: String,
        server_key: String,
        client_cert: String,
        client_key: String,
    }

    fn mint_certs() -> Certs {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair, KeyUsagePurpose, SanType,
        };

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "rsigma-otlp-test-ca");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem().into_bytes();
        let issuer = Issuer::new(ca_params, ca_key);

        let mut server = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server
            .subject_alt_names
            .push(SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])));
        server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().unwrap();
        let server_cert = server.signed_by(&server_key, &issuer).unwrap();

        let mut client = CertificateParams::new(Vec::<String>::new()).unwrap();
        client
            .distinguished_name
            .push(DnType::CommonName, "rsigma-otlp-test-client");
        client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().unwrap();
        let client_cert = client.signed_by(&client_key, &issuer).unwrap();

        Certs {
            ca_pem,
            server_cert: server_cert.pem(),
            server_key: server_key.serialize_pem(),
            client_cert: client_cert.pem(),
            client_key: client_key.serialize_pem(),
        }
    }

    #[tokio::test]
    async fn grpc_export_over_tls_server_auth() {
        use tonic::transport::{Identity, ServerTlsConfig};

        install_crypto_provider();
        let certs = mint_certs();
        let addr = free_port();
        let received = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let service = Recording {
            received: received.clone(),
        };
        let identity = Identity::from_pem(&certs.server_cert, &certs.server_key);
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .tls_config(ServerTlsConfig::new().identity(identity))
                .unwrap()
                .add_service(LogsServiceServer::new(service))
                .serve(addr)
                .await
                .unwrap();
        });
        wait_reachable(addr).await;

        let tls = OtlpClientTls {
            ca_pem: Some(certs.ca_pem.clone()),
            ..Default::default()
        };
        let mut sink =
            OtlpSink::new(OtlpProtocol::Grpc, &addr.to_string(), false, Some(tls)).unwrap();
        sink.send(&one_detection()).await.unwrap();

        assert_eq!(received.lock().await.len(), 1, "TLS export should arrive");
        server.abort();
    }

    #[tokio::test]
    async fn grpc_export_over_mutual_tls() {
        use tonic::transport::{Certificate, Identity, ServerTlsConfig};

        install_crypto_provider();
        let certs = mint_certs();
        let addr = free_port();
        let received = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let service = Recording {
            received: received.clone(),
        };
        let identity = Identity::from_pem(&certs.server_cert, &certs.server_key);
        let client_ca = Certificate::from_pem(&certs.ca_pem);
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .tls_config(
                    ServerTlsConfig::new()
                        .identity(identity)
                        .client_ca_root(client_ca),
                )
                .unwrap()
                .add_service(LogsServiceServer::new(service))
                .serve(addr)
                .await
                .unwrap();
        });
        wait_reachable(addr).await;

        let tls = OtlpClientTls {
            ca_pem: Some(certs.ca_pem.clone()),
            client_cert_pem: Some(certs.client_cert.clone().into_bytes()),
            client_key_pem: Some(certs.client_key.clone().into_bytes()),
            ..Default::default()
        };
        let mut sink =
            OtlpSink::new(OtlpProtocol::Grpc, &addr.to_string(), false, Some(tls)).unwrap();
        sink.send(&one_detection()).await.unwrap();

        assert_eq!(received.lock().await.len(), 1, "mTLS export should arrive");
        server.abort();
    }

    #[tokio::test]
    async fn http_tls_client_builds_with_ca_and_identity() {
        let certs = mint_certs();
        let tls = OtlpClientTls {
            ca_pem: Some(certs.ca_pem.clone()),
            client_cert_pem: Some(certs.client_cert.clone().into_bytes()),
            client_key_pem: Some(certs.client_key.clone().into_bytes()),
            ..Default::default()
        };
        // Building the sink must parse the CA and client identity and produce
        // an HTTPS reqwest client without error.
        let sink = OtlpSink::new(
            OtlpProtocol::Http,
            "collector.example:4318",
            false,
            Some(tls),
        );
        assert!(
            sink.is_ok(),
            "HTTPS client with CA + mTLS identity should build: {:?}",
            sink.err(),
        );
    }
}
