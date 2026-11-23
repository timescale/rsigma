//! OTLP output sink: export evaluation results to an OpenTelemetry collector
//! over OTLP/HTTP (protobuf) or OTLP/gRPC.

use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsPartialSuccess, ExportLogsServiceRequest, ExportLogsServiceResponse,
    logs_service_client::LogsServiceClient,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

use prost::Message;
use tonic::codec::CompressionEncoding;
use tonic::transport::Channel;

use rsigma_eval::ProcessResult;

use super::convert::{evaluation_results_to_logs_request, ocsf_findings_to_logs_request};
use crate::error::RuntimeError;
use crate::io::{DeliveryContext, SinkFormat, ocsf_finding};
use crate::log_throttle::WarnThrottle;
use crate::metrics::{MetricsHook, NoopMetrics};

/// Cap on the OTLP/HTTP response bytes read to look for a partial success.
/// A longer body is drained no further and treated as a full success.
const RESPONSE_CAP: usize = 64 * 1024;

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

/// Default deadline for one OTLP export attempt, matching the webhook sink.
pub const DEFAULT_OTLP_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on establishing a connection to the collector, for both transports.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP/2 keepalive ping interval and ack deadline on the gRPC channel, so a
/// collector that stops answering is detected even between exports.
const GRPC_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const GRPC_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Exports detection and correlation results to an OTLP collector.
///
/// In the default format each result becomes a log record whose body is the
/// rule title and whose attributes are the native result fields. With
/// [`SinkFormat::Ocsf`] the body is the OCSF Detection Finding as a JSON string.
/// The record keeps the native attribute set.
///
/// The gRPC channel connects lazily, so a collector that is not yet reachable
/// does not fail daemon startup; delivery failures are surfaced to the
/// delivery layer, which retries and ultimately routes to the DLQ. Each export
/// attempt is bounded by a deadline ([`DEFAULT_OTLP_TIMEOUT`] unless set with
/// [`OtlpSink::with_timeout`]), so a collector that accepts the connection but
/// never replies fails the attempt instead of stalling delivery.
///
/// A drained batch of results goes out in one export request. Log records a
/// collector rejects in a partial success are counted and logged, not
/// retried, as the OTLP specification asks.
pub struct OtlpSink {
    transport: Transport,
    timeout: Duration,
    format: SinkFormat,
    ocsf: crate::ocsf::OcsfOptions,
    tenant_filter: Option<rsigma_eval::TenantId>,
    metrics: Arc<dyn MetricsHook>,
    rejected_log: WarnThrottle,
}

impl Drop for OtlpSink {
    fn drop(&mut self) {
        let suppressed = self.rejected_log.take_pending();
        if suppressed > 0 {
            tracing::warn!(suppressed, "OTLP collector rejected log records");
        }
    }
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
                    .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?
                    .connect_timeout(CONNECT_TIMEOUT)
                    .http2_keep_alive_interval(GRPC_KEEPALIVE_INTERVAL)
                    .keep_alive_timeout(GRPC_KEEPALIVE_TIMEOUT);
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
        Ok(OtlpSink {
            transport,
            timeout: DEFAULT_OTLP_TIMEOUT,
            format: SinkFormat::default(),
            ocsf: crate::ocsf::OcsfOptions::default(),
            tenant_filter: None,
            metrics: Arc::new(NoopMetrics),
            rejected_log: WarnThrottle::new(WarnThrottle::DEFAULT_INTERVAL),
        })
    }

    /// Report log records the collector rejects to `metrics`.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<dyn MetricsHook>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Select the log-record body: the rule title ([`SinkFormat::Ndjson`], the
    /// default) or the OCSF finding ([`SinkFormat::Ocsf`]). Both keep the
    /// native attributes.
    #[must_use]
    pub fn with_format(mut self, format: SinkFormat) -> Self {
        self.format = format;
        self
    }

    /// OCSF serializer options when [`Self::format`] is [`SinkFormat::Ocsf`].
    #[must_use]
    pub fn with_ocsf_options(mut self, ocsf: crate::ocsf::OcsfOptions) -> Self {
        self.ocsf = ocsf;
        self
    }

    /// The log-record encoding this sink exports.
    pub fn format(&self) -> SinkFormat {
        self.format
    }

    /// OCSF serializer options when [`Self::format`] is [`SinkFormat::Ocsf`].
    pub fn ocsf_options(&self) -> &crate::ocsf::OcsfOptions {
        &self.ocsf
    }

    /// Set the deadline for one export attempt. An attempt that exceeds it
    /// fails with a retryable timeout error.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The deadline for one export attempt.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Only export results of `tenant`.
    #[must_use]
    pub fn with_tenant_filter(mut self, tenant: Option<rsigma_eval::TenantId>) -> Self {
        self.tenant_filter = tenant;
        self
    }

    /// Serialize and export a batch of results to the collector.
    pub async fn send(&mut self, result: &ProcessResult) -> Result<(), RuntimeError> {
        self.send_inner(result, None).await
    }

    /// Export a batch whose OCSF identity and time come from `ctx`, so they
    /// match every other sink the same dispatch reaches.
    pub(crate) async fn send_with_context(
        &mut self,
        result: &ProcessResult,
        ctx: &DeliveryContext,
    ) -> Result<(), RuntimeError> {
        self.send_inner(result, Some(ctx)).await
    }

    async fn send_inner(
        &mut self,
        result: &ProcessResult,
        ctx: Option<&DeliveryContext>,
    ) -> Result<(), RuntimeError> {
        match self.build_request(result, ctx) {
            Some(request) => self.export(request).await,
            None => Ok(()),
        }
    }

    /// Export a batch of deliveries in one request, one outcome per delivery.
    ///
    /// When the request fails, every delivery with records in it fails, and
    /// the worker retries each on its own.
    pub(crate) async fn send_batch(
        &mut self,
        items: &[(&ProcessResult, &DeliveryContext)],
    ) -> Vec<Result<(), RuntimeError>> {
        let items: Vec<(&ProcessResult, Option<&DeliveryContext>)> = items
            .iter()
            .map(|(result, ctx)| (*result, Some(*ctx)))
            .collect();
        let Some((request, records)) = self.build_batch_request(&items) else {
            return items.iter().map(|_| Ok(())).collect();
        };
        match self.export(request).await {
            Ok(()) => items.iter().map(|_| Ok(())).collect(),
            Err(err) => records
                .into_iter()
                .map(|count| {
                    if count == 0 {
                        Ok(())
                    } else {
                        Err(err.duplicate())
                    }
                })
                .collect(),
        }
    }

    /// The export request for the results this sink delivers, or `None` when
    /// the tenant filter leaves nothing.
    fn build_request(
        &self,
        result: &ProcessResult,
        ctx: Option<&DeliveryContext>,
    ) -> Option<ExportLogsServiceRequest> {
        self.build_batch_request(&[(result, ctx)])
            .map(|(request, _)| request)
    }

    /// One export request for every result of every delivery this sink
    /// delivers, with each delivery's record count, or `None` when the
    /// tenant filter leaves nothing.
    fn build_batch_request(
        &self,
        items: &[(&ProcessResult, Option<&DeliveryContext>)],
    ) -> Option<(ExportLogsServiceRequest, Vec<usize>)> {
        // Each record keeps its delivery and original position, so a finding
        // uid matches every other sink.
        let mut identities = Vec::new();
        let mut filtered: ProcessResult = Vec::new();
        let mut records = Vec::with_capacity(items.len());
        for (result, ctx) in items {
            let before = filtered.len();
            for (index, r) in result.iter().enumerate() {
                if self
                    .tenant_filter
                    .as_ref()
                    .is_none_or(|tenant| r.header.tenant_id.as_ref() == Some(tenant))
                {
                    identities.push((*ctx, index));
                    filtered.push(r.clone());
                }
            }
            records.push(filtered.len() - before);
        }
        if filtered.is_empty() {
            return None;
        }
        let request = match self.format {
            SinkFormat::Ndjson => evaluation_results_to_logs_request(&filtered),
            SinkFormat::Ocsf => {
                let ocsf = &self.ocsf;
                ocsf_findings_to_logs_request(&filtered, |index, r| {
                    let (ctx, position) = identities[index];
                    ocsf_finding(r, ctx.map(|c| (c, position)), ocsf)
                })
            }
        };
        Some((request, records))
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
        let timeout = self.timeout;
        let partial = tokio::time::timeout(timeout, self.export_unbounded(request))
            .await
            .unwrap_or_else(|_| {
                Err(RuntimeError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "OTLP export timed out after {}",
                        humantime::format_duration(timeout)
                    ),
                )))
            })?;
        if let Some(partial) = partial {
            self.report_partial_success(partial);
        }
        Ok(())
    }

    /// Count and log the records a collector rejected. They are not retried.
    fn report_partial_success(&mut self, partial: ExportLogsPartialSuccess) {
        let Ok(rejected) = u64::try_from(partial.rejected_log_records) else {
            return;
        };
        if rejected == 0 {
            return;
        }
        self.metrics.on_sink_otlp_rejected_records("otlp", rejected);
        if let Some(n) = self.rejected_log.record(Instant::now()) {
            tracing::warn!(
                rejected,
                error = %partial.error_message,
                suppressed = n - 1,
                "OTLP collector rejected log records"
            );
        }
    }

    /// Send one export request, returning the collector's partial success
    /// when its response carries one.
    async fn export_unbounded(
        &mut self,
        request: ExportLogsServiceRequest,
    ) -> Result<Option<ExportLogsPartialSuccess>, RuntimeError> {
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
                Ok(http_partial_success(response).await)
            }
            Transport::Grpc { client } => {
                let response = client
                    .export(request)
                    .await
                    .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?;
                Ok(response.into_inner().partial_success)
            }
        }
    }
}

/// The partial success in a protobuf OTLP/HTTP response body, if any. A body
/// that is empty, too long, or not protobuf counts as a full success.
async fn http_partial_success(mut response: reqwest::Response) -> Option<ExportLogsPartialSuccess> {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        if body.len() + chunk.len() > RESPONSE_CAP {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    ExportLogsServiceResponse::decode(body.as_slice())
        .ok()?
        .partial_success
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
    let mut builder = reqwest::Client::builder().connect_timeout(CONNECT_TIMEOUT);
    let Some(tls) = tls else {
        return builder
            .build()
            .map_err(|e| RuntimeError::Io(std::io::Error::other(e)));
    };
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
                tenant_id: None,
                level: Some(rsigma_parser::Level::High),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
                ruleset: None,
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

    #[test]
    fn default_timeout_applies_until_overridden() {
        let sink = OtlpSink::new(OtlpProtocol::Http, "127.0.0.1:1", false, None).unwrap();
        assert_eq!(sink.timeout(), DEFAULT_OTLP_TIMEOUT);
        let sink = sink.with_timeout(Duration::from_secs(3));
        assert_eq!(sink.timeout(), Duration::from_secs(3));
    }

    fn assert_timed_out(err: RuntimeError) {
        match err {
            RuntimeError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e}"),
            other => panic!("expected a retryable timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn http_export_times_out_on_a_silent_collector() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/logs"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
            .mount(&server)
            .await;

        let endpoint = server.address().to_string();
        let mut sink = OtlpSink::new(OtlpProtocol::Http, &endpoint, false, None)
            .unwrap()
            .with_timeout(Duration::from_millis(200));
        let started = std::time::Instant::now();
        let err = sink.send(&one_detection()).await.unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_timed_out(err);
    }

    #[tokio::test]
    async fn grpc_export_times_out_when_the_collector_never_replies() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let holder = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });

        let mut sink = OtlpSink::new(OtlpProtocol::Grpc, &addr.to_string(), false, None)
            .unwrap()
            .with_timeout(Duration::from_millis(200));
        let started = std::time::Instant::now();
        let err = sink.send(&one_detection()).await.unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_timed_out(err);
        holder.abort();
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

    #[tokio::test]
    async fn ocsf_export_carries_the_delivery_finding_as_body() {
        use opentelemetry_proto::tonic::common::v1::any_value;

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

        let mut sink = OtlpSink::new(OtlpProtocol::Grpc, &addr.to_string(), false, None)
            .unwrap()
            .with_format(SinkFormat::Ocsf)
            .with_ocsf_options(crate::ocsf::OcsfOptions::new(
                crate::ocsf::OcsfVersion::V1_3_0,
            ));
        let ctx = DeliveryContext::new();
        sink.send_with_context(&one_detection(), &ctx)
            .await
            .unwrap();

        let got = received.lock().await;
        let record = &got[0].resource_logs[0].scope_logs[0].log_records[0];
        assert_eq!(record.severity_text, "ERROR");
        assert!(
            record.attributes.iter().any(|kv| kv.key == "rule_title"),
            "native attributes stay on the record: {:?}",
            record.attributes,
        );
        let Some(any_value::Value::StringValue(raw)) =
            record.body.as_ref().and_then(|b| b.value.as_ref())
        else {
            panic!(
                "the body must be the finding JSON string: {:?}",
                record.body
            );
        };
        let finding: serde_json::Value = serde_json::from_str(raw).expect("finding JSON");
        assert_eq!(finding["class_uid"], 2004);
        assert_eq!(finding["finding_info"]["uid"], ctx.finding_uid(0));
        assert_eq!(finding["metadata"]["version"], "1.3.0");
        server.abort();
    }

    #[tokio::test]
    async fn a_tenant_filter_keeps_the_original_finding_uid() {
        use opentelemetry_proto::tonic::common::v1::any_value;

        let tenanted = |tenant: &str| {
            let mut r = one_detection().remove(0);
            r.header.tenant_id = Some(rsigma_eval::TenantId::new(tenant).unwrap());
            r
        };
        let batch = vec![tenanted("a"), tenanted("b")];
        let sink = OtlpSink::new(OtlpProtocol::Grpc, "127.0.0.1:4317", false, None)
            .unwrap()
            .with_format(SinkFormat::Ocsf)
            .with_tenant_filter(Some(rsigma_eval::TenantId::new("b").unwrap()));
        let ctx = DeliveryContext::new();
        let request = sink.build_request(&batch, Some(&ctx)).expect("tenant b");
        let records = &request.resource_logs[0].scope_logs[0].log_records;
        assert_eq!(records.len(), 1);
        let Some(any_value::Value::StringValue(raw)) =
            records[0].body.as_ref().and_then(|b| b.value.as_ref())
        else {
            panic!("finding body");
        };
        let finding: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_eq!(finding["finding_info"]["uid"], ctx.finding_uid(1));
    }

    #[tokio::test]
    async fn a_batch_goes_out_in_one_request_with_each_delivery_identity() {
        use opentelemetry_proto::tonic::common::v1::any_value;

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

        let mut sink = OtlpSink::new(OtlpProtocol::Grpc, &addr.to_string(), false, None)
            .unwrap()
            .with_format(SinkFormat::Ocsf);
        let deliveries = [one_detection(), one_detection(), one_detection()];
        let contexts = [
            DeliveryContext::new(),
            DeliveryContext::new(),
            DeliveryContext::new(),
        ];
        let items: Vec<(&ProcessResult, &DeliveryContext)> =
            deliveries.iter().zip(contexts.iter()).collect();
        let outcomes = sink.send_batch(&items).await;
        assert!(outcomes.iter().all(Result::is_ok));

        let got = received.lock().await;
        assert_eq!(got.len(), 1, "one export request for the batch");
        let records = &got[0].resource_logs[0].scope_logs[0].log_records;
        assert_eq!(records.len(), 3);
        for (record, ctx) in records.iter().zip(&contexts) {
            let Some(any_value::Value::StringValue(raw)) =
                record.body.as_ref().and_then(|b| b.value.as_ref())
            else {
                panic!("finding body");
            };
            let finding: serde_json::Value = serde_json::from_str(raw).unwrap();
            assert_eq!(finding["finding_info"]["uid"], ctx.finding_uid(0));
        }
        server.abort();
    }

    #[tokio::test]
    async fn a_failed_batch_request_is_retried_one_delivery_at_a_time() {
        use crate::io::{Dispatcher, OnFull, Sink};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/logs"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/logs"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let sink = OtlpSink::new(
            OtlpProtocol::Http,
            &server.address().to_string(),
            false,
            None,
        )
        .unwrap();
        let (ack_tx, _ack_rx) = tokio::sync::mpsc::unbounded_channel();
        let cfg = crate::io::DeliveryConfig {
            backoff_base: Duration::from_millis(1),
            backoff_max: Duration::from_millis(5),
            ..Default::default()
        };
        let dispatcher = Dispatcher::spawn(
            vec![(Sink::Otlp(Box::new(sink)), OnFull::Block, cfg)],
            None,
            ack_tx,
            Arc::new(NoopMetrics),
        );
        for _ in 0..3 {
            dispatcher.dispatch(one_detection(), Vec::new()).await;
        }
        dispatcher.shutdown().await;

        let requests = server.received_requests().await.unwrap();
        let records: Vec<usize> = requests
            .iter()
            .map(|request| {
                ExportLogsServiceRequest::decode(request.body.as_slice())
                    .unwrap()
                    .resource_logs[0]
                    .scope_logs[0]
                    .log_records
                    .len()
            })
            .collect();
        assert_eq!(
            records,
            [3, 1, 1, 1],
            "one batch request, then one retry each"
        );
    }

    #[derive(Default)]
    struct RejectedCounter(std::sync::atomic::AtomicU64);

    impl MetricsHook for RejectedCounter {
        fn on_sink_otlp_rejected_records(&self, sink: &str, count: u64) {
            assert_eq!(sink, "otlp");
            self.0.fetch_add(count, std::sync::atomic::Ordering::SeqCst);
        }
        fn on_parse_error(&self) {}
        fn on_events_processed(&self, _: u64) {}
        fn on_detection_matches(&self, _: u64) {}
        fn on_correlation_matches(&self, _: u64) {}
        fn observe_processing_latency(&self, _: f64) {}
        fn on_input_queue_depth_change(&self, _: i64) {}
        fn on_back_pressure(&self) {}
        fn observe_batch_size(&self, _: u64) {}
        fn on_output_queue_depth_change(&self, _: i64) {}
        fn observe_pipeline_latency(&self, _: f64) {}
        fn set_correlation_state_entries(&self, _: u64) {}
    }

    #[tokio::test]
    async fn a_partial_success_counts_the_rejected_records_without_retrying() {
        let server = MockServer::start().await;
        let response = ExportLogsServiceResponse {
            partial_success: Some(ExportLogsPartialSuccess {
                rejected_log_records: 2,
                error_message: "records too large".to_string(),
            }),
        };
        Mock::given(method("POST"))
            .and(path("/v1/logs"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/x-protobuf")
                    .set_body_bytes(response.encode_to_vec()),
            )
            .expect(2)
            .mount(&server)
            .await;

        let counter = Arc::new(RejectedCounter::default());
        let mut sink = OtlpSink::new(
            OtlpProtocol::Http,
            &server.address().to_string(),
            false,
            None,
        )
        .unwrap()
        .with_metrics(counter.clone());
        sink.send(&one_detection()).await.unwrap();
        sink.send(&one_detection()).await.unwrap();

        assert_eq!(counter.0.load(std::sync::atomic::Ordering::SeqCst), 4);
        assert_eq!(
            sink.rejected_log.take_pending(),
            1,
            "the first rejection is logged and the second waits for the next warning"
        );
    }

    #[tokio::test]
    async fn a_grpc_partial_success_is_reported() {
        #[derive(Clone)]
        struct Rejecting;

        #[tonic::async_trait]
        impl LogsService for Rejecting {
            async fn export(
                &self,
                _request: tonic::Request<ExportLogsServiceRequest>,
            ) -> Result<tonic::Response<ExportLogsServiceResponse>, tonic::Status> {
                Ok(tonic::Response::new(ExportLogsServiceResponse {
                    partial_success: Some(ExportLogsPartialSuccess {
                        rejected_log_records: 1,
                        error_message: String::new(),
                    }),
                }))
            }
        }

        let addr = free_port();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(LogsServiceServer::new(Rejecting))
                .serve(addr)
                .await
                .unwrap();
        });
        wait_reachable(addr).await;

        let counter = Arc::new(RejectedCounter::default());
        let mut sink = OtlpSink::new(OtlpProtocol::Grpc, &addr.to_string(), false, None)
            .unwrap()
            .with_metrics(counter.clone());
        sink.send(&one_detection()).await.unwrap();
        assert_eq!(counter.0.load(std::sync::atomic::Ordering::SeqCst), 1);
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
