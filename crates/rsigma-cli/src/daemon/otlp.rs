//! OTLP log intake shared by `POST /v1/logs` and the gRPC `LogsService`.
//!
//! Both transports admit at most [`MAX_CONCURRENT_REQUESTS`] requests at once,
//! refuse a request with more log records than the configured limit before it
//! is decoded, and flatten records within [`OtlpLimits`], reporting the
//! records they reject as an OTLP partial success. The gRPC server checks the
//! bearer token and tenancy from the request headers before it reads the
//! body.

use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::http;
use prost::Message;
use rsigma_eval::TenantId;
use rsigma_runtime::{
    ExportLogsPartialSuccess, ExportLogsServiceRequest, ExportLogsServiceResponse,
    LogRecordConverter, MetricsHook, OtlpLimits, RawEvent, RejectedRecords, count_log_records,
    log_record_count,
};
use tokio::sync::{Semaphore, mpsc};
use tonic::Status;
use tonic::codec::{Codec, CompressionEncoding, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::codegen::{BoxFuture, Service, StdError};
use tonic::server::{NamedService, UnaryService};
use tracing::Instrument;

use super::auth::{ApiAuth, AuthIdentity, IngestRefusal, authorize_ingest};
use super::metrics::Metrics;

/// Most OTLP requests, over both transports together, that are decoded and
/// converted at once. Further requests wait for a slot before their bodies
/// are read.
pub(crate) const MAX_CONCURRENT_REQUESTS: usize = 16;

/// Largest OTLP request after decompression, on both transports. Matches
/// tonic's default decoded-message limit.
pub(crate) const MAX_DECODED_BYTES: usize = 4 * 1024 * 1024;

/// The gRPC method this server answers.
const EXPORT_PATH: &str = "/opentelemetry.proto.collector.logs.v1.LogsService/Export";

/// Records a request forwarded to the engine and the ones it rejected.
pub(crate) struct Forwarded {
    pub accepted: u64,
    pub rejected: RejectedRecords,
}

/// The engine's event channel closed while a request was being forwarded.
pub(crate) struct ChannelClosed;

/// Flatten a request's records within `limits` and forward them to the
/// engine one at a time, counting accepted and rejected records.
pub(crate) async fn forward_records(
    request: &ExportLogsServiceRequest,
    tenant: Option<&TenantId>,
    limits: OtlpLimits,
    tx: &mpsc::Sender<RawEvent>,
    metrics: &Metrics,
    transport: &'static str,
) -> Result<Forwarded, ChannelClosed> {
    let mut converter = LogRecordConverter::new(request, tenant, limits);
    let mut accepted = 0u64;
    let mut outcome = Ok(());
    for event in converter.by_ref() {
        if send_counting_back_pressure(tx, event, metrics)
            .await
            .is_err()
        {
            outcome = Err(ChannelClosed);
            break;
        }
        metrics.on_input_queue_depth_change(1);
        accepted += 1;
    }
    metrics.otlp_log_records.inc_by(accepted);
    let rejected = converter.rejected();
    for (reason, count) in [
        ("too_large", rejected.too_large),
        ("over_budget", rejected.over_budget),
    ] {
        if count > 0 {
            metrics
                .otlp_rejected_log_records
                .with_label_values(&[transport, reason])
                .inc_by(count);
        }
    }
    if rejected.total() > 0 {
        tracing::warn!(
            transport,
            accepted,
            too_large = rejected.too_large,
            over_budget = rejected.over_budget,
            "OTLP log records rejected"
        );
    }
    outcome.map(|()| Forwarded { accepted, rejected })
}

/// Forward one OTLP event to the engine, counting a full channel as
/// back-pressure before waiting for room.
async fn send_counting_back_pressure(
    tx: &mpsc::Sender<RawEvent>,
    event: RawEvent,
    metrics: &Metrics,
) -> Result<(), mpsc::error::SendError<RawEvent>> {
    match tx.try_send(event) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(event)) => {
            metrics.on_back_pressure();
            tx.send(event).await
        }
        Err(mpsc::error::TrySendError::Closed(event)) => Err(mpsc::error::SendError(event)),
    }
}

/// The OTLP partial success that reports `rejected`, or `None` when every
/// record was accepted.
pub(crate) fn partial_success(
    rejected: RejectedRecords,
    limits: &OtlpLimits,
) -> Option<ExportLogsPartialSuccess> {
    if rejected.total() == 0 {
        return None;
    }
    let mut reasons = Vec::new();
    if rejected.too_large > 0 {
        reasons.push(format!(
            "{} larger than {} bytes once flattened",
            rejected.too_large, limits.max_record_bytes
        ));
    }
    if rejected.over_budget > 0 {
        reasons.push(format!(
            "{} past the {}-byte limit for one request",
            rejected.over_budget, limits.max_request_bytes
        ));
    }
    Some(ExportLogsPartialSuccess {
        rejected_log_records: i64::try_from(rejected.total()).unwrap_or(i64::MAX),
        error_message: format!("rejected log records: {}", reasons.join(", ")),
    })
}

/// The message of a request refused for carrying more than `max` records.
pub(crate) fn too_many_records_message(records: usize, max: usize) -> String {
    format!("request carries {records} log records, more than the limit of {max}")
}

/// Axum middleware that holds one of the shared OTLP request slots while
/// `POST /v1/logs` runs, so the body is read only once a slot is free.
pub(crate) async fn admit(
    axum::extract::State(permits): axum::extract::State<Arc<Semaphore>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // The semaphore is never closed, so acquiring only waits.
    let _permit = permits.acquire_owned().await;
    next.run(request).await
}

/// Handles one decoded `Export` call.
pub(crate) struct OtlpLogsGrpcService {
    pub event_tx: mpsc::Sender<RawEvent>,
    pub metrics: Arc<Metrics>,
    pub limits: OtlpLimits,
    /// Whether tenancy is enabled, so every request must carry a tenant.
    pub tenancy: bool,
}

impl OtlpLogsGrpcService {
    async fn export(
        &self,
        request: tonic::Request<ExportLogsServiceRequest>,
    ) -> Result<tonic::Response<ExportLogsServiceResponse>, Status> {
        let tenant = if self.tenancy {
            let tenant = request
                .extensions()
                .get::<AuthIdentity>()
                .filter(|identity| !identity.all_tenants)
                .and_then(|identity| identity.tenant.clone());
            match tenant {
                Some(tenant) => Some(tenant),
                None => {
                    self.metrics
                        .api_auth_failures
                        .with_label_values(&["forbidden"])
                        .inc();
                    self.metrics.on_tenant_rejected("otlp_grpc", "no_tenant");
                    return Err(Status::permission_denied(
                        "tenancy is enabled; the token must name exactly one tenant to ingest",
                    ));
                }
            }
        } else {
            None
        };
        let span = tracing::debug_span!("otlp_ingest", transport = "grpc", encoding = "protobuf");
        async move {
            self.metrics
                .otlp_requests
                .with_label_values(&["grpc", "protobuf"])
                .inc();
            let request = request.into_inner();
            let records = log_record_count(&request);
            if records > self.limits.max_records {
                self.metrics
                    .otlp_errors
                    .with_label_values(&["grpc", "too_many_records"])
                    .inc();
                return Err(Status::resource_exhausted(too_many_records_message(
                    records,
                    self.limits.max_records,
                )));
            }
            let forwarded = forward_records(
                &request,
                tenant.as_ref(),
                self.limits,
                &self.event_tx,
                &self.metrics,
                "grpc",
            )
            .await
            .map_err(|ChannelClosed| {
                self.metrics
                    .otlp_errors
                    .with_label_values(&["grpc", "channel_closed"])
                    .inc();
                Status::unavailable("event channel closed")
            })?;
            tracing::debug!(record_count = forwarded.accepted, "OTLP logs ingested");
            Ok(tonic::Response::new(ExportLogsServiceResponse {
                partial_success: partial_success(forwarded.rejected, &self.limits),
            }))
        }
        .instrument(span)
        .await
    }
}

/// The gRPC `LogsService` server.
///
/// Unlike the generated server it authenticates from the request headers,
/// then waits for one of the shared request slots, before the body is read;
/// it refuses a message over [`MAX_DECODED_BYTES`] (compressed or not) and
/// one with more log records than [`OtlpLimits::max_records`] before decoding
/// it.
#[derive(Clone)]
pub(crate) struct OtlpGrpcServer {
    service: Arc<OtlpLogsGrpcService>,
    auth: Option<Arc<ApiAuth>>,
    permits: Arc<Semaphore>,
}

impl OtlpGrpcServer {
    pub(crate) fn new(
        service: OtlpLogsGrpcService,
        auth: Option<ApiAuth>,
        permits: Arc<Semaphore>,
    ) -> Self {
        Self {
            service: Arc::new(service),
            auth: auth.map(Arc::new),
            permits,
        }
    }
}

impl NamedService for OtlpGrpcServer {
    const NAME: &'static str = "opentelemetry.proto.collector.logs.v1.LogsService";
}

impl<B> Service<http::Request<B>> for OtlpGrpcServer
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        if request.uri().path() != EXPORT_PATH {
            return Box::pin(async { Ok(Status::unimplemented("").into_http()) });
        }
        if let Some(auth) = &self.auth {
            let authorization = request
                .headers()
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            match authorize_ingest(
                auth,
                self.service.tenancy,
                &self.service.metrics,
                "otlp_grpc",
                authorization,
            ) {
                Ok(identity) => {
                    request.extensions_mut().insert(identity);
                }
                Err(refusal) => {
                    let status = refusal_status(refusal);
                    return Box::pin(async move { Ok(status.into_http()) });
                }
            }
        }
        let service = self.service.clone();
        let permits = self.permits.clone();
        Box::pin(async move {
            // The semaphore is never closed, so acquiring only waits.
            let _permit = permits.acquire_owned().await;
            let codec = LogsCodec {
                max_records: service.limits.max_records,
                metrics: service.metrics.clone(),
            };
            let mut grpc = tonic::server::Grpc::new(codec)
                .accept_compressed(CompressionEncoding::Gzip)
                .send_compressed(CompressionEncoding::Gzip)
                .max_decoding_message_size(MAX_DECODED_BYTES);
            Ok(grpc.unary(Export(service), request).await)
        })
    }
}

fn refusal_status(refusal: IngestRefusal) -> Status {
    match refusal {
        IngestRefusal::Unauthorized => Status::unauthenticated("missing or invalid bearer token"),
        IngestRefusal::Forbidden { .. } => {
            Status::permission_denied("token lacks required permission 'events:ingest'")
        }
        IngestRefusal::NoTenant => Status::permission_denied(
            "tenancy is enabled; the token must name exactly one tenant to ingest",
        ),
    }
}

struct Export(Arc<OtlpLogsGrpcService>);

impl UnaryService<ExportLogsServiceRequest> for Export {
    type Response = ExportLogsServiceResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, Status>;

    fn call(&mut self, request: tonic::Request<ExportLogsServiceRequest>) -> Self::Future {
        let service = self.0.clone();
        Box::pin(async move { service.export(request).await })
    }
}

/// Protobuf codec for `Export` that counts a message's log records before
/// decoding it.
struct LogsCodec {
    max_records: usize,
    metrics: Arc<Metrics>,
}

impl Codec for LogsCodec {
    type Encode = ExportLogsServiceResponse;
    type Decode = ExportLogsServiceRequest;
    type Encoder = ResponseEncoder;
    type Decoder = RequestDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        ResponseEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        RequestDecoder {
            max_records: self.max_records,
            metrics: self.metrics.clone(),
        }
    }
}

struct ResponseEncoder;

impl Encoder for ResponseEncoder {
    type Item = ExportLogsServiceResponse;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        item.encode(dst)
            .map_err(|e| Status::internal(format!("encoding the response failed: {e}")))
    }
}

struct RequestDecoder {
    max_records: usize,
    metrics: Arc<Metrics>,
}

impl RequestDecoder {
    fn decode_bytes(&self, bytes: &[u8]) -> Result<ExportLogsServiceRequest, Status> {
        if let Some(records) = count_log_records(bytes)
            && records > self.max_records
        {
            self.metrics
                .otlp_errors
                .with_label_values(&["grpc", "too_many_records"])
                .inc();
            return Err(Status::resource_exhausted(too_many_records_message(
                records,
                self.max_records,
            )));
        }
        ExportLogsServiceRequest::decode(bytes).map_err(|e| {
            self.metrics
                .otlp_errors
                .with_label_values(&["grpc", "decode"])
                .inc();
            Status::internal(e.to_string())
        })
    }
}

impl Decoder for RequestDecoder {
    type Item = ExportLogsServiceRequest;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Status> {
        use prost::bytes::Buf;
        let request = if src.chunk().len() == src.remaining() {
            let request = self.decode_bytes(src.chunk())?;
            src.advance(src.remaining());
            request
        } else {
            let bytes = src.copy_to_bytes(src.remaining());
            self.decode_bytes(&bytes)?
        };
        Ok(Some(request))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::body::Body;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use tower::ServiceExt;

    use super::*;
    use crate::daemon::auth::TokenSpec;

    fn auth_table() -> ApiAuth {
        let tokens = [
            TokenSpec {
                name: "shipper".into(),
                role: Some("ingest".into()),
                permissions: None,
                token_env: "SHIPPER".into(),
                tenant: None,
                all_tenants: false,
            },
            TokenSpec {
                name: "viewer".into(),
                role: Some("reader".into()),
                permissions: None,
                token_env: "VIEWER".into(),
                tenant: None,
                all_tenants: false,
            },
        ];
        ApiAuth::build(&[], &tokens, &[], |key| match key {
            "SHIPPER" => Some("ship-secret".into()),
            "VIEWER" => Some("view-secret".into()),
            _ => None,
        })
        .unwrap()
    }

    struct Harness {
        server: OtlpGrpcServer,
        events: mpsc::Receiver<RawEvent>,
        metrics: Arc<Metrics>,
    }

    fn harness(auth: Option<ApiAuth>, limits: OtlpLimits, channel: usize) -> Harness {
        let (event_tx, events) = mpsc::channel(channel);
        let metrics = Arc::new(Metrics::new());
        let server = OtlpGrpcServer::new(
            OtlpLogsGrpcService {
                event_tx,
                metrics: metrics.clone(),
                limits,
                tenancy: false,
            },
            auth,
            Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
        );
        Harness {
            server,
            events,
            metrics,
        }
    }

    fn records(n: usize) -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".into(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("svc".into())),
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                scope_logs: vec![ScopeLogs {
                    log_records: (0..n)
                        .map(|i| LogRecord {
                            body: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(format!("event-{i}"))),
                            }),
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
    }

    /// One gRPC frame holding `message`, gzip-compressed when `gzip` is set.
    fn frame(message: &[u8], gzip: bool) -> Vec<u8> {
        let payload = if gzip {
            use std::io::Write;
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(message).unwrap();
            enc.finish().unwrap()
        } else {
            message.to_vec()
        };
        let mut out = vec![u8::from(gzip)];
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// A request whose body records whether anything read it.
    fn request(
        token: Option<&str>,
        body: Vec<u8>,
        gzip: bool,
    ) -> (http::Request<Body>, Arc<AtomicBool>) {
        let read = Arc::new(AtomicBool::new(false));
        let flag = read.clone();
        let mut body = Some(bytes::Bytes::from(body));
        let stream = futures::stream::poll_fn(move |_| {
            flag.store(true, Ordering::SeqCst);
            Poll::Ready(body.take().map(Ok::<_, std::io::Error>))
        });
        let mut builder = http::Request::builder()
            .method("POST")
            .uri(format!("http://localhost{EXPORT_PATH}"))
            .header("content-type", "application/grpc")
            .header("te", "trailers");
        if gzip {
            builder = builder.header("grpc-encoding", "gzip");
        }
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        (builder.body(Body::from_stream(stream)).unwrap(), read)
    }

    fn grpc_status(response: &http::Response<tonic::body::Body>) -> Option<i32> {
        response
            .headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
    }

    #[tokio::test]
    async fn an_unauthenticated_maximum_size_gzip_message_is_refused_unread() {
        let h = harness(Some(auth_table()), OtlpLimits::default(), 8);
        let body = frame(&vec![0u8; MAX_DECODED_BYTES], true);
        let (req, read) = request(None, body, true);
        let response = h.server.oneshot(req).await.unwrap();
        assert_eq!(
            grpc_status(&response),
            Some(tonic::Code::Unauthenticated as i32)
        );
        assert!(!read.load(Ordering::SeqCst), "the body must not be read");
        assert_eq!(
            h.metrics
                .api_auth_failures
                .with_label_values(&["unauthorized"])
                .get(),
            1
        );
    }

    #[tokio::test]
    async fn a_token_without_ingest_is_refused_unread() {
        let h = harness(Some(auth_table()), OtlpLimits::default(), 8);
        let (req, read) = request(
            Some("view-secret"),
            frame(&records(1).encode_to_vec(), false),
            false,
        );
        let response = h.server.oneshot(req).await.unwrap();
        assert_eq!(
            grpc_status(&response),
            Some(tonic::Code::PermissionDenied as i32)
        );
        assert!(!read.load(Ordering::SeqCst), "the body must not be read");
    }

    #[tokio::test]
    async fn an_ingest_token_is_admitted() {
        let mut h = harness(Some(auth_table()), OtlpLimits::default(), 8);
        let (req, read) = request(
            Some("ship-secret"),
            frame(&records(2).encode_to_vec(), true),
            true,
        );
        let response = h.server.oneshot(req).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(grpc_status(&response), None, "no error in the headers");
        assert!(read.load(Ordering::SeqCst));
        assert!(h.events.recv().await.unwrap().payload.contains("event-0"));
        assert!(h.events.recv().await.unwrap().payload.contains("event-1"));
        assert_eq!(h.metrics.otlp_log_records.get(), 2);
    }

    #[tokio::test]
    async fn the_server_is_open_without_an_auth_table() {
        let mut h = harness(None, OtlpLimits::default(), 8);
        let (req, _) = request(None, frame(&records(1).encode_to_vec(), false), false);
        let response = h.server.oneshot(req).await.unwrap();
        assert_eq!(grpc_status(&response), None);
        assert!(h.events.recv().await.is_some());
    }

    #[tokio::test]
    async fn too_many_records_are_refused_before_decoding() {
        let limits = OtlpLimits {
            max_records: 3,
            ..OtlpLimits::default()
        };
        let h = harness(None, limits, 8);
        let (req, _) = request(None, frame(&records(4).encode_to_vec(), false), false);
        let response = h.server.oneshot(req).await.unwrap();
        assert_eq!(
            grpc_status(&response),
            Some(tonic::Code::ResourceExhausted as i32)
        );
        assert_eq!(
            h.metrics
                .otlp_errors
                .with_label_values(&["grpc", "too_many_records"])
                .get(),
            1
        );
        assert_eq!(
            h.metrics
                .otlp_errors
                .with_label_values(&["grpc", "decode"])
                .get(),
            0
        );
    }

    #[tokio::test]
    async fn an_over_size_message_is_refused() {
        let h = harness(None, OtlpLimits::default(), 8);
        let (req, _) = request(None, frame(&vec![0u8; MAX_DECODED_BYTES + 1], true), true);
        let response = h.server.oneshot(req).await.unwrap();
        assert_eq!(
            grpc_status(&response),
            Some(tonic::Code::ResourceExhausted as i32)
        );
    }

    #[tokio::test]
    async fn rejected_records_are_reported_as_a_partial_success() {
        let mut request = records(3);
        request.resource_logs[0].scope_logs[0].log_records[1].attributes = vec![KeyValue {
            key: "blob".into(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue("x".repeat(2 * 1024 * 1024))),
            }),
            ..Default::default()
        }];
        let (event_tx, mut events) = mpsc::channel(8);
        let metrics = Arc::new(Metrics::new());
        let service = OtlpLogsGrpcService {
            event_tx,
            metrics: metrics.clone(),
            limits: OtlpLimits::default(),
            tenancy: false,
        };
        let response = service
            .export(tonic::Request::new(request))
            .await
            .unwrap()
            .into_inner();
        let partial = response.partial_success.expect("a partial success");
        assert_eq!(partial.rejected_log_records, 1);
        assert!(
            partial.error_message.contains("1048576"),
            "{}",
            partial.error_message
        );
        assert!(events.recv().await.is_some());
        assert!(events.recv().await.is_some());
        assert_eq!(
            metrics
                .otlp_rejected_log_records
                .with_label_values(&["grpc", "too_large"])
                .get(),
            1
        );
    }

    #[tokio::test]
    async fn an_export_into_a_full_channel_counts_back_pressure() {
        let h = harness(None, OtlpLimits::default(), 1);
        let Harness {
            server,
            mut events,
            metrics,
        } = h;
        let (req, _) = request(None, frame(&records(3).encode_to_vec(), false), false);
        let export = tokio::spawn(server.oneshot(req));
        for _ in 0..3 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            events.recv().await.expect("event");
        }
        let response = export.await.unwrap().unwrap();
        assert_eq!(grpc_status(&response), None);
        assert!(metrics.back_pressure_events.get() >= 1);
    }

    #[tokio::test]
    async fn requests_past_the_slot_limit_wait_unread() {
        let (event_tx, _events) = mpsc::channel(8);
        let permits = Arc::new(Semaphore::new(1));
        let server = OtlpGrpcServer::new(
            OtlpLogsGrpcService {
                event_tx,
                metrics: Arc::new(Metrics::new()),
                limits: OtlpLimits::default(),
                tenancy: false,
            },
            None,
            permits.clone(),
        );
        let held = permits.clone().acquire_owned().await.unwrap();
        let (req, read) = request(None, frame(&records(1).encode_to_vec(), false), false);
        let pending = tokio::spawn(server.oneshot(req));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!pending.is_finished());
        assert!(
            !read.load(Ordering::SeqCst),
            "a waiting request is not read"
        );
        drop(held);
        let response = pending.await.unwrap().unwrap();
        assert_eq!(grpc_status(&response), None);
        assert!(read.load(Ordering::SeqCst));
    }
}
