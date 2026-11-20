mod convert;
mod sink;

pub use convert::{
    evaluation_results_to_logs_request, logs_request_to_raw_events, logs_request_to_raw_events_for,
};
pub use sink::{DEFAULT_OTLP_TIMEOUT, OtlpClientTls, OtlpProtocol, OtlpSink};

pub use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
    logs_service_server::{LogsService, LogsServiceServer},
};
