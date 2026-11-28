mod convert;
mod sink;

pub use convert::{
    LogRecordConverter, OtlpLimits, RejectedRecords, count_log_records, count_log_records_json,
    evaluation_results_to_logs_request, log_record_count, logs_request_to_raw_events,
    logs_request_to_raw_events_for,
};
pub use sink::{DEFAULT_OTLP_TIMEOUT, OtlpClientTls, OtlpProtocol, OtlpSink};

pub use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsPartialSuccess, ExportLogsServiceRequest, ExportLogsServiceResponse,
    logs_service_server::{LogsService, LogsServiceServer},
};
