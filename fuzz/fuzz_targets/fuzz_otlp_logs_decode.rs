#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message;
use rsigma_runtime::{
    ExportLogsServiceRequest, LogRecordConverter, OtlpLimits, count_log_records, log_record_count,
};

// `POST /v1/logs` and the gRPC `LogsService` count the records of untrusted
// protobuf before decoding it, then flatten every log record to a JSON event
// within the OTLP limits. Counting and decoding must fail cleanly, the count
// must match what decoding produces, and conversion must stay within its
// limits and account for every record.
fuzz_target!(|data: &[u8]| {
    let counted = count_log_records(data);
    let Ok(request) = ExportLogsServiceRequest::decode(data) else {
        return;
    };
    let records = log_record_count(&request);
    assert_eq!(
        counted,
        Some(records),
        "the pre-decode count matches the decoded request"
    );

    // Small limits so the fuzzer reaches both rejection paths.
    let limits = OtlpLimits {
        max_records: usize::MAX,
        max_record_bytes: 4096,
        max_request_bytes: 64 * 1024,
    };
    let mut converter = LogRecordConverter::new(&request, None, limits);
    let mut produced = 0usize;
    let mut accepted = 0u64;
    for event in converter.by_ref() {
        serde_json::from_str::<serde_json::Value>(&event.payload)
            .expect("a converted OTLP log record is valid JSON");
        assert!(event.payload.len() <= limits.max_record_bytes);
        produced += event.payload.len();
        accepted += 1;
    }
    assert!(produced <= limits.max_request_bytes);
    assert_eq!(accepted + converter.rejected().total(), records as u64);
});
