#![no_main]
use libfuzzer_sys::fuzz_target;
use rsigma_runtime::{
    ExportLogsServiceRequest, LogRecordConverter, OtlpLimits, count_log_records_json,
    log_record_count,
};

// `POST /v1/logs` with `application/json` counts the records of an untrusted
// OTLP/JSON body before decoding it. The count must never be below what
// decoding produces, so a request over the record limit cannot slip past
// it, and conversion of whatever decodes must stay within its limits.
fuzz_target!(|data: &[u8]| {
    let counted = count_log_records_json(data);
    let Ok(request) = serde_json::from_slice::<ExportLogsServiceRequest>(data) else {
        return;
    };
    let records = log_record_count(&request);
    let counted = counted.expect("a body that decodes is counted");
    assert!(
        counted >= records,
        "counted {counted} records, decoded {records}"
    );

    let limits = OtlpLimits {
        max_records: usize::MAX,
        max_record_bytes: 4096,
        max_request_bytes: 64 * 1024,
    };
    let mut converter = LogRecordConverter::new(&request, None, limits);
    let accepted = converter.by_ref().count() as u64;
    assert_eq!(accepted + converter.rejected().total(), records as u64);
});
