#![no_main]
use libfuzzer_sys::fuzz_target;

// The disposition parser and validator are the triage feedback loop's only
// untrusted-input surface: a POST body or a pull-source payload (a single JSON
// object, a JSON array, or NDJSON). Neither parsing nor validating may panic.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(records) = rsigma_runtime::parse_dispositions(s) {
        for raw in records {
            let _ = rsigma_runtime::Disposition::from_raw(raw, 0);
        }
    }
});
