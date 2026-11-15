#![no_main]

use libfuzzer_sys::fuzz_target;
use rsigma_runtime::{DnsRecordType, SUPPORTED_DNS_RECORD_TYPES};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let raw = SUPPORTED_DNS_RECORD_TYPES[usize::from(selector) % SUPPORTED_DNS_RECORD_TYPES.len()];
    let Ok(record_type) = DnsRecordType::parse(raw) else {
        return;
    };

    let _ = record_type.format_answers(rest);

    if let Ok(key) = std::str::from_utf8(rest) {
        let _ = record_type.query_name(key);
        let ptr = DnsRecordType::parse("PTR").expect("PTR is supported");
        let _ = ptr.query_name(key);
    }
});
