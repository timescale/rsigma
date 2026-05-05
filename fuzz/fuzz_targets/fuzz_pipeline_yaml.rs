#![no_main]
use libfuzzer_sys::fuzz_target;
use rsigma_eval::parse_pipeline;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let _ = parse_pipeline(s);
});
