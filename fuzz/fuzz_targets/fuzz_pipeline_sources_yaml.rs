#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(pipeline) = rsigma_eval::parse_pipeline(s) {
        let _ = pipeline.is_dynamic();
        let _ = pipeline.dynamic_references();
    }
});
