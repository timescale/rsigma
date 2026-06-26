#![no_main]
use libfuzzer_sys::fuzz_target;

// Exercises the alert-pipeline config surface: YAML deserialization plus the
// selector grammar and scope validation in `build_alert_pipeline`. The result
// data path consumes already-validated engine output and is out of scope.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = rsigma_runtime::parse_alert_pipeline_config(s);
});
