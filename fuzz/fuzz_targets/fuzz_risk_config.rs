#![no_main]
use libfuzzer_sys::fuzz_target;

// Exercises the risk-config surface: YAML deserialization plus the object
// selector grammar, scope validation, and incident-threshold validation in
// `build_risk_layer`. The result data path consumes already-validated engine
// output and is out of scope.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = rsigma_runtime::parse_risk_config(s);
});
