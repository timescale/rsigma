#![no_main]
use libfuzzer_sys::fuzz_target;

// Exercises the enrichers-config surface: YAML deserialization plus key
// validation, template namespaces, scope, and extract-type parsing in
// `parse_enrichers_config`. Building enrichers does I/O and is out of scope.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = rsigma_runtime::parse_enrichers_config(s);
});
