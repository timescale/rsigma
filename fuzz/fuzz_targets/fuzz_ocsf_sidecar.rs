#![no_main]

use libfuzzer_sys::fuzz_target;
use rsigma_runtime::ocsf::{dedup_summary_finding_opts, OcsfOptions, OcsfVersion};

/// Exercise the dedup sidecar serializer on arbitrary JSON.
fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let opts = if data.first().copied().unwrap_or(0) % 2 == 0 {
        OcsfOptions::new(OcsfVersion::V1_1_0)
    } else {
        OcsfOptions::new(OcsfVersion::V1_3_0)
    };
    let finding = dedup_summary_finding_opts(&value, opts);
    let _ = serde_json::to_vec(&finding);
});
