#![no_main]
use libfuzzer_sys::fuzz_target;
use rsigma_eval::pipeline::sources::ExtractExpr;
use rsigma_runtime::sources::extract::apply_extract;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    let Some((expr, json_str)) = s.split_once('\0') else {
        return;
    };

    let Ok(json_data) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return;
    };

    let _ = apply_extract(&json_data, &ExtractExpr::Cel(expr.to_string()));
});
