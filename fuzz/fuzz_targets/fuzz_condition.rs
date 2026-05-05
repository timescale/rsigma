#![no_main]
use libfuzzer_sys::fuzz_target;
use rsigma_parser::parse_condition;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(expr) = parse_condition(s) {
        let displayed = expr.to_string();
        let _ = parse_condition(&displayed);
    }
});
