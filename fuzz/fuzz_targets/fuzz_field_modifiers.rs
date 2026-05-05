#![no_main]
use libfuzzer_sys::fuzz_target;
use rsigma_parser::{SigmaString, Timespan, parse_field_spec};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    let _ = parse_field_spec(s);

    let sigma_str = SigmaString::new(s);
    let displayed = sigma_str.to_string();
    let _ = SigmaString::new(&displayed);

    let _ = Timespan::parse(s);
});
