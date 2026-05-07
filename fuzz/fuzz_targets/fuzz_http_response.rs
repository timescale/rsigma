#![no_main]
use libfuzzer_sys::fuzz_target;
use rsigma_eval::pipeline::sources::DataFormat;
use rsigma_runtime::sources::file::parse_data;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    let _ = parse_data(s, DataFormat::Json);
    let _ = parse_data(s, DataFormat::Yaml);
    let _ = parse_data(s, DataFormat::Lines);
    let _ = parse_data(s, DataFormat::Csv);
});
