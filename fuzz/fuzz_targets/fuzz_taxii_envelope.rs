#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let mut opts = rstix::ParseOptions::default();
    opts.max_object_count = 32;
    opts.max_nesting_depth = 8;
    opts.max_string_length = 256;
    let _ = rstix::parse_envelope(data, &opts);
});
