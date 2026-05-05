#![no_main]
use libfuzzer_sys::fuzz_target;
use rsigma_eval::matcher::sigma_string_to_regex;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // First byte selects flags; rest is the pattern string
    let flags = data[0];
    let Ok(pattern) = std::str::from_utf8(&data[1..]) else {
        return;
    };

    let case_insensitive = flags & 0x01 != 0;
    let multiline = flags & 0x02 != 0;
    let dotall = flags & 0x04 != 0;

    // Fuzz direct regex compilation (mirrors build_regex internals)
    let mut full_pattern = String::new();
    let mut flag_str = String::new();
    if case_insensitive {
        flag_str.push('i');
    }
    if multiline {
        flag_str.push('m');
    }
    if dotall {
        flag_str.push('s');
    }
    if !flag_str.is_empty() {
        full_pattern.push_str(&format!("(?{flag_str})"));
    }
    full_pattern.push_str(pattern);
    let _ = regex::Regex::new(&full_pattern);

    // Fuzz sigma_string_to_regex: parse wildcards then compile
    let sigma_str = rsigma_parser::SigmaString::new(pattern);
    let regex_pattern = sigma_string_to_regex(&sigma_str.parts, case_insensitive);
    let _ = regex::Regex::new(&regex_pattern);
});
