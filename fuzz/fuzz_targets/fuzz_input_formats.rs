#![no_main]
use libfuzzer_sys::fuzz_target;
use rsigma_runtime::input::{InputFormat, SyslogConfig, parse_line};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let syslog_config = SyslogConfig::default();

    let _ = parse_line(s, &InputFormat::Auto(syslog_config.clone()));
    let _ = parse_line(s, &InputFormat::Json);
    let _ = parse_line(s, &InputFormat::Syslog(syslog_config));
    let _ = parse_line(s, &InputFormat::Plain);
    let _ = parse_line(s, &InputFormat::Logfmt);
    let _ = parse_line(s, &InputFormat::Cef);
});
