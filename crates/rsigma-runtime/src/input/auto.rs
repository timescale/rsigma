//! Auto-detection input adapter.
//!
//! Attempts formats in order:
//! 1. JSON — if `serde_json::from_str` succeeds → [`JsonEvent`]
//! 2. Syslog — if [`syslog_loose`] extracts meaningful fields → [`KvEvent`]
//! 3. Plain text — fallback → [`PlainEvent`]
//!
//! Auto-detection is per-line, so mixed-format input works.
//! logfmt and CEF are **not** part of auto-detect because their syntax is
//! too ambiguous for reliable detection (any line with `=` could be logfmt).

use super::{EventInputDecoded, SyslogConfig, parse_json, parse_plain, parse_syslog};

/// Auto-detect the format of a single line and parse it.
///
/// The `syslog_config` is used when the syslog path is selected (e.g. to
/// honor `--syslog-tz` even in auto-detect mode).
pub fn auto_detect(line: &str, syslog_config: &SyslogConfig) -> EventInputDecoded {
    // 1. Try JSON first (fast: just check if it starts with '{' or '[').
    let trimmed = line.trim_start();
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && let Some(decoded) = parse_json(line)
    {
        return decoded;
    }

    // 2. Try syslog: if the line starts with '<' (priority), it's likely syslog.
    if trimmed.starts_with('<') {
        let decoded = parse_syslog(line, syslog_config);
        // Check if syslog extracted meaningful fields (not just _raw).
        if has_syslog_fields(&decoded) {
            return decoded;
        }
    }

    // 3. Fall back to plain text.
    parse_plain(line)
}

/// Check if the syslog adapter extracted meaningful structured fields
/// beyond just `_raw`. The syslog adapter never returns `Plain`, so only
/// `Kv` and `Json` variants are possible here.
fn has_syslog_fields(decoded: &EventInputDecoded) -> bool {
    match decoded {
        EventInputDecoded::Kv(kv) => kv.fields().iter().any(|(k, _)| k != "_raw"),
        EventInputDecoded::Json(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::Event;

    fn cfg() -> SyslogConfig {
        SyslogConfig::default()
    }

    #[test]
    fn auto_detect_json() {
        let decoded = auto_detect(r#"{"EventID": 1, "host": "web01"}"#, &cfg());
        assert!(matches!(decoded, EventInputDecoded::Json(_)));
        assert!(decoded.get_field("EventID").is_some());
    }

    #[test]
    fn auto_detect_syslog() {
        let decoded = auto_detect(
            "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick",
            &cfg(),
        );
        assert!(
            matches!(
                decoded,
                EventInputDecoded::Kv(_) | EventInputDecoded::Json(_)
            ),
            "Expected Kv or Json for syslog, got Plain"
        );
    }

    #[test]
    fn auto_detect_plain() {
        let decoded = auto_detect("ERROR: something went wrong on server", &cfg());
        assert!(matches!(decoded, EventInputDecoded::Plain(_)));
    }

    #[test]
    fn auto_detect_syslog_wrapped_json() {
        let decoded = auto_detect(
            r#"<134>1 2024-01-15T10:30:00Z host app - - - {"key": "value"}"#,
            &cfg(),
        );
        assert!(
            matches!(decoded, EventInputDecoded::Json(_)),
            "Expected embedded JSON to be extracted"
        );
    }

    #[test]
    fn auto_detect_invalid_json_falls_through() {
        let decoded = auto_detect("{not valid json}", &cfg());
        assert!(matches!(decoded, EventInputDecoded::Plain(_)));
    }

    #[test]
    fn mixed_format_batch() {
        let c = cfg();
        let lines = [
            r#"{"EventID": 1}"#,
            "<34>Oct 11 22:14:15 host su: test",
            "plain log line",
        ];
        let results: Vec<_> = lines.iter().map(|l| auto_detect(l, &c)).collect();
        assert!(matches!(results[0], EventInputDecoded::Json(_)));
        assert!(matches!(
            results[1],
            EventInputDecoded::Kv(_) | EventInputDecoded::Json(_)
        ));
        assert!(matches!(results[2], EventInputDecoded::Plain(_)));
    }

    #[test]
    fn auto_detect_syslog_respects_config() {
        let config = SyslogConfig {
            default_tz_offset_secs: 5 * 3600,
            ..SyslogConfig::default()
        };
        let decoded = auto_detect("<34>Oct 11 22:14:15 mymachine su: test", &config);
        assert!(matches!(
            decoded,
            EventInputDecoded::Kv(_) | EventInputDecoded::Json(_)
        ));
    }

    #[test]
    fn auto_detect_syslog_strips_bom() {
        // A BOM-prefixed RFC 5424 line still extracts structured fields, and
        // the BOM does not leak into any string value.
        let line =
            "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \u{FEFF}an event";
        let decoded = auto_detect(line, &cfg());
        assert!(
            matches!(
                decoded,
                EventInputDecoded::Kv(_) | EventInputDecoded::Json(_)
            ),
            "Expected Kv or Json for syslog, got Plain"
        );
        assert!(decoded.get_field("hostname").is_some());
        assert!(
            !decoded.any_string_value(&|s| s.starts_with('\u{FEFF}')),
            "no string value should retain the BOM"
        );
    }
}
