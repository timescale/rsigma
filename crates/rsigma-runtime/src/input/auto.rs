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
pub fn auto_detect(line: &str) -> EventInputDecoded {
    // 1. Try JSON first (fast: just check if it starts with '{' or '[').
    let trimmed = line.trim_start();
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && let Some(decoded) = parse_json(line)
    {
        return decoded;
    }

    // 2. Try syslog: if the line starts with '<' (priority), it's likely syslog.
    if trimmed.starts_with('<') {
        let decoded = parse_syslog(line, &SyslogConfig::default());
        // Check if syslog extracted meaningful fields (not just _raw).
        if has_syslog_fields(&decoded) {
            return decoded;
        }
    }

    // 3. Fall back to plain text.
    parse_plain(line)
}

/// Check if the syslog adapter extracted meaningful structured fields
/// beyond just `_raw`.
fn has_syslog_fields(decoded: &EventInputDecoded) -> bool {
    match decoded {
        EventInputDecoded::Kv(kv) => kv.fields().iter().any(|(k, _)| k != "_raw"),
        // If it produced a JsonEvent (embedded JSON), that's meaningful.
        EventInputDecoded::Json(_) => true,
        EventInputDecoded::Plain(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::Event;

    #[test]
    fn auto_detect_json() {
        let decoded = auto_detect(r#"{"EventID": 1, "host": "web01"}"#);
        assert!(matches!(decoded, EventInputDecoded::Json(_)));
        assert!(decoded.get_field("EventID").is_some());
    }

    #[test]
    fn auto_detect_syslog() {
        let decoded = auto_detect("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick");
        // Should detect as syslog, not plain.
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
        let decoded = auto_detect("ERROR: something went wrong on server");
        assert!(matches!(decoded, EventInputDecoded::Plain(_)));
    }

    #[test]
    fn auto_detect_syslog_wrapped_json() {
        let decoded = auto_detect(r#"<134>1 2024-01-15T10:30:00Z host app - - - {"key": "value"}"#);
        // Should extract the embedded JSON.
        assert!(
            matches!(decoded, EventInputDecoded::Json(_)),
            "Expected embedded JSON to be extracted"
        );
    }

    #[test]
    fn auto_detect_invalid_json_falls_through() {
        let decoded = auto_detect("{not valid json}");
        // Doesn't start with '<' so not syslog either → plain.
        assert!(matches!(decoded, EventInputDecoded::Plain(_)));
    }

    #[test]
    fn mixed_format_batch() {
        let lines = vec![
            r#"{"EventID": 1}"#,
            "<34>Oct 11 22:14:15 host su: test",
            "plain log line",
        ];
        let results: Vec<_> = lines.iter().map(|l| auto_detect(l)).collect();
        assert!(matches!(results[0], EventInputDecoded::Json(_)));
        assert!(matches!(
            results[1],
            EventInputDecoded::Kv(_) | EventInputDecoded::Json(_)
        ));
        assert!(matches!(results[2], EventInputDecoded::Plain(_)));
    }
}
