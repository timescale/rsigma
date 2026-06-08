//! Syslog RFC 3164 / 5424 input adapter.
//!
//! Wraps [`syslog_loose::parse_message`] and extracts structured data, header
//! fields, and the message body into a [`KvEvent`].
//!
//! ## Edge cases handled
//!
//! - **Embedded JSON in msg**: if the `msg` field parses as a JSON object,
//!   the adapter returns a `JsonEvent` with the syslog header fields merged in.
//! - **Year resolution (RFC 3164)**: timestamps lack a year; defaults to
//!   current year with December→January rollover logic.
//! - **Timezone**: RFC 3164 may lack timezone info; configurable default (UTC).

use rsigma_eval::{JsonEvent, KvEvent};
use syslog_loose::Message;

use super::EventInputDecoded;

/// Configuration for the syslog adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogConfig {
    /// Default timezone offset in seconds east of UTC for RFC 3164 messages
    /// that lack timezone information.
    pub default_tz_offset_secs: i32,
    /// Strip a leading UTF-8 BOM (`U+FEFF`) from the syslog message body.
    ///
    /// RFC 5424 section 6.4 mandates that a UTF-8 `MSG` begin with a BOM as an
    /// encoding marker, not as content. `syslog_loose` preserves it verbatim,
    /// so without this the BOM leaks into `_raw` (breaking anchored matchers)
    /// and blocks embedded-JSON detection (`serde_json` errors on a leading
    /// BOM). Defaults to `true`; disable to keep the message byte-for-byte.
    pub strip_bom: bool,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            default_tz_offset_secs: 0,
            strip_bom: true,
        }
    }
}

/// Parse a syslog line into an event.
///
/// If the syslog `msg` body contains a valid JSON object, returns a
/// `JsonEvent` with syslog headers merged in. Otherwise returns a `KvEvent`
/// with syslog fields as key-value pairs.
pub fn parse_syslog(line: &str, config: &SyslogConfig) -> EventInputDecoded {
    let tz = chrono::FixedOffset::east_opt(config.default_tz_offset_secs)
        .unwrap_or(chrono::FixedOffset::east_opt(0).unwrap());

    let parsed = syslog_loose::parse_message_with_year_tz(
        line,
        resolve_year,
        Some(tz),
        syslog_loose::Variant::Either,
    );

    build_event_from_message(&parsed, config.strip_bom)
}

/// Build an EventInputDecoded from a parsed syslog message.
///
/// When `strip_bom` is set, a single leading UTF-8 BOM (`U+FEFF`) is removed
/// from the message body before JSON detection and `_raw` extraction. See
/// [`SyslogConfig::strip_bom`].
fn build_event_from_message(parsed: &Message<&str>, strip_bom: bool) -> EventInputDecoded {
    let msg = if strip_bom {
        parsed.msg.strip_prefix('\u{FEFF}').unwrap_or(parsed.msg)
    } else {
        parsed.msg
    };
    let msg_str = msg.trim();

    // Try to parse the message body as JSON.
    if let Ok(mut json_obj) = serde_json::from_str::<serde_json::Value>(msg_str)
        && let Some(obj) = json_obj.as_object_mut()
    {
        inject_syslog_headers(parsed, obj);
        return EventInputDecoded::Json(JsonEvent::owned(serde_json::Value::Object(obj.clone())));
    }

    // Not JSON — build a KvEvent from syslog fields.
    let mut fields = Vec::new();

    if let Some(ts) = &parsed.timestamp {
        fields.push(("timestamp".to_string(), ts.to_rfc3339()));
    }
    if let Some(host) = &parsed.hostname {
        fields.push(("hostname".to_string(), host.to_string()));
    }
    if let Some(app) = &parsed.appname {
        fields.push(("appname".to_string(), app.to_string()));
    }
    if let Some(pid) = &parsed.procid {
        fields.push(("procid".to_string(), pid.to_string()));
    }
    if let Some(mid) = &parsed.msgid {
        fields.push(("msgid".to_string(), mid.to_string()));
    }
    if let Some(facility) = &parsed.facility {
        fields.push(("facility".to_string(), format!("{facility:?}")));
    }
    if let Some(severity) = &parsed.severity {
        fields.push(("severity".to_string(), format!("{severity:?}")));
    }

    // Extract RFC 5424 structured data key-value pairs.
    for elem in &parsed.structured_data {
        for (key, val) in elem.params() {
            let prefixed_key = format!("{}.{}", elem.id, key);
            fields.push((prefixed_key, val));
        }
    }

    if !msg_str.is_empty() {
        fields.push(("_raw".to_string(), msg_str.to_string()));
    }

    EventInputDecoded::Kv(KvEvent::new(fields))
}

/// Inject syslog header fields into a JSON object (for embedded-JSON case).
///
/// Includes all fields that the KvEvent path extracts: timestamp, hostname,
/// appname, procid, msgid, facility, severity, and RFC 5424 structured data.
fn inject_syslog_headers(
    parsed: &Message<&str>,
    obj: &mut serde_json::Map<String, serde_json::Value>,
) {
    if let Some(ts) = &parsed.timestamp {
        obj.entry("syslog_timestamp")
            .or_insert_with(|| serde_json::Value::String(ts.to_rfc3339()));
    }
    if let Some(host) = &parsed.hostname {
        obj.entry("syslog_hostname")
            .or_insert_with(|| serde_json::Value::String(host.to_string()));
    }
    if let Some(app) = &parsed.appname {
        obj.entry("syslog_appname")
            .or_insert_with(|| serde_json::Value::String(app.to_string()));
    }
    if let Some(pid) = &parsed.procid {
        obj.entry("syslog_procid")
            .or_insert_with(|| serde_json::Value::String(pid.to_string()));
    }
    if let Some(mid) = &parsed.msgid {
        obj.entry("syslog_msgid")
            .or_insert_with(|| serde_json::Value::String(mid.to_string()));
    }
    if let Some(facility) = &parsed.facility {
        obj.entry("syslog_facility")
            .or_insert_with(|| serde_json::Value::String(format!("{facility:?}")));
    }
    if let Some(severity) = &parsed.severity {
        obj.entry("syslog_severity")
            .or_insert_with(|| serde_json::Value::String(format!("{severity:?}")));
    }

    // RFC 5424 structured data parameters.
    for elem in &parsed.structured_data {
        for (key, val) in elem.params() {
            let prefixed_key = format!("sd.{}.{}", elem.id, key);
            obj.entry(prefixed_key)
                .or_insert_with(|| serde_json::Value::String(val));
        }
    }
}

/// Year resolver for RFC 3164 timestamps.
///
/// `IncompleteDate` is `(month, day, hour, minute, second)`. Uses the current
/// year, with December→January rollover: if the parsed month is January and
/// we're in December, assume next year (and vice versa).
fn resolve_year(date: syslog_loose::IncompleteDate) -> i32 {
    let now = chrono::Utc::now();
    let current_year = chrono::Datelike::year(&now);
    let current_month = chrono::Datelike::month(&now);
    let parsed_month = date.0;

    if current_month == 12 && parsed_month == 1 {
        current_year + 1
    } else if current_month == 1 && parsed_month == 12 {
        current_year - 1
    } else {
        current_year
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::Event;

    #[test]
    fn rfc5424_basic() {
        let line = "<165>1 2024-01-15T10:30:00.000Z web01 myapp 1234 ID47 - Connection established";
        let decoded = parse_syslog(line, &SyslogConfig::default());
        assert!(decoded.get_field("hostname").is_some());
        assert!(decoded.get_field("appname").is_some());
        assert!(decoded.get_field("_raw").is_some());
    }

    #[test]
    fn rfc3164_basic() {
        let line = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";
        let decoded = parse_syslog(line, &SyslogConfig::default());
        assert!(decoded.any_string_value(&|s| s.contains("su root")));
    }

    #[test]
    fn syslog_wrapped_json() {
        let line = r#"<134>1 2024-01-15T10:30:00Z docker01 myapp 9876 MSGID1 - {"EventID": 1, "user": "admin"}"#;
        let decoded = parse_syslog(line, &SyslogConfig::default());
        assert!(decoded.get_field("EventID").is_some());
        assert!(decoded.get_field("user").is_some());
        // Syslog headers should be merged into the JSON object.
        assert!(decoded.get_field("syslog_hostname").is_some());
        assert!(decoded.get_field("syslog_appname").is_some());
    }

    #[test]
    fn rfc5424_structured_data() {
        let line = r#"<165>1 2024-01-15T10:30:00Z host app - ID1 [exampleSDID@32473 iut="3" eventSource="App" eventID="1011"] message"#;
        let decoded = parse_syslog(line, &SyslogConfig::default());
        let json = decoded.to_json();
        let json_str = serde_json::to_string(&json).unwrap();
        assert!(json_str.contains("eventSource") || json_str.contains("_raw"));
    }

    #[test]
    fn empty_msg() {
        let line = "<13>1 2024-01-15T10:30:00Z host app - - -";
        let decoded = parse_syslog(line, &SyslogConfig::default());
        assert!(decoded.get_field("hostname").is_some());
    }

    #[test]
    fn custom_timezone() {
        let config = SyslogConfig {
            default_tz_offset_secs: 5 * 3600, // UTC+5
            ..SyslogConfig::default()
        };
        let line = "<34>Oct 11 22:14:15 mymachine su: test message";
        let decoded = parse_syslog(line, &config);
        assert!(decoded.any_string_value(&|s| s.contains("test message")));
    }

    #[test]
    fn rfc5424_strips_bom() {
        // RFC 5424 UTF-8 MSG begins with a BOM (U+FEFF) as an encoding marker.
        let line =
            "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \u{FEFF}an event";
        let decoded = parse_syslog(line, &SyslogConfig::default());
        let raw = decoded
            .get_field("_raw")
            .and_then(|v| v.as_str().map(|s| s.into_owned()))
            .expect("_raw present");
        assert!(!raw.starts_with('\u{FEFF}'), "BOM should be stripped");
        assert_eq!(raw, "an event");
    }

    #[test]
    fn rfc5424_bom_json_detected() {
        // A BOM-prefixed JSON payload must still be detected as embedded JSON;
        // serde_json errors on a leading BOM, so this would degrade to a
        // KvEvent without the strip.
        let line = "<134>1 2024-01-15T10:30:00Z docker01 myapp 9876 MSGID1 - \u{FEFF}{\"EventID\": 1, \"user\": \"admin\"}";
        let decoded = parse_syslog(line, &SyslogConfig::default());
        assert!(
            matches!(decoded, EventInputDecoded::Json(_)),
            "BOM-prefixed JSON should be parsed as JSON"
        );
        assert!(decoded.get_field("EventID").is_some());
        assert!(decoded.get_field("user").is_some());
        assert!(decoded.get_field("syslog_hostname").is_some());
    }

    #[test]
    fn rfc5424_keep_bom_when_disabled() {
        let config = SyslogConfig {
            strip_bom: false,
            ..SyslogConfig::default()
        };
        let line =
            "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \u{FEFF}an event";
        let decoded = parse_syslog(line, &config);
        let raw = decoded
            .get_field("_raw")
            .and_then(|v| v.as_str().map(|s| s.into_owned()))
            .expect("_raw present");
        assert!(
            raw.starts_with('\u{FEFF}'),
            "BOM should be preserved when stripping is disabled"
        );
    }

    #[test]
    fn bom_only_message() {
        // A message consisting solely of a BOM collapses to empty after the
        // strip, so no _raw field is emitted.
        let line = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \u{FEFF}";
        let decoded = parse_syslog(line, &SyslogConfig::default());
        assert!(decoded.get_field("_raw").is_none());
        assert!(decoded.get_field("hostname").is_some());
    }
}
