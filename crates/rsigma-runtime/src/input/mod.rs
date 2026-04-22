//! Input format adapters for the rsigma runtime.
//!
//! Each adapter parses a raw log line into a typed [`EventInputDecoded`] that
//! implements [`rsigma_eval::Event`]. The [`InputFormat`] enum selects which
//! adapter to use, and [`parse_line`] is the main dispatch function.
//!
//! Always-on formats: JSON/GELF, syslog (RFC 3164/5424), plain text, auto-detect.
//! Feature-gated formats: logfmt (`logfmt`), CEF (`cef`), EVTX (`evtx`).

use std::borrow::Cow;

use rsigma_eval::{Event, EventValue, JsonEvent, KvEvent, PlainEvent};
use serde_json::Value;

mod auto;
#[cfg(feature = "cef")]
mod cef;
mod json;
#[cfg(feature = "logfmt")]
mod logfmt;
mod plain;
mod syslog;

#[cfg(feature = "cef")]
pub use self::cef::parse_cef;
pub use self::json::parse_json;
#[cfg(feature = "logfmt")]
pub use self::logfmt::parse_logfmt;
pub use self::syslog::{SyslogConfig, parse_syslog};
pub use auto::auto_detect;
pub use plain::parse_plain;

/// Selects which input format adapter to use for raw log lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum InputFormat {
    /// Try JSON → syslog → plain (default).
    #[default]
    Auto,
    /// NDJSON / GELF.
    Json,
    /// Syslog RFC 3164 / 5424.
    Syslog(SyslogConfig),
    /// Raw text (keyword matching only).
    Plain,
    /// logfmt `key=value` pairs (requires `logfmt` feature).
    #[cfg(feature = "logfmt")]
    Logfmt,
    /// ArcSight Common Event Format (requires `cef` feature).
    #[cfg(feature = "cef")]
    Cef,
}

/// A decoded event ready for Sigma rule evaluation.
///
/// Static dispatch enum — avoids `Box<dyn Event>` on the hot path while
/// supporting all input formats through a single type.
#[derive(Debug)]
pub enum EventInputDecoded {
    Json(JsonEvent<'static>),
    Kv(KvEvent),
    Plain(PlainEvent),
}

impl Event for EventInputDecoded {
    fn get_field(&self, path: &str) -> Option<EventValue<'_>> {
        match self {
            EventInputDecoded::Json(e) => e.get_field(path),
            EventInputDecoded::Kv(e) => e.get_field(path),
            EventInputDecoded::Plain(e) => e.get_field(path),
        }
    }

    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool {
        match self {
            EventInputDecoded::Json(e) => e.any_string_value(pred),
            EventInputDecoded::Kv(e) => e.any_string_value(pred),
            EventInputDecoded::Plain(e) => e.any_string_value(pred),
        }
    }

    fn all_string_values(&self) -> Vec<Cow<'_, str>> {
        match self {
            EventInputDecoded::Json(e) => e.all_string_values(),
            EventInputDecoded::Kv(e) => e.all_string_values(),
            EventInputDecoded::Plain(e) => e.all_string_values(),
        }
    }

    fn to_json(&self) -> Value {
        match self {
            EventInputDecoded::Json(e) => e.to_json(),
            EventInputDecoded::Kv(e) => e.to_json(),
            EventInputDecoded::Plain(e) => e.to_json(),
        }
    }
}

/// Parse a raw log line using the specified format.
///
/// Returns `None` if the line is empty or whitespace-only.
pub fn parse_line(line: &str, format: &InputFormat) -> Option<EventInputDecoded> {
    if line.trim().is_empty() {
        return None;
    }
    Some(match format {
        InputFormat::Auto => auto_detect(line),
        InputFormat::Json => parse_json(line)?,
        InputFormat::Syslog(config) => parse_syslog(line, config),
        InputFormat::Plain => parse_plain(line),
        #[cfg(feature = "logfmt")]
        InputFormat::Logfmt => parse_logfmt(line),
        #[cfg(feature = "cef")]
        InputFormat::Cef => parse_cef(line)?,
    })
}
