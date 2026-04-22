//! Compiled matchers for zero-allocation hot-path evaluation.
//!
//! Each `CompiledMatcher` variant is pre-compiled at rule load time.
//! At evaluation time, `matches()` performs the comparison against an
//! [`EventValue`] from the event with no dynamic dispatch or allocation.

use std::net::IpAddr;

use chrono::{Datelike, Timelike};
use ipnet::IpNet;
use regex::Regex;

use crate::event::{Event, EventValue};

/// A pre-compiled matcher for a single value comparison.
///
/// All string matchers store their values in the form needed for comparison
/// (Unicode-lowercased for case-insensitive). The `case_insensitive` flag
/// controls whether the input is lowercased before comparison.
#[derive(Debug, Clone)]
pub enum CompiledMatcher {
    // -- String matchers --
    Exact {
        value: String,
        case_insensitive: bool,
    },
    Contains {
        value: String,
        case_insensitive: bool,
    },
    StartsWith {
        value: String,
        case_insensitive: bool,
    },
    EndsWith {
        value: String,
        case_insensitive: bool,
    },
    Regex(Regex),

    // -- Network --
    Cidr(IpNet),

    // -- Numeric --
    NumericEq(f64),
    NumericGt(f64),
    NumericGte(f64),
    NumericLt(f64),
    NumericLte(f64),

    // -- Special --
    Exists(bool),
    FieldRef {
        field: String,
        case_insensitive: bool,
    },
    Null,
    BoolEq(bool),

    // -- Expand --
    Expand {
        template: Vec<ExpandPart>,
        case_insensitive: bool,
    },

    // -- Timestamp --
    TimestampPart {
        part: TimePart,
        inner: Box<CompiledMatcher>,
    },

    // -- Negation --
    Not(Box<CompiledMatcher>),

    // -- Composite --
    AnyOf(Vec<CompiledMatcher>),
    AllOf(Vec<CompiledMatcher>),
}

/// A part of an expand template.
#[derive(Debug, Clone)]
pub enum ExpandPart {
    Literal(String),
    Placeholder(String),
}

/// Which time component to extract from a timestamp.
#[derive(Debug, Clone, Copy)]
pub enum TimePart {
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
}

impl CompiledMatcher {
    /// Check if this matcher matches an [`EventValue`] from an event.
    #[inline]
    pub fn matches(&self, value: &EventValue, event: &impl Event) -> bool {
        match self {
            // -- String matchers --
            CompiledMatcher::Exact {
                value: expected,
                case_insensitive,
            } => match_str_value(value, |s| {
                if *case_insensitive {
                    s.to_lowercase() == *expected
                } else {
                    s == expected
                }
            }),

            CompiledMatcher::Contains {
                value: needle,
                case_insensitive,
            } => match_str_value(value, |s| {
                if *case_insensitive {
                    s.to_lowercase().contains(needle.as_str())
                } else {
                    s.contains(needle.as_str())
                }
            }),

            CompiledMatcher::StartsWith {
                value: prefix,
                case_insensitive,
            } => match_str_value(value, |s| {
                if *case_insensitive {
                    s.to_lowercase().starts_with(prefix.as_str())
                } else {
                    s.starts_with(prefix.as_str())
                }
            }),

            CompiledMatcher::EndsWith {
                value: suffix,
                case_insensitive,
            } => match_str_value(value, |s| {
                if *case_insensitive {
                    s.to_lowercase().ends_with(suffix.as_str())
                } else {
                    s.ends_with(suffix.as_str())
                }
            }),

            CompiledMatcher::Regex(re) => match_str_value(value, |s| re.is_match(s)),

            // -- Network --
            CompiledMatcher::Cidr(net) => match_str_value(value, |s| {
                s.parse::<IpAddr>().is_ok_and(|ip| net.contains(&ip))
            }),

            // -- Numeric --
            CompiledMatcher::NumericEq(n) => {
                match_numeric_value(value, |v| (v - n).abs() < f64::EPSILON)
            }
            CompiledMatcher::NumericGt(n) => match_numeric_value(value, |v| v > *n),
            CompiledMatcher::NumericGte(n) => match_numeric_value(value, |v| v >= *n),
            CompiledMatcher::NumericLt(n) => match_numeric_value(value, |v| v < *n),
            CompiledMatcher::NumericLte(n) => match_numeric_value(value, |v| v <= *n),

            // -- Special --
            CompiledMatcher::Exists(expect) => {
                let exists = !value.is_null();
                exists == *expect
            }

            CompiledMatcher::FieldRef {
                field: ref_field,
                case_insensitive,
            } => {
                if let Some(ref_value) = event.get_field(ref_field) {
                    if *case_insensitive {
                        match (value.as_str(), ref_value.as_str()) {
                            (Some(a), Some(b)) => a.to_lowercase() == b.to_lowercase(),
                            _ => value == &ref_value,
                        }
                    } else {
                        value == &ref_value
                    }
                } else {
                    false
                }
            }

            CompiledMatcher::Null => value.is_null(),

            CompiledMatcher::BoolEq(expected) => match value {
                EventValue::Bool(b) => b == expected,
                EventValue::Str(s) => match s.to_lowercase().as_str() {
                    "true" | "1" | "yes" => *expected,
                    "false" | "0" | "no" => !*expected,
                    _ => false,
                },
                _ => false,
            },

            // -- Expand --
            CompiledMatcher::Expand {
                template,
                case_insensitive,
            } => {
                let expanded = expand_template(template, event);
                match_str_value(value, |s| {
                    if *case_insensitive {
                        s.to_lowercase() == expanded.to_lowercase()
                    } else {
                        s == expanded
                    }
                })
            }

            // -- Timestamp --
            CompiledMatcher::TimestampPart { part, inner } => {
                match extract_timestamp_part(value, *part) {
                    Some(n) => {
                        let num_val = EventValue::Int(n);
                        inner.matches(&num_val, event)
                    }
                    None => false,
                }
            }

            // -- Negation --
            CompiledMatcher::Not(inner) => !inner.matches(value, event),

            // -- Composite --
            CompiledMatcher::AnyOf(matchers) => matchers.iter().any(|m| m.matches(value, event)),
            CompiledMatcher::AllOf(matchers) => matchers.iter().all(|m| m.matches(value, event)),
        }
    }

    /// Check if this matcher matches any string value in the event.
    /// Used for keyword detection (field-less matching).
    #[inline]
    pub fn matches_keyword(&self, event: &impl Event) -> bool {
        event.any_string_value(&|s| self.matches_str(s))
    }

    /// Check if this matcher matches a plain `&str` value.
    fn matches_str(&self, s: &str) -> bool {
        match self {
            CompiledMatcher::Exact {
                value: expected,
                case_insensitive,
            } => {
                if *case_insensitive {
                    s.to_lowercase() == *expected
                } else {
                    s == expected
                }
            }
            CompiledMatcher::Contains {
                value: needle,
                case_insensitive,
            } => {
                if *case_insensitive {
                    s.to_lowercase().contains(needle.as_str())
                } else {
                    s.contains(needle.as_str())
                }
            }
            CompiledMatcher::StartsWith {
                value: prefix,
                case_insensitive,
            } => {
                if *case_insensitive {
                    s.to_lowercase().starts_with(prefix.as_str())
                } else {
                    s.starts_with(prefix.as_str())
                }
            }
            CompiledMatcher::EndsWith {
                value: suffix,
                case_insensitive,
            } => {
                if *case_insensitive {
                    s.to_lowercase().ends_with(suffix.as_str())
                } else {
                    s.ends_with(suffix.as_str())
                }
            }
            CompiledMatcher::Regex(re) => re.is_match(s),
            CompiledMatcher::Not(inner) => !inner.matches_str(s),
            CompiledMatcher::AnyOf(matchers) => matchers.iter().any(|m| m.matches_str(s)),
            CompiledMatcher::AllOf(matchers) => matchers.iter().all(|m| m.matches_str(s)),
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn match_str_value(value: &EventValue, pred: impl Fn(&str) -> bool) -> bool {
    match_str_value_ref(value, &pred)
}

fn match_str_value_ref(value: &EventValue, pred: &dyn Fn(&str) -> bool) -> bool {
    match value {
        EventValue::Str(s) => pred(s),
        EventValue::Int(n) => pred(&n.to_string()),
        EventValue::Float(f) => pred(&f.to_string()),
        EventValue::Bool(b) => pred(if *b { "true" } else { "false" }),
        EventValue::Array(arr) => arr.iter().any(|v| match_str_value_ref(v, pred)),
        _ => false,
    }
}

fn match_numeric_value(value: &EventValue, pred: impl Fn(f64) -> bool) -> bool {
    match_numeric_value_ref(value, &pred)
}

fn match_numeric_value_ref(value: &EventValue, pred: &dyn Fn(f64) -> bool) -> bool {
    match value {
        EventValue::Int(n) => pred(*n as f64),
        EventValue::Float(f) => pred(*f),
        EventValue::Str(s) => s.parse::<f64>().is_ok_and(pred),
        EventValue::Array(arr) => arr.iter().any(|v| match_numeric_value_ref(v, pred)),
        _ => false,
    }
}

/// Convert a [`SigmaString`](rsigma_parser::SigmaString) to a regex pattern string.
pub fn sigma_string_to_regex(
    parts: &[rsigma_parser::value::StringPart],
    case_insensitive: bool,
) -> String {
    use rsigma_parser::value::{SpecialChar, StringPart};

    let mut pattern = String::new();
    if case_insensitive {
        pattern.push_str("(?i)");
    }
    pattern.push('^');
    for part in parts {
        match part {
            StringPart::Plain(text) => {
                pattern.push_str(&regex::escape(text));
            }
            StringPart::Special(SpecialChar::WildcardMulti) => {
                pattern.push_str(".*");
            }
            StringPart::Special(SpecialChar::WildcardSingle) => {
                pattern.push('.');
            }
        }
    }
    pattern.push('$');
    pattern
}

// ---------------------------------------------------------------------------
// Expand helpers
// ---------------------------------------------------------------------------

fn expand_template(template: &[ExpandPart], event: &impl Event) -> String {
    let mut result = String::new();
    for part in template {
        match part {
            ExpandPart::Literal(s) => result.push_str(s),
            ExpandPart::Placeholder(field) => {
                if let Some(val) = event.get_field(field)
                    && let Some(s) = val.as_str()
                {
                    result.push_str(&s);
                }
            }
        }
    }
    result
}

/// Parse an expand template string like `C:\Users\%user%\AppData` into parts.
pub fn parse_expand_template(s: &str) -> Vec<ExpandPart> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_placeholder = false;
    let mut placeholder = String::new();

    for ch in s.chars() {
        if ch == '%' {
            if in_placeholder {
                if !placeholder.is_empty() {
                    parts.push(ExpandPart::Placeholder(placeholder.clone()));
                    placeholder.clear();
                }
                in_placeholder = false;
            } else {
                if !current.is_empty() {
                    parts.push(ExpandPart::Literal(current.clone()));
                    current.clear();
                }
                in_placeholder = true;
            }
        } else if in_placeholder {
            placeholder.push(ch);
        } else {
            current.push(ch);
        }
    }

    if in_placeholder && !placeholder.is_empty() {
        current.push('%');
        current.push_str(&placeholder);
    }
    if !current.is_empty() {
        parts.push(ExpandPart::Literal(current));
    }

    parts
}

// ---------------------------------------------------------------------------
// Timestamp part helpers
// ---------------------------------------------------------------------------

fn extract_timestamp_part(value: &EventValue, part: TimePart) -> Option<i64> {
    match value {
        EventValue::Str(s) => parse_timestamp_str(s, part),
        EventValue::Int(n) => {
            let secs = if *n > 1_000_000_000_000 { n / 1000 } else { *n };
            let dt = chrono::DateTime::from_timestamp(secs, 0)?;
            Some(extract_part_from_datetime(&dt, part))
        }
        EventValue::Float(f) => {
            let secs = *f as i64;
            let secs = if secs > 1_000_000_000_000 {
                secs / 1000
            } else {
                secs
            };
            let dt = chrono::DateTime::from_timestamp(secs, 0)?;
            Some(extract_part_from_datetime(&dt, part))
        }
        _ => None,
    }
}

fn parse_timestamp_str(ts_str: &str, part: TimePart) -> Option<i64> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts_str) {
        return Some(extract_part_from_datetime(&dt.to_utc(), part));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%dT%H:%M:%S") {
        let dt = naive.and_utc();
        return Some(extract_part_from_datetime(&dt, part));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%d %H:%M:%S") {
        let dt = naive.and_utc();
        return Some(extract_part_from_datetime(&dt, part));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%dT%H:%M:%S%.f") {
        let dt = naive.and_utc();
        return Some(extract_part_from_datetime(&dt, part));
    }
    None
}

fn extract_part_from_datetime(dt: &chrono::DateTime<chrono::Utc>, part: TimePart) -> i64 {
    match part {
        TimePart::Minute => dt.minute() as i64,
        TimePart::Hour => dt.hour() as i64,
        TimePart::Day => dt.day() as i64,
        TimePart::Week => dt.iso_week().week() as i64,
        TimePart::Month => dt.month() as i64,
        TimePart::Year => dt.year() as i64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::JsonEvent;
    use serde_json::json;

    fn empty_event() -> serde_json::Value {
        json!({})
    }

    #[test]
    fn test_exact_case_insensitive() {
        let m = CompiledMatcher::Exact {
            value: "whoami".into(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("whoami".into()), &event));
        assert!(m.matches(&EventValue::Str("WHOAMI".into()), &event));
        assert!(m.matches(&EventValue::Str("Whoami".into()), &event));
        assert!(!m.matches(&EventValue::Str("other".into()), &event));
    }

    #[test]
    fn test_exact_case_sensitive() {
        let m = CompiledMatcher::Exact {
            value: "whoami".into(),
            case_insensitive: false,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("whoami".into()), &event));
        assert!(!m.matches(&EventValue::Str("WHOAMI".into()), &event));
    }

    #[test]
    fn test_contains() {
        let m = CompiledMatcher::Contains {
            value: "admin".to_lowercase(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("superadminuser".into()), &event));
        assert!(m.matches(&EventValue::Str("ADMIN".into()), &event));
        assert!(!m.matches(&EventValue::Str("user".into()), &event));
    }

    #[test]
    fn test_starts_with() {
        let m = CompiledMatcher::StartsWith {
            value: "cmd".into(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("cmd.exe".into()), &event));
        assert!(m.matches(&EventValue::Str("CMD.EXE".into()), &event));
        assert!(!m.matches(&EventValue::Str("xcmd".into()), &event));
    }

    #[test]
    fn test_ends_with() {
        let m = CompiledMatcher::EndsWith {
            value: ".exe".into(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("cmd.exe".into()), &event));
        assert!(m.matches(&EventValue::Str("CMD.EXE".into()), &event));
        assert!(!m.matches(&EventValue::Str("cmd.bat".into()), &event));
    }

    #[test]
    fn test_regex() {
        let re = Regex::new("(?i)^test.*value$").unwrap();
        let m = CompiledMatcher::Regex(re);
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("testXYZvalue".into()), &event));
        assert!(m.matches(&EventValue::Str("TESTvalue".into()), &event));
        assert!(!m.matches(&EventValue::Str("notamatch".into()), &event));
    }

    #[test]
    fn test_cidr() {
        let net: IpNet = "10.0.0.0/8".parse().unwrap();
        let m = CompiledMatcher::Cidr(net);
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("10.1.2.3".into()), &event));
        assert!(!m.matches(&EventValue::Str("192.168.1.1".into()), &event));
    }

    #[test]
    fn test_numeric() {
        let m = CompiledMatcher::NumericGte(100.0);
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Int(100), &event));
        assert!(m.matches(&EventValue::Int(200), &event));
        assert!(!m.matches(&EventValue::Int(50), &event));
        assert!(m.matches(&EventValue::Str("150".into()), &event));
    }

    #[test]
    fn test_null() {
        let m = CompiledMatcher::Null;
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Null, &event));
        assert!(!m.matches(&EventValue::Str("".into()), &event));
    }

    #[test]
    fn test_bool() {
        let m = CompiledMatcher::BoolEq(true);
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Bool(true), &event));
        assert!(!m.matches(&EventValue::Bool(false), &event));
        assert!(m.matches(&EventValue::Str("true".into()), &event));
    }

    #[test]
    fn test_field_ref() {
        let e = json!({"src": "10.0.0.1", "dst": "10.0.0.1"});
        let event = JsonEvent::borrow(&e);
        let m = CompiledMatcher::FieldRef {
            field: "dst".into(),
            case_insensitive: true,
        };
        assert!(m.matches(&EventValue::Str("10.0.0.1".into()), &event));
    }

    #[test]
    fn test_any_of() {
        let m = CompiledMatcher::AnyOf(vec![
            CompiledMatcher::Exact {
                value: "a".into(),
                case_insensitive: false,
            },
            CompiledMatcher::Exact {
                value: "b".into(),
                case_insensitive: false,
            },
        ]);
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("a".into()), &event));
        assert!(m.matches(&EventValue::Str("b".into()), &event));
        assert!(!m.matches(&EventValue::Str("c".into()), &event));
    }

    #[test]
    fn test_all_of() {
        let m = CompiledMatcher::AllOf(vec![
            CompiledMatcher::Contains {
                value: "admin".into(),
                case_insensitive: false,
            },
            CompiledMatcher::Contains {
                value: "user".into(),
                case_insensitive: false,
            },
        ]);
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("adminuser".into()), &event));
        assert!(!m.matches(&EventValue::Str("admin".into()), &event));
    }

    #[test]
    fn test_array_value_matching() {
        let m = CompiledMatcher::Exact {
            value: "target".into(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        let arr = EventValue::Array(vec![
            EventValue::Str("other".into()),
            EventValue::Str("target".into()),
            EventValue::Str("more".into()),
        ]);
        assert!(m.matches(&arr, &event));
        let arr2 = EventValue::Array(vec![
            EventValue::Str("other".into()),
            EventValue::Str("nope".into()),
        ]);
        assert!(!m.matches(&arr2, &event));
    }

    #[test]
    fn test_number_coercion_to_string() {
        let m = CompiledMatcher::Exact {
            value: "42".into(),
            case_insensitive: false,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Int(42), &event));
    }

    // =========================================================================
    // Unicode case folding tests
    // =========================================================================

    #[test]
    fn test_exact_unicode_case_insensitive() {
        let m = CompiledMatcher::Exact {
            value: "ärzte".to_lowercase(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("ÄRZTE".into()), &event));
        assert!(m.matches(&EventValue::Str("Ärzte".into()), &event));
        assert!(m.matches(&EventValue::Str("ärzte".into()), &event));
    }

    #[test]
    fn test_contains_unicode_case_insensitive() {
        let m = CompiledMatcher::Contains {
            value: "ñ".to_lowercase(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("España".into()), &event));
        assert!(m.matches(&EventValue::Str("ESPAÑA".into()), &event));
    }

    #[test]
    fn test_startswith_unicode_case_insensitive() {
        let m = CompiledMatcher::StartsWith {
            value: "über".to_lowercase(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("Übersicht".into()), &event));
        assert!(m.matches(&EventValue::Str("ÜBERSICHT".into()), &event));
        assert!(!m.matches(&EventValue::Str("not-uber".into()), &event));
    }

    #[test]
    fn test_endswith_unicode_case_insensitive() {
        let m = CompiledMatcher::EndsWith {
            value: "ção".to_lowercase(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("Aplicação".into()), &event));
        assert!(m.matches(&EventValue::Str("APLICAÇÃO".into()), &event));
        assert!(!m.matches(&EventValue::Str("Aplicacao".into()), &event));
    }

    #[test]
    fn test_greek_case_insensitive() {
        let m = CompiledMatcher::Exact {
            value: "σίγμα".to_lowercase(),
            case_insensitive: true,
        };
        let e = empty_event();
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("ΣΊΓΜΑ".into()), &event));
        assert!(m.matches(&EventValue::Str("σίγμα".into()), &event));
    }

    // =========================================================================
    // Expand modifier tests
    // =========================================================================

    #[test]
    fn test_parse_expand_template() {
        let parts = parse_expand_template("C:\\Users\\%user%\\AppData");
        assert_eq!(parts.len(), 3);
        assert!(matches!(&parts[0], ExpandPart::Literal(s) if s == "C:\\Users\\"));
        assert!(matches!(&parts[1], ExpandPart::Placeholder(s) if s == "user"));
        assert!(matches!(&parts[2], ExpandPart::Literal(s) if s == "\\AppData"));
    }

    #[test]
    fn test_parse_expand_template_no_placeholders() {
        let parts = parse_expand_template("just a literal");
        assert_eq!(parts.len(), 1);
        assert!(matches!(&parts[0], ExpandPart::Literal(s) if s == "just a literal"));
    }

    #[test]
    fn test_parse_expand_template_multiple_placeholders() {
        let parts = parse_expand_template("%a%:%b%");
        assert_eq!(parts.len(), 3);
        assert!(matches!(&parts[0], ExpandPart::Placeholder(s) if s == "a"));
        assert!(matches!(&parts[1], ExpandPart::Literal(s) if s == ":"));
        assert!(matches!(&parts[2], ExpandPart::Placeholder(s) if s == "b"));
    }

    #[test]
    fn test_expand_matcher() {
        let template = parse_expand_template("C:\\Users\\%user%\\Downloads");
        let m = CompiledMatcher::Expand {
            template,
            case_insensitive: true,
        };
        let e = json!({"user": "admin", "path": "C:\\Users\\admin\\Downloads"});
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(
            &EventValue::Str("C:\\Users\\admin\\Downloads".into()),
            &event
        ));
        assert!(!m.matches(
            &EventValue::Str("C:\\Users\\other\\Downloads".into()),
            &event
        ));
    }

    #[test]
    fn test_expand_matcher_missing_field() {
        let template = parse_expand_template("%user%@%domain%");
        let m = CompiledMatcher::Expand {
            template,
            case_insensitive: false,
        };
        let e = json!({"user": "admin"});
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("admin@".into()), &event));
    }

    // =========================================================================
    // Timestamp part tests
    // =========================================================================

    #[test]
    fn test_timestamp_part_hour() {
        let m = CompiledMatcher::TimestampPart {
            part: TimePart::Hour,
            inner: Box::new(CompiledMatcher::NumericEq(12.0)),
        };
        let e = json!({});
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("2024-07-10T12:30:00Z".into()), &event));
        assert!(!m.matches(&EventValue::Str("2024-07-10T15:30:00Z".into()), &event));
    }

    #[test]
    fn test_timestamp_part_month() {
        let m = CompiledMatcher::TimestampPart {
            part: TimePart::Month,
            inner: Box::new(CompiledMatcher::NumericEq(7.0)),
        };
        let e = json!({});
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("2024-07-10T12:30:00Z".into()), &event));
        assert!(!m.matches(&EventValue::Str("2024-08-10T12:30:00Z".into()), &event));
    }

    #[test]
    fn test_timestamp_part_day() {
        let m = CompiledMatcher::TimestampPart {
            part: TimePart::Day,
            inner: Box::new(CompiledMatcher::NumericEq(10.0)),
        };
        let e = json!({});
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("2024-07-10T12:30:00Z".into()), &event));
        assert!(!m.matches(&EventValue::Str("2024-07-15T12:30:00Z".into()), &event));
    }

    #[test]
    fn test_timestamp_part_year() {
        let m = CompiledMatcher::TimestampPart {
            part: TimePart::Year,
            inner: Box::new(CompiledMatcher::NumericEq(2024.0)),
        };
        let e = json!({});
        let event = JsonEvent::borrow(&e);
        assert!(m.matches(&EventValue::Str("2024-07-10T12:30:00Z".into()), &event));
        assert!(!m.matches(&EventValue::Str("2023-07-10T12:30:00Z".into()), &event));
    }

    #[test]
    fn test_timestamp_part_from_epoch() {
        let m = CompiledMatcher::TimestampPart {
            part: TimePart::Hour,
            inner: Box::new(CompiledMatcher::NumericEq(12.0)),
        };
        let e = json!({});
        let event = JsonEvent::borrow(&e);
        // 2024-07-10T12:30:00Z = 1720614600
        assert!(m.matches(&EventValue::Int(1720614600), &event));
    }
}

// =============================================================================
// Property-based tests
// =============================================================================

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::event::JsonEvent;
    use proptest::prelude::*;
    use rsigma_parser::value::{SpecialChar, StringPart};
    use serde_json::json;

    fn arb_string_parts() -> impl Strategy<Value = Vec<StringPart>> {
        prop::collection::vec(
            prop_oneof![
                "[[:print:]]{0,20}".prop_map(StringPart::Plain),
                Just(StringPart::Special(SpecialChar::WildcardMulti)),
                Just(StringPart::Special(SpecialChar::WildcardSingle)),
            ],
            0..8,
        )
    }

    proptest! {
        #[test]
        fn wildcard_regex_always_valid(parts in arb_string_parts(), ci in any::<bool>()) {
            let pattern = sigma_string_to_regex(&parts, ci);
            prop_assert!(regex::Regex::new(&pattern).is_ok(),
                "sigma_string_to_regex produced invalid regex: {}", pattern);
        }
    }

    proptest! {
        #[test]
        fn plain_text_matches_itself(text in "[[:print:]]{1,30}") {
            let parts = vec![StringPart::Plain(text.clone())];
            let pattern = sigma_string_to_regex(&parts, false);
            let re = regex::Regex::new(&pattern).unwrap();
            prop_assert!(re.is_match(&text),
                "plain text should match itself: text={:?}, pattern={}", text, pattern);
        }
    }

    proptest! {
        #[test]
        fn plain_text_rejects_different_string(
            text in "[a-zA-Z0-9]{1,10}",
            other in "[a-zA-Z0-9]{1,10}",
        ) {
            prop_assume!(text != other);
            let parts = vec![StringPart::Plain(text.clone())];
            let pattern = sigma_string_to_regex(&parts, false);
            let re = regex::Regex::new(&pattern).unwrap();
            prop_assert!(!re.is_match(&other),
                "plain {:?} should not match {:?}", text, other);
        }
    }

    proptest! {
        #[test]
        fn exact_ci_symmetric(s in "[[:alpha:]]{1,20}") {
            let m = CompiledMatcher::Exact {
                value: s.to_lowercase(),
                case_insensitive: true,
            };
            let e = json!({});
            let event = JsonEvent::borrow(&e);
            let upper = EventValue::Str(s.to_uppercase().into());
            let lower = EventValue::Str(s.to_lowercase().into());
            prop_assert!(m.matches(&upper, &event),
                "CI exact should match uppercase: {:?}", s.to_uppercase());
            prop_assert!(m.matches(&lower, &event),
                "CI exact should match lowercase: {:?}", s.to_lowercase());
        }
    }

    proptest! {
        #[test]
        fn contains_agrees_with_stdlib(
            haystack in "[[:print:]]{0,30}",
            needle in "[[:print:]]{1,10}",
        ) {
            let expected = haystack.contains(&needle);
            let m = CompiledMatcher::Contains {
                value: needle.clone(),
                case_insensitive: false,
            };
            let e = json!({});
            let event = JsonEvent::borrow(&e);
            let val = EventValue::Str(haystack.clone().into());
            prop_assert_eq!(m.matches(&val, &event), expected,
                "Contains({:?}) on {:?}", needle, haystack);
        }
    }

    proptest! {
        #[test]
        fn startswith_agrees_with_stdlib(
            haystack in "[[:print:]]{0,30}",
            prefix in "[[:print:]]{1,10}",
        ) {
            let expected = haystack.starts_with(&prefix);
            let m = CompiledMatcher::StartsWith {
                value: prefix.clone(),
                case_insensitive: false,
            };
            let e = json!({});
            let event = JsonEvent::borrow(&e);
            let val = EventValue::Str(haystack.clone().into());
            prop_assert_eq!(m.matches(&val, &event), expected,
                "StartsWith({:?}) on {:?}", prefix, haystack);
        }
    }

    proptest! {
        #[test]
        fn endswith_agrees_with_stdlib(
            haystack in "[[:print:]]{0,30}",
            suffix in "[[:print:]]{1,10}",
        ) {
            let expected = haystack.ends_with(&suffix);
            let m = CompiledMatcher::EndsWith {
                value: suffix.clone(),
                case_insensitive: false,
            };
            let e = json!({});
            let event = JsonEvent::borrow(&e);
            let val = EventValue::Str(haystack.clone().into());
            prop_assert_eq!(m.matches(&val, &event), expected,
                "EndsWith({:?}) on {:?}", suffix, haystack);
        }
    }

    proptest! {
        #[test]
        fn ci_contains_agrees_with_lowercased(
            haystack in "[[:alpha:]]{0,20}",
            needle in "[[:alpha:]]{1,8}",
        ) {
            let expected = haystack.to_lowercase().contains(&needle.to_lowercase());
            let m = CompiledMatcher::Contains {
                value: needle.to_lowercase(),
                case_insensitive: true,
            };
            let e = json!({});
            let event = JsonEvent::borrow(&e);
            let val = EventValue::Str(haystack.clone().into());
            prop_assert_eq!(m.matches(&val, &event), expected,
                "CI Contains({:?}) on {:?}", needle, haystack);
        }

        #[test]
        fn ci_startswith_agrees_with_lowercased(
            haystack in "[[:alpha:]]{0,20}",
            prefix in "[[:alpha:]]{1,8}",
        ) {
            let expected = haystack.to_lowercase().starts_with(&prefix.to_lowercase());
            let m = CompiledMatcher::StartsWith {
                value: prefix.to_lowercase(),
                case_insensitive: true,
            };
            let e = json!({});
            let event = JsonEvent::borrow(&e);
            let val = EventValue::Str(haystack.clone().into());
            prop_assert_eq!(m.matches(&val, &event), expected,
                "CI StartsWith({:?}) on {:?}", prefix, haystack);
        }

        #[test]
        fn ci_endswith_agrees_with_lowercased(
            haystack in "[[:alpha:]]{0,20}",
            suffix in "[[:alpha:]]{1,8}",
        ) {
            let expected = haystack.to_lowercase().ends_with(&suffix.to_lowercase());
            let m = CompiledMatcher::EndsWith {
                value: suffix.to_lowercase(),
                case_insensitive: true,
            };
            let e = json!({});
            let event = JsonEvent::borrow(&e);
            let val = EventValue::Str(haystack.clone().into());
            prop_assert_eq!(m.matches(&val, &event), expected,
                "CI EndsWith({:?}) on {:?}", suffix, haystack);
        }
    }

    proptest! {
        #[test]
        fn wildcard_star_matches_anything(s in "[[:print:]]{0,30}") {
            let parts = vec![StringPart::Special(SpecialChar::WildcardMulti)];
            let pattern = sigma_string_to_regex(&parts, false);
            let re = regex::Regex::new(&pattern).unwrap();
            prop_assert!(re.is_match(&s), "* should match any string: {:?}", s);
        }

        #[test]
        fn wildcard_question_matches_single_char(c in proptest::char::range('!', '~')) {
            let parts = vec![StringPart::Special(SpecialChar::WildcardSingle)];
            let pattern = sigma_string_to_regex(&parts, false);
            let re = regex::Regex::new(&pattern).unwrap();
            let s = c.to_string();
            prop_assert!(re.is_match(&s), "? should match single char: {:?}", s);
        }
    }
}
