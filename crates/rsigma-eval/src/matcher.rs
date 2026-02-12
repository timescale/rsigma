//! Compiled matchers for zero-allocation hot-path evaluation.
//!
//! Each `CompiledMatcher` variant is pre-compiled at rule load time.
//! At evaluation time, `matches()` performs the comparison against a JSON
//! value from the event with no dynamic dispatch or allocation.

use std::net::IpAddr;

use chrono::{Datelike, Timelike};
use ipnet::IpNet;
use regex::Regex;
use serde_json::Value;

use crate::event::Event;

/// A pre-compiled matcher for a single value comparison.
///
/// All string matchers store their values in the form needed for comparison
/// (Unicode-lowercased for case-insensitive). The `case_insensitive` flag
/// controls whether the input is lowercased before comparison.
#[derive(Debug, Clone)]
pub enum CompiledMatcher {
    // -- String matchers --
    /// Exact string equality.
    Exact {
        value: String,
        case_insensitive: bool,
    },

    /// Substring containment.
    Contains {
        value: String,
        case_insensitive: bool,
    },

    /// String starts with prefix.
    StartsWith {
        value: String,
        case_insensitive: bool,
    },

    /// String ends with suffix.
    EndsWith {
        value: String,
        case_insensitive: bool,
    },

    /// Compiled regex pattern (flags baked in at compile time).
    Regex(Regex),

    // -- Network --
    /// CIDR network match for IP addresses.
    Cidr(IpNet),

    // -- Numeric --
    /// Numeric equality.
    NumericEq(f64),
    /// Numeric greater-than.
    NumericGt(f64),
    /// Numeric greater-than-or-equal.
    NumericGte(f64),
    /// Numeric less-than.
    NumericLt(f64),
    /// Numeric less-than-or-equal.
    NumericLte(f64),

    // -- Special --
    /// Field existence check. `true` = field must exist, `false` = must not exist.
    Exists(bool),

    /// Compare against another field's value.
    FieldRef {
        field: String,
        case_insensitive: bool,
    },

    /// Match null / missing values.
    Null,

    /// Boolean equality.
    BoolEq(bool),

    // -- Expand --
    /// Placeholder expansion: `%fieldname%` is resolved from the event at match time.
    Expand {
        template: Vec<ExpandPart>,
        case_insensitive: bool,
    },

    // -- Timestamp --
    /// Extract a time component from a timestamp field value and match it.
    TimestampPart {
        part: TimePart,
        inner: Box<CompiledMatcher>,
    },

    // -- Negation --
    /// Negated matcher: matches if the inner matcher does NOT match.
    Not(Box<CompiledMatcher>),

    // -- Composite --
    /// Match if ANY child matches (OR).
    AnyOf(Vec<CompiledMatcher>),

    /// Match if ALL children match (AND).
    AllOf(Vec<CompiledMatcher>),
}

/// A part of an expand template.
#[derive(Debug, Clone)]
pub enum ExpandPart {
    /// Literal text.
    Literal(String),
    /// A placeholder field name (between `%` delimiters).
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
    /// Check if this matcher matches a JSON value from an event.
    ///
    /// The `event` parameter is needed for `FieldRef` to access other fields.
    /// The `field_name` is the name of the field being matched (for `FieldRef` comparison).
    pub fn matches(&self, value: &Value, event: &Event) -> bool {
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
            CompiledMatcher::Exists(_expect) => {
                // Exists is handled at the detection item level, not here.
                // This variant should not be reached during normal value matching.
                // If it is, treat `value` presence as existence.
                let exists = !value.is_null();
                exists == *_expect
            }

            CompiledMatcher::FieldRef {
                field: ref_field,
                case_insensitive,
            } => {
                if let Some(ref_value) = event.get_field(ref_field) {
                    if *case_insensitive {
                        match (value_to_str(value), value_to_str(ref_value)) {
                            (Some(a), Some(b)) => a.to_lowercase() == b.to_lowercase(),
                            _ => value == ref_value,
                        }
                    } else {
                        value == ref_value
                    }
                } else {
                    false
                }
            }

            CompiledMatcher::Null => value.is_null(),

            CompiledMatcher::BoolEq(expected) => match value {
                Value::Bool(b) => b == expected,
                // Also accept string representations
                Value::String(s) => match s.to_lowercase().as_str() {
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
                // Resolve all placeholders from the event
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
                // Extract the time component from the value and match it
                let component = extract_timestamp_part(value, *part);
                match component {
                    Some(n) => {
                        let num_val = Value::Number(serde_json::Number::from(n));
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

    /// Check if this matcher matches any of the given keyword strings.
    /// Used for keyword detection (field-less matching).
    pub fn matches_keyword(&self, event: &Event) -> bool {
        let strings = event.all_string_values();
        strings.iter().any(|s| {
            let v = Value::String((*s).to_string());
            self.matches(&v, event)
        })
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Try to extract a string representation from a JSON value and apply a predicate.
///
/// Handles `String` directly and coerces numbers/bools to string for comparison.
fn match_str_value(value: &Value, pred: impl Fn(&str) -> bool) -> bool {
    match_str_value_ref(value, &pred)
}

fn match_str_value_ref(value: &Value, pred: &dyn Fn(&str) -> bool) -> bool {
    match value {
        Value::String(s) => pred(s),
        // Coerce numeric and bool types to strings for string matching
        Value::Number(n) => pred(&n.to_string()),
        Value::Bool(b) => pred(if *b { "true" } else { "false" }),
        // For arrays, match if any element matches
        Value::Array(arr) => arr.iter().any(|v| match_str_value_ref(v, pred)),
        _ => false,
    }
}

/// Try to extract a numeric value and apply a predicate.
///
/// Handles JSON numbers directly and tries to parse strings as numbers.
fn match_numeric_value(value: &Value, pred: impl Fn(f64) -> bool) -> bool {
    match_numeric_value_ref(value, &pred)
}

fn match_numeric_value_ref(value: &Value, pred: &dyn Fn(f64) -> bool) -> bool {
    match value {
        Value::Number(n) => n.as_f64().is_some_and(pred),
        Value::String(s) => s.parse::<f64>().is_ok_and(pred),
        Value::Array(arr) => arr.iter().any(|v| match_numeric_value_ref(v, pred)),
        _ => false,
    }
}

/// Extract a string representation from a JSON value (for FieldRef comparison).
fn value_to_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Convert a [`SigmaString`](rsigma_parser::SigmaString) to a regex pattern string.
///
/// Wildcards are converted: `*` → `.*`, `?` → `.`
/// Plain text is regex-escaped.
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

/// Resolve all placeholders in an expand template from the event.
fn expand_template(template: &[ExpandPart], event: &Event) -> String {
    let mut result = String::new();
    for part in template {
        match part {
            ExpandPart::Literal(s) => result.push_str(s),
            ExpandPart::Placeholder(field) => {
                if let Some(val) = event.get_field(field) {
                    match val {
                        Value::String(s) => result.push_str(s),
                        Value::Number(n) => result.push_str(&n.to_string()),
                        Value::Bool(b) => result.push_str(&b.to_string()),
                        _ => {}
                    }
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
                // End of placeholder
                if !placeholder.is_empty() {
                    parts.push(ExpandPart::Placeholder(placeholder.clone()));
                    placeholder.clear();
                }
                in_placeholder = false;
            } else {
                // Start of placeholder — flush current literal
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

    // Flush remaining
    if in_placeholder && !placeholder.is_empty() {
        // Unterminated placeholder — treat as literal
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

/// Extract a time component from a JSON value (timestamp string or number).
fn extract_timestamp_part(value: &Value, part: TimePart) -> Option<i64> {
    let ts_str = match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => {
            // Interpret numeric timestamps as epoch seconds.
            // Values above 1e12 (i.e. 1_000_000_000_000, ~= Sep 2001 in millis)
            // are assumed to be **milliseconds** and divided by 1000.  This
            // heuristic mirrors the approach used by pySigma and covers all
            // real-world epoch-second timestamps (the threshold won't be
            // reached in seconds until the year ~33658).
            let secs = n.as_i64()?;
            let secs = if secs > 1_000_000_000_000 {
                secs / 1000
            } else {
                secs
            };
            let dt = chrono::DateTime::from_timestamp(secs, 0)?;
            return Some(extract_part_from_datetime(&dt, part));
        }
        _ => return None,
    };

    // Try parsing as RFC 3339 / ISO 8601
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&ts_str) {
        return Some(extract_part_from_datetime(&dt.to_utc(), part));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(&ts_str, "%Y-%m-%dT%H:%M:%S") {
        let dt = naive.and_utc();
        return Some(extract_part_from_datetime(&dt, part));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(&ts_str, "%Y-%m-%d %H:%M:%S") {
        let dt = naive.and_utc();
        return Some(extract_part_from_datetime(&dt, part));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(&ts_str, "%Y-%m-%dT%H:%M:%S%.f") {
        let dt = naive.and_utc();
        return Some(extract_part_from_datetime(&dt, part));
    }

    None
}

/// Extract a specific time component from a UTC DateTime.
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
    use serde_json::json;

    fn ev() -> serde_json::Value {
        json!({})
    }

    #[test]
    fn test_exact_case_insensitive() {
        let m = CompiledMatcher::Exact {
            value: "whoami".into(),
            case_insensitive: true,
        };
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("whoami"), &event));
        assert!(m.matches(&json!("WHOAMI"), &event));
        assert!(m.matches(&json!("Whoami"), &event));
        assert!(!m.matches(&json!("other"), &event));
    }

    #[test]
    fn test_exact_case_sensitive() {
        let m = CompiledMatcher::Exact {
            value: "whoami".into(),
            case_insensitive: false,
        };
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("whoami"), &event));
        assert!(!m.matches(&json!("WHOAMI"), &event));
    }

    #[test]
    fn test_contains() {
        let m = CompiledMatcher::Contains {
            value: "admin".to_lowercase(),
            case_insensitive: true,
        };
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("superadminuser"), &event));
        assert!(m.matches(&json!("ADMIN"), &event));
        assert!(!m.matches(&json!("user"), &event));
    }

    #[test]
    fn test_starts_with() {
        let m = CompiledMatcher::StartsWith {
            value: "cmd".into(),
            case_insensitive: true,
        };
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("cmd.exe"), &event));
        assert!(m.matches(&json!("CMD.EXE"), &event));
        assert!(!m.matches(&json!("xcmd"), &event));
    }

    #[test]
    fn test_ends_with() {
        let m = CompiledMatcher::EndsWith {
            value: ".exe".into(),
            case_insensitive: true,
        };
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("cmd.exe"), &event));
        assert!(m.matches(&json!("CMD.EXE"), &event));
        assert!(!m.matches(&json!("cmd.bat"), &event));
    }

    #[test]
    fn test_regex() {
        let re = Regex::new("(?i)^test.*value$").unwrap();
        let m = CompiledMatcher::Regex(re);
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("testXYZvalue"), &event));
        assert!(m.matches(&json!("TESTvalue"), &event));
        assert!(!m.matches(&json!("notamatch"), &event));
    }

    #[test]
    fn test_cidr() {
        let net: IpNet = "10.0.0.0/8".parse().unwrap();
        let m = CompiledMatcher::Cidr(net);
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("10.1.2.3"), &event));
        assert!(!m.matches(&json!("192.168.1.1"), &event));
    }

    #[test]
    fn test_numeric() {
        let m = CompiledMatcher::NumericGte(100.0);
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!(100), &event));
        assert!(m.matches(&json!(200), &event));
        assert!(!m.matches(&json!(50), &event));
        // String coercion
        assert!(m.matches(&json!("150"), &event));
    }

    #[test]
    fn test_null() {
        let m = CompiledMatcher::Null;
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&Value::Null, &event));
        assert!(!m.matches(&json!(""), &event));
    }

    #[test]
    fn test_bool() {
        let m = CompiledMatcher::BoolEq(true);
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!(true), &event));
        assert!(!m.matches(&json!(false), &event));
        assert!(m.matches(&json!("true"), &event));
    }

    #[test]
    fn test_field_ref() {
        let e = json!({"src": "10.0.0.1", "dst": "10.0.0.1"});
        let event = Event::from_value(&e);
        let m = CompiledMatcher::FieldRef {
            field: "dst".into(),
            case_insensitive: true,
        };
        assert!(m.matches(&json!("10.0.0.1"), &event));
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
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("a"), &event));
        assert!(m.matches(&json!("b"), &event));
        assert!(!m.matches(&json!("c"), &event));
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
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("adminuser"), &event));
        assert!(!m.matches(&json!("admin"), &event));
    }

    #[test]
    fn test_array_value_matching() {
        let m = CompiledMatcher::Exact {
            value: "target".into(),
            case_insensitive: true,
        };
        let e = ev();
        let event = Event::from_value(&e);
        // Match within a JSON array
        assert!(m.matches(&json!(["other", "target", "more"]), &event));
        assert!(!m.matches(&json!(["other", "nope"]), &event));
    }

    #[test]
    fn test_number_coercion_to_string() {
        let m = CompiledMatcher::Exact {
            value: "42".into(),
            case_insensitive: false,
        };
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!(42), &event));
    }

    // =========================================================================
    // Unicode case folding tests
    // =========================================================================

    #[test]
    fn test_exact_unicode_case_insensitive() {
        // German uppercase Ä should match lowercase ä
        let m = CompiledMatcher::Exact {
            value: "ärzte".to_lowercase(),
            case_insensitive: true,
        };
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("ÄRZTE"), &event));
        assert!(m.matches(&json!("Ärzte"), &event));
        assert!(m.matches(&json!("ärzte"), &event));
    }

    #[test]
    fn test_contains_unicode_case_insensitive() {
        let m = CompiledMatcher::Contains {
            value: "ñ".to_lowercase(),
            case_insensitive: true,
        };
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("España"), &event));
        assert!(m.matches(&json!("ESPAÑA"), &event));
    }

    #[test]
    fn test_startswith_unicode_case_insensitive() {
        let m = CompiledMatcher::StartsWith {
            value: "über".to_lowercase(),
            case_insensitive: true,
        };
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("Übersicht"), &event));
        assert!(m.matches(&json!("ÜBERSICHT"), &event));
        assert!(!m.matches(&json!("not-uber"), &event));
    }

    #[test]
    fn test_endswith_unicode_case_insensitive() {
        let m = CompiledMatcher::EndsWith {
            value: "ção".to_lowercase(),
            case_insensitive: true,
        };
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("Aplicação"), &event));
        assert!(m.matches(&json!("APLICAÇÃO"), &event));
        assert!(!m.matches(&json!("Aplicacao"), &event));
    }

    #[test]
    fn test_greek_case_insensitive() {
        let m = CompiledMatcher::Exact {
            value: "σίγμα".to_lowercase(),
            case_insensitive: true,
        };
        let e = ev();
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("ΣΊΓΜΑ"), &event));
        assert!(m.matches(&json!("σίγμα"), &event));
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
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("C:\\Users\\admin\\Downloads"), &event));
        assert!(!m.matches(&json!("C:\\Users\\other\\Downloads"), &event));
    }

    #[test]
    fn test_expand_matcher_missing_field() {
        let template = parse_expand_template("%user%@%domain%");
        let m = CompiledMatcher::Expand {
            template,
            case_insensitive: false,
        };
        // user is present but domain is not — should produce "admin@"
        let e = json!({"user": "admin"});
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("admin@"), &event));
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
        let event = Event::from_value(&e);
        // 2024-07-10T12:30:00Z — hour should be 12
        assert!(m.matches(&json!("2024-07-10T12:30:00Z"), &event));
        assert!(!m.matches(&json!("2024-07-10T15:30:00Z"), &event));
    }

    #[test]
    fn test_timestamp_part_month() {
        let m = CompiledMatcher::TimestampPart {
            part: TimePart::Month,
            inner: Box::new(CompiledMatcher::NumericEq(7.0)),
        };
        let e = json!({});
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("2024-07-10T12:30:00Z"), &event));
        assert!(!m.matches(&json!("2024-08-10T12:30:00Z"), &event));
    }

    #[test]
    fn test_timestamp_part_day() {
        let m = CompiledMatcher::TimestampPart {
            part: TimePart::Day,
            inner: Box::new(CompiledMatcher::NumericEq(10.0)),
        };
        let e = json!({});
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("2024-07-10T12:30:00Z"), &event));
        assert!(!m.matches(&json!("2024-07-15T12:30:00Z"), &event));
    }

    #[test]
    fn test_timestamp_part_year() {
        let m = CompiledMatcher::TimestampPart {
            part: TimePart::Year,
            inner: Box::new(CompiledMatcher::NumericEq(2024.0)),
        };
        let e = json!({});
        let event = Event::from_value(&e);
        assert!(m.matches(&json!("2024-07-10T12:30:00Z"), &event));
        assert!(!m.matches(&json!("2023-07-10T12:30:00Z"), &event));
    }

    #[test]
    fn test_timestamp_part_from_epoch() {
        let m = CompiledMatcher::TimestampPart {
            part: TimePart::Hour,
            inner: Box::new(CompiledMatcher::NumericEq(12.0)),
        };
        let e = json!({});
        let event = Event::from_value(&e);
        // 2024-07-10T12:30:00Z = 1720614600
        assert!(m.matches(&json!(1720614600), &event));
    }
}

// =============================================================================
// Property-based tests
// =============================================================================

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use rsigma_parser::value::{SpecialChar, StringPart};
    use serde_json::json;

    /// Strategy to generate a random sequence of StringParts (plain text + wildcards).
    fn arb_string_parts() -> impl Strategy<Value = Vec<StringPart>> {
        prop::collection::vec(
            prop_oneof![
                // Plain text: ASCII printable, including regex metacharacters
                "[[:print:]]{0,20}".prop_map(StringPart::Plain),
                Just(StringPart::Special(SpecialChar::WildcardMulti)),
                Just(StringPart::Special(SpecialChar::WildcardSingle)),
            ],
            0..8,
        )
    }

    // -------------------------------------------------------------------------
    // 1. Wildcard → regex compilation never panics and always produces valid regex
    // -------------------------------------------------------------------------
    proptest! {
        #[test]
        fn wildcard_regex_always_valid(parts in arb_string_parts(), ci in any::<bool>()) {
            let pattern = sigma_string_to_regex(&parts, ci);
            // Must compile without error
            prop_assert!(regex::Regex::new(&pattern).is_ok(),
                "sigma_string_to_regex produced invalid regex: {}", pattern);
        }
    }

    // -------------------------------------------------------------------------
    // 2. Plain text roundtrip: a plain-only SigmaString matches its own text
    // -------------------------------------------------------------------------
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

    // -------------------------------------------------------------------------
    // 3. Plain text never accidentally matches unrelated strings via regex injection
    // -------------------------------------------------------------------------
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

    // -------------------------------------------------------------------------
    // 4. Case-insensitive Exact matcher: symmetric under case change
    // -------------------------------------------------------------------------
    proptest! {
        #[test]
        fn exact_ci_symmetric(s in "[[:alpha:]]{1,20}") {
            let m = CompiledMatcher::Exact {
                value: s.to_lowercase(),
                case_insensitive: true,
            };
            let e = json!({});
            let event = Event::from_value(&e);
            let upper = json!(s.to_uppercase());
            let lower = json!(s.to_lowercase());
            prop_assert!(m.matches(&upper, &event),
                "CI exact should match uppercase: {:?}", s.to_uppercase());
            prop_assert!(m.matches(&lower, &event),
                "CI exact should match lowercase: {:?}", s.to_lowercase());
        }
    }

    // -------------------------------------------------------------------------
    // 5. Contains matcher agrees with str::contains
    // -------------------------------------------------------------------------
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
            let event = Event::from_value(&e);
            let val = json!(haystack);
            prop_assert_eq!(m.matches(&val, &event), expected,
                "Contains({:?}) on {:?}", needle, haystack);
        }
    }

    // -------------------------------------------------------------------------
    // 6. StartsWith matcher agrees with str::starts_with
    // -------------------------------------------------------------------------
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
            let event = Event::from_value(&e);
            let val = json!(haystack);
            prop_assert_eq!(m.matches(&val, &event), expected,
                "StartsWith({:?}) on {:?}", prefix, haystack);
        }
    }

    // -------------------------------------------------------------------------
    // 7. EndsWith matcher agrees with str::ends_with
    // -------------------------------------------------------------------------
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
            let event = Event::from_value(&e);
            let val = json!(haystack);
            prop_assert_eq!(m.matches(&val, &event), expected,
                "EndsWith({:?}) on {:?}", suffix, haystack);
        }
    }

    // -------------------------------------------------------------------------
    // 8. CI Contains/StartsWith/EndsWith agree with lowercased stdlib equivalents
    // -------------------------------------------------------------------------
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
            let event = Event::from_value(&e);
            let val = json!(haystack);
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
            let event = Event::from_value(&e);
            let val = json!(haystack);
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
            let event = Event::from_value(&e);
            let val = json!(haystack);
            prop_assert_eq!(m.matches(&val, &event), expected,
                "CI EndsWith({:?}) on {:?}", suffix, haystack);
        }
    }

    // -------------------------------------------------------------------------
    // 9. Wildcard * matches any string, ? matches any single char
    // -------------------------------------------------------------------------
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
