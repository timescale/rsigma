//! Compiled matchers for zero-allocation hot-path evaluation.
//!
//! Each `CompiledMatcher` variant is pre-compiled at rule load time.
//! At evaluation time, `matches()` performs the comparison against a JSON
//! value from the event with no dynamic dispatch or allocation.

use std::net::IpAddr;

use ipnet::IpNet;
use regex::Regex;
use serde_json::Value;

use crate::event::Event;

/// A pre-compiled matcher for a single value comparison.
///
/// All string matchers store their values in the form needed for comparison
/// (lowercased for case-insensitive). The `case_insensitive` flag controls
/// whether the input is lowercased before comparison.
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

    // -- Composite --
    /// Match if ANY child matches (OR).
    AnyOf(Vec<CompiledMatcher>),

    /// Match if ALL children match (AND).
    AllOf(Vec<CompiledMatcher>),
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
                    s.eq_ignore_ascii_case(expected)
                } else {
                    s == expected
                }
            }),

            CompiledMatcher::Contains {
                value: needle,
                case_insensitive,
            } => match_str_value(value, |s| {
                if *case_insensitive {
                    s.to_ascii_lowercase().contains(needle.as_str())
                } else {
                    s.contains(needle.as_str())
                }
            }),

            CompiledMatcher::StartsWith {
                value: prefix,
                case_insensitive,
            } => match_str_value(value, |s| {
                if *case_insensitive {
                    s.len() >= prefix.len()
                        && s[..prefix.len()].eq_ignore_ascii_case(prefix)
                } else {
                    s.starts_with(prefix.as_str())
                }
            }),

            CompiledMatcher::EndsWith {
                value: suffix,
                case_insensitive,
            } => match_str_value(value, |s| {
                if *case_insensitive {
                    s.len() >= suffix.len()
                        && s[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
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
            CompiledMatcher::NumericEq(n) => match_numeric_value(value, |v| (v - n).abs() < f64::EPSILON),
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
                            (Some(a), Some(b)) => a.eq_ignore_ascii_case(&b),
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
                Value::String(s) => match s.to_ascii_lowercase().as_str() {
                    "true" | "1" | "yes" => *expected,
                    "false" | "0" | "no" => !*expected,
                    _ => false,
                },
                _ => false,
            },

            // -- Composite --
            CompiledMatcher::AnyOf(matchers) => {
                matchers.iter().any(|m| m.matches(value, event))
            }

            CompiledMatcher::AllOf(matchers) => {
                matchers.iter().all(|m| m.matches(value, event))
            }
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
            value: "admin".to_ascii_lowercase(),
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
}
