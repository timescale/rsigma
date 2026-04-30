//! Event abstraction for Sigma rule evaluation.
//!
//! Provides the [`Event`] trait for generic event access, the [`EventValue`]
//! enum representing field values, and concrete implementations:
//! - [`JsonEvent`] — zero-copy wrapper around `serde_json::Value`
//! - [`KvEvent`] — flat key-value pairs (e.g., from logfmt / syslog)
//! - [`PlainEvent`] — raw log line (keyword matching only)
//! - [`MapEvent`] — generic `HashMap<K, V>` adapter

mod json;
mod kv;
mod map;
mod plain;

pub use json::JsonEvent;
pub use kv::KvEvent;
pub use map::MapEvent;
pub use plain::PlainEvent;

use std::borrow::Cow;

use serde_json::Value;

// =============================================================================
// EventValue
// =============================================================================

/// A value retrieved from an event field.
///
/// Supports zero-copy borrows from JSON-backed events (`Cow::Borrowed`)
/// and owned values from non-JSON sources (`Cow::Owned`).
/// Null is distinct from field-absent (`get_field` returns `None`).
#[derive(Debug, Clone, PartialEq)]
pub enum EventValue<'a> {
    Str(Cow<'a, str>),
    Int(i64),
    Float(f64),
    Bool(bool),
    Null,
    Array(Vec<EventValue<'a>>),
    Map(Vec<(Cow<'a, str>, EventValue<'a>)>),
}

impl<'a> EventValue<'a> {
    /// Coerce to string. Str as-is, Int/Float decimal, Bool "true"/"false".
    #[inline]
    pub fn as_str(&self) -> Option<Cow<'_, str>> {
        match self {
            EventValue::Str(s) => Some(Cow::Borrowed(s)),
            EventValue::Int(n) => Some(Cow::Owned(n.to_string())),
            EventValue::Float(f) => Some(Cow::Owned(f.to_string())),
            EventValue::Bool(b) => Some(Cow::Borrowed(if *b { "true" } else { "false" })),
            _ => None,
        }
    }

    /// Coerce to f64. Int lossless, Float as-is, Str parsed.
    #[inline]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            EventValue::Float(f) => Some(*f),
            EventValue::Int(n) => Some(*n as f64),
            EventValue::Str(s) => s.parse().ok(),
            _ => None,
        }
    }

    /// Coerce to i64. Int as-is, Float truncated if exact, Str parsed.
    #[inline]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            EventValue::Int(n) => Some(*n),
            EventValue::Float(f) => {
                let truncated = *f as i64;
                if (truncated as f64 - f).abs() < f64::EPSILON {
                    Some(truncated)
                } else {
                    None
                }
            }
            EventValue::Str(s) => s.parse().ok(),
            _ => None,
        }
    }

    /// Coerce to bool. Bool as-is, Str: true/false/1/0/yes/no.
    #[inline]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            EventValue::Bool(b) => Some(*b),
            EventValue::Str(s) => match s.to_lowercase().as_str() {
                "true" | "1" | "yes" => Some(true),
                "false" | "0" | "no" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    #[inline]
    pub fn is_null(&self) -> bool {
        matches!(self, EventValue::Null)
    }

    /// Convert to `serde_json::Value`.
    pub fn to_json(&self) -> Value {
        match self {
            EventValue::Str(s) => Value::String(s.to_string()),
            EventValue::Int(n) => Value::Number((*n).into()),
            EventValue::Float(f) => {
                serde_json::Number::from_f64(*f).map_or(Value::Null, Value::Number)
            }
            EventValue::Bool(b) => Value::Bool(*b),
            EventValue::Null => Value::Null,
            EventValue::Array(arr) => Value::Array(arr.iter().map(|v| v.to_json()).collect()),
            EventValue::Map(entries) => {
                let map = entries
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_json()))
                    .collect();
                Value::Object(map)
            }
        }
    }
}

impl<'a> From<&'a Value> for EventValue<'a> {
    fn from(v: &'a Value) -> Self {
        match v {
            Value::String(s) => EventValue::Str(Cow::Borrowed(s.as_str())),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    EventValue::Int(i)
                } else {
                    EventValue::Float(n.as_f64().unwrap_or(f64::NAN))
                }
            }
            Value::Bool(b) => EventValue::Bool(*b),
            Value::Null => EventValue::Null,
            Value::Array(arr) => EventValue::Array(arr.iter().map(EventValue::from).collect()),
            Value::Object(map) => EventValue::Map(
                map.iter()
                    .map(|(k, v)| (Cow::Borrowed(k.as_str()), EventValue::from(v)))
                    .collect(),
            ),
        }
    }
}

// =============================================================================
// Event trait
// =============================================================================

/// Generic interface for accessing event data during Sigma rule evaluation.
///
/// Implementations provide field lookup (with dot-notation), keyword search
/// over all string values, and serialization to JSON for correlation storage.
pub trait Event {
    /// Look up a field by name. Supports dot-notation for nested access.
    ///
    /// Returns `None` if the field is absent.
    /// Returns `Some(EventValue::Null)` if the field exists but is null.
    fn get_field(&self, path: &str) -> Option<EventValue<'_>>;

    /// Check if any string value anywhere in the event satisfies a predicate.
    /// Used by keyword detection.
    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool;

    /// Collect all string values in the event.
    fn all_string_values(&self) -> Vec<Cow<'_, str>>;

    /// Materialize the event as a `serde_json::Value`.
    fn to_json(&self) -> Value;
}

impl<T: Event + ?Sized> Event for &T {
    fn get_field(&self, path: &str) -> Option<EventValue<'_>> {
        (**self).get_field(path)
    }

    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool {
        (**self).any_string_value(pred)
    }

    fn all_string_values(&self) -> Vec<Cow<'_, str>> {
        (**self).all_string_values()
    }

    fn to_json(&self) -> Value {
        (**self).to_json()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn event_value_as_str() {
        assert_eq!(EventValue::Str(Cow::Borrowed("hi")).as_str().unwrap(), "hi");
        assert_eq!(EventValue::Int(42).as_str().unwrap(), "42");
        assert_eq!(EventValue::Float(2.71).as_str().unwrap(), "2.71");
        assert_eq!(EventValue::Bool(true).as_str().unwrap(), "true");
        assert!(EventValue::Null.as_str().is_none());
    }

    #[test]
    fn event_value_as_f64() {
        assert_eq!(EventValue::Float(2.71).as_f64(), Some(2.71));
        assert_eq!(EventValue::Int(42).as_f64(), Some(42.0));
        assert_eq!(EventValue::Str(Cow::Borrowed("1.5")).as_f64(), Some(1.5));
        assert!(EventValue::Bool(true).as_f64().is_none());
    }

    #[test]
    fn event_value_as_i64() {
        assert_eq!(EventValue::Int(42).as_i64(), Some(42));
        assert_eq!(EventValue::Float(42.0).as_i64(), Some(42));
        assert_eq!(EventValue::Float(42.5).as_i64(), None);
        assert_eq!(EventValue::Str(Cow::Borrowed("100")).as_i64(), Some(100));
    }

    #[test]
    fn event_value_to_json() {
        assert_eq!(EventValue::Str(Cow::Borrowed("hi")).to_json(), json!("hi"));
        assert_eq!(EventValue::Int(42).to_json(), json!(42));
        assert_eq!(EventValue::Bool(true).to_json(), json!(true));
        assert_eq!(EventValue::Null.to_json(), Value::Null);
    }
}
