//! Event abstraction for Sigma rule evaluation.
//!
//! Provides the [`Event`] trait for generic event access, the [`EventValue`]
//! enum representing field values, and concrete implementations:
//! - [`JsonEvent`] — zero-copy wrapper around `serde_json::Value`
//! - [`KvEvent`] — flat key-value pairs (e.g., from logfmt / syslog)
//! - [`PlainEvent`] — raw log line (keyword matching only)
//! - [`MapEvent`] — generic `HashMap<K, V>` adapter

use std::borrow::Cow;
use std::collections::HashMap;

use serde_json::Value;

/// Maximum nesting depth for recursive JSON traversal.
const MAX_NESTING_DEPTH: usize = 64;

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

// =============================================================================
// JsonEvent
// =============================================================================

/// Zero-copy event backed by `serde_json::Value`.
///
/// Supports both borrowed (`&Value`) and owned (`Value`) backing via `Cow`.
/// This is the primary implementation for JSON/NDJSON input.
///
/// Flat keys are checked first: `"actor.id"` as a single key takes precedence
/// over `{"actor": {"id": ...}}` nested traversal.
#[derive(Debug)]
pub struct JsonEvent<'a> {
    inner: Cow<'a, Value>,
}

impl<'a> JsonEvent<'a> {
    /// Wrap a borrowed JSON value as an event.
    pub fn borrow(v: &'a Value) -> Self {
        Self {
            inner: Cow::Borrowed(v),
        }
    }

    /// Wrap an owned JSON value as an event.
    pub fn owned(v: Value) -> Self {
        Self {
            inner: Cow::Owned(v),
        }
    }
}

impl<'a> From<&'a Value> for JsonEvent<'a> {
    fn from(v: &'a Value) -> Self {
        Self::borrow(v)
    }
}

impl From<Value> for JsonEvent<'static> {
    fn from(v: Value) -> Self {
        Self::owned(v)
    }
}

impl<'a> Event for JsonEvent<'a> {
    /// Get a field value by name, supporting dot-notation for nested access.
    ///
    /// Checks for a flat key first (exact match), then falls back to
    /// dot-separated traversal. When a path segment yields an array,
    /// each element is tried and the first match is returned (OR semantics).
    fn get_field(&self, path: &str) -> Option<EventValue<'_>> {
        let value: &Value = &self.inner;

        if let Some(obj) = value.as_object()
            && let Some(v) = obj.get(path)
        {
            return Some(EventValue::from(v));
        }

        if path.contains('.') {
            let parts: Vec<&str> = path.split('.').collect();
            return traverse_json(value, &parts).map(EventValue::from);
        }

        None
    }

    /// Check if any string value in the event satisfies a predicate.
    ///
    /// Short-circuits on the first match, avoiding the allocation of
    /// collecting all string values into a `Vec`.
    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool {
        any_string_value_json(&self.inner, pred, MAX_NESTING_DEPTH)
    }

    /// Iterate over all string values in the event (for keyword detection).
    ///
    /// Recursively walks the entire event object and yields every string
    /// value found, including inside nested objects and arrays. Traversal
    /// is capped at 64 levels of nesting to prevent stack overflow.
    fn all_string_values(&self) -> Vec<Cow<'_, str>> {
        let mut values = Vec::new();
        collect_string_values_json(&self.inner, &mut values, MAX_NESTING_DEPTH);
        values
    }

    fn to_json(&self) -> Value {
        self.inner.as_ref().clone()
    }
}

// -- JsonEvent helpers --------------------------------------------------------

/// Recursively traverse a JSON value following dot-notation path segments.
///
/// When a segment resolves to an array, each element is tried and the first
/// match for the remaining path is returned.
fn traverse_json<'a>(current: &'a Value, parts: &[&str]) -> Option<&'a Value> {
    if parts.is_empty() {
        return Some(current);
    }

    let (head, rest) = (parts[0], &parts[1..]);

    match current {
        Value::Object(map) => {
            let next = map.get(head)?;
            traverse_json(next, rest)
        }
        Value::Array(arr) => {
            for item in arr {
                if let Some(v) = traverse_json(item, parts) {
                    return Some(v);
                }
            }
            None
        }
        _ => None,
    }
}

fn any_string_value_json(v: &Value, pred: &dyn Fn(&str) -> bool, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    match v {
        Value::String(s) => pred(s.as_str()),
        Value::Object(map) => map
            .values()
            .any(|val| any_string_value_json(val, pred, depth - 1)),
        Value::Array(arr) => arr
            .iter()
            .any(|val| any_string_value_json(val, pred, depth - 1)),
        _ => false,
    }
}

fn collect_string_values_json<'a>(v: &'a Value, out: &mut Vec<Cow<'a, str>>, depth: usize) {
    if depth == 0 {
        return;
    }
    match v {
        Value::String(s) => out.push(Cow::Borrowed(s.as_str())),
        Value::Object(map) => {
            for val in map.values() {
                collect_string_values_json(val, out, depth - 1);
            }
        }
        Value::Array(arr) => {
            for val in arr {
                collect_string_values_json(val, out, depth - 1);
            }
        }
        _ => {}
    }
}

// =============================================================================
// KvEvent
// =============================================================================

/// Flat key-value event (e.g., from logfmt, syslog structured data).
///
/// No nested access (no dot-notation traversal), no arrays.
/// All values are strings.
#[derive(Debug, Clone)]
pub struct KvEvent {
    fields: Vec<(String, String)>,
}

impl KvEvent {
    pub fn new(fields: Vec<(String, String)>) -> Self {
        Self { fields }
    }

    pub fn fields(&self) -> &[(String, String)] {
        &self.fields
    }
}

impl Event for KvEvent {
    fn get_field(&self, path: &str) -> Option<EventValue<'_>> {
        self.fields
            .iter()
            .find(|(k, _)| k == path)
            .map(|(_, v)| EventValue::Str(Cow::Borrowed(v.as_str())))
    }

    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool {
        self.fields.iter().any(|(_, v)| pred(v.as_str()))
    }

    fn all_string_values(&self) -> Vec<Cow<'_, str>> {
        self.fields
            .iter()
            .map(|(_, v)| Cow::Borrowed(v.as_str()))
            .collect()
    }

    fn to_json(&self) -> Value {
        let map: serde_json::Map<String, Value> = self
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        Value::Object(map)
    }
}

// =============================================================================
// PlainEvent
// =============================================================================

/// Raw log line event (keyword matching only).
///
/// `get_field` always returns `None`. Useful for keyword-only Sigma rules.
#[derive(Debug, Clone)]
pub struct PlainEvent {
    raw: String,
}

impl PlainEvent {
    pub fn new(raw: String) -> Self {
        Self { raw }
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }
}

impl Event for PlainEvent {
    fn get_field(&self, _path: &str) -> Option<EventValue<'_>> {
        None
    }

    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool {
        pred(&self.raw)
    }

    fn all_string_values(&self) -> Vec<Cow<'_, str>> {
        vec![Cow::Borrowed(&self.raw)]
    }

    fn to_json(&self) -> Value {
        serde_json::json!({ "_raw": self.raw })
    }
}

// =============================================================================
// MapEvent
// =============================================================================

/// Generic flat-map event for user-defined key-value stores.
///
/// Flat key lookup only (no dot-notation, no nesting).
#[derive(Debug, Clone)]
pub struct MapEvent<K = String, V = String>
where
    K: AsRef<str> + std::fmt::Debug + Clone,
    V: AsRef<str> + std::fmt::Debug + Clone,
{
    inner: HashMap<K, V>,
}

impl<K, V> MapEvent<K, V>
where
    K: AsRef<str> + std::fmt::Debug + Clone,
    V: AsRef<str> + std::fmt::Debug + Clone,
{
    pub fn new(inner: HashMap<K, V>) -> Self {
        Self { inner }
    }
}

impl<K, V> Event for MapEvent<K, V>
where
    K: AsRef<str> + std::fmt::Debug + Clone,
    V: AsRef<str> + std::fmt::Debug + Clone,
{
    fn get_field(&self, path: &str) -> Option<EventValue<'_>> {
        self.inner
            .iter()
            .find(|(k, _)| k.as_ref() == path)
            .map(|(_, v)| EventValue::Str(Cow::Borrowed(v.as_ref())))
    }

    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool {
        self.inner.values().any(|v| pred(v.as_ref()))
    }

    fn all_string_values(&self) -> Vec<Cow<'_, str>> {
        self.inner
            .values()
            .map(|v| Cow::Borrowed(v.as_ref()))
            .collect()
    }

    fn to_json(&self) -> Value {
        let map: serde_json::Map<String, Value> = self
            .inner
            .iter()
            .map(|(k, v)| {
                (
                    k.as_ref().to_string(),
                    Value::String(v.as_ref().to_string()),
                )
            })
            .collect();
        Value::Object(map)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- JsonEvent tests ------------------------------------------------------

    #[test]
    fn json_flat_field() {
        let v = json!({"CommandLine": "whoami", "User": "admin"});
        let event = JsonEvent::borrow(&v);
        assert_eq!(
            event.get_field("CommandLine"),
            Some(EventValue::Str(Cow::Borrowed("whoami")))
        );
    }

    #[test]
    fn json_nested_field() {
        let v = json!({"actor": {"id": "user123", "type": "User"}});
        let event = JsonEvent::borrow(&v);
        assert_eq!(
            event.get_field("actor.id"),
            Some(EventValue::Str(Cow::Borrowed("user123")))
        );
    }

    #[test]
    fn json_flat_key_precedence() {
        let v = json!({"actor.id": "flat_value", "actor": {"id": "nested_value"}});
        let event = JsonEvent::borrow(&v);
        assert_eq!(
            event.get_field("actor.id"),
            Some(EventValue::Str(Cow::Borrowed("flat_value")))
        );
    }

    #[test]
    fn json_missing_field() {
        let v = json!({"foo": "bar"});
        let event = JsonEvent::borrow(&v);
        assert_eq!(event.get_field("missing"), None);
    }

    #[test]
    fn json_null_field() {
        let v = json!({"foo": null});
        let event = JsonEvent::borrow(&v);
        assert_eq!(event.get_field("foo"), Some(EventValue::Null));
    }

    #[test]
    fn json_array_traversal() {
        let v = json!({"a": {"b": [{"c": "found"}, {"c": "other"}]}});
        let event = JsonEvent::borrow(&v);
        assert_eq!(
            event.get_field("a.b.c"),
            Some(EventValue::Str(Cow::Borrowed("found")))
        );
    }

    #[test]
    fn json_array_traversal_no_match() {
        let v = json!({"a": {"b": [{"x": 1}, {"y": 2}]}});
        let event = JsonEvent::borrow(&v);
        assert_eq!(event.get_field("a.b.c"), None);
    }

    #[test]
    fn json_array_traversal_deep() {
        let v = json!({
            "events": [
                {"actors": [{"name": "alice"}, {"name": "bob"}]},
                {"actors": [{"name": "charlie"}]}
            ]
        });
        let event = JsonEvent::borrow(&v);
        assert_eq!(
            event.get_field("events.actors.name"),
            Some(EventValue::Str(Cow::Borrowed("alice")))
        );
    }

    #[test]
    fn json_array_at_root_level() {
        let v = json!({"process": [{"command_line": "whoami"}, {"command_line": "id"}]});
        let event = JsonEvent::borrow(&v);
        assert_eq!(
            event.get_field("process.command_line"),
            Some(EventValue::Str(Cow::Borrowed("whoami")))
        );
    }

    #[test]
    fn json_array_returns_array_value() {
        let v = json!({"a": {"tags": ["t1", "t2"]}});
        let event = JsonEvent::borrow(&v);
        let result = event.get_field("a.tags");
        assert!(matches!(result, Some(EventValue::Array(_))));
    }

    #[test]
    fn json_flat_key_wins_over_array_traversal() {
        let v = json!({"a.b.c": "flat", "a": {"b": [{"c": "nested"}]}});
        let event = JsonEvent::borrow(&v);
        assert_eq!(
            event.get_field("a.b.c"),
            Some(EventValue::Str(Cow::Borrowed("flat")))
        );
    }

    #[test]
    fn json_all_string_values() {
        let v = json!({
            "a": "hello",
            "b": 42,
            "c": {"d": "world", "e": true},
            "f": ["one", "two"]
        });
        let event = JsonEvent::borrow(&v);
        let values = event.all_string_values();
        let strs: Vec<&str> = values.iter().map(|c| c.as_ref()).collect();
        assert!(strs.contains(&"hello"));
        assert!(strs.contains(&"world"));
        assert!(strs.contains(&"one"));
        assert!(strs.contains(&"two"));
        assert_eq!(values.len(), 4);
    }

    #[test]
    fn json_to_json_roundtrip() {
        let v = json!({"a": 1, "b": "hello", "c": [1, 2]});
        let event = JsonEvent::borrow(&v);
        assert_eq!(event.to_json(), v);
    }

    #[test]
    fn json_owned_works() {
        let v = json!({"key": "value"});
        let event = JsonEvent::owned(v.clone());
        assert_eq!(
            event.get_field("key"),
            Some(EventValue::Str(Cow::Borrowed("value")))
        );
        assert_eq!(event.to_json(), v);
    }

    // -- EventValue coercion tests --------------------------------------------

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

    // -- KvEvent tests --------------------------------------------------------

    #[test]
    fn kv_get_field() {
        let event = KvEvent::new(vec![
            ("host".into(), "web01".into()),
            ("status".into(), "200".into()),
        ]);
        assert_eq!(
            event.get_field("host"),
            Some(EventValue::Str(Cow::Borrowed("web01")))
        );
        assert_eq!(event.get_field("missing"), None);
    }

    #[test]
    fn kv_all_string_values() {
        let event = KvEvent::new(vec![("a".into(), "one".into()), ("b".into(), "two".into())]);
        let vals = event.all_string_values();
        assert_eq!(vals.len(), 2);
    }

    #[test]
    fn kv_to_json() {
        let event = KvEvent::new(vec![("key".into(), "val".into())]);
        let j = event.to_json();
        assert_eq!(j, json!({"key": "val"}));
    }

    // -- PlainEvent tests -----------------------------------------------------

    #[test]
    fn plain_get_field_always_none() {
        let event = PlainEvent::new("raw log line".into());
        assert_eq!(event.get_field("anything"), None);
    }

    #[test]
    fn plain_keyword_search() {
        let event = PlainEvent::new("error: disk full".into());
        assert!(event.any_string_value(&|s| s.contains("disk")));
        assert!(!event.any_string_value(&|s| s.contains("memory")));
    }

    #[test]
    fn plain_to_json() {
        let event = PlainEvent::new("hello".into());
        assert_eq!(event.to_json(), json!({"_raw": "hello"}));
    }

    // -- MapEvent tests -------------------------------------------------------

    #[test]
    fn map_event_get_field() {
        let mut m = HashMap::new();
        m.insert("user".to_string(), "admin".to_string());
        let event = MapEvent::new(m);
        assert_eq!(
            event.get_field("user"),
            Some(EventValue::Str(Cow::Borrowed("admin")))
        );
        assert_eq!(event.get_field("missing"), None);
    }

    #[test]
    fn map_event_to_json() {
        let mut m = HashMap::new();
        m.insert("k".to_string(), "v".to_string());
        let event = MapEvent::new(m);
        assert_eq!(event.to_json(), json!({"k": "v"}));
    }
}
