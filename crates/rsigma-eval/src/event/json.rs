use std::borrow::Cow;

use serde_json::Value;

use super::{Event, EventValue};

/// Maximum nesting depth for recursive JSON traversal.
const MAX_NESTING_DEPTH: usize = 64;

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
