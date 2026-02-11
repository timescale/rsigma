//! Event wrapper with dot-notation field access.
//!
//! Provides a thin wrapper around `serde_json::Value` that supports nested
//! field access via dot notation (e.g., `actor.id`) with flat-key precedence.

use serde_json::Value;

/// A reference to a JSON event for field access during evaluation.
///
/// Flat keys are checked first: `"actor.id"` as a single key takes precedence
/// over `{"actor": {"id": ...}}` nested traversal.
#[derive(Debug)]
pub struct Event<'a> {
    inner: &'a Value,
}

impl<'a> Event<'a> {
    /// Wrap a JSON value as an event.
    pub fn from_value(value: &'a Value) -> Self {
        Event { inner: value }
    }

    /// Get a field value by name, supporting dot-notation for nested access.
    ///
    /// Checks for a flat key first (exact match), then falls back to
    /// dot-separated traversal. When a path segment yields an array,
    /// each element is tried and the first match is returned (OR semantics).
    pub fn get_field(&self, path: &str) -> Option<&'a Value> {
        // Flat key check first
        if let Some(obj) = self.inner.as_object()
            && let Some(v) = obj.get(path)
        {
            return Some(v);
        }

        // Dot-notation traversal
        if path.contains('.') {
            let parts: Vec<&str> = path.split('.').collect();
            return traverse(self.inner, &parts);
        }

        None
    }

    /// Iterate over all string values in the event (for keyword detection).
    ///
    /// Recursively walks the entire event object and yields every string
    /// value found, including inside nested objects and arrays.
    pub fn all_string_values(&self) -> Vec<&'a str> {
        let mut values = Vec::new();
        collect_string_values(self.inner, &mut values);
        values
    }

    /// Access the underlying JSON value.
    pub fn as_value(&self) -> &'a Value {
        self.inner
    }
}

/// Recursively traverse a JSON value following dot-notation path segments.
///
/// When a segment resolves to an array, each element is tried and the first
/// match for the remaining path is returned.
fn traverse<'a>(current: &'a Value, parts: &[&str]) -> Option<&'a Value> {
    if parts.is_empty() {
        return Some(current);
    }

    let (head, rest) = (parts[0], &parts[1..]);

    match current {
        Value::Object(map) => {
            let next = map.get(head)?;
            traverse(next, rest)
        }
        Value::Array(arr) => {
            // Try each element — return first that resolves the remaining path
            for item in arr {
                if let Some(v) = traverse(item, parts) {
                    return Some(v);
                }
            }
            None
        }
        _ => None,
    }
}

fn collect_string_values<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s.as_str()),
        Value::Object(map) => {
            for val in map.values() {
                collect_string_values(val, out);
            }
        }
        Value::Array(arr) => {
            for val in arr {
                collect_string_values(val, out);
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
    fn test_flat_field() {
        let v = json!({"CommandLine": "whoami", "User": "admin"});
        let event = Event::from_value(&v);
        assert_eq!(
            event.get_field("CommandLine"),
            Some(&Value::String("whoami".into()))
        );
    }

    #[test]
    fn test_nested_field() {
        let v = json!({"actor": {"id": "user123", "type": "User"}});
        let event = Event::from_value(&v);
        assert_eq!(
            event.get_field("actor.id"),
            Some(&Value::String("user123".into()))
        );
    }

    #[test]
    fn test_flat_key_precedence() {
        // Flat key "actor.id" takes precedence over nested {"actor":{"id":...}}
        let v = json!({"actor.id": "flat_value", "actor": {"id": "nested_value"}});
        let event = Event::from_value(&v);
        assert_eq!(
            event.get_field("actor.id"),
            Some(&Value::String("flat_value".into()))
        );
    }

    #[test]
    fn test_missing_field() {
        let v = json!({"foo": "bar"});
        let event = Event::from_value(&v);
        assert_eq!(event.get_field("missing"), None);
    }

    #[test]
    fn test_array_traversal() {
        // a.b is an array of objects; a.b.c should find the first match
        let v = json!({"a": {"b": [{"c": "found"}, {"c": "other"}]}});
        let event = Event::from_value(&v);
        assert_eq!(
            event.get_field("a.b.c"),
            Some(&Value::String("found".into()))
        );
    }

    #[test]
    fn test_array_traversal_no_match() {
        // Array elements don't have the requested key
        let v = json!({"a": {"b": [{"x": 1}, {"y": 2}]}});
        let event = Event::from_value(&v);
        assert_eq!(event.get_field("a.b.c"), None);
    }

    #[test]
    fn test_array_traversal_deep() {
        // Two levels of arrays: events[].actors[].name
        let v = json!({
            "events": [
                {"actors": [{"name": "alice"}, {"name": "bob"}]},
                {"actors": [{"name": "charlie"}]}
            ]
        });
        let event = Event::from_value(&v);
        // Should return first match through the nested arrays
        assert_eq!(
            event.get_field("events.actors.name"),
            Some(&Value::String("alice".into()))
        );
    }

    #[test]
    fn test_array_at_root_level() {
        // Top-level field is an array of objects
        let v = json!({"process": [{"command_line": "whoami"}, {"command_line": "id"}]});
        let event = Event::from_value(&v);
        assert_eq!(
            event.get_field("process.command_line"),
            Some(&Value::String("whoami".into()))
        );
    }

    #[test]
    fn test_array_returns_array_value() {
        // Path resolves to an array (not traversing into it)
        let v = json!({"a": {"tags": ["t1", "t2"]}});
        let event = Event::from_value(&v);
        assert_eq!(event.get_field("a.tags"), Some(&json!(["t1", "t2"])));
    }

    #[test]
    fn test_flat_key_still_wins_over_array_traversal() {
        // Flat key "a.b.c" takes precedence over nested array traversal
        let v = json!({"a.b.c": "flat", "a": {"b": [{"c": "nested"}]}});
        let event = Event::from_value(&v);
        assert_eq!(
            event.get_field("a.b.c"),
            Some(&Value::String("flat".into()))
        );
    }

    #[test]
    fn test_all_string_values() {
        let v = json!({
            "a": "hello",
            "b": 42,
            "c": {"d": "world", "e": true},
            "f": ["one", "two"]
        });
        let event = Event::from_value(&v);
        let values = event.all_string_values();
        assert!(values.contains(&"hello"));
        assert!(values.contains(&"world"));
        assert!(values.contains(&"one"));
        assert!(values.contains(&"two"));
        assert_eq!(values.len(), 4);
    }
}
