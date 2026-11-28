use std::borrow::Cow;

use rsigma_parser::fieldpath::{first_unescaped, unescape_brackets};
use serde_json::Value;

use super::{Event, EventValue, FieldKeyBudget, FieldKeyOverflow};

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

    /// Unwrap the JSON value, cloning only when the event borrows it.
    pub fn into_value(self) -> Value {
        self.inner.into_owned()
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
    /// dot-separated traversal. When a path segment crosses an array, every
    /// element is followed and all terminal values are collected: a single
    /// hit is returned as-is, multiple hits are returned as an
    /// [`EventValue::Array`] so the matcher applies any-member semantics
    /// (rather than only testing the first element).
    fn get_field(&self, path: &str) -> Option<EventValue<'_>> {
        let value: &Value = &self.inner;

        if let Some(obj) = value.as_object() {
            if let Some(v) = obj.get(path) {
                return Some(EventValue::from(v));
            }

            if path.contains('.') || path.contains('[') || path.contains('\\') {
                // Most candidate-index probes miss. If the first path segment
                // is absent at the root, skip path parsing and traversal.
                if let Some(root) = path_root_key(path)
                    && !obj.contains_key(root.as_ref())
                {
                    return None;
                }
                let ops = parse_path_ops(path);
                let mut collected: Vec<EventValue<'_>> = Vec::new();
                collect_by_ops(value, &ops, &mut collected);
                return match collected.len() {
                    0 => None,
                    1 => collected.pop(),
                    _ => Some(EventValue::Array(collected)),
                };
            }

            return None;
        }

        if path.contains('.') || path.contains('[') || path.contains('\\') {
            let ops = parse_path_ops(path);
            let mut collected: Vec<EventValue<'_>> = Vec::new();
            collect_by_ops(value, &ops, &mut collected);
            return match collected.len() {
                0 => None,
                1 => collected.pop(),
                _ => Some(EventValue::Array(collected)),
            };
        }

        None
    }

    fn top_level_keys(&self) -> Option<Vec<Cow<'_, str>>> {
        match self.inner.as_ref() {
            Value::Object(map) => Some(map.keys().map(|k| Cow::Borrowed(k.as_str())).collect()),
            // Non-object roots (arrays, scalars) cannot cheaply describe the
            // keys the path walker may touch, so callers fall back.
            _ => None,
        }
    }

    fn visit_top_level_keys(&self, visit: &mut dyn FnMut(&str)) -> bool {
        match self.inner.as_ref() {
            Value::Object(map) => {
                for key in map.keys() {
                    visit(key.as_str());
                }
                true
            }
            _ => false,
        }
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
    /// value found, including inside nested objects and arrays. Numbers are
    /// yielded in their JSON text form, since keywords match them too. Traversal
    /// is capped at 64 levels of nesting to prevent stack overflow.
    fn all_string_values(&self) -> Vec<Cow<'_, str>> {
        let mut values = Vec::new();
        collect_string_values_json(&self.inner, &mut values, MAX_NESTING_DEPTH);
        values
    }

    fn visit_string_values(&self, visit: &mut dyn FnMut(&str)) {
        visit_string_values_json(&self.inner, visit, MAX_NESTING_DEPTH);
    }

    fn to_json(&self) -> Value {
        self.inner.as_ref().clone()
    }

    /// Walk the leaf fields in the event and yield dot-joined paths.
    /// Intermediate object names (`actor` for `{"actor":{"id":"x"}}`)
    /// are NOT emitted; only the leaves (`actor.id`) appear. This
    /// matches typical Sigma rules, which reference nested values via
    /// dot-notation; emitting the intermediate name would falsely flag
    /// every parent object as "unknown" in the gap signal even when
    /// the rule references a child path. Top-level scalar fields
    /// (`{"actor":"alice"}`) emit `actor` because they ARE leaves.
    /// Arrays contribute their parent path once; per-index suffixes
    /// are not emitted.
    fn visit_field_keys(
        &self,
        budget: &FieldKeyBudget,
        visit: &mut dyn FnMut(&str),
    ) -> FieldKeyOverflow {
        super::visit_field_keys_json(&self.inner, budget, visit)
    }

    fn has_any_field(&self) -> bool {
        super::json_has_any_field(&self.inner)
    }
}

/// First object-key segment of a field path, bracket-unescaped.
///
/// `actor.id` → `actor`, `name[0].x` → `name`, `CommandLine` → `CommandLine`.
/// Leading dots or a bare `[index]` yield `None` (no root object key).
fn path_root_key(path: &str) -> Option<Cow<'_, str>> {
    let segment = match first_unescaped(path, b'.') {
        Some(0) => return None,
        Some(pos) => &path[..pos],
        None => path,
    };
    if segment.is_empty() {
        return None;
    }
    let name = match first_unescaped(segment, b'[') {
        Some(0) => return None,
        Some(pos) => &segment[..pos],
        None => segment,
    };
    if name.is_empty() {
        return None;
    }
    Some(unescape_brackets(name))
}

/// A single field-path navigation step.
enum PathOp<'a> {
    /// Object key lookup (bracket-unescaped). Distributes over arrays (implicit
    /// any-member).
    Key(Cow<'a, str>),
    /// Positional array index, possibly negative. Selects one element; never
    /// fans out.
    Index(i64),
}

/// Resolve a positional index against an array length. Negative indices count
/// from the end (`-1` is the last element); out-of-range yields `None`.
pub(crate) fn resolve_array_index(index: i64, len: usize) -> Option<usize> {
    if index >= 0 {
        usize::try_from(index).ok().filter(|&i| i < len)
    } else {
        usize::try_from(index.unsigned_abs())
            .ok()
            .and_then(|abs| len.checked_sub(abs))
    }
}

/// Parse a dot path into navigation ops, recognizing positional `name[N]`
/// (and chained `name[N][M]`, with negative indices counting from the end). A
/// bracket group that is not an integer degrades to a literal object key so it
/// simply fails to match.
fn parse_path_ops(path: &str) -> Vec<PathOp<'_>> {
    let mut ops = Vec::new();
    for part in path.split('.') {
        match first_unescaped(part, b'[') {
            Some(bpos) if parse_index_groups(&part[bpos..]).is_some() => {
                let name = &part[..bpos];
                if !name.is_empty() {
                    ops.push(PathOp::Key(unescape_brackets(name)));
                }
                for idx in parse_index_groups(&part[bpos..]).expect("checked") {
                    ops.push(PathOp::Index(idx));
                }
            }
            // No unescaped index group: the whole segment is a literal key,
            // with `\[` / `\]` unescaped to match the event's actual key.
            _ => ops.push(PathOp::Key(unescape_brackets(part))),
        }
    }
    ops
}

/// Parse `[N]` or `[N][M]...` into the contained indices (negative allowed), or
/// `None` if any group is malformed or non-numeric.
fn parse_index_groups(s: &str) -> Option<Vec<i64>> {
    let mut out = Vec::new();
    let mut rem = s;
    while !rem.is_empty() {
        let rest = rem.strip_prefix('[')?;
        let close = rest.find(']')?;
        let idx: i64 = rest[..close].parse().ok()?;
        out.push(idx);
        rem = &rest[close + 1..];
    }
    Some(out)
}

/// Follow navigation ops, collecting every terminal value into `out`.
///
/// A `Key` op distributes over arrays (implicit any-member): the remaining ops
/// are applied to every element, so a path crossing an array of objects yields
/// one value per element. An `Index` op selects a single element and never
/// fans out, giving deterministic positional access.
fn collect_by_ops<'a>(current: &'a Value, ops: &[PathOp<'_>], out: &mut Vec<EventValue<'a>>) {
    let Some((op, rest)) = ops.split_first() else {
        out.push(EventValue::from(current));
        return;
    };

    match op {
        PathOp::Key(key) => match current {
            Value::Object(map) => {
                if let Some(next) = map.get(key.as_ref()) {
                    collect_by_ops(next, rest, out);
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    collect_by_ops(item, ops, out);
                }
            }
            _ => {}
        },
        PathOp::Index(i) => {
            if let Value::Array(arr) = current
                && let Some(idx) = resolve_array_index(*i, arr.len())
                && let Some(next) = arr.get(idx)
            {
                collect_by_ops(next, rest, out);
            }
        }
    }
}

fn any_string_value_json(v: &Value, pred: &dyn Fn(&str) -> bool, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    match v {
        Value::String(s) => pred(s.as_str()),
        Value::Number(n) => pred(&n.to_string()),
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
        Value::Number(n) => out.push(Cow::Owned(n.to_string())),
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

fn visit_string_values_json(v: &Value, visit: &mut dyn FnMut(&str), depth: usize) {
    if depth == 0 {
        return;
    }
    match v {
        Value::String(s) => visit(s.as_str()),
        Value::Number(n) => visit(&n.to_string()),
        Value::Object(map) => {
            for val in map.values() {
                visit_string_values_json(val, visit, depth - 1);
            }
        }
        Value::Array(arr) => {
            for val in arr {
                visit_string_values_json(val, visit, depth - 1);
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
    fn into_value_returns_the_wrapped_value() {
        let v = json!({"records": [{"EventID": 1}]});
        assert_eq!(JsonEvent::owned(v.clone()).into_value(), v);
        assert_eq!(JsonEvent::borrow(&v).into_value(), v);
    }

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
    fn json_dotted_miss_skips_absent_root() {
        let v = json!({"message": "x", "product": "windows"});
        let event = JsonEvent::borrow(&v);
        assert_eq!(event.get_field("Event.EventData.CommandLine"), None);
        assert_eq!(event.get_field("actor.id"), None);
        assert_eq!(event.get_field("name[0].x"), None);
    }

    #[test]
    fn json_top_level_keys_object() {
        let v = json!({"message": "x", "product": "windows"});
        let event = JsonEvent::borrow(&v);
        let mut keys: Vec<String> = event
            .top_level_keys()
            .unwrap()
            .into_iter()
            .map(|k| k.into_owned())
            .collect();
        keys.sort();
        assert_eq!(keys, vec!["message", "product"]);
    }

    #[test]
    fn json_top_level_keys_non_object_unknown() {
        let v = json!([{"a": 1}]);
        let event = JsonEvent::borrow(&v);
        assert_eq!(event.top_level_keys(), None);
    }

    #[test]
    fn path_root_key_segments() {
        assert_eq!(path_root_key("CommandLine").as_deref(), Some("CommandLine"));
        assert_eq!(path_root_key("actor.id").as_deref(), Some("actor"));
        assert_eq!(path_root_key("name[0].x").as_deref(), Some("name"));
        assert_eq!(path_root_key(".id"), None);
        assert_eq!(path_root_key("[0].x"), None);
    }

    #[test]
    fn json_null_field() {
        let v = json!({"foo": null});
        let event = JsonEvent::borrow(&v);
        assert_eq!(event.get_field("foo"), Some(EventValue::Null));
    }

    #[test]
    fn json_array_traversal() {
        // A path crossing an array of objects now collects every element's
        // leaf value (any-member semantics), not just the first.
        let v = json!({"a": {"b": [{"c": "found"}, {"c": "other"}]}});
        let event = JsonEvent::borrow(&v);
        assert_eq!(
            event.get_field("a.b.c"),
            Some(EventValue::Array(vec![
                EventValue::Str(Cow::Borrowed("found")),
                EventValue::Str(Cow::Borrowed("other")),
            ]))
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
        // Nested arrays flatten to every leaf value.
        assert_eq!(
            event.get_field("events.actors.name"),
            Some(EventValue::Array(vec![
                EventValue::Str(Cow::Borrowed("alice")),
                EventValue::Str(Cow::Borrowed("bob")),
                EventValue::Str(Cow::Borrowed("charlie")),
            ]))
        );
    }

    #[test]
    fn json_array_at_root_level() {
        let v = json!({"process": [{"command_line": "whoami"}, {"command_line": "id"}]});
        let event = JsonEvent::borrow(&v);
        assert_eq!(
            event.get_field("process.command_line"),
            Some(EventValue::Array(vec![
                EventValue::Str(Cow::Borrowed("whoami")),
                EventValue::Str(Cow::Borrowed("id")),
            ]))
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
        assert!(strs.contains(&"42"));
        assert_eq!(values.len(), 5);
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

    #[test]
    fn json_field_keys_flat() {
        let v = json!({"CommandLine": "x", "User": "y"});
        let event = JsonEvent::borrow(&v);
        let mut keys: Vec<String> = event.field_keys().iter().map(|c| c.to_string()).collect();
        keys.sort();
        assert_eq!(keys, vec!["CommandLine", "User"]);
    }

    #[test]
    fn json_field_keys_nested_leaves_only() {
        // Intermediate object names like `actor` are NOT emitted; only
        // leaves (`actor.id`, `actor.type`) and top-level scalars
        // (`verb`) appear.
        let v = json!({"actor": {"id": "u1", "type": "User"}, "verb": "login"});
        let event = JsonEvent::borrow(&v);
        let mut keys: Vec<String> = event.field_keys().iter().map(|c| c.to_string()).collect();
        keys.sort();
        assert_eq!(keys, vec!["actor.id", "actor.type", "verb"]);
    }

    #[test]
    fn json_field_keys_deeply_nested_leaves_only() {
        let v = json!({"a": {"b": {"c": 1}}, "flat": "x"});
        let event = JsonEvent::borrow(&v);
        let mut keys: Vec<String> = event.field_keys().iter().map(|c| c.to_string()).collect();
        keys.sort();
        assert_eq!(keys, vec!["a.b.c", "flat"]);
    }

    #[test]
    fn json_field_keys_array_parent_only() {
        let v = json!({"events": [{"id": 1}, {"id": 2}]});
        let event = JsonEvent::borrow(&v);
        let keys: Vec<String> = event.field_keys().iter().map(|c| c.to_string()).collect();
        // Arrays contribute their parent key only; array indices are not enumerated.
        assert_eq!(keys, vec!["events"]);
    }

    #[test]
    fn json_field_keys_top_level_non_object_empty() {
        let v = json!("just a string");
        let event = JsonEvent::owned(v);
        assert!(event.field_keys().is_empty());
    }

    #[test]
    fn json_field_keys_skip_paths_over_the_length_cap() {
        let long = "k".repeat(600);
        let v = json!({ "short": 1, long.clone(): 2, "nested": { long: { "x": 1 } , "y": 2 } });
        let event = JsonEvent::borrow(&v);
        let mut keys = Vec::new();
        let overflow = event.visit_field_keys(&FieldKeyBudget::default(), &mut |k| {
            keys.push(k.to_string())
        });
        keys.sort();
        assert_eq!(keys, ["nested.y", "short"]);
        assert_eq!(overflow.too_long, 2);
        assert!(!overflow.truncated);
    }

    #[test]
    fn json_field_keys_stop_at_the_key_budget() {
        let v = json!({ "a": 1, "b": 2, "c": 3, "d": 4 });
        let event = JsonEvent::borrow(&v);
        let budget = FieldKeyBudget {
            max_keys: 2,
            ..FieldKeyBudget::default()
        };
        let mut keys = Vec::new();
        let overflow = event.visit_field_keys(&budget, &mut |k| keys.push(k.to_string()));
        assert_eq!(keys.len(), 2);
        assert!(overflow.truncated);
    }

    #[test]
    fn json_field_keys_stop_at_the_byte_budget() {
        let v = json!({ "aaaa": 1, "bbbb": 2, "cccc": 3 });
        let event = JsonEvent::borrow(&v);
        let budget = FieldKeyBudget {
            max_total_bytes: 9,
            ..FieldKeyBudget::default()
        };
        let mut keys = Vec::new();
        let overflow = event.visit_field_keys(&budget, &mut |k| keys.push(k.to_string()));
        assert_eq!(keys.len(), 2);
        assert!(overflow.truncated);
    }

    #[test]
    fn json_has_any_field_needs_a_leaf() {
        assert!(JsonEvent::owned(json!({"a": 1})).has_any_field());
        assert!(JsonEvent::owned(json!({"a": {"b": [1]}})).has_any_field());
        assert!(JsonEvent::owned(json!({"a": null})).has_any_field());
        assert!(!JsonEvent::owned(json!({})).has_any_field());
        assert!(!JsonEvent::owned(json!({"a": {}, "b": {"c": {}}})).has_any_field());
        assert!(!JsonEvent::owned(json!("text")).has_any_field());
        assert!(!JsonEvent::owned(json!([{"a": 1}])).has_any_field());
    }

    #[test]
    fn json_traversal_with_consecutive_dots_does_not_panic() {
        // Pathological input -- a path like `a..b` used to be tokenised
        // by `split('.')` into `["a", "", "b"]` and then walked head-by-
        // head; the new `split_once('.')` recursion produces the same
        // `("a", ".b")` -> `("", "b")` -> ... sequence with no
        // allocation. Verify the lookup falls back to `None` rather
        // than panicking or accidentally matching.
        let v = json!({"a": {"b": "x"}});
        let event = JsonEvent::borrow(&v);
        assert_eq!(event.get_field("a..b"), None);
    }

    #[test]
    fn json_traversal_with_trailing_dot_does_not_panic() {
        // A trailing dot used to leave an empty trailing segment in the
        // `Vec<&str>` path which the object branch tried to look up
        // against the map; the iterator-based walker preserves that
        // miss without allocating.
        let v = json!({"a": {"b": "x"}});
        let event = JsonEvent::borrow(&v);
        assert_eq!(event.get_field("a.b."), None);
    }
}
