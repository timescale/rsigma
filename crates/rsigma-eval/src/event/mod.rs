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
mod mapped;
mod plain;

pub use json::JsonEvent;
pub(crate) use json::resolve_array_index;
pub use kv::KvEvent;
pub use map::MapEvent;
pub use mapped::MappedEvent;
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
    /// Used by keyword detection. Numeric values count as their decimal text.
    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool;

    /// Collect all string values in the event.
    fn all_string_values(&self) -> Vec<Cow<'_, str>>;

    /// Visit every string value in the event without collecting them.
    ///
    /// Used by the keyword candidate index. The default walks
    /// [`Self::all_string_values`]; concrete types override to avoid the `Vec`.
    fn visit_string_values(&self, visit: &mut dyn FnMut(&str)) {
        for value in self.all_string_values() {
            visit(value.as_ref());
        }
    }

    /// Materialize the event as a `serde_json::Value`.
    fn to_json(&self) -> Value;

    /// Collect the names of the leaf fields in the event, with nested
    /// objects flattened to dot-separated paths (e.g. `actor.id`), within
    /// the default [`FieldKeyBudget`].
    /// Intermediate object names are not emitted; only leaves count.
    /// Arrays contribute their parent path once; per-index suffixes are
    /// not emitted.
    ///
    /// Used by field-observability and authoring tools; not on the detection
    /// hot path. The default collects [`Self::visit_field_keys`] into owned
    /// strings; flat formats like `KvEvent` return `Cow::Borrowed`.
    fn field_keys(&self) -> Vec<Cow<'_, str>> {
        let mut paths: Vec<Cow<'_, str>> = Vec::new();
        self.visit_field_keys(&FieldKeyBudget::default(), &mut |path| {
            paths.push(Cow::Owned(path.to_owned()));
        });
        paths
    }

    /// Visit the leaf field paths [`Self::field_keys`] describes, within
    /// `budget`, and report what the budget left out.
    ///
    /// A path longer than [`FieldKeyBudget::max_key_bytes`] is skipped, and
    /// so is every path under a nested object whose own path is already too
    /// long. The walk stops at [`FieldKeyBudget::max_keys`] paths or
    /// [`FieldKeyBudget::max_total_bytes`] bytes of paths. Paths are built in
    /// one reused buffer, so the walk allocates no string per leaf.
    ///
    /// The default walks `to_json()`; concrete event types override it to
    /// skip that clone.
    fn visit_field_keys(
        &self,
        budget: &FieldKeyBudget,
        visit: &mut dyn FnMut(&str),
    ) -> FieldKeyOverflow {
        visit_field_keys_json(&self.to_json(), budget, visit)
    }

    /// Whether the event has at least one leaf field.
    ///
    /// Stops at the first leaf and builds no paths. The default visits field
    /// keys with a one-key budget; concrete event types override it.
    fn has_any_field(&self) -> bool {
        let budget = FieldKeyBudget {
            max_keys: 1,
            max_key_bytes: usize::MAX,
            max_total_bytes: usize::MAX,
        };
        let mut found = false;
        self.visit_field_keys(&budget, &mut |_| found = true);
        found
    }

    /// Top-level object keys when the event can report them cheaply.
    ///
    /// `Some(keys)` means only those roots exist, so the candidate index may
    /// restrict field probes to paths under them. `None` means the shape is
    /// unknown or not a single object root, so every indexed field must be
    /// probed. The default is `None`.
    fn top_level_keys(&self) -> Option<Vec<Cow<'_, str>>> {
        None
    }

    /// Visit top-level object keys without collecting them.
    ///
    /// Returns `false` when the shape is unknown (same meaning as
    /// [`Self::top_level_keys`] returning `None`). The default collects via
    /// `top_level_keys`.
    fn visit_top_level_keys(&self, visit: &mut dyn FnMut(&str)) -> bool {
        let Some(keys) = self.top_level_keys() else {
            return false;
        };
        for key in keys {
            visit(key.as_ref());
        }
        true
    }
}

/// Maximum nesting depth honoured by field-key walks. Matches the existing
/// 64-level cap used elsewhere in the crate for recursive JSON traversal.
pub(crate) const FIELD_KEYS_MAX_DEPTH: usize = 64;

/// Limits on one field-key walk ([`Event::visit_field_keys`]).
///
/// Field names come from untrusted events, so a walk is bounded in the
/// number of paths it reports, the length of each path, and their total
/// size, however large or deeply nested the event is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldKeyBudget {
    /// Most paths reported.
    pub max_keys: usize,
    /// Longest path reported, in bytes.
    pub max_key_bytes: usize,
    /// Most bytes of paths reported in total.
    pub max_total_bytes: usize,
}

impl Default for FieldKeyBudget {
    /// 4,096 paths of at most 512 bytes each, and 256 KiB in total.
    fn default() -> Self {
        Self {
            max_keys: 4096,
            max_key_bytes: 512,
            max_total_bytes: 256 * 1024,
        }
    }
}

/// What a field-key walk left out to stay within its [`FieldKeyBudget`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FieldKeyOverflow {
    /// Paths skipped for being longer than `max_key_bytes`. A nested object
    /// whose own path is too long counts once for everything under it.
    pub too_long: u64,
    /// The walk stopped at `max_keys` or `max_total_bytes` before it had
    /// seen every field.
    pub truncated: bool,
}

impl FieldKeyOverflow {
    /// Whether the walk reported every field.
    pub fn is_empty(&self) -> bool {
        self.too_long == 0 && !self.truncated
    }
}

/// Walk a JSON value's leaf field paths within `budget`.
pub(crate) fn visit_field_keys_json(
    value: &Value,
    budget: &FieldKeyBudget,
    visit: &mut dyn FnMut(&str),
) -> FieldKeyOverflow {
    let mut walker = KeyWalker {
        budget,
        path: String::new(),
        emitted: 0,
        emitted_bytes: 0,
        overflow: FieldKeyOverflow::default(),
        visit,
    };
    if let Value::Object(map) = value {
        walker.walk(map, FIELD_KEYS_MAX_DEPTH);
    }
    walker.overflow
}

struct KeyWalker<'b, 'v> {
    budget: &'b FieldKeyBudget,
    /// The current path. Never longer than `budget.max_key_bytes`.
    path: String,
    emitted: usize,
    emitted_bytes: usize,
    overflow: FieldKeyOverflow,
    visit: &'v mut dyn FnMut(&str),
}

impl KeyWalker<'_, '_> {
    /// Walk one object's fields. `false` once the walk has to stop.
    fn walk(&mut self, map: &serde_json::Map<String, Value>, depth: usize) -> bool {
        if depth == 0 {
            return true;
        }
        for (key, child) in map {
            let base = self.path.len();
            let separator = usize::from(base > 0);
            if base + separator + key.len() > self.budget.max_key_bytes {
                self.overflow.too_long += 1;
                continue;
            }
            if separator == 1 {
                self.path.push('.');
            }
            self.path.push_str(key);
            let more = match child {
                // Only leaves are reported; a nested object contributes the
                // paths of its descendants.
                Value::Object(inner) => self.walk(inner, depth - 1),
                _ => self.emit(),
            };
            self.path.truncate(base);
            if !more {
                return false;
            }
        }
        true
    }

    fn emit(&mut self) -> bool {
        if self.emitted >= self.budget.max_keys
            || self.emitted_bytes + self.path.len() > self.budget.max_total_bytes
        {
            self.overflow.truncated = true;
            return false;
        }
        self.emitted += 1;
        self.emitted_bytes += self.path.len();
        (self.visit)(&self.path);
        true
    }
}

/// Visit flat field names (no nesting) within `budget`.
pub(crate) fn visit_flat_field_keys<'a>(
    keys: impl IntoIterator<Item = &'a str>,
    budget: &FieldKeyBudget,
    visit: &mut impl FnMut(&'a str),
) -> FieldKeyOverflow {
    let mut overflow = FieldKeyOverflow::default();
    let (mut emitted, mut emitted_bytes) = (0usize, 0usize);
    for key in keys {
        if key.len() > budget.max_key_bytes {
            overflow.too_long += 1;
            continue;
        }
        if emitted >= budget.max_keys || emitted_bytes + key.len() > budget.max_total_bytes {
            overflow.truncated = true;
            break;
        }
        emitted += 1;
        emitted_bytes += key.len();
        visit(key);
    }
    overflow
}

/// Whether a JSON value has a leaf field within the nesting cap.
pub(crate) fn json_has_any_field(value: &Value) -> bool {
    fn walk(map: &serde_json::Map<String, Value>, depth: usize) -> bool {
        depth > 0
            && map.values().any(|child| match child {
                Value::Object(inner) => walk(inner, depth - 1),
                _ => true,
            })
    }
    matches!(value, Value::Object(map) if walk(map, FIELD_KEYS_MAX_DEPTH))
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

    fn visit_string_values(&self, visit: &mut dyn FnMut(&str)) {
        (**self).visit_string_values(visit)
    }

    fn to_json(&self) -> Value {
        (**self).to_json()
    }

    fn field_keys(&self) -> Vec<Cow<'_, str>> {
        (**self).field_keys()
    }

    fn visit_field_keys(
        &self,
        budget: &FieldKeyBudget,
        visit: &mut dyn FnMut(&str),
    ) -> FieldKeyOverflow {
        (**self).visit_field_keys(budget, visit)
    }

    fn has_any_field(&self) -> bool {
        (**self).has_any_field()
    }

    fn top_level_keys(&self) -> Option<Vec<Cow<'_, str>>> {
        (**self).top_level_keys()
    }

    fn visit_top_level_keys(&self, visit: &mut dyn FnMut(&str)) -> bool {
        (**self).visit_top_level_keys(visit)
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
