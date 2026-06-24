//! A field-name-remapping [`Event`] view.
//!
//! Schema routing runs detection in a per-schema engine (the schema's pipeline
//! is applied to the rules) but feeds every detection into one shared,
//! Sigma-native correlation store. The correlation layer extracts group-by and
//! value fields from the event by their Sigma-native names (for example
//! `User`), but a routed event carries the schema's field names (for example
//! ECS `user.name`). [`MappedEvent`] bridges that gap: it rewrites a configured
//! set of field names on read so the shared correlation layer reads the right
//! values regardless of the event's schema.
//!
//! Only [`Event::get_field`] is remapped. The keyword-search and serialization
//! methods delegate to the inner event unchanged: detection already ran in the
//! routed engine, so correlation only needs field lookups.

use std::borrow::Cow;
use std::collections::HashMap;

use serde_json::Value;

use super::{Event, EventValue};

/// An [`Event`] that rewrites field names via a `Sigma -> [event field]` map
/// before reading from the inner event.
pub struct MappedEvent<'a, E: Event + ?Sized> {
    inner: &'a E,
    /// Logical (Sigma) field name -> one or more event field names to try in
    /// order. A one-to-many pipeline mapping yields several candidates; the
    /// first present value wins.
    mapping: &'a HashMap<String, Vec<String>>,
}

impl<'a, E: Event + ?Sized> MappedEvent<'a, E> {
    /// Wrap `inner`, remapping field names via `mapping`. An empty mapping
    /// makes this a transparent pass-through.
    pub fn new(inner: &'a E, mapping: &'a HashMap<String, Vec<String>>) -> Self {
        Self { inner, mapping }
    }
}

impl<E: Event + ?Sized> Event for MappedEvent<'_, E> {
    fn get_field(&self, path: &str) -> Option<EventValue<'_>> {
        if let Some(targets) = self.mapping.get(path) {
            for target in targets {
                if let Some(value) = self.inner.get_field(target) {
                    return Some(value);
                }
            }
            // Mapped but no target present: fall back to the original name so
            // a field the pipeline did not rename still resolves.
            return self.inner.get_field(path);
        }
        self.inner.get_field(path)
    }

    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool {
        self.inner.any_string_value(pred)
    }

    fn all_string_values(&self) -> Vec<Cow<'_, str>> {
        self.inner.all_string_values()
    }

    fn to_json(&self) -> Value {
        self.inner.to_json()
    }

    fn field_keys(&self) -> Vec<Cow<'_, str>> {
        self.inner.field_keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::JsonEvent;
    use serde_json::json;

    fn map(pairs: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, vs)| {
                (
                    (*k).to_string(),
                    vs.iter().map(|s| (*s).to_string()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn remaps_field_to_schema_name() {
        let v = json!({"user": {"name": "alice"}});
        let inner = JsonEvent::borrow(&v);
        let m = map(&[("User", &["user.name"])]);
        let mapped = MappedEvent::new(&inner, &m);
        assert_eq!(
            mapped
                .get_field("User")
                .and_then(|x| x.as_str().map(|s| s.to_string())),
            Some("alice".to_string())
        );
    }

    #[test]
    fn falls_back_to_original_name_when_unmapped() {
        let v = json!({"User": "bob"});
        let inner = JsonEvent::borrow(&v);
        // Sysmon-style event with no field rename: empty mapping passes through.
        let m = HashMap::new();
        let mapped = MappedEvent::new(&inner, &m);
        assert_eq!(
            mapped
                .get_field("User")
                .and_then(|x| x.as_str().map(|s| s.to_string())),
            Some("bob".to_string())
        );
    }

    #[test]
    fn one_to_many_picks_first_present() {
        let v = json!({"source": {"user": {"name": "carol"}}});
        let inner = JsonEvent::borrow(&v);
        let m = map(&[("User", &["user.name", "source.user.name"])]);
        let mapped = MappedEvent::new(&inner, &m);
        assert_eq!(
            mapped
                .get_field("User")
                .and_then(|x| x.as_str().map(|s| s.to_string())),
            Some("carol".to_string())
        );
    }
}
