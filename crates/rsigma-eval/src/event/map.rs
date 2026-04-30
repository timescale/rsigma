use std::borrow::Cow;
use std::collections::HashMap;

use serde_json::Value;

use super::{Event, EventValue};

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
