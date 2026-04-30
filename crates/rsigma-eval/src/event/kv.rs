use std::borrow::Cow;

use serde_json::Value;

use super::{Event, EventValue};

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
