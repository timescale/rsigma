use std::borrow::Cow;

use serde_json::Value;

use super::{Event, EventValue};

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
