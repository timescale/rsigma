//! JSON / NDJSON / GELF input adapter.
//!
//! GELF is just JSON with conventions (`version`, `host`, `short_message`,
//! underscore-prefixed custom fields) — no special parser needed.

use rsigma_eval::JsonEvent;

use super::EventInputDecoded;

/// Parse a line as JSON. Returns `None` on parse failure.
pub fn parse_json(line: &str) -> Option<EventInputDecoded> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    Some(EventInputDecoded::Json(JsonEvent::owned(value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::Event;

    #[test]
    fn valid_json_object() {
        let decoded = parse_json(r#"{"EventID": 1, "host": "web01"}"#).unwrap();
        assert!(decoded.get_field("EventID").is_some());
        assert!(decoded.get_field("host").is_some());
    }

    #[test]
    fn invalid_json_returns_none() {
        assert!(parse_json("not json").is_none());
    }

    #[test]
    fn gelf_message() {
        let gelf = r#"{"version":"1.1","host":"example.org","short_message":"A short message","_user_id":"9001"}"#;
        let decoded = parse_json(gelf).unwrap();
        assert!(decoded.get_field("version").is_some());
        assert!(decoded.get_field("_user_id").is_some());
    }

    #[test]
    fn empty_string_returns_none() {
        assert!(parse_json("").is_none());
    }
}
