//! Plain text input adapter.
//!
//! One event per line. Only keyword matching works against plain events
//! (`get_field` always returns `None`).

use rsigma_eval::PlainEvent;

use super::EventInputDecoded;

/// Wrap a raw line as a plain text event.
pub fn parse_plain(line: &str) -> EventInputDecoded {
    EventInputDecoded::Plain(PlainEvent::new(line.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::Event;

    #[test]
    fn plain_keyword_match() {
        let decoded = parse_plain("ERROR: disk full on /dev/sda1");
        assert!(decoded.any_string_value(&|s| s.contains("disk full")));
    }

    #[test]
    fn plain_no_fields() {
        let decoded = parse_plain("some log line");
        assert!(decoded.get_field("anything").is_none());
    }
}
