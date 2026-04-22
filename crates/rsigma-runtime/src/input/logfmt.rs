//! logfmt input adapter (behind `logfmt` feature).
//!
//! Wraps the hand-rolled [`crate::parse::logfmt`] parser and returns a
//! [`KvEvent`].

use rsigma_eval::KvEvent;

use super::EventInputDecoded;

/// Parse a logfmt line into a KvEvent.
pub fn parse_logfmt(line: &str) -> EventInputDecoded {
    let pairs = crate::parse::logfmt::parse(line);
    EventInputDecoded::Kv(KvEvent::new(pairs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::Event;

    #[test]
    fn basic_logfmt() {
        let decoded = parse_logfmt("level=info msg=hello duration=12ms");
        assert!(decoded.get_field("level").is_some());
        assert!(decoded.get_field("msg").is_some());
        assert!(decoded.get_field("duration").is_some());
    }

    #[test]
    fn quoted_values() {
        let decoded = parse_logfmt(r#"level=error msg="disk full" host=web01"#);
        assert!(decoded.any_string_value(&|s| s.contains("disk full")));
    }
}
