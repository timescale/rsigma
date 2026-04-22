//! CEF (Common Event Format) input adapter (behind `cef` feature).
//!
//! Wraps the hand-rolled [`crate::parse::cef`] parser. CEF header fields and
//! extension key-value pairs are merged into a single [`KvEvent`].
//!
//! ## CEF-over-syslog
//!
//! If the input line contains a syslog prefix before the `CEF:` marker,
//! [`crate::parse::cef::find_cef_start`] locates the CEF portion and only
//! that part is parsed. The syslog envelope is discarded (use the syslog
//! adapter if you need the envelope fields too).

use rsigma_eval::KvEvent;

use super::EventInputDecoded;

/// Parse a CEF line into a KvEvent. Returns `None` if the line is not valid CEF.
pub fn parse_cef(line: &str) -> Option<EventInputDecoded> {
    // Handle CEF-over-syslog: find where CEF: starts.
    let cef_input = match crate::parse::cef::find_cef_start(line) {
        Some(offset) => &line[offset..],
        None => return None,
    };

    let record = crate::parse::cef::parse(cef_input).ok()?;

    let mut fields = Vec::with_capacity(7 + record.extensions.len());
    fields.push(("cef_version".to_string(), record.version.to_string()));
    fields.push(("deviceVendor".to_string(), record.device_vendor));
    fields.push(("deviceProduct".to_string(), record.device_product));
    fields.push(("deviceVersion".to_string(), record.device_version));
    fields.push(("signatureId".to_string(), record.signature_id));
    fields.push(("name".to_string(), record.name));
    fields.push(("severity".to_string(), record.severity));
    fields.extend(record.extensions);

    Some(EventInputDecoded::Kv(KvEvent::new(fields)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::Event;

    #[test]
    fn basic_cef() {
        let line = "CEF:0|Security|IDS|1.0|100|Attack|9|src=10.0.0.1 dst=192.168.1.1";
        let decoded = parse_cef(line).unwrap();
        assert!(decoded.get_field("deviceVendor").is_some());
        assert!(decoded.get_field("src").is_some());
        assert!(decoded.get_field("dst").is_some());
    }

    #[test]
    fn cef_over_syslog() {
        let line =
            "<134>Feb 14 19:04:54 fw01 CEF:0|Palo Alto|PAN-OS|10|THREAT|threat|7|src=10.0.0.1";
        let decoded = parse_cef(line).unwrap();
        assert!(decoded.get_field("deviceVendor").is_some());
        assert!(decoded.get_field("src").is_some());
    }

    #[test]
    fn not_cef_returns_none() {
        assert!(parse_cef("just a regular log line").is_none());
    }
}
