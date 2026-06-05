//! Canonical JSON serialization helper for deterministic IDs.

/// Error type for canonicalization failures.
#[derive(Debug, thiserror::Error)]
#[error("JCS canonicalization failed: {0}")]
pub struct JcsError(String);

/// Serialize a JSON value to canonical bytes suitable for deterministic UUIDv5 derivation.
pub fn jcs_canonicalize(value: &serde_json::Value) -> Result<Vec<u8>, JcsError> {
    serde_jcs::to_vec(value).map_err(|err| JcsError(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_map_keys_canonically() {
        let value = serde_json::json!({
            "b": 2,
            "a": 1
        });
        let canonical = jcs_canonicalize(&value).expect("canonical");
        assert_eq!(canonical, br#"{"a":1,"b":2}"#);
    }
}
