//! Versioned serialization of lowered rules, the HIR cache.
//!
//! A slice of [`IrRule`] serializes to a self-describing blob: a
//! [`HirCacheHeader`] (schema version + producing `rsigma-ir` version) followed
//! by the rules. CBOR is the compact binary format for the on-disk cache
//! (e.g. a daemon restart cache that skips parse, pipeline, and lowering);
//! [`to_json`] gives a human-readable debug export of the same shape.
//!
//! CBOR (not a fixed-layout format like postcard) is used deliberately: the HIR
//! embeds `rsigma_parser::LogSource`, whose `#[serde(flatten)]` custom-key map
//! serializes with an unknown length, which fixed-layout encoders reject. CBOR
//! encodes such maps natively.
//!
//! The header is read and version-checked *before* the rules are decoded, so a
//! blob written by an incompatible schema is rejected cleanly rather than
//! misparsed. Bump [`HIR_SCHEMA_VERSION`] on any breaking change to the HIR
//! types or the embedded parser types they reference.

use serde::{Deserialize, Serialize};

use crate::hir::IrRule;

/// Schema version of the serialized HIR. Bump on any breaking change to the
/// HIR types or the embedded `rsigma-parser` types they contain.
pub const HIR_SCHEMA_VERSION: u32 = 1;

/// Header prefixed to a serialized HIR blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HirCacheHeader {
    /// The [`HIR_SCHEMA_VERSION`] the blob was written with.
    pub ir_schema_version: u32,
    /// The `rsigma-ir` package version that produced the blob (informational;
    /// not enforced on load).
    pub rsigma_version: String,
}

impl HirCacheHeader {
    /// The header for the running build.
    pub fn current() -> Self {
        Self {
            ir_schema_version: HIR_SCHEMA_VERSION,
            rsigma_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// A full HIR cache: header plus the lowered rules. Used for JSON export; the
/// binary path encodes the same fields in order via [`encode_rules`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirCache {
    pub header: HirCacheHeader,
    pub rules: Vec<IrRule>,
}

/// Errors from encoding or decoding a HIR cache blob.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("HIR cache encode failed: {0}")]
    Encode(String),
    #[error("HIR cache decode failed: {0}")]
    Decode(String),
    #[error("HIR cache schema mismatch: blob is v{found}, this build expects v{expected}")]
    SchemaMismatch { expected: u32, found: u32 },
}

/// Encode a slice of lowered rules into a versioned CBOR blob: the header CBOR
/// item followed by the rules CBOR item.
pub fn encode_rules(rules: &[IrRule]) -> Result<Vec<u8>, CacheError> {
    let mut buf = Vec::new();
    ciborium::into_writer(&HirCacheHeader::current(), &mut buf)
        .map_err(|e| CacheError::Encode(e.to_string()))?;
    ciborium::into_writer(&rules, &mut buf).map_err(|e| CacheError::Encode(e.to_string()))?;
    Ok(buf)
}

/// Decode a versioned CBOR blob, rejecting a schema-version mismatch before
/// attempting to decode the rules.
pub fn decode_rules(bytes: &[u8]) -> Result<Vec<IrRule>, CacheError> {
    let mut cursor = std::io::Cursor::new(bytes);
    let header: HirCacheHeader =
        ciborium::from_reader(&mut cursor).map_err(|e| CacheError::Decode(e.to_string()))?;
    if header.ir_schema_version != HIR_SCHEMA_VERSION {
        return Err(CacheError::SchemaMismatch {
            expected: HIR_SCHEMA_VERSION,
            found: header.ir_schema_version,
        });
    }
    ciborium::from_reader(&mut cursor).map_err(|e| CacheError::Decode(e.to_string()))
}

/// Human-readable JSON debug export of the cache (header + rules), pretty-printed.
pub fn to_json(rules: &[IrRule]) -> Result<String, CacheError> {
    let cache = HirCache {
        header: HirCacheHeader::current(),
        rules: rules.to_vec(),
    };
    serde_json::to_string_pretty(&cache).map_err(|e| CacheError::Encode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hir::{IrRule, IrRuleMetadata};
    use rsigma_parser::LogSource;

    fn sample_rule(title: &str) -> IrRule {
        IrRule {
            metadata: IrRuleMetadata {
                title: title.to_string(),
                ..Default::default()
            },
            logsource: LogSource::default(),
            sigma_version: None,
            detections: Default::default(),
            conditions: Vec::new(),
        }
    }

    #[test]
    fn round_trips_through_postcard() {
        let rules = vec![sample_rule("a"), sample_rule("b")];
        let blob = encode_rules(&rules).unwrap();
        let decoded = decode_rules(&blob).unwrap();
        assert_eq!(decoded, rules);
    }

    #[test]
    fn rejects_schema_mismatch() {
        let rules = vec![sample_rule("a")];
        // Craft a blob with a future schema version.
        let mut blob = Vec::new();
        let header = HirCacheHeader {
            ir_schema_version: HIR_SCHEMA_VERSION + 1,
            rsigma_version: "test".to_string(),
        };
        ciborium::into_writer(&header, &mut blob).unwrap();
        ciborium::into_writer(&rules, &mut blob).unwrap();

        match decode_rules(&blob) {
            Err(CacheError::SchemaMismatch { expected, found }) => {
                assert_eq!(expected, HIR_SCHEMA_VERSION);
                assert_eq!(found, HIR_SCHEMA_VERSION + 1);
            }
            other => panic!("expected schema mismatch, got {other:?}"),
        }
    }

    #[test]
    fn json_export_is_readable() {
        let rules = vec![sample_rule("json")];
        let json = to_json(&rules).unwrap();
        assert!(json.contains("\"ir_schema_version\""));
        assert!(json.contains("\"json\""));
    }
}
