#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! STIX 2.1 + TAXII 2.1 library for Rust.

/// Core types shared across the crate.
pub mod core;

/// Deterministic SCO ID generation helpers.
pub mod id;

/// STIX vocabulary tables.
pub mod vocab;

/// Serialization and deserialization helpers.
#[cfg(feature = "serde")]
pub mod serde_impls;

/// STIX pattern parser and evaluator.
#[cfg(feature = "pattern")]
pub mod pattern;

/// STIX validation pipeline.
#[cfg(feature = "validate")]
pub mod validate;

/// CTI graph traversal APIs.
#[cfg(feature = "graph")]
pub mod graph;

/// Marking and TLP resolution APIs.
#[cfg(feature = "marking")]
pub mod marking;

/// Storage APIs for STIX objects.
#[cfg(feature = "store")]
pub mod store;

/// Enrichment APIs for post-detection workflows.
#[cfg(feature = "enrichment")]
pub mod enrichment;

/// TAXII 2.1 client APIs.
#[cfg(feature = "taxii")]
pub mod taxii;

/// Testing utilities, including mock infrastructure.
#[cfg(feature = "testing")]
pub mod testing;

/// Top-level parse error.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// Returned while Phase 0 infrastructure is being implemented.
    #[error("not yet implemented")]
    NotImplemented,
}

/// Parse a STIX bundle from a JSON string.
pub fn parse_bundle(_json: &str) -> Result<(), ParseError> {
    Err(ParseError::NotImplemented)
}
