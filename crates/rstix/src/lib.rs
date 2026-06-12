#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! STIX 2.1 + TAXII 2.1 library for Rust.

/// Core types shared across the crate.
pub mod core;

/// Deterministic SCO ID generation helpers.
pub mod id;

/// STIX vocabulary tables.
pub mod vocab;

/// STIX 2.1 data model: typed objects and common properties.
pub mod model;

#[cfg(feature = "serde")]
mod serde_impls;

/// Top-level parse error.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// Returned while parsing is pending a follow-up implementation phase.
    #[error("not yet implemented")]
    NotImplemented,
}

/// Parse a STIX bundle from a JSON string.
pub fn parse_bundle(_json: &str) -> Result<(), ParseError> {
    Err(ParseError::NotImplemented)
}
