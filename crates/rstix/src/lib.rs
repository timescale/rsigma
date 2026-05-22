#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! STIX 2.1 + TAXII 2.1 library crate.
//!
//! Phase 0 intentionally ships only infrastructure scaffolding and feature-gated
//! module boundaries. Production semantics are introduced in later phases.

/// Core module placeholder.
pub mod core;

/// Serde-focused module placeholder.
#[cfg(feature = "serde")]
pub mod serde_impls;

/// STIX pattern module placeholder.
#[cfg(feature = "pattern")]
pub mod pattern;

/// Validation module placeholder.
#[cfg(feature = "validate")]
pub mod validate;

/// Graph module placeholder.
#[cfg(feature = "graph")]
pub mod graph;

/// Data marking module placeholder.
#[cfg(feature = "marking")]
pub mod marking;

/// Object store module placeholder.
#[cfg(feature = "store")]
pub mod store;

/// Enrichment module placeholder.
#[cfg(feature = "enrichment")]
pub mod enrichment;

/// TAXII client module placeholder.
#[cfg(feature = "taxii")]
pub mod taxii;

/// Testing helper module placeholder.
#[cfg(feature = "testing")]
pub mod testing;

/// Top-level parse error placeholder for the Phase 0 stub API.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// Feature not implemented yet.
    #[error("not yet implemented")]
    NotImplemented,
}

/// Parse a STIX bundle from a JSON string.
///
/// # Errors
///
/// Always returns [`ParseError::NotImplemented`] during Phase 0 scaffolding.
pub fn parse_bundle(_json: &str) -> Result<(), ParseError> {
    Err(ParseError::NotImplemented)
}
