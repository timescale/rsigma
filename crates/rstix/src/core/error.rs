//! Error types for core STIX/TAXII primitives.

/// Errors for STIX ID parsing and typed-ID conversion.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StixIdError {
    /// Input did not contain the `--` delimiter.
    #[error("missing '--' delimiter")]
    MissingDelimiter,
    /// Type name prefix was empty.
    #[error("empty type name")]
    EmptyTypeName,
    /// UUID segment was not a valid UUID.
    #[error("invalid UUID: {0}")]
    InvalidUuid(#[from] uuid::Error),
    /// Typed-ID conversion expected a different type prefix.
    #[error("type mismatch: expected '{expected}', found '{found}'")]
    TypeMismatch {
        /// Expected type name prefix.
        expected: &'static str,
        /// Found type name prefix.
        found: String,
    },
}

/// Errors for confidence parsing and scale mapping.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfidenceError {
    /// Confidence value must be between 0 and 100 inclusive.
    #[error("confidence value out of range: {0}")]
    OutOfRange(u8),
    /// Label was not found for the selected confidence scale.
    #[error("unknown confidence label: {0}")]
    UnknownLabel(String),
}

/// Errors for timestamp parsing and conversion.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TimestampError {
    /// Timestamp string was not valid RFC 3339 UTC.
    #[error("invalid timestamp: {0}")]
    Invalid(String),
}

/// Errors for RFC 5646-like language tag parsing.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LanguageTagError {
    /// Language tag was empty.
    #[error("language tag is empty")]
    Empty,
    /// Language tag did not match the accepted syntax.
    #[error("invalid language tag: {0}")]
    Invalid(String),
}
