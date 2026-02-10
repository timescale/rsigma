//! Evaluation-specific error types.

use thiserror::Error;

/// Errors that can occur during rule compilation or evaluation.
#[derive(Debug, Error)]
pub enum EvalError {
    /// A regex pattern failed to compile.
    #[error("invalid regex pattern: {0}")]
    InvalidRegex(#[from] regex::Error),

    /// A CIDR pattern failed to parse.
    #[error("invalid CIDR: {0}")]
    InvalidCidr(#[from] ipnet::AddrParseError),

    /// A base64 operation failed.
    #[error("base64 encoding error: {0}")]
    Base64(String),

    /// A detection referenced in a condition was not found.
    #[error("unknown detection identifier: {0}")]
    UnknownDetection(String),

    /// A modifier combination is invalid.
    #[error("invalid modifier combination: {0}")]
    InvalidModifiers(String),

    /// A value type is incompatible with the modifier.
    #[error("incompatible value for modifier: {0}")]
    IncompatibleValue(String),

    /// A numeric value was expected but not found.
    #[error("expected numeric value: {0}")]
    ExpectedNumeric(String),

    /// A parser error propagated during compilation.
    #[error("parser error: {0}")]
    Parser(#[from] rsigma_parser::SigmaParserError),

    /// A correlation rule compilation or evaluation error.
    #[error("correlation error: {0}")]
    CorrelationError(String),

    /// A timestamp could not be parsed from an event field.
    #[error("timestamp parse error: {0}")]
    TimestampParse(String),

    /// A rule referenced by a correlation was not found.
    #[error("unknown rule reference: {0}")]
    UnknownRuleRef(String),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, EvalError>;
