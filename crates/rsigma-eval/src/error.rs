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

    /// A rule referenced by a correlation was not found.
    #[error("unknown rule reference: {0}")]
    UnknownRuleRef(String),

    /// A cycle was detected in correlation rule references.
    #[error("correlation cycle detected: {0}")]
    CorrelationCycle(String),

    /// An error from the IR lowering pipeline that has no more specific mapping.
    #[error("IR lowering error: {0}")]
    Ir(String),

    /// A HIR cache (de)serialization error.
    #[error("HIR cache error: {0}")]
    HirCache(String),
}

impl From<rsigma_ir::CacheError> for EvalError {
    fn from(err: rsigma_ir::CacheError) -> Self {
        EvalError::HirCache(err.to_string())
    }
}

impl From<rsigma_ir::IrError> for EvalError {
    fn from(err: rsigma_ir::IrError) -> Self {
        use rsigma_ir::IrError;
        match err {
            IrError::UnknownDetection(name) => EvalError::UnknownDetection(name),
            IrError::InvalidModifiers(msg) => EvalError::InvalidModifiers(msg),
            IrError::IncompatibleValue(msg) => EvalError::IncompatibleValue(msg),
            IrError::ExpectedNumeric(msg) => EvalError::ExpectedNumeric(msg),
            IrError::Parser(e) => EvalError::Parser(e),
            other => EvalError::Ir(other.to_string()),
        }
    }
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, EvalError>;
