//! Pattern parse and type errors.

use crate::pattern::ast::ComparisonOp;

/// Error parsing or type-checking a STIX pattern.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PatternError {
    /// Input exceeds the maximum pattern size.
    #[error("pattern exceeds maximum size of {max} bytes")]
    InputTooLarge {
        /// Configured maximum (64 KiB).
        max: usize,
    },
    /// Lexer failure.
    #[error("lexer error at byte {pos}: {msg}")]
    LexError {
        /// Byte offset.
        pos: usize,
        /// Human-readable detail.
        msg: String,
    },
    /// Parser failure.
    #[error("parse error at byte {pos}: {msg}")]
    ParseError {
        /// Byte offset.
        pos: usize,
        /// Human-readable detail.
        msg: String,
    },
    /// AST depth limit exceeded.
    #[error("parse error at byte {pos}: AST depth exceeds maximum of {max}")]
    DepthExceeded {
        /// Byte offset.
        pos: usize,
        /// Maximum nesting depth.
        max: usize,
    },
    /// Comparison count limit exceeded within one observation.
    #[error("parse error at byte {pos}: comparison count exceeds maximum of {max}")]
    ComparisonLimitExceeded {
        /// Byte offset.
        pos: usize,
        /// Maximum comparisons per observation.
        max: usize,
    },
    /// Type-check failure (emitted once the type-checker ships).
    #[error("type error at path {path}: {msg}")]
    TypeError {
        /// Object path string.
        path: String,
        /// Human-readable detail.
        msg: String,
    },
}

/// Evaluation-time error (Pattern Engine evaluator).
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PatternMatchError {
    /// Pattern requires observation timestamps that were not supplied.
    #[error("pattern requires observation timestamps but none were provided")]
    MissingTimestamp,
    /// Operator is parsed but not supported at evaluation time.
    #[error("operator {0:?} is not supported at evaluation time")]
    UnsupportedOperator(ComparisonOp),
    /// Regular expression in a `MATCHES` comparison failed to compile.
    #[error("invalid MATCHES regular expression: {msg}")]
    RegexCompile {
        /// Detail from the regex engine.
        msg: String,
    },
    /// Non-STIX indicator pattern language.
    #[error("pattern type {0} cannot be evaluated by the STIX evaluator")]
    NonStixPattern(String),
    /// `_ref` chain could not be resolved in the evaluation context.
    #[error("_ref resolution failed at path {path}: {msg}")]
    RefResolution {
        /// Object path string.
        path: String,
        /// Human-readable detail.
        msg: String,
    },
    /// [`crate::Pattern::matches_single`] requires a single observation without temporal qualifiers.
    #[error(
        "matches_single requires a single observation expression without temporal or multi-observation operators"
    )]
    NotSingleObservation,
    /// Evaluation context exceeds the observation cap (aligned with [`crate::pattern::lexer::MAX_OBSERVATIONS`]).
    #[error("evaluation context contains {count} observations; maximum is {max}")]
    TooManyObservations {
        /// Actual observation count supplied.
        count: usize,
        /// Configured maximum.
        max: usize,
    },
}
