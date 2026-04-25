//! # rsigma-convert
//!
//! Sigma rule conversion engine for transforming parsed Sigma rules into
//! backend-native query strings (SQL, SPL, KQL, Lucene, etc.).
//!
//! This crate provides:
//!
//! - A [`Backend`] trait that backends implement to produce query strings.
//! - A [`TextQueryConfig`] struct carrying tokens, operators, and expressions
//!   for text-based query backends (the vast majority).
//! - A condition-expression tree walker that recurses over [`ConditionExpr`]
//!   and dispatches to the backend's conversion methods.
//! - An orchestrator ([`convert_collection`]) that applies pipelines, converts
//!   each rule, and collects results/errors.
//! - Deferred-expression support for backends that need post-query appendages
//!   (e.g. Splunk `| regex`, `| where`).
//!
//! [`ConditionExpr`]: rsigma_parser::ConditionExpr

pub mod backend;
pub mod backends;
pub mod condition;
pub mod convert;
pub mod error;
pub mod output;
pub mod state;

pub use backend::{Backend, TextQueryConfig, TokenType};
pub use condition::convert_condition_expr;
pub use convert::convert_collection;
pub use error::{ConvertError, Result};
pub use output::{ConversionOutput, ConversionResult};
pub use state::{ConversionState, ConvertResult, DeferredExpression, DeferredTextExpression};
