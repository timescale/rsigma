//! # rsigma-eval
//!
//! Evaluator for Sigma detection rules — matches compiled rules against events.
//!
//! This crate consumes the AST produced by [`rsigma_parser`] and evaluates it
//! against JSON events in real time.
//!
//! ## Planned Features
//!
//! - Streaming rule evaluation against NDJSON events
//! - Field matching with all Sigma modifiers (contains, startswith, endswith, re, cidr, etc.)
//! - Boolean condition evaluation with short-circuit optimization
//! - Compiled matchers for zero-allocation hot-path evaluation
//! - Logsource routing (pre-filter rules by product/category/service)
//! - Correlation engine (event_count, value_count, temporal windowing)
//! - Rich match output: which selections matched, which fields triggered, matched values

pub use rsigma_parser;
