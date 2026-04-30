//! Compiled correlation types, group key, window state, and compilation.
//!
//! Transforms the parser's `CorrelationRule` AST into an optimized
//! `CompiledCorrelation` with associated `WindowState` for stateful evaluation.

mod buffers;
mod compiler;
mod keys;
#[cfg(test)]
mod tests;
mod types;
mod window;

pub use buffers::{EventBuffer, EventRef, EventRefBuffer};
pub use compiler::compile_correlation;
pub use keys::GroupKey;
pub use types::{CompiledCondition, CompiledCorrelation, GroupByField};
pub use window::WindowState;

#[cfg(test)]
use buffers::{compress_event, decompress_event, extract_event_id};
#[cfg(test)]
use rsigma_parser::{ConditionExpr, ConditionOperator, CorrelationType};
#[cfg(test)]
use std::collections::{HashMap, VecDeque};
#[cfg(test)]
use window::{eval_temporal_expr, percentile_linear_interp};
