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

#[cfg(test)]
use buffers::FullEntry;
pub use buffers::{EventBuffer, EventRef, EventRefBuffer};
pub(crate) use buffers::{RefEntry, Retained};
pub use compiler::compile_correlation;
pub use keys::GroupKey;
pub(crate) use types::CompiledAbsence;
pub use types::{CompiledCondition, CompiledCorrelation, GroupByField};
pub use window::{
    Deadman, Obligation, WindowDecision, WindowState, apply_window_open, sliding_cutoff,
};
pub(crate) use window::{
    bucket_start, obligation_for, satisfying_set_ordered, satisfying_set_unordered,
};

#[cfg(test)]
use buffers::{compress_event, decompress_event, extract_event_id};
#[cfg(test)]
use rsigma_parser::{ConditionExpr, ConditionOperator, CorrelationType};
#[cfg(test)]
use std::collections::{HashMap, VecDeque};
#[cfg(test)]
use window::{check_temporal_ordered, eval_temporal_expr, percentile_linear_interp};
