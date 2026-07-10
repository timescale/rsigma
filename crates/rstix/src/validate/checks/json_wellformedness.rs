//! JSON well-formedness.

use super::{ValidationContext, ValidationReport};

/// Runs at the `validate_json_*` entry point before a value exists.
/// When a parsed value is already available, this check is a no-op.
pub fn run(_ctx: &ValidationContext<'_>, _report: &mut ValidationReport) {}
