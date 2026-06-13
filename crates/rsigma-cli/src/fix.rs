//! File-level wrapper around the shared string-level fix applier.
//!
//! The fix machinery itself lives in [`rsigma_parser::lint::fix`] so the CLI,
//! LSP, and MCP server share one implementation. This module is the CLI's thin
//! disk layer: it groups fixable warnings by file, reads each file, delegates
//! to [`apply_fixes_to_source`], and writes the result back when it changed.

use std::collections::HashMap;
use std::path::Path;

use rsigma_parser::lint::fix::apply_fixes_to_source;
use rsigma_parser::lint::{FileLintResult, LintWarning};

/// Result of applying fixes to a set of files.
pub struct FixResult {
    pub applied: usize,
    pub failed: usize,
    pub files_modified: usize,
}

/// Collect fixable warnings from lint results, grouped by file path.
fn collect_fixable_warnings(results: &[FileLintResult]) -> HashMap<&Path, Vec<&LintWarning>> {
    let mut by_file: HashMap<&Path, Vec<&LintWarning>> = HashMap::new();
    for result in results {
        for w in &result.warnings {
            if w.fix.is_some() {
                by_file.entry(&result.path).or_default().push(w);
            }
        }
    }
    by_file
}

/// Apply all safe fixes from lint results to the files on disk.
///
/// For each file with fixable warnings:
/// 1. Reads the file source.
/// 2. Applies all safe fixes via [`apply_fixes_to_source`].
/// 3. Writes the modified source back only if it actually changed.
pub fn apply_fixes(results: &[FileLintResult]) -> FixResult {
    let by_file = collect_fixable_warnings(results);

    let mut total_applied = 0usize;
    let mut total_failed = 0usize;
    let mut files_modified = 0usize;

    for (file_path, warnings) in &by_file {
        let source = match std::fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  cannot read {}: {e}", file_path.display());
                total_failed += warnings.len();
                continue;
            }
        };

        let outcome = apply_fixes_to_source(&source, warnings);
        total_failed += outcome.failed;

        if outcome.fixed_source != source {
            if let Err(e) = std::fs::write(file_path, &outcome.fixed_source) {
                eprintln!("  cannot write {}: {e}", file_path.display());
                total_failed += outcome.applied;
            } else {
                total_applied += outcome.applied;
                files_modified += 1;
            }
        }
    }

    FixResult {
        applied: total_applied,
        failed: total_failed,
        files_modified,
    }
}
