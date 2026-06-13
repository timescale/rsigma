#![no_main]

//! Fuzz the lint auto-fix applier: lint arbitrary YAML with defaults, apply
//! every safe fix to the source, and assert the applier never panics and that
//! the rewritten source can be re-linted and either re-parses as YAML or fails
//! cleanly (no panic).

use libfuzzer_sys::fuzz_target;
use rsigma_parser::{LintWarning, apply_fixes_to_source, lint_yaml_str};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Lint, collect fixable findings, apply the safe ones to the source.
    let warnings = lint_yaml_str(text);
    let fixable: Vec<&LintWarning> = warnings.iter().filter(|w| w.fix.is_some()).collect();
    let outcome = apply_fixes_to_source(text, &fixable);

    // The fixed output must be re-lintable without panicking ...
    let _ = lint_yaml_str(&outcome.fixed_source);
    // ... and either re-parse as YAML or fail cleanly (never panic).
    let _ = yaml_serde::from_str::<yaml_serde::Value>(&outcome.fixed_source);
});
