//! Cross-object semantics and granular selectors.

use super::super::diagnostic::{Diagnostic, DiagnosticCode};
use super::super::semantic::run_cross_object_semantics;
use super::super::wire::{collect_granular_marking_issues, collect_object_marking_ref_kind_issues};
use super::{ValidationContext, ValidationReport};

pub fn run(ctx: &ValidationContext<'_>, report: &mut ValidationReport) {
    if let Some(value) = ctx.value {
        for (path, code, message) in collect_granular_marking_issues(value) {
            report.push(Diagnostic::new(code, message).with_property_path(path));
        }
        for (path, target) in collect_object_marking_ref_kind_issues(value) {
            report.push(
                Diagnostic::new(
                    DiagnosticCode::E0022,
                    format!("object_marking_refs element `{target}` is not a marking-definition"),
                )
                .with_property_path(path),
            );
        }
    }

    if let Some(bundle) = ctx.bundle {
        run_cross_object_semantics(bundle, report);
    }
}
