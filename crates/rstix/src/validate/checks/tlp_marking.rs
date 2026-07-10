//! TLP marking computation.

use super::super::diagnostic::{Diagnostic, DiagnosticCode};
use super::super::semantic::run_tlp_marking_semantics;
use super::super::wire::collect_tlp_marking_issues;
use super::{ValidationContext, ValidationReport};

pub fn run(ctx: &ValidationContext<'_>, report: &mut ValidationReport) {
    if let Some(value) = ctx.value {
        for (path, code, message) in collect_tlp_marking_issues(value) {
            let mut diagnostic = Diagnostic::new(code, message).with_property_path(path.clone());
            if code == DiagnosticCode::W0030 {
                let hint_path = diagnostic
                    .property_path
                    .clone()
                    .unwrap_or_else(|| "definition.tlp".into());
                diagnostic = diagnostic
                    .with_fix_suggestion("Change the TLP level to `amber+strict`.")
                    .with_property_path(path);
                report.push(
                    Diagnostic::new(
                        DiagnosticCode::H0001,
                        "TLP 2.0 uses `amber+strict`, not `amber+stict`.",
                    )
                    .with_property_path(hint_path),
                );
            }
            report.push(diagnostic);
        }
    }

    if let Some(bundle) = ctx.bundle {
        run_tlp_marking_semantics(bundle, report);
    }
}
