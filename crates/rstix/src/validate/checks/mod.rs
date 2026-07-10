//! Validation check dispatcher and shared context.

use crate::model::{Bundle, ParseOptions};

use super::report::ValidationReport;
use super::{Leniency, ValidationPhase};

mod cross_object_semantic;
mod extension_resolution;
mod id_structure;
mod json_wellformedness;
mod open_vocabulary;
mod pattern_parse;
mod pattern_semantic;
mod property_types;
mod references;
mod schema;
mod tlp_marking;
mod type_discrimination;

pub(crate) use type_discrimination::document_root_type;

/// Input to a validation check.
pub struct ValidationContext<'a> {
    /// Parsed bundle when typed deserialization succeeded.
    pub bundle: Option<&'a Bundle>,
    /// Raw JSON value (always present for `validate_json_*` after JSON parse).
    pub value: Option<&'a serde_json::Value>,
    /// Profile leniency policy.
    #[allow(dead_code)]
    pub leniency: Leniency,
    /// Bundle parse policy for type discrimination and typed resolution.
    #[allow(dead_code)]
    pub parse_options: &'a ParseOptions,
}

impl<'a> ValidationContext<'a> {
    pub(crate) fn new(
        bundle: Option<&'a Bundle>,
        value: Option<&'a serde_json::Value>,
        leniency: Leniency,
        parse_options: &'a ParseOptions,
    ) -> Self {
        Self {
            bundle,
            value,
            leniency,
            parse_options,
        }
    }
}

pub(crate) fn run_checks(
    checks: &[ValidationPhase],
    ctx: &ValidationContext<'_>,
    report: &mut ValidationReport,
) {
    for check in checks {
        run_check(*check, ctx, report);
    }
}

fn run_check(check: ValidationPhase, ctx: &ValidationContext<'_>, report: &mut ValidationReport) {
    match check {
        ValidationPhase::JsonWellFormedness => json_wellformedness::run(ctx, report),
        ValidationPhase::TypeDiscrimination => type_discrimination::run(ctx, report),
        ValidationPhase::Schema => schema::run(ctx, report),
        ValidationPhase::IdStructure => id_structure::run(ctx, report),
        ValidationPhase::PropertyTypes => property_types::run(ctx, report),
        ValidationPhase::OpenVocabulary => open_vocabulary::run(ctx, report),
        ValidationPhase::PatternParse => pattern_parse::run(ctx, report),
        ValidationPhase::PatternSemantic => pattern_semantic::run(ctx, report),
        ValidationPhase::References => references::run(ctx, report),
        ValidationPhase::CrossObjectSemantic => cross_object_semantic::run(ctx, report),
        ValidationPhase::ExtensionResolution => extension_resolution::run(ctx, report),
        ValidationPhase::TlpMarkingComputation => tlp_marking::run(ctx, report),
    }
}
