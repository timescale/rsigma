//! Schema, required fields, and mutual exclusion.

use super::{ValidationContext, ValidationReport};
use crate::model::StixObject;

use super::super::diagnostic::{Diagnostic, DiagnosticCode};
use super::super::object_validate::validate_typed_objects;
use super::super::wire::{
    collect_granular_marking_issues, collect_reserved_custom_property_issues,
    collect_sco_forbidden_property_issues,
};

pub fn run(ctx: &ValidationContext<'_>, report: &mut ValidationReport) {
    if let Some(value) = ctx.value {
        for (path, property) in collect_reserved_custom_property_issues(value) {
            report.push(
                Diagnostic::new(
                    DiagnosticCode::E0006,
                    format!("reserved property name `{property}` in custom properties"),
                )
                .with_property_path(path),
            );
        }
        for (path, code, message) in collect_granular_marking_issues(value) {
            if matches!(code, DiagnosticCode::E0040 | DiagnosticCode::E0041) {
                report.push(Diagnostic::new(code, message).with_property_path(path));
            }
        }
        for (path, property) in collect_sco_forbidden_property_issues(value) {
            report.push(
                Diagnostic::new(
                    DiagnosticCode::W0040,
                    format!("SCO object has unexpected SDO-only property `{property}`"),
                )
                .with_property_path(path),
            );
        }
    }

    if let Some(bundle) = ctx.bundle {
        validate_typed_objects(bundle.objects(), report);
        for object in bundle.objects() {
            if let StixObject::Custom(custom) = object {
                validate_custom_object_schema(custom, report);
            }
        }
    }
}

fn validate_custom_object_schema(
    custom: &crate::model::CustomStixObject,
    report: &mut ValidationReport,
) {
    let Some(obj) = custom.raw.as_object() else {
        return;
    };
    for key in obj.keys() {
        if matches!(
            key.as_str(),
            "severity" | "username" | "phone_number" | "action"
        ) && !key.starts_with("x_")
        {
            report.push(
                Diagnostic::new(
                    DiagnosticCode::E0006,
                    format!("reserved property name `{key}` in custom object"),
                )
                .with_object_id(custom.id.clone())
                .with_property_path(key.clone()),
            );
        }
    }
}
