//! Property types, timestamps, hashes, and closed vocab.

use crate::model::Bundle;
use crate::model::StixObject;
use crate::vocab::OPINION_ENUM;

use super::super::diagnostic::{Diagnostic, DiagnosticCode};
use super::super::wire::{
    collect_invalid_hash_paths, collect_post_revocation_version_issues,
    collect_short_timestamp_paths, collect_unsafe_integer_paths, collect_versioned_objects,
};
use super::{ValidationContext, ValidationReport};

pub fn run(ctx: &ValidationContext<'_>, report: &mut ValidationReport) {
    if let Some(value) = ctx.value {
        for (path, timestamp) in collect_short_timestamp_paths(value) {
            report.push(
                Diagnostic::new(
                    DiagnosticCode::E0012,
                    format!("timestamp `{timestamp}` has fewer than three fractional digits"),
                )
                .with_property_path(path),
            );
        }
        for (path, value) in collect_unsafe_integer_paths(value) {
            report.push(
                Diagnostic::new(
                    DiagnosticCode::E0014,
                    format!("integer `{value}` is outside the ±2^53 safe range"),
                )
                .with_property_path(path),
            );
        }
        for (path, detail) in collect_invalid_hash_paths(value) {
            report.push(Diagnostic::new(DiagnosticCode::E0013, detail).with_property_path(path));
        }
        check_closed_vocabulary_on_wire(value, report);

        let versioned = collect_versioned_objects(value);
        for (path, message) in collect_post_revocation_version_issues(&versioned) {
            report.push(Diagnostic::new(DiagnosticCode::W0003, message).with_property_path(path));
        }
    }

    if let Some(bundle) = ctx.bundle {
        check_modified_gte_created(bundle, report);
    }
}

fn check_closed_vocabulary_on_wire(value: &serde_json::Value, report: &mut ValidationReport) {
    let Some(objects) = value.get("objects").and_then(serde_json::Value::as_array) else {
        return;
    };
    for (index, object) in objects.iter().enumerate() {
        let Some(object_type) = object.get("type").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if object_type == "opinion"
            && let Some(opinion) = object.get("opinion").and_then(serde_json::Value::as_str)
            && !OPINION_ENUM.contains(opinion)
        {
            report.push(
                Diagnostic::new(
                    DiagnosticCode::E0013,
                    format!("unknown opinion value `{opinion}`"),
                )
                .with_property_path(format!("objects[{index}].opinion")),
            );
        }
        if object_type == "artifact"
            && let Some(algorithm) = object
                .get("encryption_algorithm")
                .and_then(serde_json::Value::as_str)
            && crate::model::validate::validate_encryption_algorithm(algorithm).is_err()
        {
            report.push(
                Diagnostic::new(
                    DiagnosticCode::E0013,
                    format!("unknown encryption_algorithm value `{algorithm}`"),
                )
                .with_property_path(format!("objects[{index}].encryption_algorithm")),
            );
        }
    }
}

fn check_modified_gte_created(bundle: &Bundle, report: &mut ValidationReport) {
    for object in bundle.objects() {
        let common = match object {
            StixObject::Sdo(sdo) => Some(sdo.common_props()),
            StixObject::Sro(sro) => Some(sro.common_props()),
            _ => None,
        };
        let Some(common) = common else {
            continue;
        };
        if common.modified < common.created {
            report.push(
                Diagnostic::new(
                    DiagnosticCode::E0015,
                    "modified must be greater than or equal to created",
                )
                .with_object_id(common.id.clone())
                .with_property_path("modified"),
            );
        }
    }
}
