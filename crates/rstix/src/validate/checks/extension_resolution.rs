//! Extension resolution.

use crate::model::common::ExtensionType;

use super::super::diagnostic::{Diagnostic, DiagnosticCode};
use super::super::wire::collect_extension_schema_issues;
use super::{ValidationContext, ValidationReport};

const PREDEFINED_PROPERTY_EXTENSION_ID: &str =
    "extension-definition--60477d8d-78ac-1058-8160-d776f9386f83";

pub fn run(ctx: &ValidationContext<'_>, report: &mut ValidationReport) {
    let Some(value) = ctx.value else {
        return;
    };
    let ids = super::super::wire::collect_object_ids(value);
    check_unknown_extensions(value, &ids, report);
    check_extension_serialization(value, report);
    for (path, message) in collect_extension_schema_issues(value) {
        report.push(Diagnostic::new(DiagnosticCode::E0030, message).with_property_path(path));
    }
}

fn check_unknown_extensions(
    value: &serde_json::Value,
    ids: &std::collections::HashSet<String>,
    report: &mut ValidationReport,
) {
    let Some(objects) = value.get("objects").and_then(serde_json::Value::as_array) else {
        return;
    };
    for (index, object) in objects.iter().enumerate() {
        let Some(extensions) = object
            .get("extensions")
            .and_then(serde_json::Value::as_object)
        else {
            continue;
        };
        for key in extensions.keys() {
            if key.ends_with("-ext") {
                continue;
            }
            if key.starts_with("extension-definition--")
                && *key != PREDEFINED_PROPERTY_EXTENSION_ID
                && !ids.contains(key.as_str())
            {
                report.push(
                    Diagnostic::new(
                        DiagnosticCode::W0020,
                        format!("unknown extension definition `{key}`"),
                    )
                    .with_property_path(format!("objects[{index}].extensions.{key}")),
                );
            }
        }
    }
}

fn check_extension_serialization(value: &serde_json::Value, report: &mut ValidationReport) {
    let Some(objects) = value.get("objects").and_then(serde_json::Value::as_array) else {
        return;
    };
    for (index, object) in objects.iter().enumerate() {
        let Some(extensions) = object
            .get("extensions")
            .and_then(serde_json::Value::as_object)
        else {
            continue;
        };
        for (key, entry) in extensions {
            let Some(entry_obj) = entry.as_object() else {
                continue;
            };
            let extension_type = entry_obj
                .get("extension_type")
                .and_then(serde_json::Value::as_str)
                .and_then(ExtensionType::from_str_value);
            if extension_type == Some(ExtensionType::ToplevelPropertyExtension) {
                for (prop, prop_value) in entry_obj {
                    if prop == "extension_type" {
                        continue;
                    }
                    if object.get(prop) != Some(prop_value) {
                        report.push(
                            Diagnostic::new(
                                DiagnosticCode::E0031,
                                format!(
                                    "toplevel-property-extension `{key}` property `{prop}` is not hoisted to the object top level"
                                ),
                            )
                            .with_property_path(format!("objects[{index}].{prop}")),
                        );
                    }
                }
            }
            if extension_type == Some(ExtensionType::PropertyExtension) {
                for (prop, prop_value) in entry_obj {
                    if prop == "extension_type" {
                        continue;
                    }
                    if object.get(prop).is_some() {
                        report.push(
                            Diagnostic::new(
                                DiagnosticCode::E0031,
                                format!(
                                    "property-extension `{key}` property `{prop}` must not also appear at the object top level"
                                ),
                            )
                            .with_property_path(format!("objects[{index}].{prop}")),
                        );
                    }
                    let _ = prop_value;
                }
            }
        }
    }
}
