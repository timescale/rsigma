//! Open vocabulary findings (info only).

use crate::vocab::{
    ATTACK_MOTIVATION_OV, ATTACK_RESOURCE_LEVEL_OV, GROUPING_CONTEXT_OV, IDENTITY_CLASS_OV,
    IMPLEMENTATION_LANGUAGE_OV, INDICATOR_TYPE_OV, INDUSTRY_SECTOR_OV, INFRASTRUCTURE_TYPE_OV,
    MALWARE_CAPABILITIES_OV, MALWARE_TYPE_OV, PATTERN_TYPE_OV, PROCESSOR_ARCHITECTURE_OV,
    REGION_OV, REPORT_TYPE_OV, THREAT_ACTOR_ROLE_OV, THREAT_ACTOR_SOPHISTICATION_OV,
    THREAT_ACTOR_TYPE_OV, TOOL_TYPE_OV,
};

use super::super::diagnostic::{Diagnostic, DiagnosticCode};
use super::{ValidationContext, ValidationReport};

pub fn run(ctx: &ValidationContext<'_>, report: &mut ValidationReport) {
    let Some(value) = ctx.value else {
        return;
    };
    let Some(objects) = value.get("objects").and_then(serde_json::Value::as_array) else {
        return;
    };

    for (index, object) in objects.iter().enumerate() {
        let Some(object_type) = object.get("type").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let prefix = format!("objects[{index}]");
        match object_type {
            "identity" => {
                check_string_field(
                    object,
                    "identity_class",
                    &IDENTITY_CLASS_OV,
                    &prefix,
                    report,
                );
                check_string_list(object, "sectors", &INDUSTRY_SECTOR_OV, &prefix, report);
            }
            "indicator" => {
                check_string_list(
                    object,
                    "indicator_types",
                    &INDICATOR_TYPE_OV,
                    &prefix,
                    report,
                );
                check_string_field(object, "pattern_type", &PATTERN_TYPE_OV, &prefix, report);
            }
            "threat-actor" => {
                check_string_list(
                    object,
                    "threat_actor_types",
                    &THREAT_ACTOR_TYPE_OV,
                    &prefix,
                    report,
                );
                check_string_list(object, "roles", &THREAT_ACTOR_ROLE_OV, &prefix, report);
                check_string_field(
                    object,
                    "sophistication",
                    &THREAT_ACTOR_SOPHISTICATION_OV,
                    &prefix,
                    report,
                );
                check_string_list(object, "goals", &ATTACK_MOTIVATION_OV, &prefix, report);
                check_string_list(
                    object,
                    "secondary_motivations",
                    &ATTACK_MOTIVATION_OV,
                    &prefix,
                    report,
                );
                check_string_list(
                    object,
                    "personal_motivations",
                    &ATTACK_MOTIVATION_OV,
                    &prefix,
                    report,
                );
                check_string_field(
                    object,
                    "resource_level",
                    &ATTACK_RESOURCE_LEVEL_OV,
                    &prefix,
                    report,
                );
            }
            "malware" => {
                check_string_list(object, "malware_types", &MALWARE_TYPE_OV, &prefix, report);
                check_string_list(
                    object,
                    "capabilities",
                    &MALWARE_CAPABILITIES_OV,
                    &prefix,
                    report,
                );
                check_string_list(
                    object,
                    "implementation_languages",
                    &IMPLEMENTATION_LANGUAGE_OV,
                    &prefix,
                    report,
                );
                check_string_list(
                    object,
                    "architecture_execution_envs",
                    &PROCESSOR_ARCHITECTURE_OV,
                    &prefix,
                    report,
                );
            }
            "tool" => check_string_list(object, "tool_types", &TOOL_TYPE_OV, &prefix, report),
            "infrastructure" => {
                check_string_list(
                    object,
                    "infrastructure_types",
                    &INFRASTRUCTURE_TYPE_OV,
                    &prefix,
                    report,
                );
            }
            "grouping" => {
                check_string_field(object, "context", &GROUPING_CONTEXT_OV, &prefix, report);
            }
            "report" => check_string_list(object, "report_types", &REPORT_TYPE_OV, &prefix, report),
            "location" => check_string_field(object, "region", &REGION_OV, &prefix, report),
            _ => {}
        }
    }
}

fn check_string_field(
    object: &serde_json::Value,
    field: &str,
    vocabulary: &phf::Set<&'static str>,
    prefix: &str,
    report: &mut ValidationReport,
) {
    let Some(value) = object.get(field).and_then(serde_json::Value::as_str) else {
        return;
    };
    if !value.is_empty() && !vocabulary.contains(value) {
        report.push(
            Diagnostic::new(
                DiagnosticCode::I0001,
                format!("open vocabulary extension value `{value}` for `{field}`"),
            )
            .with_property_path(format!("{prefix}.{field}")),
        );
    }
}

fn check_string_list(
    object: &serde_json::Value,
    field: &str,
    vocabulary: &phf::Set<&'static str>,
    prefix: &str,
    report: &mut ValidationReport,
) {
    let Some(values) = object.get(field).and_then(serde_json::Value::as_array) else {
        return;
    };
    for (index, entry) in values.iter().enumerate() {
        let Some(value) = entry.as_str() else {
            continue;
        };
        if !value.is_empty() && !vocabulary.contains(value) {
            report.push(
                Diagnostic::new(
                    DiagnosticCode::I0001,
                    format!("open vocabulary extension value `{value}` for `{field}`"),
                )
                .with_property_path(format!("{prefix}.{field}[{index}]")),
            );
        }
    }
}
