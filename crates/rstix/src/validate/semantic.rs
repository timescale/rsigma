//! Bundle-level semantic checks migrated from [`crate::model::Bundle::validate`].

use std::collections::HashSet;

use crate::core::{QueryableStixObject, StixId};
use crate::model::common::{GranularMarking, SdoSroCommonProps};
use crate::model::meta::{
    LanguageContent, MarkingDefinition, MetaObject, TLP1_AMBER_ID, TLP1_GREEN_ID, TLP1_RED_ID,
    TLP1_WHITE_ID,
};
use crate::model::sco::{Artifact, ScoObject};
use crate::model::sdo::{
    AttackPattern, Location, ObservedData, ObservedDataEmbeddedObject, ObservedDataForm, SdoObject,
    Vulnerability,
};
use crate::model::sro::SroObject;
use crate::model::validate::{
    language_content_translation_matches_target, resolve_selector_value,
    validate_capec_external_refs, validate_cve_external_refs, validate_encryption_algorithm,
    validate_granular_selector_syntax, validate_relationship_endpoints,
    validate_sco_deterministic_id,
};
use crate::model::{Bundle, StixObject};
use crate::vocab::{REGION_OV, is_iso3166_alpha2};

use super::ValidationReport;
use super::diagnostic::{Diagnostic, DiagnosticCode};

/// Cross-object semantic checks (relationship matrix, granular selectors, language-content).
pub(crate) fn run_cross_object_semantics(bundle: &Bundle, report: &mut ValidationReport) {
    for object in bundle.objects() {
        let object_id = object.id();
        if let Ok(wire) = serde_json::to_value(object) {
            if let StixObject::Sco(sco) = object
                && validate_sco_deterministic_id(sco.type_name(), &wire).is_err()
            {
                report.push(
                    Diagnostic::new(
                        DiagnosticCode::W0002,
                        format!(
                            "SCO `{}` id does not match deterministic UUIDv5 from id-contributing properties",
                            sco.type_name()
                        ),
                    )
                    .with_object_id(object_id.clone())
                    .with_property_path("id"),
                );
            }
            check_granular_selectors(object, &wire, object_id, report);
        }

        if let StixObject::Sdo(SdoObject::ObservedData(ObservedData {
            form: ObservedDataForm::DeprecatedObjects(objects),
            ..
        })) = object
        {
            for embedded in objects.values() {
                if let ObservedDataEmbeddedObject::Sco(sco) = embedded
                    && let Ok(wire) = serde_json::to_value(sco)
                    && validate_sco_deterministic_id(sco.type_name(), &wire).is_err()
                {
                    report.push(
                        Diagnostic::new(
                            DiagnosticCode::W0002,
                            format!(
                                "SCO `{}` id does not match deterministic UUIDv5 from id-contributing properties",
                                sco.type_name()
                            ),
                        )
                        .with_object_id(sco.id().clone())
                        .with_property_path("id"),
                    );
                }
            }
        }

        if let StixObject::Sdo(sdo) = object {
            match sdo {
                SdoObject::AttackPattern(AttackPattern { common, .. }) => {
                    if validate_capec_external_refs(&common.external_references).is_err() {
                        report.push(
                            Diagnostic::new(
                                DiagnosticCode::W0010,
                                "CAPEC external reference should use source_name `capec` with external_id prefixed `CAPEC-`",
                            )
                            .with_object_id(object_id.clone())
                            .with_property_path("external_references"),
                        );
                    }
                }
                SdoObject::Vulnerability(Vulnerability { common, .. }) => {
                    if validate_cve_external_refs(&common.external_references).is_err() {
                        report.push(
                            Diagnostic::new(
                                DiagnosticCode::W0010,
                                "CVE external reference should use source_name `cve` with external_id prefixed `CVE-`",
                            )
                            .with_object_id(object_id.clone())
                            .with_property_path("external_references"),
                        );
                    }
                }
                SdoObject::Location(Location {
                    country, region, ..
                }) => {
                    if let Some(country) = country
                        && !country.is_empty()
                        && !is_iso3166_alpha2(country)
                    {
                        report.push(
                            Diagnostic::new(
                                DiagnosticCode::W0010,
                                format!(
                                    "location country `{country}` should be ISO 3166-1 alpha-2"
                                ),
                            )
                            .with_object_id(object_id.clone())
                            .with_property_path("country"),
                        );
                    }
                    if let Some(region) = region
                        && !region.is_empty()
                        && !REGION_OV.contains(region.as_str())
                    {
                        report.push(
                            Diagnostic::new(
                                DiagnosticCode::I0001,
                                format!(
                                    "location region `{region}` is not in the STIX region open vocabulary"
                                ),
                            )
                            .with_object_id(object_id.clone())
                            .with_property_path("region"),
                        );
                    }
                }
                _ => {}
            }
        }

        if let StixObject::Sco(ScoObject::Artifact(Artifact {
            encryption_algorithm,
            ..
        })) = object
            && let Some(algorithm) = encryption_algorithm
            && validate_encryption_algorithm(algorithm).is_err()
        {
            report.push(
                Diagnostic::new(
                    DiagnosticCode::W0010,
                    format!(
                        "encryption_algorithm `{algorithm}` is not in the STIX closed vocabulary"
                    ),
                )
                .with_object_id(object_id.clone())
                .with_property_path("encryption_algorithm"),
            );
        }

        if let StixObject::Sro(SroObject::Relationship(relationship)) = object
            && validate_relationship_endpoints(
                &relationship.source_ref,
                &relationship.target_ref,
                &relationship.relationship_type,
            )
            .is_err()
        {
            report.push(
                Diagnostic::new(
                    DiagnosticCode::I0002,
                    format!(
                        "relationship `{}` from `{}` to `{}` is outside the STIX 2.1 matrix",
                        relationship.relationship_type,
                        relationship.source_ref.type_name(),
                        relationship.target_ref.type_name(),
                    ),
                )
                .with_object_id(object_id.clone())
                .with_property_path(format!(
                    "relationship_type[{}]",
                    relationship.relationship_type
                )),
            );
        }

        if let StixObject::Meta(MetaObject::LanguageContent(content)) = object {
            check_language_content(bundle, content, report);
        }
    }
}

/// TLP marking computation and deprecated encoding checks.
pub(crate) fn run_tlp_marking_semantics(bundle: &Bundle, report: &mut ValidationReport) {
    let tlp1_ids: HashSet<&str> =
        HashSet::from([TLP1_WHITE_ID, TLP1_GREEN_ID, TLP1_AMBER_ID, TLP1_RED_ID]);

    for object in bundle.objects() {
        let object_id = object.id();
        check_tlp_v1_usage(object, object_id, &tlp1_ids, report);
        if let StixObject::Meta(MetaObject::MarkingDefinition(marking)) = object {
            check_marking_definition_tlp(marking, object_id, report);
        }
    }
}

fn check_tlp_v1_usage(
    object: &StixObject,
    object_id: &StixId,
    tlp1_ids: &HashSet<&str>,
    report: &mut ValidationReport,
) {
    for marking in common_marking_refs(object) {
        if tlp1_ids.contains(marking.as_str()) {
            report.push(
                Diagnostic::new(
                    DiagnosticCode::W0031,
                    "object references a TLP 1.x marking-definition id (STIX-W0031)",
                )
                .with_object_id(object_id.clone())
                .with_property_path("object_marking_refs"),
            );
            return;
        }
    }
}

fn check_marking_definition_tlp(
    marking: &MarkingDefinition,
    object_id: &StixId,
    report: &mut ValidationReport,
) {
    if marking.definition_type.is_some() {
        report.push(
            Diagnostic::new(
                DiagnosticCode::W0031,
                "marking-definition uses legacy TLP 1.x encoding via definition_type (STIX-W0031)",
            )
            .with_object_id(object_id.clone())
            .with_property_path("definition_type"),
        );
    }
    if let Some(definition) = &marking.definition
        && let Some(tlp) = definition.get("tlp").and_then(serde_json::Value::as_str)
        && tlp.eq_ignore_ascii_case("amber+stict")
    {
        report.push(
            Diagnostic::new(
                DiagnosticCode::W0030,
                "TLP 2.0 marking uses typo `amber+stict`; use `amber+strict`",
            )
            .with_object_id(object_id.clone())
            .with_property_path("definition.tlp")
            .with_fix_suggestion("Change the TLP level to `amber+strict`."),
        );
    }
    if !marking.extensions.is_empty()
        && let Some(tlp) = marking
            .extensions
            .0
            .get("extension-definition--60477d8d-78ac-1058-8160-d776f9386f83")
            .and_then(|entry| entry.properties.get("tlp_2_0"))
            .and_then(serde_json::Value::as_str)
        && tlp.eq_ignore_ascii_case("amber+stict")
    {
        report.push(
            Diagnostic::new(
                DiagnosticCode::W0030,
                "TLP 2.0 marking uses typo `amber+stict`; use `amber+strict`",
            )
            .with_object_id(object_id.clone())
            .with_property_path("extensions.tlp_2_0")
            .with_fix_suggestion("Change the TLP level to `amber+strict`."),
        );
    }
}

fn common_marking_refs(object: &StixObject) -> Vec<&StixId> {
    let mut refs = Vec::new();
    match object {
        StixObject::Sdo(sdo) => push_sdo_sro_marking_refs(sdo.common_props(), &mut refs),
        StixObject::Sro(sro) => push_sdo_sro_marking_refs(sro.common_props(), &mut refs),
        StixObject::Sco(sco) => {
            let common = sco.common_props();
            for marking in &common.object_marking_refs {
                refs.push(marking.as_stix_id());
            }
            for granular in &common.granular_markings {
                push_granular_marking_ref(granular, &mut refs);
            }
        }
        StixObject::Meta(MetaObject::MarkingDefinition(marking)) => {
            for marking_ref in &marking.object_marking_refs {
                refs.push(marking_ref.as_stix_id());
            }
            for granular in &marking.granular_markings {
                push_granular_marking_ref(granular, &mut refs);
            }
        }
        StixObject::Meta(MetaObject::LanguageContent(LanguageContent { common, .. })) => {
            push_sdo_sro_marking_refs(common, &mut refs);
        }
        StixObject::Meta(MetaObject::ExtensionDefinition(ext)) => {
            push_sdo_sro_marking_refs(&ext.common, &mut refs);
        }
        StixObject::Custom(_) => {}
    }
    refs
}

fn push_sdo_sro_marking_refs<'a>(common: &'a SdoSroCommonProps, refs: &mut Vec<&'a StixId>) {
    for marking in &common.object_marking_refs {
        refs.push(marking.as_stix_id());
    }
    for granular in &common.granular_markings {
        push_granular_marking_ref(granular, refs);
    }
}

fn push_granular_marking_ref<'a>(granular: &'a GranularMarking, refs: &mut Vec<&'a StixId>) {
    if let Some(marking_ref) = &granular.marking_ref {
        refs.push(marking_ref.as_stix_id());
    }
}

fn check_granular_selectors(
    object: &StixObject,
    wire: &serde_json::Value,
    object_id: &StixId,
    report: &mut ValidationReport,
) {
    let granular_markings = match object {
        StixObject::Sdo(sdo) => &sdo.common_props().granular_markings,
        StixObject::Sro(sro) => &sro.common_props().granular_markings,
        StixObject::Sco(sco) => &sco.common_props().granular_markings,
        StixObject::Meta(MetaObject::MarkingDefinition(marking)) => &marking.granular_markings,
        StixObject::Meta(MetaObject::LanguageContent(LanguageContent { common, .. })) => {
            &common.granular_markings
        }
        StixObject::Meta(MetaObject::ExtensionDefinition(ext)) => &ext.common.granular_markings,
        StixObject::Custom(_) => return,
    };

    for granular in granular_markings {
        for selector in &granular.selectors {
            if validate_granular_selector_syntax(selector).is_err() {
                report.push(
                    Diagnostic::new(
                        DiagnosticCode::E0024,
                        format!("granular-marking selector `{selector}` has invalid syntax"),
                    )
                    .with_object_id(object_id.clone())
                    .with_property_path(format!("selectors[{selector}]")),
                );
            } else if !selector_resolves(wire, selector) {
                report.push(
                    Diagnostic::new(
                        DiagnosticCode::E0024,
                        format!(
                            "granular-marking selector `{selector}` does not resolve on object"
                        ),
                    )
                    .with_object_id(object_id.clone())
                    .with_property_path(format!("selectors[{selector}]")),
                );
            }
        }
    }
}

fn selector_resolves(value: &serde_json::Value, selector: &str) -> bool {
    resolve_selector_value(value, selector).is_some()
}

fn check_language_content(
    bundle: &Bundle,
    content: &LanguageContent,
    report: &mut ValidationReport,
) {
    let object_id = &content.common.id;
    let target = match bundle.get(&content.object_ref) {
        Some(target) => target,
        None => return,
    };

    if let Some(object_modified) = &content.object_modified {
        match QueryableStixObject::modified(target) {
            Some(target_modified) if object_modified != target_modified => {
                report.push(
                    Diagnostic::new(
                        DiagnosticCode::E0024,
                        "language-content object_modified does not match target modified timestamp",
                    )
                    .with_object_id(object_id.clone())
                    .with_property_path("object_modified"),
                );
            }
            None => {
                report.push(
                    Diagnostic::new(
                        DiagnosticCode::E0024,
                        "language-content object_modified set but target has no modified timestamp",
                    )
                    .with_object_id(object_id.clone())
                    .with_property_path("object_modified"),
                );
            }
            _ => {}
        }
    }

    let Ok(target_wire) = serde_json::to_value(target) else {
        return;
    };
    for (lang, fields) in &content.contents {
        for (field, translation) in fields {
            let Some(target_value) = resolve_selector_value(&target_wire, field) else {
                report.push(
                    Diagnostic::new(
                        DiagnosticCode::E0024,
                        format!(
                            "language-content field `{field}` for lang `{lang}` is not a property on target `{}`",
                            content.object_ref.type_name()
                        ),
                    )
                    .with_object_id(object_id.clone())
                    .with_property_path(format!("contents.{lang}.{field}")),
                );
                continue;
            };
            if !language_content_translation_matches_target(target_value, translation) {
                report.push(
                    Diagnostic::new(
                        DiagnosticCode::E0024,
                        format!(
                            "language-content translation for `{field}` (lang `{lang}`) does not mirror target property type or list length"
                        ),
                    )
                    .with_object_id(object_id.clone())
                    .with_property_path(format!("contents.{lang}.{field}")),
                );
            }
        }
    }
}
