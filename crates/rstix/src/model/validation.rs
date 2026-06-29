//! Bundle-level semantic validation (STIX SHOULD rules and advisory codes).

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
    validate_relationship_endpoints, validate_sco_deterministic_id,
};
use crate::model::{Bundle, StixObject};
use crate::vocab::{REGION_OV, is_iso3166_alpha2};

/// Machine-readable validation code (STIX advisory ids where applicable).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ValidationCode {
    /// STIX-W0031: legacy TLP 1.x marking encoding on a STIX 2.1 object.
    StixW0031TlpV1Encoding,
    /// SCO id does not match deterministic UUIDv5 from id-contributing properties.
    ScoDeterministicIdMismatch,
    /// Granular-marking selector does not resolve to a property on the object.
    GranularSelectorSemanticInvalid,
    /// Language-content translation key is not a property on the target object.
    LanguageContentFieldUnknown,
    /// Language-content translation type or list length does not mirror the target property.
    LanguageContentValueMismatch,
    /// Language-content `object_modified` does not match the target object's `modified`.
    LanguageContentObjectModifiedMismatch,
    /// Location `country` is not a valid ISO 3166-1 alpha-2 code.
    LocationCountryNotIso3166,
    /// Location `region` is not in the STIX region open vocabulary.
    LocationRegionNotInOpenVocab,
    /// CAPEC external reference is malformed (SHOULD).
    InvalidCapecExternalReference,
    /// CVE external reference is malformed (SHOULD).
    InvalidCveExternalReference,
    /// Relationship endpoint types fall outside the STIX 2.1 matrix (SHOULD).
    RelationshipEndpointMatrixInvalid,
    /// Artifact `encryption_algorithm` is not in the closed vocabulary (SHOULD).
    EncryptionAlgorithmInvalid,
}

/// A single validation finding (always emitted as a warning).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationFinding {
    /// Advisory code.
    pub code: ValidationCode,
    /// Object id the finding applies to, when known.
    pub object_id: Option<String>,
    /// Human-readable detail.
    pub message: String,
    /// Related selector or field path, when applicable.
    pub detail: Option<String>,
}

impl ValidationFinding {
    fn warning(
        code: ValidationCode,
        object_id: Option<&StixId>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            object_id: object_id.map(|id| id.as_str().to_owned()),
            message: message.into(),
            detail: None,
        }
    }

    fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Aggregated bundle validation output (SHOULD-level checks only).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidationReport {
    /// Non-fatal findings from semantic validation.
    pub warnings: Vec<ValidationFinding>,
}

impl ValidationReport {
    /// Returns true when no warnings were recorded.
    pub fn is_clean(&self) -> bool {
        self.warnings.is_empty()
    }

    /// Number of warnings.
    pub fn warning_count(&self) -> usize {
        self.warnings.len()
    }

    /// All findings with the given code.
    pub fn warnings_with_code(
        &self,
        code: ValidationCode,
    ) -> impl Iterator<Item = &ValidationFinding> {
        self.warnings
            .iter()
            .filter(move |finding| finding.code == code)
    }
}

impl Bundle {
    /// Run SHOULD-level semantic validation over parsed bundle contents.
    ///
    /// Parse-time checks enforce STIX MUST rules; this method collects advisory
    /// findings (for example STIX-W0031, SCO deterministic id mismatches, and
    /// relationship matrix violations) without rejecting the bundle.
    pub fn validate(&self) -> ValidationReport {
        let mut report = ValidationReport::default();
        let tlp1_ids: HashSet<&str> =
            HashSet::from([TLP1_WHITE_ID, TLP1_GREEN_ID, TLP1_AMBER_ID, TLP1_RED_ID]);

        for object in self.objects() {
            let object_id = object.id();
            if let Ok(wire) = serde_json::to_value(object) {
                if let StixObject::Sco(sco) = object {
                    check_sco_deterministic_id(sco, &wire, object_id, &mut report);
                }
                check_granular_selectors(object, &wire, object_id, &mut report);
            }
            check_tlp_v1_usage(object, object_id, &tlp1_ids, &mut report);

            match object {
                StixObject::Sdo(sdo) => match sdo {
                    SdoObject::AttackPattern(AttackPattern { common, .. }) => {
                        if validate_capec_external_refs(&common.external_references).is_err() {
                            report.warnings.push(ValidationFinding::warning(
                                ValidationCode::InvalidCapecExternalReference,
                                Some(object_id),
                                "CAPEC external reference should use source_name `capec` with external_id prefixed `CAPEC-`",
                            ));
                        }
                    }
                    SdoObject::Vulnerability(Vulnerability { common, .. }) => {
                        if validate_cve_external_refs(&common.external_references).is_err() {
                            report.warnings.push(ValidationFinding::warning(
                                ValidationCode::InvalidCveExternalReference,
                                Some(object_id),
                                "CVE external reference should use source_name `cve` with external_id prefixed `CVE-`",
                            ));
                        }
                    }
                    SdoObject::Location(Location {
                        country, region, ..
                    }) => {
                        if let Some(country) = country
                            && !country.is_empty()
                            && !is_iso3166_alpha2(country)
                        {
                            report.warnings.push(
                                ValidationFinding::warning(
                                    ValidationCode::LocationCountryNotIso3166,
                                    Some(object_id),
                                    format!(
                                        "location country `{country}` should be ISO 3166-1 alpha-2"
                                    ),
                                )
                                .with_detail(country.clone()),
                            );
                        }
                        if let Some(region) = region
                            && !region.is_empty()
                            && !REGION_OV.contains(region.as_str())
                        {
                            report.warnings.push(
                                ValidationFinding::warning(
                                    ValidationCode::LocationRegionNotInOpenVocab,
                                    Some(object_id),
                                    format!(
                                        "location region `{region}` is not in the STIX region open vocabulary"
                                    ),
                                )
                                .with_detail(region.clone()),
                            );
                        }
                    }
                    SdoObject::ObservedData(ObservedData {
                        form: ObservedDataForm::DeprecatedObjects(objects),
                        ..
                    }) => {
                        for embedded in objects.values() {
                            if let ObservedDataEmbeddedObject::Sco(sco) = embedded
                                && let Ok(wire) = serde_json::to_value(sco)
                            {
                                check_sco_deterministic_id(sco, &wire, sco.id(), &mut report);
                            }
                        }
                    }
                    _ => {}
                },
                StixObject::Sro(SroObject::Relationship(relationship)) => {
                    if validate_relationship_endpoints(
                        &relationship.source_ref,
                        &relationship.target_ref,
                        &relationship.relationship_type,
                    )
                    .is_err()
                    {
                        report.warnings.push(
                            ValidationFinding::warning(
                                ValidationCode::RelationshipEndpointMatrixInvalid,
                                Some(object_id),
                                format!(
                                    "relationship `{}` from `{}` to `{}` is outside the STIX 2.1 matrix",
                                    relationship.relationship_type,
                                    relationship.source_ref.type_name(),
                                    relationship.target_ref.type_name(),
                                ),
                            )
                            .with_detail(relationship.relationship_type.clone()),
                        );
                    }
                }
                StixObject::Sco(ScoObject::Artifact(Artifact {
                    encryption_algorithm,
                    ..
                })) => {
                    if let Some(algorithm) = encryption_algorithm
                        && validate_encryption_algorithm(algorithm).is_err()
                    {
                        report.warnings.push(
                            ValidationFinding::warning(
                                ValidationCode::EncryptionAlgorithmInvalid,
                                Some(object_id),
                                format!("encryption_algorithm `{algorithm}` is not in the STIX closed vocabulary"),
                            )
                            .with_detail(algorithm.clone()),
                        );
                    }
                }
                StixObject::Meta(MetaObject::LanguageContent(content)) => {
                    check_language_content(self, content, &mut report);
                }
                StixObject::Meta(MetaObject::MarkingDefinition(marking)) => {
                    check_marking_definition_tlp_v1(marking, object_id, &mut report);
                }
                _ => {}
            }
        }

        report
    }
}

fn check_sco_deterministic_id(
    sco: &ScoObject,
    wire: &serde_json::Value,
    object_id: &StixId,
    report: &mut ValidationReport,
) {
    if validate_sco_deterministic_id(sco.type_name(), wire).is_err() {
        report.warnings.push(ValidationFinding::warning(
            ValidationCode::ScoDeterministicIdMismatch,
            Some(object_id),
            format!(
                "SCO `{}` id does not match deterministic UUIDv5 from id-contributing properties",
                sco.type_name()
            ),
        ));
    }
}

fn check_tlp_v1_usage(
    object: &StixObject,
    object_id: &StixId,
    tlp1_ids: &HashSet<&str>,
    report: &mut ValidationReport,
) {
    let marking_refs = common_marking_refs(object);
    for marking in marking_refs {
        if tlp1_ids.contains(marking.as_str()) {
            report.warnings.push(ValidationFinding::warning(
                ValidationCode::StixW0031TlpV1Encoding,
                Some(object_id),
                "object references a TLP 1.x marking-definition id (STIX-W0031)",
            ));
            return;
        }
    }
}

fn check_marking_definition_tlp_v1(
    marking: &MarkingDefinition,
    object_id: &StixId,
    report: &mut ValidationReport,
) {
    if marking.definition_type.is_some() {
        report.warnings.push(ValidationFinding::warning(
            ValidationCode::StixW0031TlpV1Encoding,
            Some(object_id),
            "marking-definition uses legacy TLP 1.x encoding via definition_type (STIX-W0031)",
        ));
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
            if !selector_resolves(wire, selector) {
                report.warnings.push(
                    ValidationFinding::warning(
                        ValidationCode::GranularSelectorSemanticInvalid,
                        Some(object_id),
                        format!(
                            "granular-marking selector `{selector}` does not resolve on object"
                        ),
                    )
                    .with_detail(selector.clone()),
                );
            }
        }
    }
}

fn selector_resolves(value: &serde_json::Value, selector: &str) -> bool {
    resolve_selector_value(value, selector).is_some()
}

/// Language-content nested rules (STIX 2.1 Specification §7.1.1).
///
/// When **`object_modified`** is present it MUST exactly match the referenced object's
/// **`modified`** timestamp (§7.1.1). Mismatch is reported at validate time rather than
/// during parse. [`Bundle::validate()`] emits
/// [`ValidationCode::LanguageContentObjectModifiedMismatch`] when the target is in the
/// bundle and the timestamps differ.
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
                report.warnings.push(ValidationFinding::warning(
                    ValidationCode::LanguageContentObjectModifiedMismatch,
                    Some(object_id),
                    "language-content object_modified does not match target modified timestamp",
                ));
            }
            None => {
                report.warnings.push(ValidationFinding::warning(
                    ValidationCode::LanguageContentObjectModifiedMismatch,
                    Some(object_id),
                    "language-content object_modified set but target has no modified timestamp",
                ));
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
                report.warnings.push(
                    ValidationFinding::warning(
                        ValidationCode::LanguageContentFieldUnknown,
                        Some(object_id),
                        format!(
                            "language-content field `{field}` for lang `{lang}` is not a property on target `{}`",
                            content.object_ref.type_name()
                        ),
                    )
                    .with_detail(format!("{lang}.{field}")),
                );
                continue;
            };
            if !language_content_translation_matches_target(target_value, translation) {
                report.warnings.push(
                    ValidationFinding::warning(
                        ValidationCode::LanguageContentValueMismatch,
                        Some(object_id),
                        format!(
                            "language-content translation for `{field}` (lang `{lang}`) does not mirror target property type or list length"
                        ),
                    )
                    .with_detail(format!("{lang}.{field}")),
                );
            }
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::model::Bundle;

    #[test]
    fn validate_reports_tlp_v1_marking_definition() {
        let marking = include_str!(
            "../../tests/fixtures/spec/meta/marking-definition-tlp-v1-white-stix21.json"
        );
        let json = format!(
            r#"{{"type":"bundle","id":"bundle--00000000-0000-0000-0000-000000000001","objects":[{marking}]}}"#
        );
        let bundle = Bundle::parse(&json).expect("parse bundle");
        let report = bundle.validate();
        assert!(
            report
                .warnings_with_code(ValidationCode::StixW0031TlpV1Encoding)
                .next()
                .is_some()
        );
    }
}
