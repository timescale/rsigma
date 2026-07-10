//! Reference resolution and versioning.

use crate::core::StixId;
use crate::model::sro::{Relationship, Sighting, SroObject};
use crate::model::validate::{
    validate_identity_ref, validate_marking_definition_ref, validate_sco_or_sro_ref,
    validate_sco_ref, validate_sdo_ref, validate_stix_or_sco_ref,
};
use crate::model::{Bundle, ModelError, StixObject};

use super::super::diagnostic::{Diagnostic, DiagnosticCode};
use super::super::model_bridge::push_model_error;
use super::super::wire::{
    collect_object_ids, collect_reference_targets, collect_third_party_version_issues,
    collect_versioned_objects,
};
use super::{ValidationContext, ValidationReport};

pub fn run(ctx: &ValidationContext<'_>, report: &mut ValidationReport) {
    if let Some(value) = ctx.value {
        let ids = collect_object_ids(value);
        for (path, target) in collect_reference_targets(value) {
            check_reference_kind_on_wire(&path, &target, report);
            if !ids.contains(&target) {
                report.push(
                    Diagnostic::new(
                        DiagnosticCode::W0010,
                        format!("reference `{target}` does not resolve within the bundle"),
                    )
                    .with_property_path(path),
                );
            }
        }

        let versioned = collect_versioned_objects(value);
        for (path, message) in collect_third_party_version_issues(&versioned) {
            report.push(Diagnostic::new(DiagnosticCode::W0004, message).with_property_path(path));
        }
    }

    if let Some(bundle) = ctx.bundle {
        check_bundle_reference_kinds(bundle, report);
    }
}

fn check_reference_kind_on_wire(path: &str, target: &str, report: &mut ValidationReport) {
    let Ok(id) = StixId::parse(target) else {
        return;
    };
    let property = path.rsplit('.').next().unwrap_or(path);
    let err = if property == "sighting_of_ref" {
        validate_sdo_ref(&id).err()
    } else if property == "object_marking_refs" || property == "marking_ref" {
        validate_marking_definition_ref(&id).err()
    } else {
        None
    };
    if let Some(err) = err {
        push_model_error(report, &err, None, Some(path));
    }
}

fn check_bundle_reference_kinds(bundle: &Bundle, report: &mut ValidationReport) {
    for object in bundle.objects() {
        if let Err(err) = validate_object_reference_kinds(object) {
            push_model_error(report, &err, Some(object.id()), None);
        }
    }
}

fn validate_object_reference_kinds(object: &StixObject) -> Result<(), ModelError> {
    use crate::model::meta::{ExtensionDefinition, LanguageContent, MetaObject};
    use crate::model::sdo::{
        Grouping, MalwareAnalysis, Note, ObservedData, ObservedDataForm, Opinion, Report, SdoObject,
    };

    match object {
        StixObject::Sdo(sdo) => {
            let common = sdo.common_props();
            if let Some(created_by) = &common.created_by_ref {
                validate_identity_ref(created_by.as_stix_id())?;
            }
            for marking in &common.object_marking_refs {
                validate_marking_definition_ref(marking.as_stix_id())?;
            }
            match sdo {
                SdoObject::MalwareAnalysis(MalwareAnalysis {
                    analysis_sco_refs, ..
                }) => {
                    for sco_ref in analysis_sco_refs {
                        validate_sco_ref(sco_ref)?;
                    }
                }
                SdoObject::ObservedData(ObservedData {
                    form: ObservedDataForm::ObjectRefs(object_refs),
                    ..
                }) => {
                    for object_ref in object_refs {
                        validate_sco_or_sro_ref(object_ref)?;
                    }
                }
                SdoObject::Grouping(Grouping { object_refs, .. })
                | SdoObject::Note(Note { object_refs, .. })
                | SdoObject::Opinion(Opinion { object_refs, .. })
                | SdoObject::Report(Report { object_refs, .. }) => {
                    for object_ref in object_refs {
                        validate_stix_or_sco_ref(object_ref)?;
                    }
                }
                _ => {}
            }
        }
        StixObject::Sro(sro) => {
            let common = sro.common_props();
            if let Some(created_by) = &common.created_by_ref {
                validate_identity_ref(created_by.as_stix_id())?;
            }
            for marking in &common.object_marking_refs {
                validate_marking_definition_ref(marking.as_stix_id())?;
            }
            match sro {
                SroObject::Relationship(Relationship {
                    source_ref,
                    target_ref,
                    ..
                }) => {
                    validate_stix_or_sco_ref(source_ref)?;
                    validate_stix_or_sco_ref(target_ref)?;
                }
                SroObject::Sighting(Sighting {
                    sighting_of_ref, ..
                }) => validate_sdo_ref(sighting_of_ref)?,
            }
        }
        StixObject::Meta(meta) => match meta {
            MetaObject::MarkingDefinition(marking) => {
                if let Some(created_by) = &marking.created_by_ref {
                    validate_identity_ref(created_by.as_stix_id())?;
                }
                for marking_ref in &marking.object_marking_refs {
                    validate_marking_definition_ref(marking_ref.as_stix_id())?;
                }
            }
            MetaObject::ExtensionDefinition(ExtensionDefinition { common, .. }) => {
                if let Some(created_by) = &common.created_by_ref {
                    validate_identity_ref(created_by.as_stix_id())?;
                }
            }
            MetaObject::LanguageContent(LanguageContent {
                common, object_ref, ..
            }) => {
                if let Some(created_by) = &common.created_by_ref {
                    validate_identity_ref(created_by.as_stix_id())?;
                }
                validate_sdo_ref(object_ref)?;
            }
        },
        StixObject::Sco(_) | StixObject::Custom(_) => {}
    }
    Ok(())
}
