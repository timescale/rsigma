//! ID structure and SCO UUIDv5 advisory.

use crate::core::{QueryableStixObject, StixId};

use super::super::diagnostic::{Diagnostic, DiagnosticCode};
use super::super::wire::{collect_id_prefix_mismatches, collect_sco_deterministic_id_issues};
use super::{ValidationContext, ValidationReport};

pub fn run(ctx: &ValidationContext<'_>, report: &mut ValidationReport) {
    let Some(value) = ctx.value else {
        return;
    };

    for (path, id, type_name) in collect_id_prefix_mismatches(value) {
        let object_id = StixId::parse(&id).ok();
        let mut diagnostic = Diagnostic::new(
            DiagnosticCode::E0003,
            format!("STIX id `{id}` type prefix does not match object type `{type_name}`"),
        )
        .with_property_path(path);
        if let Some(id) = object_id {
            diagnostic = diagnostic.with_object_id(id);
        }
        report.push(diagnostic);
    }

    for (path, type_name) in collect_sco_deterministic_id_issues(value) {
        report.push(
            Diagnostic::new(
                DiagnosticCode::W0002,
                format!(
                    "SCO `{type_name}` id does not match deterministic UUIDv5 from id-contributing properties"
                ),
            )
            .with_property_path(path),
        );
    }

    if let Some(bundle) = ctx.bundle {
        validate_sco_deterministic_ids(bundle, report);
    }
}

fn validate_sco_deterministic_ids(bundle: &crate::model::Bundle, report: &mut ValidationReport) {
    use crate::model::validate::validate_sco_deterministic_id;
    use crate::model::{
        StixObject,
        sdo::{ObservedDataEmbeddedObject, ObservedDataForm, SdoObject},
    };

    for object in bundle.objects() {
        let object_id = object.id();
        if let StixObject::Sco(sco) = object
            && let Ok(wire) = serde_json::to_value(object)
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
        if let StixObject::Sdo(SdoObject::ObservedData(observed)) = object
            && let ObservedDataForm::DeprecatedObjects(objects) = &observed.form
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
    }
}
