//! Re-run typed object invariant checks for the schema validation phase.

use crate::model::meta::{ExtensionDefinition, LanguageContent, MarkingDefinition, MetaObject};
use crate::model::sco::{CustomSco, ScoObject};
use crate::model::sdo::SdoObject;
use crate::model::sro::{Sighting, SroObject};
use crate::model::{ModelError, StixObject};

use super::ValidationReport;
use super::model_bridge::push_model_error;

/// Re-validate all objects in a parsed bundle and map [`ModelError`] to pipeline diagnostics.
pub(crate) fn validate_typed_objects(objects: &[StixObject], report: &mut ValidationReport) {
    for object in objects {
        if let Err(err) = validate_object_invariants(object) {
            push_model_error(report, &err, Some(object.id()), None);
        }
    }
}

fn validate_object_invariants(object: &StixObject) -> Result<(), ModelError> {
    match object {
        StixObject::Sdo(sdo) => validate_sdo(sdo),
        StixObject::Sco(sco) => validate_sco(sco),
        StixObject::Sro(sro) => validate_sro(sro),
        StixObject::Meta(meta) => validate_meta(meta),
        StixObject::Custom(_) => Ok(()),
    }
}

fn validate_sdo(sdo: &SdoObject) -> Result<(), ModelError> {
    match sdo {
        SdoObject::AttackPattern(v) => v.validate(),
        SdoObject::Campaign(v) => v.validate(),
        SdoObject::CourseOfAction(v) => v.validate(),
        SdoObject::Grouping(v) => v.validate(),
        SdoObject::Identity(v) => v.validate(),
        SdoObject::Incident(v) => v.validate(),
        SdoObject::Indicator(v) => v.validate(),
        SdoObject::Infrastructure(v) => v.validate(),
        SdoObject::IntrusionSet(v) => v.validate(),
        SdoObject::Location(v) => v.validate(),
        SdoObject::Malware(v) => v.validate(),
        SdoObject::MalwareAnalysis(v) => v.validate(),
        SdoObject::Note(v) => v.validate(),
        SdoObject::ObservedData(v) => v.validate(),
        SdoObject::Opinion(v) => v.validate(),
        SdoObject::Report(v) => v.validate(),
        SdoObject::ThreatActor(v) => v.validate(),
        SdoObject::Tool(v) => v.validate(),
        SdoObject::Vulnerability(v) => v.validate(),
    }
}

fn validate_sco(sco: &ScoObject) -> Result<(), ModelError> {
    match sco {
        ScoObject::Artifact(v) => v.validate(),
        ScoObject::AutonomousSystem(v) => v.validate(),
        ScoObject::Directory(v) => v.validate(),
        ScoObject::DomainName(v) => {
            v.validate()?;
            #[cfg(feature = "validate")]
            crate::model::validate::validate_domain_name_format_strict(&v.value)?;
            Ok(())
        }
        ScoObject::EmailAddr(v) => {
            v.validate()?;
            #[cfg(feature = "validate")]
            crate::model::validate::validate_email_addr_format_strict(&v.value)?;
            Ok(())
        }
        ScoObject::EmailMessage(v) => v.validate(),
        ScoObject::File(v) => v.validate(),
        ScoObject::Ipv4Addr(v) => v.validate(),
        ScoObject::Ipv6Addr(v) => v.validate(),
        ScoObject::MacAddr(v) => v.validate(),
        ScoObject::Mutex(v) => v.validate(),
        ScoObject::NetworkTraffic(v) => v.validate(),
        ScoObject::Process(v) => v.validate(),
        ScoObject::Software(v) => v.validate(),
        ScoObject::Url(v) => {
            v.validate()?;
            #[cfg(feature = "validate")]
            crate::model::validate::validate_url_format_strict(&v.value)?;
            Ok(())
        }
        ScoObject::UserAccount(v) => v.validate(),
        ScoObject::WindowsRegistryKey(v) => v.validate(),
        ScoObject::X509Certificate(v) => v.validate(),
        ScoObject::Custom(CustomSco { .. }) => Ok(()),
    }
}

fn validate_sro(sro: &SroObject) -> Result<(), ModelError> {
    match sro {
        SroObject::Relationship(relationship) => relationship.validate(),
        SroObject::Sighting(Sighting { common, .. }) => common.validate(Sighting::TYPE_NAME),
    }
}

fn validate_meta(meta: &MetaObject) -> Result<(), ModelError> {
    match meta {
        MetaObject::MarkingDefinition(MarkingDefinition { .. }) => Ok(()),
        MetaObject::ExtensionDefinition(ExtensionDefinition { common, .. }) => {
            common.validate(ExtensionDefinition::TYPE_NAME)
        }
        MetaObject::LanguageContent(LanguageContent { common, .. }) => {
            common.validate(LanguageContent::TYPE_NAME)
        }
    }
}
