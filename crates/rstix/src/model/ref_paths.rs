//! Path-aware STIX reference collection for graph and bundle validation.

use crate::core::StixId;
use crate::model::common::ExtensionMap;
use crate::model::common::{GranularMarking, ScoCommonProps, SdoSroCommonProps};
use crate::model::meta::{ExtensionDefinition, LanguageContent, MarkingDefinition};
use crate::model::sco::ScoObject;
use crate::model::sco::extensions::{
    ArchiveExt, HttpRequestExt, WindowsServiceExt, deserialize_from_entry,
};
use crate::model::sdo::SdoObject;
use crate::model::sdo::{
    Grouping, Malware, MalwareAnalysis, Note, ObservedData, ObservedDataForm, Opinion, Report,
};
use crate::model::sro::{Relationship, Sighting, SroObject};
use crate::model::stix_object::StixObject;

/// A STIX reference edge with a JSON-like property path on the source object.
pub type RefPath = (String, StixId);

/// Collect all `_ref` / `_refs` targets reachable from `object` with property paths.
pub fn collect_ref_paths(object: &StixObject, out: &mut Vec<RefPath>) {
    match object {
        StixObject::Sdo(sdo) => collect_sdo_ref_paths(sdo, out),
        StixObject::Sco(sco) => collect_sco_ref_paths(sco, out),
        StixObject::Sro(sro) => collect_sro_ref_paths(sro, out),
        StixObject::Meta(meta) => match meta {
            crate::model::meta::MetaObject::MarkingDefinition(MarkingDefinition {
                created_by_ref,
                object_marking_refs,
                granular_markings,
                ..
            }) => {
                push_marking_ref_paths(created_by_ref, object_marking_refs, granular_markings, out);
            }
            crate::model::meta::MetaObject::ExtensionDefinition(ExtensionDefinition {
                common,
                ..
            }) => {
                push_common_ref_paths(common, out);
            }
            crate::model::meta::MetaObject::LanguageContent(LanguageContent {
                common,
                object_ref,
                ..
            }) => {
                push_common_ref_paths(common, out);
                out.push(("object_ref".to_owned(), object_ref.clone()));
            }
        },
        StixObject::Custom(custom) => collect_ref_paths_from_value(&custom.raw, "", out),
    }
}

fn collect_sdo_ref_paths(sdo: &SdoObject, out: &mut Vec<RefPath>) {
    match sdo {
        SdoObject::AttackPattern(inner) => push_common_ref_paths(&inner.common, out),
        SdoObject::Campaign(inner) => push_common_ref_paths(&inner.common, out),
        SdoObject::CourseOfAction(inner) => push_common_ref_paths(&inner.common, out),
        SdoObject::Grouping(Grouping {
            common,
            object_refs,
            ..
        }) => {
            push_common_ref_paths(common, out);
            push_id_list("object_refs", object_refs, out);
        }
        SdoObject::Identity(inner) => push_common_ref_paths(&inner.common, out),
        SdoObject::Incident(inner) => push_common_ref_paths(&inner.common, out),
        SdoObject::Indicator(inner) => push_common_ref_paths(&inner.common, out),
        SdoObject::Infrastructure(inner) => push_common_ref_paths(&inner.common, out),
        SdoObject::IntrusionSet(inner) => push_common_ref_paths(&inner.common, out),
        SdoObject::Location(inner) => push_common_ref_paths(&inner.common, out),
        SdoObject::Malware(Malware {
            common,
            sample_refs,
            operating_system_refs,
            ..
        }) => {
            push_common_ref_paths(common, out);
            for (index, sample) in sample_refs.iter().enumerate() {
                out.push((format!("sample_refs[{index}]"), sample.as_stix_id().clone()));
            }
            for (index, os_ref) in operating_system_refs.iter().enumerate() {
                out.push((
                    format!("operating_system_refs[{index}]"),
                    os_ref.as_stix_id().clone(),
                ));
            }
        }
        SdoObject::MalwareAnalysis(MalwareAnalysis {
            common,
            host_vm_ref,
            operating_system_ref,
            installed_software_refs,
            sample_ref,
            analysis_sco_refs,
            ..
        }) => {
            push_common_ref_paths(common, out);
            if let Some(host_vm) = host_vm_ref {
                out.push(("host_vm_ref".to_owned(), host_vm.as_stix_id().clone()));
            }
            if let Some(os_ref) = operating_system_ref {
                out.push((
                    "operating_system_ref".to_owned(),
                    os_ref.as_stix_id().clone(),
                ));
            }
            for (index, sw_ref) in installed_software_refs.iter().enumerate() {
                out.push((
                    format!("installed_software_refs[{index}]"),
                    sw_ref.as_stix_id().clone(),
                ));
            }
            if let Some(sample) = sample_ref {
                out.push(("sample_ref".to_owned(), sample.as_stix_id().clone()));
            }
            push_id_list("analysis_sco_refs", analysis_sco_refs, out);
        }
        SdoObject::Note(Note {
            common,
            object_refs,
            ..
        }) => {
            push_common_ref_paths(common, out);
            push_id_list("object_refs", object_refs, out);
        }
        SdoObject::ObservedData(ObservedData { common, form, .. }) => {
            push_common_ref_paths(common, out);
            match form {
                ObservedDataForm::ObjectRefs(object_refs) => {
                    push_id_list("object_refs", object_refs, out);
                }
                ObservedDataForm::DeprecatedObjects(objects) => {
                    for (key, embedded) in objects {
                        let prefix = format!("objects.{key}");
                        push_embedded_ref_paths(embedded, &prefix, out);
                    }
                }
            }
        }
        SdoObject::Opinion(Opinion {
            common,
            object_refs,
            ..
        }) => {
            push_common_ref_paths(common, out);
            push_id_list("object_refs", object_refs, out);
        }
        SdoObject::Report(Report {
            common,
            object_refs,
            ..
        }) => {
            push_common_ref_paths(common, out);
            push_id_list("object_refs", object_refs, out);
        }
        SdoObject::ThreatActor(inner) => push_common_ref_paths(&inner.common, out),
        SdoObject::Tool(inner) => push_common_ref_paths(&inner.common, out),
        SdoObject::Vulnerability(inner) => push_common_ref_paths(&inner.common, out),
    }
}

fn collect_sco_ref_paths(sco: &ScoObject, out: &mut Vec<RefPath>) {
    use crate::model::sco::{
        Artifact, AutonomousSystem, Directory, DomainName, EmailAddr, EmailMessage, File, Ipv4Addr,
        Ipv6Addr, MacAddr, Mutex, NetworkTraffic, Process, Software, Url, UserAccount,
        WindowsRegistryKey, X509Certificate,
    };

    match sco {
        ScoObject::Artifact(Artifact { common, .. }) => push_sco_common_ref_paths(common, out),
        ScoObject::AutonomousSystem(AutonomousSystem { common, .. }) => {
            push_sco_common_ref_paths(common, out);
        }
        ScoObject::Directory(Directory {
            common,
            contains_refs,
            ..
        }) => {
            push_sco_common_ref_paths(common, out);
            for (index, child) in contains_refs.iter().enumerate() {
                out.push((
                    format!("contains_refs[{index}]"),
                    child.as_stix_id().clone(),
                ));
            }
        }
        ScoObject::DomainName(DomainName {
            common,
            resolves_to_refs,
            ..
        }) => {
            push_sco_common_ref_paths(common, out);
            for (index, target) in resolves_to_refs.iter().enumerate() {
                out.push((
                    format!("resolves_to_refs[{index}]"),
                    target.as_stix_id().clone(),
                ));
            }
        }
        ScoObject::EmailAddr(EmailAddr {
            common,
            belongs_to_ref,
            ..
        }) => {
            push_sco_common_ref_paths(common, out);
            if let Some(belongs_to) = belongs_to_ref {
                out.push(("belongs_to_ref".to_owned(), belongs_to.as_stix_id().clone()));
            }
        }
        ScoObject::EmailMessage(EmailMessage {
            common,
            from_ref,
            sender_ref,
            to_refs,
            cc_refs,
            bcc_refs,
            raw_email_ref,
            body_multipart,
            ..
        }) => {
            push_sco_common_ref_paths(common, out);
            if let Some(from_ref) = from_ref {
                out.push(("from_ref".to_owned(), from_ref.as_stix_id().clone()));
            }
            if let Some(sender_ref) = sender_ref {
                out.push(("sender_ref".to_owned(), sender_ref.as_stix_id().clone()));
            }
            for (index, recipient) in to_refs.iter().enumerate() {
                out.push((format!("to_refs[{index}]"), recipient.as_stix_id().clone()));
            }
            for (index, recipient) in cc_refs.iter().enumerate() {
                out.push((format!("cc_refs[{index}]"), recipient.as_stix_id().clone()));
            }
            for (index, recipient) in bcc_refs.iter().enumerate() {
                out.push((format!("bcc_refs[{index}]"), recipient.as_stix_id().clone()));
            }
            if let Some(raw_ref) = raw_email_ref {
                out.push(("raw_email_ref".to_owned(), raw_ref.as_stix_id().clone()));
            }
            if let Some(parts) = body_multipart {
                for (index, part) in parts.iter().enumerate() {
                    if let Some(body_raw_ref) = &part.body_raw_ref {
                        out.push((
                            format!("body_multipart[{index}].body_raw_ref"),
                            body_raw_ref.as_stix_id().clone(),
                        ));
                    }
                }
            }
        }
        ScoObject::File(File {
            common,
            parent_directory_ref,
            contains_refs,
            content_ref,
            ..
        }) => {
            push_sco_common_ref_paths(common, out);
            if let Some(parent) = parent_directory_ref {
                out.push((
                    "parent_directory_ref".to_owned(),
                    parent.as_stix_id().clone(),
                ));
            }
            for (index, child) in contains_refs.iter().enumerate() {
                out.push((format!("contains_refs[{index}]"), child.clone()));
            }
            if let Some(content) = content_ref {
                out.push(("content_ref".to_owned(), content.as_stix_id().clone()));
            }
            push_sco_extension_ref_paths(&common.extensions, out);
        }
        ScoObject::Ipv4Addr(Ipv4Addr {
            common,
            resolves_to_refs,
            belongs_to_refs,
            ..
        }) => {
            push_sco_common_ref_paths(common, out);
            for (index, target) in resolves_to_refs.iter().enumerate() {
                out.push((
                    format!("resolves_to_refs[{index}]"),
                    target.as_stix_id().clone(),
                ));
            }
            for (index, belongs_to) in belongs_to_refs.iter().enumerate() {
                out.push((
                    format!("belongs_to_refs[{index}]"),
                    belongs_to.as_stix_id().clone(),
                ));
            }
        }
        ScoObject::Ipv6Addr(Ipv6Addr {
            common,
            resolves_to_refs,
            belongs_to_refs,
            ..
        }) => {
            push_sco_common_ref_paths(common, out);
            for (index, target) in resolves_to_refs.iter().enumerate() {
                out.push((
                    format!("resolves_to_refs[{index}]"),
                    target.as_stix_id().clone(),
                ));
            }
            for (index, belongs_to) in belongs_to_refs.iter().enumerate() {
                out.push((
                    format!("belongs_to_refs[{index}]"),
                    belongs_to.as_stix_id().clone(),
                ));
            }
        }
        ScoObject::MacAddr(MacAddr { common, .. }) => push_sco_common_ref_paths(common, out),
        ScoObject::Mutex(Mutex { common, .. }) => push_sco_common_ref_paths(common, out),
        ScoObject::NetworkTraffic(NetworkTraffic {
            common,
            src_ref,
            dst_ref,
            src_payload_ref,
            dst_payload_ref,
            encapsulates_refs,
            encapsulated_by_ref,
            ..
        }) => {
            push_sco_common_ref_paths(common, out);
            if let Some(src) = src_ref {
                out.push(("src_ref".to_owned(), src.as_stix_id().clone()));
            }
            if let Some(dst) = dst_ref {
                out.push(("dst_ref".to_owned(), dst.as_stix_id().clone()));
            }
            if let Some(payload) = src_payload_ref {
                out.push(("src_payload_ref".to_owned(), payload.as_stix_id().clone()));
            }
            if let Some(payload) = dst_payload_ref {
                out.push(("dst_payload_ref".to_owned(), payload.as_stix_id().clone()));
            }
            for (index, encapsulated) in encapsulates_refs.iter().enumerate() {
                out.push((
                    format!("encapsulates_refs[{index}]"),
                    encapsulated.as_stix_id().clone(),
                ));
            }
            if let Some(encapsulated_by) = encapsulated_by_ref {
                out.push((
                    "encapsulated_by_ref".to_owned(),
                    encapsulated_by.as_stix_id().clone(),
                ));
            }
            push_sco_extension_ref_paths(&common.extensions, out);
        }
        ScoObject::Process(Process {
            common,
            parent_ref,
            child_refs,
            opened_connection_refs,
            creator_user_ref,
            image_ref,
            ..
        }) => {
            push_sco_common_ref_paths(common, out);
            if let Some(parent) = parent_ref {
                out.push(("parent_ref".to_owned(), parent.as_stix_id().clone()));
            }
            for (index, child) in child_refs.iter().enumerate() {
                out.push((format!("child_refs[{index}]"), child.as_stix_id().clone()));
            }
            for (index, opened) in opened_connection_refs.iter().enumerate() {
                out.push((
                    format!("opened_connection_refs[{index}]"),
                    opened.as_stix_id().clone(),
                ));
            }
            if let Some(creator) = creator_user_ref {
                out.push(("creator_user_ref".to_owned(), creator.as_stix_id().clone()));
            }
            if let Some(image) = image_ref {
                out.push(("image_ref".to_owned(), image.as_stix_id().clone()));
            }
            push_sco_extension_ref_paths(&common.extensions, out);
        }
        ScoObject::Software(Software { common, .. }) => push_sco_common_ref_paths(common, out),
        ScoObject::Url(Url { common, .. }) => push_sco_common_ref_paths(common, out),
        ScoObject::UserAccount(UserAccount { common, .. }) => {
            push_sco_common_ref_paths(common, out);
        }
        ScoObject::WindowsRegistryKey(WindowsRegistryKey {
            common,
            creator_user_ref,
            ..
        }) => {
            push_sco_common_ref_paths(common, out);
            if let Some(creator) = creator_user_ref {
                out.push(("creator_user_ref".to_owned(), creator.as_stix_id().clone()));
            }
        }
        ScoObject::X509Certificate(X509Certificate { common, .. }) => {
            push_sco_common_ref_paths(common, out);
        }
        ScoObject::Custom(inner) => push_sco_common_ref_paths(&inner.common, out),
    }
}

fn collect_sro_ref_paths(sro: &SroObject, out: &mut Vec<RefPath>) {
    match sro {
        SroObject::Relationship(Relationship {
            common,
            source_ref,
            target_ref,
            ..
        }) => {
            push_common_ref_paths(common, out);
            out.push(("source_ref".to_owned(), source_ref.clone()));
            out.push(("target_ref".to_owned(), target_ref.clone()));
        }
        SroObject::Sighting(Sighting {
            common,
            sighting_of_ref,
            observed_data_refs,
            where_sighted_refs,
            ..
        }) => {
            push_common_ref_paths(common, out);
            out.push(("sighting_of_ref".to_owned(), sighting_of_ref.clone()));
            for (index, observed) in observed_data_refs.iter().enumerate() {
                out.push((
                    format!("observed_data_refs[{index}]"),
                    observed.as_stix_id().clone(),
                ));
            }
            for (index, where_sighted) in where_sighted_refs.iter().enumerate() {
                out.push((
                    format!("where_sighted_refs[{index}]"),
                    where_sighted.as_stix_id().clone(),
                ));
            }
        }
    }
}

fn push_common_ref_paths(common: &SdoSroCommonProps, out: &mut Vec<RefPath>) {
    if let Some(created_by) = &common.created_by_ref {
        out.push(("created_by_ref".to_owned(), created_by.as_stix_id().clone()));
    }
    for (index, marking) in common.object_marking_refs.iter().enumerate() {
        out.push((
            format!("object_marking_refs[{index}]"),
            marking.as_stix_id().clone(),
        ));
    }
    push_granular_ref_paths("granular_markings", &common.granular_markings, out);
}

fn push_marking_ref_paths(
    created_by_ref: &Option<crate::core::IdentityId>,
    object_marking_refs: &[crate::core::MarkingDefinitionId],
    granular_markings: &[GranularMarking],
    out: &mut Vec<RefPath>,
) {
    if let Some(created_by) = created_by_ref {
        out.push(("created_by_ref".to_owned(), created_by.as_stix_id().clone()));
    }
    for (index, marking) in object_marking_refs.iter().enumerate() {
        out.push((
            format!("object_marking_refs[{index}]"),
            marking.as_stix_id().clone(),
        ));
    }
    push_granular_ref_paths("granular_markings", granular_markings, out);
}

fn push_granular_ref_paths(
    prefix: &str,
    granular_markings: &[GranularMarking],
    out: &mut Vec<RefPath>,
) {
    for (index, granular) in granular_markings.iter().enumerate() {
        if let Some(marking_ref) = &granular.marking_ref {
            out.push((
                format!("{prefix}[{index}].marking_ref"),
                marking_ref.as_stix_id().clone(),
            ));
        }
    }
}

fn push_sco_common_ref_paths(common: &ScoCommonProps, out: &mut Vec<RefPath>) {
    for (index, marking) in common.object_marking_refs.iter().enumerate() {
        out.push((
            format!("object_marking_refs[{index}]"),
            marking.as_stix_id().clone(),
        ));
    }
    push_granular_ref_paths("granular_markings", &common.granular_markings, out);
}

fn push_id_list(prefix: &str, ids: &[StixId], out: &mut Vec<RefPath>) {
    for (index, id) in ids.iter().enumerate() {
        out.push((format!("{prefix}[{index}]"), id.clone()));
    }
}

fn push_embedded_ref_paths(
    embedded: &crate::model::sdo::ObservedDataEmbeddedObject,
    prefix: &str,
    out: &mut Vec<RefPath>,
) {
    let mut local = Vec::new();
    match embedded {
        crate::model::sdo::ObservedDataEmbeddedObject::Sco(sco) => {
            collect_sco_ref_paths(sco, &mut local);
        }
        crate::model::sdo::ObservedDataEmbeddedObject::Sro(sro) => {
            collect_sro_ref_paths(sro, &mut local);
        }
    }
    for (path, id) in local {
        out.push((format!("{prefix}.{path}"), id));
    }
}

fn push_sco_extension_ref_paths(map: &ExtensionMap, out: &mut Vec<RefPath>) {
    if let Some(entry) = map.get(ArchiveExt::KEY)
        && let Ok(archive) = deserialize_from_entry::<ArchiveExt>(ArchiveExt::KEY, entry)
    {
        push_archive_ext_ref_paths(&archive, out);
    }
    if let Some(entry) = map.get(HttpRequestExt::KEY)
        && let Ok(http) = deserialize_from_entry::<HttpRequestExt>(HttpRequestExt::KEY, entry)
    {
        push_http_request_ext_ref_paths(&http, out);
    }
    if let Some(entry) = map.get(WindowsServiceExt::KEY)
        && let Ok(service) =
            deserialize_from_entry::<WindowsServiceExt>(WindowsServiceExt::KEY, entry)
    {
        push_windows_service_ext_ref_paths(&service, out);
    }
}

fn push_archive_ext_ref_paths(archive: &ArchiveExt, out: &mut Vec<RefPath>) {
    for (index, child) in archive.contains_refs.iter().enumerate() {
        out.push((
            format!("extensions.archive-ext.contains_refs[{index}]"),
            child.as_stix_id().clone(),
        ));
    }
}

fn push_http_request_ext_ref_paths(http: &HttpRequestExt, out: &mut Vec<RefPath>) {
    if let Some(body) = &http.message_body_data_ref {
        out.push((
            "extensions.http-request-ext.message_body_data_ref".to_owned(),
            body.as_stix_id().clone(),
        ));
    }
}

fn push_windows_service_ext_ref_paths(service: &WindowsServiceExt, out: &mut Vec<RefPath>) {
    for (index, dll) in service.service_dll_refs.iter().enumerate() {
        out.push((
            format!("extensions.windows-service-ext.service_dll_refs[{index}]"),
            dll.as_stix_id().clone(),
        ));
    }
}

fn collect_ref_paths_from_value(value: &serde_json::Value, prefix: &str, out: &mut Vec<RefPath>) {
    match value {
        serde_json::Value::String(text) => {
            if let Ok(id) = text.parse::<StixId>() {
                let path = if prefix.is_empty() {
                    "_ref".to_owned()
                } else {
                    prefix.to_owned()
                };
                out.push((path, id));
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let child_prefix = if prefix.is_empty() {
                    format!("[{index}]")
                } else {
                    format!("{prefix}[{index}]")
                };
                collect_ref_paths_from_value(item, &child_prefix, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                let child_prefix = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                collect_ref_paths_from_value(item, &child_prefix, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::sdo::ObservedDataEmbeddedObject;

    #[test]
    fn email_multipart_body_raw_ref_is_collected() {
        let json = include_str!("../../tests/fixtures/spec/sco/email-message-multipart.json");
        let message: crate::model::sco::EmailMessage = serde_json::from_str(json).unwrap();
        let mut paths = Vec::new();
        collect_sco_ref_paths(&ScoObject::EmailMessage(message), &mut paths);
        assert!(
            paths
                .iter()
                .any(|(path, _)| path.contains("body_multipart") && path.contains("body_raw_ref"))
        );
    }

    #[test]
    fn archive_ext_contains_refs_are_collected() {
        let json = include_str!("../../tests/fixtures/spec/sco/file-with-archive-ext.json");
        let file: crate::model::sco::File = serde_json::from_str(json).unwrap();
        let mut paths = Vec::new();
        collect_sco_ref_paths(&ScoObject::File(file), &mut paths);
        assert!(
            paths
                .iter()
                .any(|(path, _)| path.contains("archive-ext.contains_refs"))
        );
    }

    #[test]
    fn embedded_observed_data_object_refs_are_collected() {
        let mut paths = Vec::new();
        let file: crate::model::sco::File = serde_json::from_str(include_str!(
            "../../tests/fixtures/spec/sco/file-with-archive-ext.json"
        ))
        .unwrap();
        let embedded = ObservedDataEmbeddedObject::Sco(ScoObject::File(file));
        push_embedded_ref_paths(&embedded, "objects.0", &mut paths);
        assert!(paths.iter().any(|(path, _)| path.starts_with("objects.0.")));
    }
}
