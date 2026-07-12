//! Top-level STIX object dispatch enum.

use std::collections::BTreeMap;

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::meta::MetaObject;
use crate::model::parse_options::ParseOptions;
use crate::model::sco::ScoObject;
use crate::model::sdo::SdoObject;
use crate::model::sro::SroObject;

/// A STIX object whose `type` is not modeled as a built-in variant.
#[derive(Debug)]
pub struct CustomStixObject {
    /// STIX `type` field value.
    pub type_name: String,
    /// Object identifier parsed from the raw JSON.
    pub id: StixId,
    /// Remaining object properties (excluding top-level `x_*` keys peeled at parse).
    pub raw: serde_json::Value,
    /// Typed payload when the type was registered in [`ParseOptions::type_registry`].
    pub(crate) typed: Option<Box<dyn std::any::Any + Send + Sync>>,
}

impl Clone for CustomStixObject {
    fn clone(&self) -> Self {
        Self {
            type_name: self.type_name.clone(),
            id: self.id.clone(),
            raw: self.raw.clone(),
            typed: None,
        }
    }
}

impl PartialEq for CustomStixObject {
    fn eq(&self, other: &Self) -> bool {
        self.type_name == other.type_name && self.id == other.id && self.raw == other.raw
    }
}

impl CustomStixObject {
    /// Downcast a registry-parsed custom object to its concrete type.
    pub fn downcast_typed<T: 'static>(&self) -> Option<&T> {
        self.typed.as_ref()?.downcast_ref()
    }
}

/// Any STIX object contained in a bundle.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum StixObject {
    /// STIX Domain Object.
    Sdo(SdoObject),
    /// STIX Cyber-observable Object.
    Sco(ScoObject),
    /// STIX Relationship Object.
    Sro(SroObject),
    /// STIX Meta Object.
    Meta(MetaObject),
    /// Unmodeled or extension-defined object type.
    Custom(CustomStixObject),
}

impl StixObject {
    /// Borrow the object's STIX id.
    pub fn id(&self) -> &StixId {
        QueryableStixObject::id(self)
    }

    /// Collect STIX id references that should resolve within a bundle.
    pub(crate) fn collect_internal_refs(&self, refs: &mut Vec<StixId>) {
        use crate::model::common::SdoSroCommonProps;
        use crate::model::meta::{ExtensionDefinition, LanguageContent, MarkingDefinition};
        use crate::model::sdo::{
            Grouping, Malware, MalwareAnalysis, Note, ObservedData, ObservedDataForm, Opinion,
            Report,
        };
        use crate::model::sro::{Relationship, Sighting};

        fn push_common_refs(common: &SdoSroCommonProps, refs: &mut Vec<StixId>) {
            if let Some(created_by) = &common.created_by_ref {
                refs.push(created_by.as_stix_id().clone());
            }
            for marking in &common.object_marking_refs {
                refs.push(marking.as_stix_id().clone());
            }
            for granular in &common.granular_markings {
                if let Some(marking_ref) = &granular.marking_ref {
                    refs.push(marking_ref.as_stix_id().clone());
                }
            }
        }

        fn push_marking_refs(
            created_by_ref: &Option<crate::core::IdentityId>,
            object_marking_refs: &[crate::core::MarkingDefinitionId],
            granular_markings: &[crate::model::common::GranularMarking],
            refs: &mut Vec<StixId>,
        ) {
            if let Some(created_by) = created_by_ref {
                refs.push(created_by.as_stix_id().clone());
            }
            for marking in object_marking_refs {
                refs.push(marking.as_stix_id().clone());
            }
            for granular in granular_markings {
                if let Some(marking_ref) = &granular.marking_ref {
                    refs.push(marking_ref.as_stix_id().clone());
                }
            }
        }

        fn push_sco_common_refs(
            common: &crate::model::common::ScoCommonProps,
            refs: &mut Vec<StixId>,
        ) {
            for marking in &common.object_marking_refs {
                refs.push(marking.as_stix_id().clone());
            }
            for granular in &common.granular_markings {
                if let Some(marking_ref) = &granular.marking_ref {
                    refs.push(marking_ref.as_stix_id().clone());
                }
            }
        }

        match self {
            Self::Sdo(sdo) => match sdo {
                SdoObject::AttackPattern(inner) => push_common_refs(&inner.common, refs),
                SdoObject::Campaign(inner) => push_common_refs(&inner.common, refs),
                SdoObject::CourseOfAction(inner) => push_common_refs(&inner.common, refs),
                SdoObject::Grouping(Grouping {
                    common,
                    object_refs,
                    ..
                }) => {
                    push_common_refs(common, refs);
                    refs.extend(object_refs.iter().cloned());
                }
                SdoObject::Identity(inner) => push_common_refs(&inner.common, refs),
                SdoObject::Incident(inner) => push_common_refs(&inner.common, refs),
                SdoObject::Indicator(inner) => push_common_refs(&inner.common, refs),
                SdoObject::Infrastructure(inner) => push_common_refs(&inner.common, refs),
                SdoObject::IntrusionSet(inner) => push_common_refs(&inner.common, refs),
                SdoObject::Location(inner) => push_common_refs(&inner.common, refs),
                SdoObject::Malware(Malware {
                    common,
                    sample_refs,
                    operating_system_refs,
                    ..
                }) => {
                    push_common_refs(common, refs);
                    for sample in sample_refs {
                        refs.push(sample.as_stix_id().clone());
                    }
                    for os_ref in operating_system_refs {
                        refs.push(os_ref.as_stix_id().clone());
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
                    push_common_refs(common, refs);
                    if let Some(host_vm) = host_vm_ref {
                        refs.push(host_vm.as_stix_id().clone());
                    }
                    if let Some(os_ref) = operating_system_ref {
                        refs.push(os_ref.as_stix_id().clone());
                    }
                    for sw_ref in installed_software_refs {
                        refs.push(sw_ref.as_stix_id().clone());
                    }
                    if let Some(sample) = sample_ref {
                        refs.push(sample.as_stix_id().clone());
                    }
                    refs.extend(analysis_sco_refs.iter().cloned());
                }
                SdoObject::Note(Note {
                    common,
                    object_refs,
                    ..
                }) => {
                    push_common_refs(common, refs);
                    refs.extend(object_refs.iter().cloned());
                }
                SdoObject::ObservedData(ObservedData { common, form, .. }) => {
                    push_common_refs(common, refs);
                    match form {
                        ObservedDataForm::ObjectRefs(object_refs) => {
                            refs.extend(object_refs.iter().cloned());
                        }
                        ObservedDataForm::DeprecatedObjects(objects) => {
                            for embedded in objects.values() {
                                embedded.collect_internal_refs(refs);
                            }
                        }
                    }
                }
                SdoObject::Opinion(Opinion {
                    common,
                    object_refs,
                    ..
                }) => {
                    push_common_refs(common, refs);
                    refs.extend(object_refs.iter().cloned());
                }
                SdoObject::Report(Report {
                    common,
                    object_refs,
                    ..
                }) => {
                    push_common_refs(common, refs);
                    refs.extend(object_refs.iter().cloned());
                }
                SdoObject::ThreatActor(inner) => push_common_refs(&inner.common, refs),
                SdoObject::Tool(inner) => push_common_refs(&inner.common, refs),
                SdoObject::Vulnerability(inner) => push_common_refs(&inner.common, refs),
            },
            Self::Sco(sco) => match sco {
                ScoObject::Artifact(inner) => push_sco_common_refs(&inner.common, refs),
                ScoObject::AutonomousSystem(inner) => push_sco_common_refs(&inner.common, refs),
                ScoObject::Directory(inner) => {
                    push_sco_common_refs(&inner.common, refs);
                    for child in &inner.contains_refs {
                        refs.push(child.as_stix_id().clone());
                    }
                }
                ScoObject::DomainName(inner) => {
                    push_sco_common_refs(&inner.common, refs);
                    for target in &inner.resolves_to_refs {
                        refs.push(target.as_stix_id().clone());
                    }
                }
                ScoObject::EmailAddr(inner) => {
                    push_sco_common_refs(&inner.common, refs);
                    if let Some(belongs_to) = &inner.belongs_to_ref {
                        refs.push(belongs_to.as_stix_id().clone());
                    }
                }
                ScoObject::EmailMessage(inner) => {
                    push_sco_common_refs(&inner.common, refs);
                    if let Some(from_ref) = &inner.from_ref {
                        refs.push(from_ref.as_stix_id().clone());
                    }
                    if let Some(sender_ref) = &inner.sender_ref {
                        refs.push(sender_ref.as_stix_id().clone());
                    }
                    for recipient in &inner.to_refs {
                        refs.push(recipient.as_stix_id().clone());
                    }
                    for recipient in &inner.cc_refs {
                        refs.push(recipient.as_stix_id().clone());
                    }
                    for recipient in &inner.bcc_refs {
                        refs.push(recipient.as_stix_id().clone());
                    }
                    if let Some(raw_ref) = &inner.raw_email_ref {
                        refs.push(raw_ref.as_stix_id().clone());
                    }
                }
                ScoObject::File(inner) => {
                    push_sco_common_refs(&inner.common, refs);
                    if let Some(parent) = &inner.parent_directory_ref {
                        refs.push(parent.as_stix_id().clone());
                    }
                    for child in &inner.contains_refs {
                        refs.push(child.clone());
                    }
                    if let Some(content) = &inner.content_ref {
                        refs.push(content.as_stix_id().clone());
                    }
                }
                ScoObject::Ipv4Addr(inner) => {
                    push_sco_common_refs(&inner.common, refs);
                    for target in &inner.resolves_to_refs {
                        refs.push(target.as_stix_id().clone());
                    }
                    for belongs_to in &inner.belongs_to_refs {
                        refs.push(belongs_to.as_stix_id().clone());
                    }
                }
                ScoObject::Ipv6Addr(inner) => {
                    push_sco_common_refs(&inner.common, refs);
                    for target in &inner.resolves_to_refs {
                        refs.push(target.as_stix_id().clone());
                    }
                    for belongs_to in &inner.belongs_to_refs {
                        refs.push(belongs_to.as_stix_id().clone());
                    }
                }
                ScoObject::MacAddr(inner) => push_sco_common_refs(&inner.common, refs),
                ScoObject::Mutex(inner) => push_sco_common_refs(&inner.common, refs),
                ScoObject::NetworkTraffic(inner) => {
                    push_sco_common_refs(&inner.common, refs);
                    if let Some(src) = &inner.src_ref {
                        refs.push(src.as_stix_id().clone());
                    }
                    if let Some(dst) = &inner.dst_ref {
                        refs.push(dst.as_stix_id().clone());
                    }
                    if let Some(payload) = &inner.src_payload_ref {
                        refs.push(payload.as_stix_id().clone());
                    }
                    if let Some(payload) = &inner.dst_payload_ref {
                        refs.push(payload.as_stix_id().clone());
                    }
                    for encapsulated in &inner.encapsulates_refs {
                        refs.push(encapsulated.as_stix_id().clone());
                    }
                    if let Some(encapsulated_by) = &inner.encapsulated_by_ref {
                        refs.push(encapsulated_by.as_stix_id().clone());
                    }
                }
                ScoObject::Process(inner) => {
                    push_sco_common_refs(&inner.common, refs);
                    if let Some(parent) = &inner.parent_ref {
                        refs.push(parent.as_stix_id().clone());
                    }
                    for child in &inner.child_refs {
                        refs.push(child.as_stix_id().clone());
                    }
                    for opened in &inner.opened_connection_refs {
                        refs.push(opened.as_stix_id().clone());
                    }
                    if let Some(creator) = &inner.creator_user_ref {
                        refs.push(creator.as_stix_id().clone());
                    }
                    if let Some(image) = &inner.image_ref {
                        refs.push(image.as_stix_id().clone());
                    }
                }
                ScoObject::Software(inner) => push_sco_common_refs(&inner.common, refs),
                ScoObject::Url(inner) => push_sco_common_refs(&inner.common, refs),
                ScoObject::UserAccount(inner) => push_sco_common_refs(&inner.common, refs),
                ScoObject::WindowsRegistryKey(inner) => {
                    push_sco_common_refs(&inner.common, refs);
                    if let Some(creator) = &inner.creator_user_ref {
                        refs.push(creator.as_stix_id().clone());
                    }
                }
                ScoObject::X509Certificate(inner) => push_sco_common_refs(&inner.common, refs),
                ScoObject::Custom(inner) => push_sco_common_refs(&inner.common, refs),
            },
            Self::Sro(sro) => match sro {
                SroObject::Relationship(Relationship {
                    common,
                    source_ref,
                    target_ref,
                    ..
                }) => {
                    push_common_refs(common, refs);
                    refs.push(source_ref.clone());
                    refs.push(target_ref.clone());
                }
                SroObject::Sighting(Sighting {
                    common,
                    sighting_of_ref,
                    observed_data_refs,
                    where_sighted_refs,
                    ..
                }) => {
                    push_common_refs(common, refs);
                    refs.push(sighting_of_ref.clone());
                    for observed in observed_data_refs {
                        refs.push(observed.as_stix_id().clone());
                    }
                    for where_sighted in where_sighted_refs {
                        refs.push(where_sighted.as_stix_id().clone());
                    }
                }
            },
            Self::Meta(meta) => match meta {
                MetaObject::MarkingDefinition(MarkingDefinition {
                    created_by_ref,
                    object_marking_refs,
                    granular_markings,
                    ..
                }) => {
                    push_marking_refs(created_by_ref, object_marking_refs, granular_markings, refs)
                }
                MetaObject::ExtensionDefinition(ExtensionDefinition { common, .. }) => {
                    push_common_refs(common, refs);
                }
                MetaObject::LanguageContent(LanguageContent {
                    common, object_ref, ..
                }) => {
                    push_common_refs(common, refs);
                    refs.push(object_ref.clone());
                }
            },
            Self::Custom(custom) => collect_refs_from_value(&custom.raw, refs),
        }
    }
}

fn collect_refs_from_value(value: &serde_json::Value, refs: &mut Vec<StixId>) {
    match value {
        serde_json::Value::String(text) => {
            if let Ok(id) = text.parse::<StixId>() {
                refs.push(id);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_refs_from_value(item, refs);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                if key.ends_with("_ref") || key.ends_with("_refs") {
                    collect_refs_from_value(item, refs);
                }
            }
        }
        _ => {}
    }
}

#[cfg(feature = "serde")]
pub(crate) fn peel_custom_properties(
    obj: &mut serde_json::Map<String, serde_json::Value>,
) -> BTreeMap<String, serde_json::Value> {
    let keys: Vec<String> = obj
        .keys()
        .filter(|key| key.starts_with("x_"))
        .cloned()
        .collect();
    let mut extra = BTreeMap::new();
    for key in keys {
        if let Some(value) = obj.remove(&key) {
            extra.insert(key, value);
        }
    }
    extra
}

#[cfg(feature = "serde")]
fn peel_toplevel_property_extensions(
    obj: &mut serde_json::Map<String, serde_json::Value>,
) -> BTreeMap<String, serde_json::Value> {
    use crate::model::common::ExtensionType;

    let Some(extensions) = obj.remove("extensions") else {
        return BTreeMap::new();
    };
    let Some(mut ext_map) = extensions.as_object().cloned() else {
        obj.insert("extensions".into(), extensions);
        return BTreeMap::new();
    };

    let keys: Vec<String> = ext_map.keys().cloned().collect();
    let mut peeled = BTreeMap::new();
    for key in keys {
        let Some(entry) = ext_map.remove(&key) else {
            continue;
        };
        let Some(entry_obj) = entry.as_object() else {
            ext_map.insert(key, entry);
            continue;
        };
        let is_toplevel = entry_obj
            .get("extension_type")
            .and_then(serde_json::Value::as_str)
            .and_then(ExtensionType::from_str_value)
            .is_some_and(|kind| kind == ExtensionType::ToplevelPropertyExtension);
        if !is_toplevel {
            ext_map.insert(key, entry);
            continue;
        }
        for (prop, value) in entry_obj {
            if prop != "extension_type" {
                peeled.insert(prop.clone(), value.clone());
            }
        }
    }
    for (prop, value) in &peeled {
        obj.insert(prop.clone(), value.clone());
    }
    if !ext_map.is_empty() {
        obj.insert("extensions".into(), serde_json::Value::Object(ext_map));
    }
    peeled
}

#[cfg(feature = "serde")]
fn capture_unmodeled_properties(
    wire: &serde_json::Map<String, serde_json::Value>,
    object: &StixObject,
    extra: &mut BTreeMap<String, serde_json::Value>,
) -> Result<(), crate::ParseError> {
    if matches!(object, StixObject::Custom(_)) {
        return Ok(());
    }

    let serialized = serde_json::to_value(object).map_err(crate::ParseError::Json)?;
    let Some(serialized_map) = serialized.as_object() else {
        return Ok(());
    };

    for (key, value) in wire {
        if key == "type" || extra.contains_key(key) {
            continue;
        }
        if !serialized_map.contains_key(key) {
            extra.insert(key.clone(), value.clone());
        }
    }
    Ok(())
}

#[cfg(feature = "serde")]
fn serde_json_error_to_parse_error(err: serde_json::Error) -> crate::ParseError {
    let message = err.to_string();
    if let Some(model_err) = crate::model::ModelError::from_serde_message(&message) {
        crate::ParseError::Model(model_err)
    } else {
        crate::ParseError::Json(err)
    }
}

#[cfg(feature = "serde")]
pub(crate) fn deserialize_stix_object_from_value(
    value: serde_json::Value,
    opts: &ParseOptions,
) -> Result<(StixObject, BTreeMap<String, serde_json::Value>), crate::ParseError> {
    let mut map = value.as_object().cloned().ok_or_else(|| {
        crate::ParseError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "STIX object must be a JSON object",
        )))
    })?;

    let mut extra = peel_custom_properties(&mut map);
    extra.extend(peel_toplevel_property_extensions(&mut map));
    let typed_value = serde_json::Value::Object(map);
    let wire_for_extra = typed_value.as_object().cloned();

    let type_name = typed_value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            crate::ParseError::Json(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "STIX object missing type field",
            )))
        })?;

    let mut object = if let Some(kind) = crate::core::StixObjectKind::from_type_str(type_name) {
        match kind {
            crate::core::StixObjectKind::Sdo(_) => {
                super::sdo::deserialize_sdo_object_from_value(typed_value)
                    .map(StixObject::Sdo)
                    .map_err(serde_json_error_to_parse_error)?
            }
            crate::core::StixObjectKind::Sco(_) => {
                super::sco::deserialize_sco_object_from_value(typed_value)
                    .map(StixObject::Sco)
                    .map_err(serde_json_error_to_parse_error)?
            }
            crate::core::StixObjectKind::Sro(_) => {
                super::sro::deserialize_sro_object_from_value(typed_value)
                    .map(StixObject::Sro)
                    .map_err(serde_json_error_to_parse_error)?
            }
            crate::core::StixObjectKind::Meta(_) => {
                super::meta::deserialize_meta_object_from_value(typed_value)
                    .map(StixObject::Meta)
                    .map_err(serde_json_error_to_parse_error)?
            }
        }
    } else if let Some(result) = opts
        .type_registry
        .deserialize(type_name, typed_value.clone())
    {
        let typed = result?;
        let id = typed_value
            .get("id")
            .ok_or(crate::ParseError::MissingObjectId)
            .and_then(|id_value| {
                serde_json::from_value::<StixId>(id_value.clone()).map_err(crate::ParseError::Json)
            })?;
        StixObject::Custom(CustomStixObject {
            type_name: type_name.to_owned(),
            id,
            raw: typed_value,
            typed: Some(typed),
        })
    } else if opts.allow_custom || opts.type_registry.is_registered(type_name) {
        let id = typed_value
            .get("id")
            .ok_or(crate::ParseError::MissingObjectId)
            .and_then(|id_value| {
                serde_json::from_value::<StixId>(id_value.clone()).map_err(crate::ParseError::Json)
            })?;
        StixObject::Custom(CustomStixObject {
            type_name: type_name.to_owned(),
            id,
            raw: typed_value,
            typed: None,
        })
    } else {
        return Err(crate::ParseError::UnknownObjectType(type_name.to_owned()));
    };

    if let Some(wire) = wire_for_extra.as_ref() {
        capture_unmodeled_properties(wire, &object, &mut extra)?;
    }
    extra.extend(drain_common_extra(&mut object));

    Ok((object, extra))
}

#[cfg(feature = "serde")]
fn drain_common_extra(object: &mut StixObject) -> BTreeMap<String, serde_json::Value> {
    match object {
        StixObject::Sdo(sdo) => std::mem::take(&mut sdo.common_props_mut().extra),
        StixObject::Sro(sro) => std::mem::take(&mut sro.common_props_mut().extra),
        StixObject::Sco(sco) => std::mem::take(&mut sco.common_props_mut().extra),
        StixObject::Meta(meta) => meta.drain_extra(),
        StixObject::Custom(_) => BTreeMap::new(),
    }
}

impl QueryableStixObject for StixObject {
    fn id(&self) -> &StixId {
        match self {
            Self::Sdo(inner) => inner.id(),
            Self::Sco(inner) => inner.id(),
            Self::Sro(inner) => inner.id(),
            Self::Meta(inner) => inner.id(),
            Self::Custom(custom) => &custom.id,
        }
    }

    fn type_name(&self) -> &str {
        match self {
            Self::Sdo(inner) => inner.type_name(),
            Self::Sco(inner) => inner.type_name(),
            Self::Sro(inner) => inner.type_name(),
            Self::Meta(inner) => inner.type_name(),
            Self::Custom(custom) => custom.type_name.as_str(),
        }
    }

    fn spec_version(&self) -> Option<SpecVersion> {
        match self {
            Self::Sdo(inner) => inner.spec_version(),
            Self::Sco(inner) => inner.spec_version(),
            Self::Sro(inner) => inner.spec_version(),
            Self::Meta(inner) => inner.spec_version(),
            Self::Custom(custom) => custom
                .raw
                .get("spec_version")
                .and_then(|value| serde_json::from_value(value.clone()).ok()),
        }
    }

    fn created(&self) -> Option<&StixTimestamp> {
        match self {
            Self::Sdo(inner) => inner.created(),
            Self::Sco(_) => None,
            Self::Sro(inner) => inner.created(),
            Self::Meta(inner) => inner.created(),
            Self::Custom(_) => None,
        }
    }

    fn modified(&self) -> Option<&StixTimestamp> {
        match self {
            Self::Sdo(inner) => inner.modified(),
            Self::Sco(_) => None,
            Self::Sro(inner) => inner.modified(),
            Self::Meta(inner) => inner.modified(),
            Self::Custom(_) => None,
        }
    }

    fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
        match self {
            Self::Sdo(inner) => inner.get_field(path),
            Self::Sco(inner) => inner.get_field(path),
            Self::Sro(inner) => inner.get_field(path),
            Self::Meta(inner) => inner.get_field(path),
            Self::Custom(_) => None,
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for StixObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Sdo(inner) => inner.serialize(serializer),
            Self::Sco(inner) => inner.serialize(serializer),
            Self::Sro(inner) => inner.serialize(serializer),
            Self::Meta(inner) => inner.serialize(serializer),
            Self::Custom(custom) => custom.raw.serialize(serializer),
        }
    }
}
