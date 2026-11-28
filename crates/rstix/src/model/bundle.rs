//! STIX 2.1 bundle container and parsing.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;

use crate::core::{QueryableStixObject, StixId};
use crate::model::BundleObjectCast;
use crate::model::ModelError;
use crate::model::common::GranularMarking;
use crate::model::json_limits::{LimitedReader, validate_value_limits};
use crate::model::meta::LanguageContent;
use crate::model::meta::MetaObject;
use crate::model::parse_options::ParseOptions;
use crate::model::sdo::{ObservedData, ObservedDataEmbeddedObject, ObservedDataForm, SdoObject};
use crate::model::stix_object::{
    StixObject, deserialize_stix_object_from_value, serde_json_error_to_parse_error,
};
use crate::model::validate::{
    TargetWires, granular_markings_from_wire, language_content_translation_matches_target,
    resolve_selector_value, validate_granular_markings_semantics, validate_identity_ref,
    validate_marking_definition_ref, validate_sco_or_sro_ref, validate_sco_ref, validate_sdo_ref,
    validate_stix_object_ref, validate_stix_or_sco_ref,
};

/// Container trait for bundle navigation.
pub trait QueryableContainer {
    /// Bundle identifier.
    fn bundle_id(&self) -> &StixId;
    /// Contained STIX objects in document order.
    fn objects(&self) -> &[StixObject];
    /// Number of contained objects.
    fn object_count(&self) -> usize;
}

/// A STIX 2.1 bundle with typed objects and preserved custom properties.
#[derive(Clone, Debug, PartialEq)]
pub struct Bundle {
    id: StixId,
    objects: Vec<StixObject>,
    id_index: HashMap<String, usize>,
    extra_properties: HashMap<String, BTreeMap<String, serde_json::Value>>,
    /// When true, refs to [`StixObject::Custom`] targets in this bundle pass SDO/SCO kind checks.
    allow_custom: bool,
    /// When true, predefined TLP marking ids may be referenced without bundle membership.
    exempt_predefined_tlp_marking_refs: bool,
}

impl QueryableContainer for Bundle {
    fn bundle_id(&self) -> &StixId {
        self.id()
    }

    fn objects(&self) -> &[StixObject] {
        Bundle::objects(self)
    }

    fn object_count(&self) -> usize {
        self.objects.len()
    }
}

impl Bundle {
    /// Parse a bundle using default [`ParseOptions`].
    pub fn parse(json: &str) -> Result<Self, crate::ParseError> {
        Self::parse_with_options(json, &ParseOptions::default())
    }

    /// Parse a bundle with explicit options.
    pub fn parse_with_options(json: &str, opts: &ParseOptions) -> Result<Self, crate::ParseError> {
        if json.len() > opts.max_bundle_bytes {
            return Err(crate::ParseError::BundleByteLimitExceeded {
                max: opts.max_bundle_bytes,
            });
        }
        let root: serde_json::Value =
            serde_json::from_str(json).map_err(crate::ParseError::Json)?;
        Self::parse_root_value(root, opts)
    }

    /// Parse a bundle from any byte source using default options.
    pub fn parse_reader<R: Read>(reader: R) -> Result<Self, crate::ParseError> {
        Self::parse_reader_with_options(reader, &ParseOptions::default())
    }

    /// Parse a bundle from any byte source with explicit options.
    pub fn parse_reader_with_options<R: Read>(
        reader: R,
        opts: &ParseOptions,
    ) -> Result<Self, crate::ParseError> {
        let limited = LimitedReader::new(reader, opts.max_bundle_bytes);
        let root: serde_json::Value = serde_json::from_reader(limited).map_err(|err| {
            if err.to_string().contains("bundle byte limit exceeded") {
                crate::ParseError::BundleByteLimitExceeded {
                    max: opts.max_bundle_bytes,
                }
            } else {
                crate::ParseError::Json(err)
            }
        })?;
        Self::parse_root_value(root, opts)
    }

    fn parse_root_value(
        mut root: serde_json::Value,
        opts: &ParseOptions,
    ) -> Result<Self, crate::ParseError> {
        validate_value_limits(&root, opts)?;

        let map = root.as_object_mut().ok_or_else(|| {
            crate::ParseError::Json(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bundle must be a JSON object",
            )))
        })?;

        let bundle_type = map
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                crate::ParseError::Json(serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "bundle missing type field",
                )))
            })?;
        if bundle_type != "bundle" {
            return Err(crate::ParseError::NotABundle {
                actual_type: bundle_type.to_owned(),
            });
        }

        if map.contains_key("spec_version") {
            return Err(crate::ParseError::Model(
                ModelError::BundleSpecVersionNotAllowed,
            ));
        }

        let id = map
            .get("id")
            .ok_or(crate::ParseError::MissingBundleId)
            .and_then(|value| {
                serde_json::from_value::<StixId>(value.clone())
                    .map_err(serde_json_error_to_parse_error)
            })?;

        if id.type_name() != "bundle" {
            return Err(crate::ParseError::Model(ModelError::BundleIdPrefixInvalid));
        }

        let object_values = match map.remove("objects") {
            Some(serde_json::Value::Array(values)) => values,
            Some(_) => {
                return Err(crate::ParseError::Json(serde_json::Error::io(
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "bundle objects must be an array",
                    ),
                )));
            }
            None => Vec::new(),
        };

        if object_values.len() > opts.max_object_count {
            return Err(crate::ParseError::ObjectLimitExceeded {
                count: object_values.len(),
                max: opts.max_object_count,
            });
        }

        let mut objects = Vec::with_capacity(object_values.len());
        let mut id_index = HashMap::with_capacity(object_values.len());
        let mut extra_properties = HashMap::with_capacity(object_values.len());

        for value in object_values {
            let object_id = value
                .get("id")
                .ok_or(crate::ParseError::MissingObjectId)
                .and_then(|id_value| {
                    serde_json::from_value::<StixId>(id_value.clone())
                        .map_err(serde_json_error_to_parse_error)
                })?;
            let id_key = object_id.as_str().to_owned();
            if id_index.contains_key(&id_key) {
                return Err(crate::ParseError::DuplicateObjectId(id_key));
            }

            let (object, extra) = deserialize_stix_object_from_value(value, opts)?;
            if !extra.is_empty() {
                extra_properties.insert(id_key.clone(), extra);
            }
            let index = objects.len();
            id_index.insert(id_key, index);
            objects.push(object);
        }

        let bundle = Self {
            id,
            objects,
            id_index,
            extra_properties,
            allow_custom: opts.allow_custom,
            exempt_predefined_tlp_marking_refs: opts.exempt_predefined_tlp_marking_refs,
        };
        bundle.validate_refs()?;
        Ok(bundle)
    }

    /// Build a bundle from already-parsed objects (no reference validation).
    pub fn from_objects(id: StixId, objects: Vec<StixObject>) -> Self {
        let mut id_index = HashMap::with_capacity(objects.len());
        for (index, object) in objects.iter().enumerate() {
            id_index.insert(object.id().as_str().to_owned(), index);
        }
        Self {
            id,
            objects,
            id_index,
            extra_properties: HashMap::new(),
            allow_custom: false,
            exempt_predefined_tlp_marking_refs: false,
        }
    }

    fn custom_object_in_bundle(&self, id: &StixId) -> bool {
        self.get(id)
            .is_some_and(|object| matches!(object, StixObject::Custom(_)))
    }

    fn validate_stix_object_ref_in_bundle(&self, id: &StixId) -> Result<(), ModelError> {
        match validate_stix_object_ref(id) {
            Ok(()) => Ok(()),
            Err(_err) if self.allow_custom && self.custom_object_in_bundle(id) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn validate_stix_or_sco_ref_in_bundle(&self, id: &StixId) -> Result<(), ModelError> {
        match validate_stix_or_sco_ref(id) {
            Ok(()) => Ok(()),
            Err(_err) if self.allow_custom && self.custom_object_in_bundle(id) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn validate_sdo_ref_in_bundle(&self, id: &StixId) -> Result<(), ModelError> {
        match validate_sdo_ref(id) {
            Ok(()) => Ok(()),
            Err(_err) if self.allow_custom && self.custom_object_in_bundle(id) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn validate_sco_or_sro_ref_in_bundle(&self, id: &StixId) -> Result<(), ModelError> {
        match validate_sco_or_sro_ref(id) {
            Ok(()) => Ok(()),
            Err(_err) if self.allow_custom && self.custom_object_in_bundle(id) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn embedded_object_ids(&self) -> HashSet<String> {
        let mut ids = HashSet::new();
        for object in &self.objects {
            let StixObject::Sdo(SdoObject::ObservedData(ObservedData {
                form: ObservedDataForm::DeprecatedObjects(objects),
                ..
            })) = object
            else {
                continue;
            };
            for embedded in objects.values() {
                ids.insert(embedded.id().as_str().to_string());
            }
        }
        ids
    }

    fn ref_resolves_in_bundle(&self, id: &StixId, embedded_ids: &HashSet<String>) -> bool {
        self.id_index.contains_key(id.as_str()) || embedded_ids.contains(id.as_str())
    }

    fn validate_ref_resolves_in_bundle(
        &self,
        id: &StixId,
        embedded_ids: &HashSet<String>,
    ) -> Result<(), ModelError> {
        if self.exempt_predefined_tlp_marking_refs
            && crate::model::meta::is_predefined_tlp_marking_id(id.as_str())
        {
            return Ok(());
        }
        if self.ref_resolves_in_bundle(id, embedded_ids) {
            Ok(())
        } else {
            Err(ModelError::BundleReferenceMissing {
                ref_id: id.as_str().to_owned(),
            })
        }
    }

    fn validate_embedded_observed_data_refs(
        &self,
        objects: &BTreeMap<String, ObservedDataEmbeddedObject>,
    ) -> Result<(), ModelError> {
        let embedded_ids: HashSet<String> = objects
            .values()
            .map(|embedded| embedded.id().as_str().to_string())
            .collect();
        for embedded in objects.values() {
            match embedded {
                ObservedDataEmbeddedObject::Sco(sco) => {
                    let mut paths = Vec::new();
                    crate::model::ref_paths::collect_sco_ref_paths(sco, &mut paths);
                    for (_, reference) in paths {
                        self.validate_ref_resolves_in_bundle(&reference, &embedded_ids)?;
                    }
                }
                ObservedDataEmbeddedObject::Sro(sro) => {
                    use crate::model::sro::{Relationship, Sighting, SroObject};
                    match sro {
                        SroObject::Relationship(Relationship {
                            source_ref,
                            target_ref,
                            ..
                        }) => {
                            validate_stix_or_sco_ref(source_ref)?;
                            validate_stix_or_sco_ref(target_ref)?;
                            self.validate_ref_resolves_in_bundle(source_ref, &embedded_ids)?;
                            self.validate_ref_resolves_in_bundle(target_ref, &embedded_ids)?;
                        }
                        SroObject::Sighting(Sighting {
                            sighting_of_ref, ..
                        }) => {
                            validate_sdo_ref(sighting_of_ref)?;
                            self.validate_ref_resolves_in_bundle(sighting_of_ref, &embedded_ids)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Bundle identifier.
    pub fn id(&self) -> &StixId {
        &self.id
    }

    /// Parsed bundle objects in document order.
    pub fn objects(&self) -> &[StixObject] {
        &self.objects
    }

    /// Lookup a typed object by STIX id.
    pub fn get(&self, id: &StixId) -> Option<&StixObject> {
        self.id_index
            .get(id.as_str())
            .and_then(|index| self.objects.get(*index))
    }

    /// Typed lookup — returns `None` when the id exists but is the wrong type.
    pub fn get_typed<T: BundleObjectCast>(&self, id: &StixId) -> Option<&T> {
        self.get(id).and_then(T::cast_from)
    }

    /// Iterate objects of a concrete STIX type.
    pub fn objects_of_type<T: BundleObjectCast>(&self) -> impl Iterator<Item = &T> {
        self.objects.iter().filter_map(T::cast_from)
    }

    /// Top-level custom `x_*` properties captured at parse time for `id`.
    pub fn extra_properties(&self, id: &StixId) -> Option<&BTreeMap<String, serde_json::Value>> {
        self.extra_properties.get(id.as_str())
    }

    /// Validate that collected object references resolve within this bundle.
    pub fn validate_refs(&self) -> Result<(), ModelError> {
        let embedded_ids = self.embedded_object_ids();
        let mut refs = Vec::new();
        for object in &self.objects {
            object.collect_internal_refs(&mut refs);
        }

        for reference in refs {
            self.validate_ref_resolves_in_bundle(&reference, &embedded_ids)?;
        }

        for object in &self.objects {
            self.validate_ref_kinds(object)?;
        }

        self.validate_property_extensions()?;
        self.validate_semantics()?;

        Ok(())
    }

    fn object_wire_value(&self, object: &StixObject) -> Option<serde_json::Value> {
        let mut wire = serde_json::to_value(object).ok()?;
        if let Some(extra) = self.extra_properties(object.id())
            && let Some(obj) = wire.as_object_mut()
        {
            for (key, value) in extra {
                obj.insert(key.clone(), value.clone());
            }
        }
        Some(wire)
    }

    fn validate_semantics(&self) -> Result<(), ModelError> {
        let mut target_wires = TargetWires::default();
        for object in &self.objects {
            let granular_markings = granular_markings_for_object(object);
            if !granular_markings.is_empty() {
                let Some(wire) = self.object_wire_value(object) else {
                    continue;
                };
                validate_granular_markings_semantics(&wire, &granular_markings)?;
            }

            if let StixObject::Meta(MetaObject::LanguageContent(content)) = object {
                let target = self.get(&content.object_ref).ok_or_else(|| {
                    ModelError::BundleReferenceMissing {
                        ref_id: content.object_ref.as_str().to_owned(),
                    }
                })?;
                let Some(target_wire) =
                    target_wires.get(&content.object_ref, || self.object_wire_value(target))
                else {
                    continue;
                };
                validate_language_content_semantics(content, target, target_wire)?;
            }
        }
        Ok(())
    }

    fn validate_property_extensions(&self) -> Result<(), ModelError> {
        use crate::model::common::ExtensionType;
        use crate::model::meta::{ExtensionDefinition, MarkingDefinition, MetaObject};
        use crate::model::sco::ScoObject;

        const PREDEFINED_PROPERTY_EXTENSION_ID: &str =
            "extension-definition--60477d8d-78ac-1058-8160-d776f9386f83";

        for object in &self.objects {
            let extension_maps: Vec<&crate::model::common::ExtensionMap> = match object {
                StixObject::Sdo(sdo) => vec![&sdo.common_props().extensions],
                StixObject::Sro(sro) => vec![&sro.common_props().extensions],
                StixObject::Sco(sco) => match sco {
                    ScoObject::Artifact(v) => vec![&v.common.extensions],
                    ScoObject::AutonomousSystem(v) => vec![&v.common.extensions],
                    ScoObject::Directory(v) => vec![&v.common.extensions],
                    ScoObject::DomainName(v) => vec![&v.common.extensions],
                    ScoObject::EmailAddr(v) => vec![&v.common.extensions],
                    ScoObject::EmailMessage(v) => vec![&v.common.extensions],
                    ScoObject::File(v) => vec![&v.common.extensions],
                    ScoObject::Ipv4Addr(v) => vec![&v.common.extensions],
                    ScoObject::Ipv6Addr(v) => vec![&v.common.extensions],
                    ScoObject::MacAddr(v) => vec![&v.common.extensions],
                    ScoObject::Mutex(v) => vec![&v.common.extensions],
                    ScoObject::NetworkTraffic(v) => vec![&v.common.extensions],
                    ScoObject::Process(v) => vec![&v.common.extensions],
                    ScoObject::Software(v) => vec![&v.common.extensions],
                    ScoObject::Url(v) => vec![&v.common.extensions],
                    ScoObject::UserAccount(v) => vec![&v.common.extensions],
                    ScoObject::WindowsRegistryKey(v) => vec![&v.common.extensions],
                    ScoObject::X509Certificate(v) => vec![&v.common.extensions],
                    ScoObject::Custom(v) => vec![&v.common.extensions],
                },
                StixObject::Meta(meta) => match meta {
                    MetaObject::MarkingDefinition(MarkingDefinition { extensions, .. }) => {
                        vec![extensions]
                    }
                    MetaObject::ExtensionDefinition(ExtensionDefinition { common, .. }) => {
                        vec![&common.extensions]
                    }
                    MetaObject::LanguageContent(LanguageContent { common, .. }) => {
                        vec![&common.extensions]
                    }
                },
                StixObject::Custom(_) => Vec::new(),
            };

            for map in extension_maps {
                for (key, entry) in &map.0 {
                    if key.starts_with("extension-definition--")
                        && *key != PREDEFINED_PROPERTY_EXTENSION_ID
                        && entry.extension_type == Some(ExtensionType::PropertyExtension)
                        && !self.id_index.contains_key(key.as_str())
                    {
                        return Err(ModelError::PropertyExtensionDefinitionMissing {
                            extension_id: key.clone(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_ref_kinds(&self, object: &StixObject) -> Result<(), ModelError> {
        use crate::model::meta::{ExtensionDefinition, MarkingDefinition, MetaObject};
        use crate::model::sdo::{
            Grouping, MalwareAnalysis, Note, ObservedData, Opinion, Report, SdoObject,
        };
        use crate::model::sro::{Relationship, Sighting, SroObject};

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
                    SdoObject::ObservedData(ObservedData { form, .. }) => match form {
                        ObservedDataForm::ObjectRefs(object_refs) => {
                            for object_ref in object_refs {
                                self.validate_sco_or_sro_ref_in_bundle(object_ref)?;
                            }
                        }
                        ObservedDataForm::DeprecatedObjects(objects) => {
                            self.validate_embedded_observed_data_refs(objects)?;
                        }
                    },
                    SdoObject::Report(Report { object_refs, .. })
                    | SdoObject::Grouping(Grouping { object_refs, .. })
                    | SdoObject::Note(Note { object_refs, .. })
                    | SdoObject::Opinion(Opinion { object_refs, .. }) => {
                        for object_ref in object_refs {
                            self.validate_stix_object_ref_in_bundle(object_ref)?;
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
                        self.validate_stix_or_sco_ref_in_bundle(source_ref)?;
                        self.validate_stix_or_sco_ref_in_bundle(target_ref)?;
                    }
                    SroObject::Sighting(Sighting {
                        sighting_of_ref, ..
                    }) => {
                        self.validate_sdo_ref_in_bundle(sighting_of_ref)?;
                    }
                }
            }
            StixObject::Meta(meta) => match meta {
                MetaObject::MarkingDefinition(MarkingDefinition {
                    created_by_ref,
                    object_marking_refs,
                    ..
                }) => {
                    if let Some(created_by) = created_by_ref {
                        validate_identity_ref(created_by.as_stix_id())?;
                    }
                    for marking in object_marking_refs {
                        validate_marking_definition_ref(marking.as_stix_id())?;
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
                    self.validate_stix_object_ref_in_bundle(object_ref)?;
                }
            },
            StixObject::Sco(_) | StixObject::Custom(_) => {}
        }
        Ok(())
    }
}

/// Collect granular markings from any bundle object variant for wire semantic checks.
fn granular_markings_for_object(object: &StixObject) -> Cow<'_, [GranularMarking]> {
    match object {
        StixObject::Sdo(sdo) => Cow::Borrowed(&sdo.common_props().granular_markings),
        StixObject::Sro(sro) => Cow::Borrowed(&sro.common_props().granular_markings),
        StixObject::Sco(sco) => Cow::Borrowed(&sco.common_props().granular_markings),
        StixObject::Meta(MetaObject::MarkingDefinition(marking)) => {
            Cow::Borrowed(&marking.granular_markings)
        }
        StixObject::Meta(MetaObject::LanguageContent(content)) => {
            Cow::Borrowed(&content.common.granular_markings)
        }
        StixObject::Meta(MetaObject::ExtensionDefinition(ext)) => {
            Cow::Borrowed(&ext.common.granular_markings)
        }
        StixObject::Custom(custom) => Cow::Owned(granular_markings_from_wire(&custom.raw)),
    }
}

/// Validate language-content bundle semantics against the target object wire JSON (STIX §7.1.1).
fn validate_language_content_semantics(
    content: &LanguageContent,
    target: &StixObject,
    target_wire: &serde_json::Value,
) -> Result<(), ModelError> {
    if let Some(object_modified) = &content.object_modified {
        match QueryableStixObject::modified(target) {
            Some(target_modified) if object_modified != target_modified => {
                return Err(ModelError::LanguageContentObjectModifiedMismatch);
            }
            None => return Err(ModelError::LanguageContentObjectModifiedMismatch),
            _ => {}
        }
    }

    for (lang, fields) in &content.contents {
        for (field, translation) in fields {
            let Some(target_value) = resolve_selector_value(target_wire, field) else {
                // §7.1.1: keys for properties that do not exist on the target MUST be ignored.
                continue;
            };
            if !language_content_translation_matches_target(target_value, translation) {
                return Err(ModelError::LanguageContentValueMismatch {
                    detail: format!("{lang}.{field}"),
                });
            }
        }
    }
    Ok(())
}

#[cfg(feature = "serde")]
fn merge_extra_properties_for_wire(
    object: &StixObject,
    obj: &mut serde_json::Map<String, serde_json::Value>,
    extra: &BTreeMap<String, serde_json::Value>,
) {
    use crate::model::common::ExtensionType;

    let mut extension_props = BTreeMap::new();
    for (key, prop) in extra {
        if key.starts_with("x_") {
            obj.insert(key.clone(), prop.clone());
        } else {
            extension_props.insert(key.clone(), prop.clone());
        }
    }
    if extension_props.is_empty() {
        return;
    }

    let extension_id = extension_maps_for_object(object)
        .into_iter()
        .find_map(|map| {
            map.0.iter().find_map(|(key, entry)| {
                (key.starts_with("extension-definition--")
                    && entry.extension_type == Some(ExtensionType::ToplevelPropertyExtension))
                .then(|| key.clone())
            })
        })
        .unwrap_or_else(|| "extension-definition--unknown".to_owned());

    let extensions = obj
        .entry("extensions".to_owned())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let Some(ext_map) = extensions.as_object_mut() else {
        return;
    };
    let entry = ext_map
        .entry(extension_id)
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let Some(entry_obj) = entry.as_object_mut() else {
        return;
    };
    entry_obj.insert(
        "extension_type".to_owned(),
        serde_json::Value::String(ExtensionType::ToplevelPropertyExtension.as_str().to_owned()),
    );
    for (key, prop) in extension_props {
        entry_obj.insert(key, prop);
    }
}

#[cfg(feature = "serde")]
fn extension_maps_for_object(object: &StixObject) -> Vec<&crate::model::common::ExtensionMap> {
    use crate::model::meta::{ExtensionDefinition, MarkingDefinition, MetaObject};
    use crate::model::sco::ScoObject;

    match object {
        StixObject::Sdo(sdo) => vec![&sdo.common_props().extensions],
        StixObject::Sro(sro) => vec![&sro.common_props().extensions],
        StixObject::Sco(sco) => match sco {
            ScoObject::Artifact(v) => vec![&v.common.extensions],
            ScoObject::AutonomousSystem(v) => vec![&v.common.extensions],
            ScoObject::Directory(v) => vec![&v.common.extensions],
            ScoObject::DomainName(v) => vec![&v.common.extensions],
            ScoObject::EmailAddr(v) => vec![&v.common.extensions],
            ScoObject::EmailMessage(v) => vec![&v.common.extensions],
            ScoObject::File(v) => vec![&v.common.extensions],
            ScoObject::Ipv4Addr(v) => vec![&v.common.extensions],
            ScoObject::Ipv6Addr(v) => vec![&v.common.extensions],
            ScoObject::MacAddr(v) => vec![&v.common.extensions],
            ScoObject::Mutex(v) => vec![&v.common.extensions],
            ScoObject::NetworkTraffic(v) => vec![&v.common.extensions],
            ScoObject::Process(v) => vec![&v.common.extensions],
            ScoObject::Software(v) => vec![&v.common.extensions],
            ScoObject::Url(v) => vec![&v.common.extensions],
            ScoObject::UserAccount(v) => vec![&v.common.extensions],
            ScoObject::WindowsRegistryKey(v) => vec![&v.common.extensions],
            ScoObject::X509Certificate(v) => vec![&v.common.extensions],
            ScoObject::Custom(v) => vec![&v.common.extensions],
        },
        StixObject::Meta(meta) => match meta {
            MetaObject::MarkingDefinition(MarkingDefinition { extensions, .. }) => {
                vec![extensions]
            }
            MetaObject::ExtensionDefinition(ExtensionDefinition { common, .. }) => {
                vec![&common.extensions]
            }
            MetaObject::LanguageContent(content) => vec![&content.common.extensions],
        },
        StixObject::Custom(_) => Vec::new(),
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Bundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let field_count = 2 + usize::from(!self.objects.is_empty());
        let mut map = serializer.serialize_map(Some(field_count))?;
        map.serialize_entry("type", "bundle")?;
        map.serialize_entry("id", &self.id)?;
        if !self.objects.is_empty() {
            let mut serialized_objects = Vec::with_capacity(self.objects.len());
            for object in &self.objects {
                let mut value = serde_json::to_value(object).map_err(serde::ser::Error::custom)?;
                if let Some(extra) = self.extra_properties(object.id())
                    && let Some(obj) = value.as_object_mut()
                {
                    merge_extra_properties_for_wire(object, obj, extra);
                }
                serialized_objects.push(value);
            }
            map.serialize_entry("objects", &serialized_objects)?;
        }
        map.end()
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::model::sdo::AttackPattern;
    use crate::model::validate::TARGET_WIRES_BUILT;
    use std::io::Cursor;

    #[test]
    fn navigation_typed_get_and_objects_of_type() {
        let raw = include_str!("../../tests/fixtures/spec/bundle/bundle-minimal.json");
        let bundle = Bundle::parse(raw).expect("parse");
        let attack_id =
            StixId::parse("attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061").unwrap();
        assert!(bundle.get_typed::<AttackPattern>(&attack_id).is_some());
        assert_eq!(bundle.objects_of_type::<AttackPattern>().count(), 1);
    }

    #[test]
    fn parse_reader_matches_string_parse() {
        let raw = include_str!("../../tests/fixtures/spec/bundle/bundle-minimal.json");
        let from_str = Bundle::parse(raw).expect("string parse");
        let from_reader = Bundle::parse_reader(Cursor::new(raw.as_bytes())).expect("reader parse");
        assert_eq!(from_str, from_reader);
    }

    #[test]
    fn language_content_target_is_serialized_once() {
        let target = "identity--00000000-0000-4000-8000-000000000001";
        let mut objects = vec![format!(
            r#"{{"type":"identity","spec_version":"2.1","id":"{target}","created":"2024-01-01T00:00:00.000Z","modified":"2024-01-01T00:00:00.000Z","name":"Large","identity_class":"organization","description":"{large}","contact_information":"{large}"}}"#,
            large = "d".repeat(1 << 20)
        )];
        let contents = 200;
        for n in 0..contents {
            objects.push(format!(
                r#"{{"type":"language-content","spec_version":"2.1","id":"language-content--00000000-0000-4000-8000-{n:012x}","created":"2024-01-01T00:00:00.000Z","modified":"2024-01-01T00:00:00.000Z","object_ref":"{target}","object_modified":"2024-01-01T00:00:00.000Z","contents":{{"de":{{"name":"Gross","description":"Beschreibung"}}}}}}"#
            ));
        }
        let raw = format!(
            r#"{{"type":"bundle","id":"bundle--00000000-0000-4000-8000-000000000001","objects":[{}]}}"#,
            objects.join(",")
        );
        TARGET_WIRES_BUILT.with(|count| count.set(0));
        Bundle::parse(&raw).expect("bundle");
        assert_eq!(TARGET_WIRES_BUILT.with(std::cell::Cell::get), 1);

        let mismatched = raw.replacen(r#""name":"Gross""#, r#""name":["Gross"]"#, 1);
        assert!(matches!(
            Bundle::parse(&mismatched),
            Err(crate::ParseError::Model(
                ModelError::LanguageContentValueMismatch { .. }
            ))
        ));
    }

    #[test]
    fn interop_parse_exempts_predefined_tlp_marking_refs() {
        let raw =
            include_str!("../../tests/fixtures/interop/testcases/common/tc-tlp-exempt-ref.json");
        let default = Bundle::parse(raw);
        assert!(
            default.is_err(),
            "default parse rejects external TLP marking ref"
        );
        let interop = Bundle::parse_with_options(raw, &ParseOptions::new().interop_bundle());
        assert!(
            interop.is_ok(),
            "interop parse accepts predefined TLP marking ref: {:?}",
            interop.as_ref().err()
        );
    }
}
