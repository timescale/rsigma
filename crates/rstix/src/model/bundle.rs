//! STIX 2.1 bundle container and parsing.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;

use crate::core::StixId;
use crate::model::BundleObjectCast;
use crate::model::ModelError;
use crate::model::json_limits::{LimitedReader, validate_value_limits};
use crate::model::meta::LanguageContent;
use crate::model::parse_options::ParseOptions;
use crate::model::sdo::ObservedDataForm;
use crate::model::stix_object::{StixObject, deserialize_stix_object_from_value};
use crate::model::validate::{
    validate_identity_ref, validate_marking_definition_ref, validate_sco_or_sro_ref,
    validate_sco_ref, validate_sdo_ref, validate_stix_or_sco_ref,
};

/// Container trait for bundle navigation (Data Model + Serialization).
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
        root: serde_json::Value,
        opts: &ParseOptions,
    ) -> Result<Self, crate::ParseError> {
        validate_value_limits(&root, opts)?;

        let map = root.as_object().ok_or_else(|| {
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
                serde_json::from_value::<StixId>(value.clone()).map_err(crate::ParseError::Json)
            })?;

        if id.type_name() != "bundle" {
            return Err(crate::ParseError::Model(ModelError::BundleIdPrefixInvalid));
        }

        let object_values = map
            .get("objects")
            .map(|value| {
                value
                    .as_array()
                    .ok_or_else(|| {
                        crate::ParseError::Json(serde_json::Error::io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "bundle objects must be an array",
                        )))
                    })
                    .cloned()
            })
            .transpose()?
            .unwrap_or_default();

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
                        .map_err(crate::ParseError::Json)
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
        };
        bundle.validate_refs()?;
        Ok(bundle)
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
        let mut refs = Vec::new();
        for object in &self.objects {
            object.collect_internal_refs(&mut refs);
        }

        for reference in refs {
            if !self.id_index.contains_key(reference.as_str()) {
                return Err(ModelError::BundleReferenceMissing {
                    ref_id: reference.as_str().to_owned(),
                });
            }
        }

        for object in &self.objects {
            self.validate_ref_kinds(object)?;
        }

        self.validate_property_extensions()?;

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
                    }) => {
                        validate_sdo_ref(sighting_of_ref)?;
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
                    validate_sdo_ref(object_ref)?;
                }
            },
            StixObject::Sco(_) | StixObject::Custom(_) => {}
        }
        Ok(())
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
                    for (key, prop) in extra {
                        obj.insert(key.clone(), prop.clone());
                    }
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
}
