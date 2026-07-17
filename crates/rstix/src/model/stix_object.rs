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
        let mut paths = Vec::new();
        crate::model::ref_paths::collect_ref_paths(self, &mut paths);
        refs.extend(paths.into_iter().map(|(_, id)| id));
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
