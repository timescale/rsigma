//! STIX `observed-data` objects (STIX §4.14).

use std::collections::BTreeMap;

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::SdoSroCommonProps;
#[cfg(feature = "serde")]
use crate::model::sco::deserialize_sco_object_from_value;
use crate::model::sco::ScoObject;
use crate::model::sdo::validate_number_observed;
#[cfg(feature = "serde")]
use crate::model::sro::deserialize_sro_object_from_value;
use crate::model::sro::SroObject;
use crate::model::validate::validate_sco_or_sro_ref;

/// Embedded object in the deprecated observed-data `objects` map (STIX §4.14.1).
///
/// The STIX 2.1 Specification §4.14.1 defines deprecated **`objects`** as a dictionary of
/// cyber-observable (SCO) content and **`object_refs`** as a list of SCO and SRO
/// identifiers. This enum accepts both SCO and SRO members in the deprecated map so
/// embedded entries align with the **`object_refs`** target set from the same section
/// (§4.14.1, embedded **`object_refs`** in §4.14.2).
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum ObservedDataEmbeddedObject {
    /// Embedded cyber-observable (SCO), the type required by §4.14.1 **`objects`**.
    Sco(ScoObject),
    /// Embedded SRO in deprecated **`objects`** (see type-level note; allowed by **`object_refs`** targets in §4.14.1).
    Sro(SroObject),
}

impl ObservedDataEmbeddedObject {
    /// STIX id of the embedded object.
    pub fn id(&self) -> &StixId {
        match self {
            Self::Sco(sco) => sco.id(),
            Self::Sro(sro) => sro.id(),
        }
    }

    #[cfg(feature = "serde")]
    pub(crate) fn collect_internal_refs(&self, refs: &mut Vec<StixId>) {
        use crate::model::stix_object::StixObject;
        match self {
            Self::Sco(sco) => StixObject::Sco(sco.clone()).collect_internal_refs(refs),
            Self::Sro(sro) => StixObject::Sro(sro.clone()).collect_internal_refs(refs),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ObservedDataEmbeddedObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Sco(sco) => sco.serialize(serializer),
            Self::Sro(sro) => sro.serialize(serializer),
        }
    }
}

/// Content form for an [`ObservedData`] object (STIX §4.14.1).
///
/// Exactly one variant MUST be present on the wire: `object_refs` (STIX 2.1) or
/// deprecated embedded `objects` (STIX 2.0 backward compatibility).
#[derive(Clone, Debug, PartialEq)]
pub enum ObservedDataForm {
    /// References to standalone SCO/SRO objects (`object_refs`).
    ObjectRefs(Vec<StixId>),
    /// Deprecated embedded SCO/SRO dictionary (`objects`).
    DeprecatedObjects(BTreeMap<String, ObservedDataEmbeddedObject>),
}

/// A STIX observed-data object capturing raw cyber-observable sightings (STIX §4.14).
#[derive(Clone, Debug, PartialEq)]
pub struct ObservedData {
    /// STIX object type (`observed-data`).
    object_type: String,
    /// SDO/SRO common properties.
    pub common: SdoSroCommonProps,
    /// Start of the observation window.
    pub first_observed: StixTimestamp,
    /// End of the observation window.
    pub last_observed: StixTimestamp,
    /// Number of times the observation occurred.
    pub number_observed: i64,
    /// Either `object_refs` or deprecated embedded `objects`.
    pub form: ObservedDataForm,
}

impl ObservedData {
    /// STIX type name for observed-data objects.
    pub const TYPE_NAME: &'static str = "observed-data";

    /// Check observed-data-specific invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)?;
        validate_number_observed(self.number_observed)?;
        if self.last_observed < self.first_observed {
            return Err(ModelError::ObservedDataLastObservedBeforeFirstObserved);
        }
        match &self.form {
            ObservedDataForm::DeprecatedObjects(objects) => {
                if objects.is_empty() {
                    return Err(ModelError::ObservedDataEmptyObjects);
                }
            }
            ObservedDataForm::ObjectRefs(object_refs) => {
                if object_refs.is_empty() {
                    return Err(ModelError::ObservedDataEmptyObjectRefs);
                }
                for object_ref in object_refs {
                    validate_sco_or_sro_ref(object_ref)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
use serde::Deserialize;

#[cfg(feature = "serde")]
fn deserialize_observed_data_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, ObservedData::TYPE_NAME)
}

#[cfg(feature = "serde")]
fn deserialize_objects<'de, D>(
    deserializer: D,
) -> Result<Option<BTreeMap<String, ObservedDataEmbeddedObject>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<BTreeMap<String, serde_json::Value>>::deserialize(deserializer)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let mut objects = BTreeMap::new();
    for (key, value) in raw {
        let type_name = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let embedded = match type_name {
            "relationship" | "sighting" => ObservedDataEmbeddedObject::Sro(
                deserialize_sro_object_from_value(value).map_err(serde::de::Error::custom)?,
            ),
            _ => ObservedDataEmbeddedObject::Sco(
                deserialize_sco_object_from_value(value).map_err(serde::de::Error::custom)?,
            ),
        };
        objects.insert(key, embedded);
    }
    Ok(Some(objects))
}

#[cfg(feature = "serde")]
fn observed_data_form_from_wire(
    objects: Option<BTreeMap<String, ObservedDataEmbeddedObject>>,
    object_refs: Option<Vec<StixId>>,
) -> Result<ObservedDataForm, ModelError> {
    match (objects, object_refs) {
        (Some(objects), None) => Ok(ObservedDataForm::DeprecatedObjects(objects)),
        (None, Some(object_refs)) => Ok(ObservedDataForm::ObjectRefs(object_refs)),
        (Some(_), Some(_)) => Err(ModelError::ObservedDataObjectsXorObjectRefs),
        (None, None) => Err(ModelError::ObservedDataMissingScoContent),
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ObservedData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (objects, object_refs) = match &self.form {
            ObservedDataForm::DeprecatedObjects(objects) => (Some(objects), None),
            ObservedDataForm::ObjectRefs(refs) => (None, Some(refs)),
        };

        #[derive(serde::Serialize)]
        struct Wire<'a> {
            #[serde(rename = "type")]
            object_type: &'a str,
            #[serde(flatten)]
            common: &'a SdoSroCommonProps,
            first_observed: &'a StixTimestamp,
            last_observed: &'a StixTimestamp,
            number_observed: i64,
            #[serde(skip_serializing_if = "Option::is_none")]
            objects: Option<&'a BTreeMap<String, ObservedDataEmbeddedObject>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            object_refs: Option<&'a Vec<StixId>>,
        }

        Wire {
            object_type: &self.object_type,
            common: &self.common,
            first_observed: &self.first_observed,
            last_observed: &self.last_observed,
            number_observed: self.number_observed,
            objects,
            object_refs,
        }
        .serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ObservedData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_observed_data_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            first_observed: StixTimestamp,
            last_observed: StixTimestamp,
            number_observed: i64,
            #[serde(default, deserialize_with = "deserialize_objects")]
            objects: Option<BTreeMap<String, ObservedDataEmbeddedObject>>,
            #[serde(default)]
            object_refs: Option<Vec<StixId>>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let form = observed_data_form_from_wire(raw.objects, raw.object_refs)
            .map_err(serde::de::Error::custom)?;
        let observed_data = Self {
            object_type: raw.object_type,
            common: raw.common,
            first_observed: raw.first_observed,
            last_observed: raw.last_observed,
            number_observed: raw.number_observed,
            form,
        };
        observed_data.validate().map_err(serde::de::Error::custom)?;
        Ok(observed_data)
    }
}

impl QueryableStixObject for ObservedData {
    fn id(&self) -> &StixId {
        &self.common.id
    }

    fn type_name(&self) -> &'static str {
        Self::TYPE_NAME
    }

    fn spec_version(&self) -> Option<SpecVersion> {
        Some(self.common.spec_version)
    }

    fn created(&self) -> Option<&StixTimestamp> {
        Some(&self.common.created)
    }

    fn modified(&self) -> Option<&StixTimestamp> {
        Some(&self.common.modified)
    }

    fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
        match path {
            ["first_observed"] => Some(QueryValue::Timestamp(&self.first_observed)),
            ["last_observed"] => Some(QueryValue::Timestamp(&self.last_observed)),
            ["number_observed"] => Some(QueryValue::Int(self.number_observed)),
            ["created_by_ref"] => self
                .common
                .created_by_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/attack-pattern-minimal.json");
        let msg = serde_json::from_str::<ObservedData>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `observed-data`"));
        assert!(msg.contains("got `attack-pattern`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/observed-data-object-refs.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err =
            serde_json::from_value::<ObservedData>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn validate_rejects_both_objects_and_object_refs() {
        let ts = StixTimestamp::parse("2016-05-12T08:17:27.000Z").expect("timestamp");
        let observed_data = ObservedData {
            object_type: ObservedData::TYPE_NAME.to_string(),
            common: observed_data_common(),
            first_observed: ts.clone(),
            last_observed: ts,
            number_observed: 1,
            form: ObservedDataForm::DeprecatedObjects(BTreeMap::new()),
        };
        // XOR is enforced at deserialization; direct construction with one form validates empty objects.
        assert_eq!(
            observed_data.validate().unwrap_err(),
            ModelError::ObservedDataEmptyObjects
        );
    }

    fn observed_data_common() -> SdoSroCommonProps {
        let ts = StixTimestamp::parse("2016-05-12T08:17:27.000Z").expect("timestamp");
        SdoSroCommonProps::new(StixId::generate("observed-data"), ts.clone(), ts)
    }
}
