//! STIX custom / vendor cyber-observable objects (STIX §6, §9.8).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::common::ScoCommonProps;

/// A vendor-defined or custom SCO type not modeled as a built-in variant.
///
/// Type-specific properties are captured in [`ScoCommonProps::extra`] during
/// deserialization so pattern paths like `x-usb-device:usbdrive.serial_number`
/// resolve without a dedicated Rust struct.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CustomSco {
    /// STIX object type (e.g. `x-usb-device`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_custom_type")
    )]
    object_type: String,
    /// SCO common properties plus unmodeled top-level fields in `extra`.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
}

impl CustomSco {
    /// Construct a custom SCO with the given type name and id.
    pub fn new(type_name: impl Into<String>, id: StixId) -> Self {
        Self {
            object_type: type_name.into(),
            common: ScoCommonProps::new(id),
        }
    }
}

#[cfg(feature = "serde")]
fn deserialize_custom_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let value = String::deserialize(deserializer)?;
    if value.is_empty() {
        return Err(serde::de::Error::custom(
            "custom SCO type must be non-empty",
        ));
    }
    Ok(value)
}

impl QueryableStixObject for CustomSco {
    fn id(&self) -> &StixId {
        &self.common.id
    }

    fn type_name(&self) -> &str {
        &self.object_type
    }

    fn spec_version(&self) -> Option<SpecVersion> {
        self.common.spec_version
    }

    fn created(&self) -> Option<&StixTimestamp> {
        None
    }

    fn modified(&self) -> Option<&StixTimestamp> {
        None
    }

    fn get_field(&self, path: &[&str]) -> Option<QueryValue<'_>> {
        match path {
            [key] => self.common.extra.get(*key).and_then(json_scalar_to_query),
            [key, field] => self
                .common
                .extra
                .get(*key)
                .and_then(|v| v.get(*field))
                .and_then(json_scalar_to_query),
            _ => None,
        }
    }
}

fn json_scalar_to_query(value: &serde_json::Value) -> Option<QueryValue<'_>> {
    match value {
        serde_json::Value::String(s) => Some(QueryValue::Str(s)),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(QueryValue::Int)
            .or_else(|| n.as_f64().map(QueryValue::Float)),
        serde_json::Value::Bool(b) => Some(QueryValue::Bool(*b)),
        serde_json::Value::Null => Some(QueryValue::Null),
        _ => None,
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CustomSco {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_custom_type")]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
        }
        let raw = Raw::deserialize(deserializer)?;
        Ok(Self {
            object_type: raw.object_type,
            common: raw.common,
        })
    }
}
