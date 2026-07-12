//! STIX `mutex` objects (STIX §6.11).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;

/// A STIX mutex cyber-observable representing a named synchronization primitive.
///
/// Per STIX §6.11, the required `name` identifies the mutex as observed on the
/// system (for example a malware mutex string).
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sco::Mutex;
///
/// let json = r#"{
///   "type": "mutex",
///   "spec_version": "2.1",
///   "id": "mutex--f93fe911-e545-5239-b9b0-597840d0c871",
///   "name": "__CLEANSWEEP__"
/// }"#;
/// let mutex: Mutex = serde_json::from_str(json)?;
/// assert_eq!(mutex.name, "__CLEANSWEEP__");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Mutex {
    /// STIX object type (`mutex`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_mutex_type")
    )]
    object_type: String,
    /// SCO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    /// Mutex name as observed on the system.
    pub name: String,
}

impl Mutex {
    /// STIX type name for mutexes.
    pub const TYPE_NAME: &'static str = "mutex";

    /// Rejects empty `name`.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.name.is_empty() {
            return Err(ModelError::MutexNameEmpty);
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_mutex_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Mutex::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Mutex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_mutex_type")]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            name: String,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
        };
        obj.validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for Mutex {
    fn id(&self) -> &StixId {
        &self.common.id
    }

    fn type_name(&self) -> &'static str {
        Mutex::TYPE_NAME
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
            ["name"] => Some(QueryValue::Str(&self.name)),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/url.json");
        let msg = serde_json::from_str::<Mutex>(json).unwrap_err().to_string();
        assert!(msg.contains("expected STIX type `mutex`"));
        assert!(msg.contains("got `"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/mutex.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Mutex>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
