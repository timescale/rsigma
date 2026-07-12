//! STIX `url` objects (STIX §6.15).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;
use crate::model::validate::validate_url_format;

/// A STIX URL cyber-observable representing a uniform resource locator.
///
/// Per STIX §6.15, the required `value` holds the URL string validated with the WHATWG URL parser.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sco::Url;
///
/// let json = r#"{
///   "type": "url",
///   "spec_version": "2.1",
///   "id": "url--47c3cf9a-5027-5bf0-997a-017c7edc7c55",
///   "value": "https://example.com/research/index.html"
/// }"#;
/// let url: Url = serde_json::from_str(json)?;
/// assert_eq!(url.value, "https://example.com/research/index.html");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Url {
    /// STIX object type (`url`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_url_type")
    )]
    object_type: String,
    /// SCO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    /// URL string (for example `https://example.com/path`).
    pub value: String,
}

impl Url {
    /// STIX type name for URLs.
    pub const TYPE_NAME: &'static str = "url";

    /// Rejects empty `value`.
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_url_format(&self.value)
    }
}

#[cfg(feature = "serde")]
fn deserialize_url_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Url::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Url {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_url_type")]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            value: String,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            value: raw.value,
        };
        obj.validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for Url {
    fn id(&self) -> &StixId {
        &self.common.id
    }

    fn type_name(&self) -> &'static str {
        Url::TYPE_NAME
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
            ["value"] => Some(QueryValue::Str(&self.value)),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/mutex.json");
        let msg = serde_json::from_str::<Url>(json).unwrap_err().to_string();
        assert!(msg.contains("expected STIX type `url`"));
        assert!(msg.contains("got `mutex`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/url.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Url>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
