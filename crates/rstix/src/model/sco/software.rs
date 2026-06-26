//! STIX `software` objects (STIX §6.14).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;

/// A STIX software cyber-observable representing an installed or observed product.
///
/// Per STIX §6.14, the required `name` identifies the software. Optional fields
/// carry CPE, SWID, language, vendor, and version metadata.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sco::Software;
///
/// let json = r#"{
///   "type": "software",
///   "spec_version": "2.1",
///   "id": "software--710b0b41-d4d0-5d6c-a400-fc9254554ffc",
///   "name": "Word",
///   "cpe": "cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
///   "version": "2002",
///   "vendor": "Microsoft"
/// }"#;
/// let software: Software = serde_json::from_str(json)?;
/// assert_eq!(software.name, "Word");
/// assert_eq!(software.vendor.as_deref(), Some("Microsoft"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Software {
    /// STIX object type (`software`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_software_type")
    )]
    object_type: String,
    /// SCO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    /// Software product name.
    pub name: String,
    /// Common Platform Enumeration (CPE) URI.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub cpe: Option<String>,
    /// Software Identification (SWID) tag identifier.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub swid: Option<String>,
    /// Language codes supported by the software.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub languages: Vec<String>,
    /// Vendor or manufacturer name.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub vendor: Option<String>,
    /// Version string.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub version: Option<String>,
}

impl Software {
    /// STIX type name for software objects.
    pub const TYPE_NAME: &'static str = "software";

    /// Rejects empty `name`.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.name.is_empty() {
            return Err(ModelError::SoftwareNameEmpty);
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_software_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Software::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Software {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_software_type")]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            name: String,
            #[serde(default)]
            cpe: Option<String>,
            #[serde(default)]
            swid: Option<String>,
            #[serde(default)]
            languages: Vec<String>,
            #[serde(default)]
            vendor: Option<String>,
            #[serde(default)]
            version: Option<String>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
            cpe: raw.cpe,
            swid: raw.swid,
            languages: raw.languages,
            vendor: raw.vendor,
            version: raw.version,
        };
        obj.validate().map_err(serde::de::Error::custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for Software {
    fn id(&self) -> &StixId {
        &self.common.id
    }

    fn type_name(&self) -> &'static str {
        Self::TYPE_NAME
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
            ["cpe"] => self.cpe.as_deref().map(QueryValue::Str),
            ["vendor"] => self.vendor.as_deref().map(QueryValue::Str),
            ["version"] => self.version.as_deref().map(QueryValue::Str),
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
        let msg = serde_json::from_str::<Software>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `software`"));
        assert!(msg.contains("got `url`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/software-basic.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Software>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
