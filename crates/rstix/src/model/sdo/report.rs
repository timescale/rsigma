//! STIX `report` objects (STIX §4.16).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::SdoSroCommonProps;

/// A collection of related STIX objects published as a threat-intelligence report (STIX §4.16).
///
/// Required properties: common SDO fields plus `name`, `published`, and a non-empty
/// [`object_refs`](Self::object_refs) list (STIX §4.16.1).
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sdo::Report;
///
/// let json = r#"{
///   "type": "report",
///   "spec_version": "2.1",
///   "id": "report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
///   "created": "2015-12-21T19:59:11.000Z",
///   "modified": "2015-12-21T19:59:11.000Z",
///   "name": "The Black Vine Cyberespionage Group",
///   "published": "2016-01-20T17:00:00.000Z",
///   "object_refs": [
///     "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2"
///   ]
/// }"#;
/// let report: Report = serde_json::from_str(json)?;
/// assert_eq!(report.name, "The Black Vine Cyberespionage Group");
/// assert_eq!(report.object_refs.len(), 1);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Report {
    /// STIX object type (`report`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_report_type")
    )]
    object_type: String,
    /// SDO common properties (STIX §3.2).
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Name identifying the report (STIX §4.16.1).
    pub name: String,
    /// Human-readable description of the report (STIX §4.16.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// Report categories (report-type-ov) (STIX §4.16.1).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub report_types: Vec<String>,
    /// Timestamp when the report was published (STIX §4.16.1).
    pub published: StixTimestamp,
    /// STIX object IDs referenced by this report (STIX §4.16.1).
    pub object_refs: Vec<StixId>,
}

impl Report {
    /// STIX type name for report objects.
    pub const TYPE_NAME: &'static str = "report";

    /// Check report common properties.
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)
    }
}

#[cfg(feature = "serde")]
fn deserialize_report_type<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(d, Report::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Report {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_report_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            name: String,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            report_types: Vec<String>,
            published: StixTimestamp,
            object_refs: Vec<StixId>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let value = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
            description: raw.description,
            report_types: raw.report_types,
            published: raw.published,
            object_refs: raw.object_refs,
        };
        value
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(value)
    }
}

impl QueryableStixObject for Report {
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
            ["name"] => Some(QueryValue::Str(&self.name)),
            ["published"] => Some(QueryValue::Timestamp(&self.published)),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/vulnerability-minimal.json");
        let msg = serde_json::from_str::<Report>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `report`"));
        assert!(msg.contains("got `vulnerability`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/report-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Report>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
