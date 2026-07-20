//! STIX `course-of-action` objects (STIX §4.3).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::SdoSroCommonProps;

/// A STIX course of action describing preventive or responsive measures (STIX §4.3).
///
/// Required properties: common SDO fields plus `name`. Optional fields include
/// `description` and the reserved `action` placeholder for future automation.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sdo::CourseOfAction;
///
/// let json = r#"{
///   "type": "course-of-action",
///   "spec_version": "2.1",
///   "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
///   "created": "2016-04-06T20:03:48.000Z",
///   "modified": "2016-04-06T20:03:48.000Z",
///   "name": "Add TCP port 80 Filter Rule",
///   "description": "Add a filter rule to block inbound TCP port 80."
/// }"#;
/// let course_of_action: CourseOfAction = serde_json::from_str(json)?;
/// assert_eq!(course_of_action.name, "Add TCP port 80 Filter Rule");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CourseOfAction {
    /// STIX object type (`course-of-action`).
    #[cfg_attr(
        feature = "serde",
        serde(
            rename = "type",
            deserialize_with = "deserialize_course_of_action_type"
        )
    )]
    object_type: String,
    /// SDO/SRO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Name identifying the course of action.
    pub name: String,
    /// Human-readable description.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// Reserved placeholder for structured or automated courses of action.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub action: Option<serde_json::Value>,
}

impl CourseOfAction {
    /// STIX type name for courses of action.
    pub const TYPE_NAME: &'static str = "course-of-action";

    /// Check common SDO properties.
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)
    }
}

#[cfg(feature = "serde")]
fn deserialize_course_of_action_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, CourseOfAction::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CourseOfAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(
                rename = "type",
                deserialize_with = "deserialize_course_of_action_type"
            )]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            name: String,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            action: Option<serde_json::Value>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let course_of_action = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
            description: raw.description,
            action: raw.action,
        };
        course_of_action
            .validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(course_of_action)
    }
}

impl QueryableStixObject for CourseOfAction {
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
            ["description"] => self.description.as_deref().map(QueryValue::Str),
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
        let json = include_str!("../../../tests/fixtures/spec/sdo/tool-minimal.json");
        let msg = serde_json::from_str::<CourseOfAction>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `course-of-action`"));
        assert!(msg.contains("got `tool`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/course-of-action-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err =
            serde_json::from_value::<CourseOfAction>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
