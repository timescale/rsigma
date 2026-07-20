//! STIX `tool` objects (STIX §4.18).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::{KillChainPhase, SdoSroCommonProps};
use crate::model::sdo::validate_kill_chain_phases;

/// A STIX tool representing legitimate software used during attacks (STIX §4.18).
///
/// Required properties: common SDO fields plus `name`. Optional fields include
/// `description`, `tool_types`, `aliases`, `kill_chain_phases`, and `tool_version`.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sdo::Tool;
///
/// let json = r#"{
///   "type": "tool",
///   "spec_version": "2.1",
///   "id": "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
///   "created": "2016-04-06T20:03:48.000Z",
///   "modified": "2016-04-06T20:03:48.000Z",
///   "tool_types": ["remote-access"],
///   "name": "VNC"
/// }"#;
/// let tool: Tool = serde_json::from_str(json)?;
/// assert_eq!(tool.name, "VNC");
/// assert_eq!(tool.tool_types, vec!["remote-access".to_string()]);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Tool {
    /// STIX object type (`tool`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_tool_type")
    )]
    object_type: String,
    /// SDO/SRO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: SdoSroCommonProps,
    /// Name identifying the tool.
    pub name: String,
    /// Human-readable description.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// Tool kinds (tool-type-ov).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub tool_types: Vec<String>,
    /// Alternative names for this tool.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub aliases: Vec<String>,
    /// Kill chain phases where this tool applies.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub kill_chain_phases: Vec<KillChainPhase>,
    /// Version identifier for the tool.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub tool_version: Option<String>,
}

impl Tool {
    /// STIX type name for tools.
    pub const TYPE_NAME: &'static str = "tool";

    /// Check tool-specific invariants (kill-chain phases).
    pub fn validate(&self) -> Result<(), ModelError> {
        self.common.validate(Self::TYPE_NAME)?;
        validate_kill_chain_phases(&self.kill_chain_phases)
    }
}

#[cfg(feature = "serde")]
fn deserialize_tool_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Tool::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Tool {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_tool_type")]
            object_type: String,
            #[serde(flatten)]
            common: SdoSroCommonProps,
            name: String,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            tool_types: Vec<String>,
            #[serde(default)]
            aliases: Vec<String>,
            #[serde(default)]
            kill_chain_phases: Vec<KillChainPhase>,
            #[serde(default)]
            tool_version: Option<String>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let tool = Self {
            object_type: raw.object_type,
            common: raw.common,
            name: raw.name,
            description: raw.description,
            tool_types: raw.tool_types,
            aliases: raw.aliases,
            kill_chain_phases: raw.kill_chain_phases,
            tool_version: raw.tool_version,
        };
        tool.validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(tool)
    }
}

impl QueryableStixObject for Tool {
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
            ["tool_version"] => self.tool_version.as_deref().map(QueryValue::Str),
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
        let json = include_str!("../../../tests/fixtures/spec/sdo/course-of-action-minimal.json");
        let msg = serde_json::from_str::<Tool>(json).unwrap_err().to_string();
        assert!(msg.contains("expected STIX type `tool`"));
        assert!(msg.contains("got `course-of-action`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sdo/tool-minimal.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Tool>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }
}
