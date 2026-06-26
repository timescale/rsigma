//! STIX `process` objects (STIX §6.13).

use std::collections::BTreeMap;

use crate::core::{
    FileId, NetworkTrafficId, ProcessId, QueryValue, QueryableStixObject, SpecVersion, StixId,
    StixTimestamp, UserAccountId,
};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;
use crate::model::sco::extensions::{WindowsProcessExt, WindowsServiceExt};

/// A running instance of a program (STIX §6.13).
///
/// At least one type-specific property or a recognized process extension
/// (`windows-process-ext`, `windows-service-ext`) must be present per STIX §6.13.2.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sco::Process;
///
/// let json = include_str!("../../../tests/fixtures/spec/sco/process-basic.json");
/// let process: Process = serde_json::from_str(json)?;
/// assert_eq!(process.pid, Some(1221));
/// assert!(process.image_ref.is_some());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Process {
    /// STIX object type (`process`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_process_type")
    )]
    object_type: String,
    /// SCO common properties (STIX §3.2).
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    /// Whether the process is hidden from task-management utilities (STIX §6.13.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub is_hidden: Option<bool>,
    /// Process identifier (STIX §6.13.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub pid: Option<u32>,
    /// Time the process was created (STIX §6.13.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub created_time: Option<StixTimestamp>,
    /// Current working directory (STIX §6.13.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub cwd: Option<String>,
    /// Full command line used to launch the process (STIX §6.13.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub command_line: Option<String>,
    /// Environment variables set when the process was launched (STIX §6.13.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub environment_variables: BTreeMap<String, String>,
    /// Network connections opened by the process (STIX §6.13.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub opened_connection_refs: Vec<NetworkTrafficId>,
    /// User account that created the process (STIX §6.13.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub creator_user_ref: Option<UserAccountId>,
    /// Executable file that backs the process (STIX §6.13.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub image_ref: Option<FileId>,
    /// Parent process (STIX §6.13.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub parent_ref: Option<ProcessId>,
    /// Child processes spawned by this process (STIX §6.13.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub child_refs: Vec<ProcessId>,
}

impl Process {
    /// STIX type name for processes.
    pub const TYPE_NAME: &'static str = "process";

    /// Check process invariants (at least one property or extension; extension validation).
    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.has_specific_property() {
            return Err(ModelError::ProcessNoProperties);
        }
        WindowsProcessExt::validate_in_map(&self.common.extensions)?;
        WindowsServiceExt::validate_in_map(&self.common.extensions)?;
        Ok(())
    }

    fn has_specific_property(&self) -> bool {
        self.is_hidden.is_some()
            || self.pid.is_some()
            || self.created_time.is_some()
            || self.cwd.is_some()
            || self.command_line.is_some()
            || !self.environment_variables.is_empty()
            || !self.opened_connection_refs.is_empty()
            || self.creator_user_ref.is_some()
            || self.image_ref.is_some()
            || self.parent_ref.is_some()
            || !self.child_refs.is_empty()
            || self.common.extensions.get(WindowsProcessExt::KEY).is_some()
            || self.common.extensions.get(WindowsServiceExt::KEY).is_some()
    }
}

#[cfg(feature = "serde")]
fn deserialize_process_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Process::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Process {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_process_type")]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            #[serde(default)]
            is_hidden: Option<bool>,
            #[serde(default)]
            pid: Option<u32>,
            #[serde(default)]
            created_time: Option<StixTimestamp>,
            #[serde(default)]
            cwd: Option<String>,
            #[serde(default)]
            command_line: Option<String>,
            #[serde(default)]
            environment_variables: BTreeMap<String, String>,
            #[serde(default)]
            opened_connection_refs: Vec<NetworkTrafficId>,
            #[serde(default)]
            creator_user_ref: Option<UserAccountId>,
            #[serde(default)]
            image_ref: Option<FileId>,
            #[serde(default)]
            parent_ref: Option<ProcessId>,
            #[serde(default)]
            child_refs: Vec<ProcessId>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            is_hidden: raw.is_hidden,
            pid: raw.pid,
            created_time: raw.created_time,
            cwd: raw.cwd,
            command_line: raw.command_line,
            environment_variables: raw.environment_variables,
            opened_connection_refs: raw.opened_connection_refs,
            creator_user_ref: raw.creator_user_ref,
            image_ref: raw.image_ref,
            parent_ref: raw.parent_ref,
            child_refs: raw.child_refs,
        };
        obj.validate().map_err(serde::de::Error::custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for Process {
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
            ["command_line"] => self.command_line.as_deref().map(QueryValue::Str),
            ["image_ref"] => self
                .image_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["parent_ref"] => self
                .parent_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["opened_connection_refs", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.opened_connection_refs.get(i))
                .map(|id| QueryValue::Id(id.as_stix_id())),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::core::QueryValue;

    #[test]
    fn rejects_wrong_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/url.json");
        let msg = serde_json::from_str::<Process>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `process`"));
        assert!(msg.contains("got `url`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/process-basic.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Process>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn get_field_exposes_refs() {
        let json = include_str!("../../../tests/fixtures/spec/sco/process-basic.json");
        let obj: Process = serde_json::from_str(json).expect("parse");
        assert!(matches!(
            obj.get_field(&["image_ref"]),
            Some(QueryValue::Id(_))
        ));
    }

    #[test]
    fn rejects_non_process_extension_without_type_specific_properties() {
        let json = r#"{
          "type": "process",
          "spec_version": "2.1",
          "id": "process--8fac80fe-a220-4ba9-8ffe-4f43ce8edff8",
          "extensions": {
            "archive-ext": {
              "contains_refs": ["file--70221dbf-52fd-5377-9619-c0ce6b3ffc8c"]
            }
          }
        }"#;
        let err = serde_json::from_str::<Process>(json).unwrap_err();
        assert!(
            err.to_string()
                .contains("process requires at least one specific property")
        );
    }

    #[test]
    fn accepts_process_extension_without_type_specific_properties() {
        let json = r#"{
          "type": "process",
          "spec_version": "2.1",
          "id": "process--8fac80fe-a220-4ba9-8ffe-4f43ce8edff8",
          "extensions": {
            "windows-process-ext": {
              "aslr_enabled": true,
              "dep_enabled": true,
              "priority": "HIGH_PRIORITY_CLASS",
              "owner_sid": "S-1-5-21-186985262-1144665072-74031268-1309"
            }
          }
        }"#;
        let parsed: Process = serde_json::from_str(json).expect("parse");
        parsed
            .validate()
            .expect("windows-process-ext satisfies STIX §6.13");
    }
}
