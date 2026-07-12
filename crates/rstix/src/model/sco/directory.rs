//! STIX `directory` objects (STIX §6.3).

use crate::core::{QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;
use crate::model::sco::ref_types::DirectoryContainsRef;

/// A STIX directory cyber-observable representing a filesystem directory.
///
/// Per STIX §6.3, the required `path` holds the directory location. Optional
/// timestamps and `contains_refs` describe contents and metadata.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use rstix::model::sco::Directory;
///
/// let json = r#"{
///   "type": "directory",
///   "spec_version": "2.1",
///   "id": "directory--0a58d0c1-59e6-5afd-8252-dcd3f13e5622",
///   "path": "C:\\Windows\\System32"
/// }"#;
/// let dir: Directory = serde_json::from_str(json)?;
/// assert_eq!(dir.path, "C:\\Windows\\System32");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Directory {
    /// STIX object type (`directory`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_directory_type")
    )]
    object_type: String,
    /// SCO common properties.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    /// Filesystem path of the directory.
    pub path: String,
    /// Alternate encoding of `path`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub path_enc: Option<String>,
    /// Creation timestamp.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub ctime: Option<StixTimestamp>,
    /// Modification timestamp.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub mtime: Option<StixTimestamp>,
    /// Last-access timestamp.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub atime: Option<StixTimestamp>,
    /// File or directory objects contained in this directory.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub contains_refs: Vec<DirectoryContainsRef>,
}

impl Directory {
    /// STIX type name for directories.
    pub const TYPE_NAME: &'static str = "directory";

    /// Rejects empty `path`.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.path.is_empty() {
            return Err(ModelError::DirectoryPathEmpty);
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_directory_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, Directory::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Directory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_directory_type")]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            path: String,
            #[serde(default)]
            path_enc: Option<String>,
            #[serde(default)]
            ctime: Option<StixTimestamp>,
            #[serde(default)]
            mtime: Option<StixTimestamp>,
            #[serde(default)]
            atime: Option<StixTimestamp>,
            #[serde(default)]
            contains_refs: Vec<DirectoryContainsRef>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            path: raw.path,
            path_enc: raw.path_enc,
            ctime: raw.ctime,
            mtime: raw.mtime,
            atime: raw.atime,
            contains_refs: raw.contains_refs,
        };
        obj.validate()
            .map_err(crate::model::ModelError::into_de_custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for Directory {
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
            ["path"] => Some(QueryValue::Str(&self.path)),
            ["path_enc"] => self.path_enc.as_deref().map(QueryValue::Str),
            ["ctime"] => self.ctime.as_ref().map(QueryValue::Timestamp),
            ["mtime"] => self.mtime.as_ref().map(QueryValue::Timestamp),
            ["atime"] => self.atime.as_ref().map(QueryValue::Timestamp),
            ["contains_refs", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.contains_refs.get(i))
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
        let msg = serde_json::from_str::<Directory>(json)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("expected STIX type `directory`"));
        assert!(msg.contains("got `url`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/directory-basic.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<Directory>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn get_field_exposes_refs() {
        let json = include_str!("../../../tests/fixtures/spec/sco/directory-with-contains.json");
        let obj: Directory = serde_json::from_str(json).expect("parse");
        assert!(matches!(
            obj.get_field(&["contains_refs", "0"]),
            Some(QueryValue::Id(_))
        ));
    }
}
