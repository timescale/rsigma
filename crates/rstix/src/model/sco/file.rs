//! STIX `file` objects (STIX §6.7).

use std::collections::BTreeMap;

use crate::core::{
    ArtifactId, DirectoryId, QueryValue, QueryableStixObject, SpecVersion, StixId, StixTimestamp,
};
use crate::model::ModelError;
use crate::model::common::ScoCommonProps;
use crate::model::sco::extensions::{
    ArchiveExt, NtfsExt, PdfExt, RasterImageExt, WindowsPeBinaryExt,
};
use crate::model::validate::validate_sco_ref;

/// Properties of a file on a file system (STIX §6.7).
///
/// At least one of [`hashes`](Self::hashes) or a non-empty [`name`](Self::name) is
/// required per STIX §6.7.2.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct File {
    /// STIX object type (`file`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", deserialize_with = "deserialize_file_type")
    )]
    object_type: String,
    /// SCO common properties (STIX §3.2).
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub common: ScoCommonProps,
    /// Dictionary of cryptographic hashes (STIX §6.7.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub hashes: BTreeMap<String, String>,
    /// Size of the file in bytes (STIX §6.7.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub size: Option<u64>,
    /// Name of the file (STIX §6.7.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub name: Option<String>,
    /// Character encoding of the file name (STIX §6.7.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub name_enc: Option<String>,
    /// First bytes of the file in hexadecimal (STIX §6.7.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub magic_number_hex: Option<String>,
    /// MIME type of the file content (STIX §6.7.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub mime_type: Option<String>,
    /// File creation time (STIX §6.7.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub ctime: Option<StixTimestamp>,
    /// File modification time (STIX §6.7.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub mtime: Option<StixTimestamp>,
    /// File last-access time (STIX §6.7.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub atime: Option<StixTimestamp>,
    /// Reference to the directory containing this file (STIX §6.7.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub parent_directory_ref: Option<DirectoryId>,
    /// References to files or directories contained in this file (STIX §6.7.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub contains_refs: Vec<StixId>,
    /// Reference to an artifact holding the raw file content (STIX §6.7.2).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub content_ref: Option<ArtifactId>,
}

impl File {
    /// STIX type name for files.
    pub const TYPE_NAME: &'static str = "file";

    /// Check file invariants (hashes or name required; extension validation).
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.hashes.is_empty() && self.name.as_ref().is_none_or(String::is_empty) {
            return Err(ModelError::FileHashesOrNameRequired);
        }
        ArchiveExt::validate_in_map(&self.common.extensions)?;
        NtfsExt::validate_in_map(&self.common.extensions)?;
        PdfExt::validate_in_map(&self.common.extensions)?;
        RasterImageExt::validate_in_map(&self.common.extensions)?;
        WindowsPeBinaryExt::validate_in_map(&self.common.extensions)?;
        for child in &self.contains_refs {
            validate_sco_ref(child)?;
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
fn deserialize_file_type<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::model::type_check::deserialize_stix_type_field(deserializer, File::TYPE_NAME)
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for File {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(rename = "type", deserialize_with = "deserialize_file_type")]
            object_type: String,
            #[serde(flatten)]
            common: ScoCommonProps,
            #[serde(default)]
            hashes: BTreeMap<String, String>,
            #[serde(default)]
            size: Option<u64>,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            name_enc: Option<String>,
            #[serde(default)]
            magic_number_hex: Option<String>,
            #[serde(default)]
            mime_type: Option<String>,
            #[serde(default)]
            ctime: Option<StixTimestamp>,
            #[serde(default)]
            mtime: Option<StixTimestamp>,
            #[serde(default)]
            atime: Option<StixTimestamp>,
            #[serde(default)]
            parent_directory_ref: Option<DirectoryId>,
            #[serde(default)]
            contains_refs: Vec<StixId>,
            #[serde(default)]
            content_ref: Option<ArtifactId>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let obj = Self {
            object_type: raw.object_type,
            common: raw.common,
            hashes: raw.hashes,
            size: raw.size,
            name: raw.name,
            name_enc: raw.name_enc,
            magic_number_hex: raw.magic_number_hex,
            mime_type: raw.mime_type,
            ctime: raw.ctime,
            mtime: raw.mtime,
            atime: raw.atime,
            parent_directory_ref: raw.parent_directory_ref,
            contains_refs: raw.contains_refs,
            content_ref: raw.content_ref,
        };
        obj.validate().map_err(serde::de::Error::custom)?;
        Ok(obj)
    }
}

impl QueryableStixObject for File {
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
            ["name"] => self.name.as_deref().map(QueryValue::Str),
            ["name_enc"] => self.name_enc.as_deref().map(QueryValue::Str),
            ["size"] => self
                .size
                .map(|n| QueryValue::Int(i64::try_from(n).unwrap_or(i64::MAX))),
            ["mime_type"] => self.mime_type.as_deref().map(QueryValue::Str),
            ["magic_number_hex"] => self.magic_number_hex.as_deref().map(QueryValue::Str),
            ["created"] | ["ctime"] => self.ctime.as_ref().map(QueryValue::Timestamp),
            ["mtime"] => self.mtime.as_ref().map(QueryValue::Timestamp),
            ["atime"] => self.atime.as_ref().map(QueryValue::Timestamp),
            ["hashes", key] => self
                .hashes
                .get(*key)
                .map(String::as_str)
                .map(QueryValue::Str),
            ["parent_directory_ref"] => self
                .parent_directory_ref
                .as_ref()
                .map(|id| QueryValue::Id(id.as_stix_id())),
            ["contains_refs", index] => index
                .parse::<usize>()
                .ok()
                .and_then(|i| self.contains_refs.get(i))
                .map(QueryValue::Id),
            ["content_ref"] => self
                .content_ref
                .as_ref()
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
        let msg = serde_json::from_str::<File>(json).unwrap_err().to_string();
        assert!(msg.contains("expected STIX type `file`"));
        assert!(msg.contains("got `url`"));
    }

    #[test]
    fn rejects_missing_type_field() {
        let json = include_str!("../../../tests/fixtures/spec/sco/file-basic.json");
        let value: serde_json::Value = serde_json::from_str(json).expect("json");
        let mut obj = value.as_object().expect("object").clone();
        obj.remove("type");
        let err = serde_json::from_value::<File>(serde_json::Value::Object(obj)).unwrap_err();
        assert!(err.to_string().contains("missing field `type`"));
    }

    #[test]
    fn get_field_exposes_refs() {
        let json = include_str!("../../../tests/fixtures/spec/sco/file-with-parent.json");
        let obj: File = serde_json::from_str(json).expect("parse");
        assert!(matches!(
            obj.get_field(&["parent_directory_ref"]),
            Some(QueryValue::Id(_))
        ));
    }
}
