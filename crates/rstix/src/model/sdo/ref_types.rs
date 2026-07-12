//! Typed reference enums for SDO embedded relationships.

use crate::core::{ArtifactId, FileId, NetworkTrafficId, StixId};
#[cfg(feature = "serde")]
use crate::model::ModelError;

/// Malware `sample_refs` target (STIX §4.11.1 — file or artifact).
#[derive(Clone, Debug, PartialEq)]
pub enum MalwareSampleRef {
    /// A `file` reference.
    File(FileId),
    /// An `artifact` reference.
    Artifact(ArtifactId),
}

impl MalwareSampleRef {
    /// Borrow the underlying STIX id.
    pub fn as_stix_id(&self) -> &StixId {
        match self {
            Self::File(id) => id.as_stix_id(),
            Self::Artifact(id) => id.as_stix_id(),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for MalwareSampleRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_stix_id().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MalwareSampleRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let id = <StixId as serde::Deserialize>::deserialize(deserializer)?;
        match id.type_name() {
            "file" => FileId::from_stix_id(id)
                .map(Self::File)
                .map_err(serde::de::Error::custom),
            "artifact" => ArtifactId::from_stix_id(id)
                .map(Self::Artifact)
                .map_err(serde::de::Error::custom),
            _ => Err(ModelError::MalwareSampleRefInvalid.into_de_custom()),
        }
    }
}

/// Malware Analysis `sample_ref` target (STIX §4.12.1 — file, network-traffic, or artifact).
#[derive(Clone, Debug, PartialEq)]
pub enum MalwareAnalysisSampleRef {
    /// A `file` reference.
    File(FileId),
    /// A `network-traffic` reference.
    NetworkTraffic(NetworkTrafficId),
    /// An `artifact` reference.
    Artifact(ArtifactId),
}

impl MalwareAnalysisSampleRef {
    /// Borrow the underlying STIX id.
    pub fn as_stix_id(&self) -> &StixId {
        match self {
            Self::File(id) => id.as_stix_id(),
            Self::NetworkTraffic(id) => id.as_stix_id(),
            Self::Artifact(id) => id.as_stix_id(),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for MalwareAnalysisSampleRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_stix_id().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MalwareAnalysisSampleRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let id = <StixId as serde::Deserialize>::deserialize(deserializer)?;
        match id.type_name() {
            "file" => FileId::from_stix_id(id)
                .map(Self::File)
                .map_err(serde::de::Error::custom),
            "network-traffic" => NetworkTrafficId::from_stix_id(id)
                .map(Self::NetworkTraffic)
                .map_err(serde::de::Error::custom),
            "artifact" => ArtifactId::from_stix_id(id)
                .map(Self::Artifact)
                .map_err(serde::de::Error::custom),
            _ => Err(ModelError::MalwareAnalysisSampleRefInvalid.into_de_custom()),
        }
    }
}
