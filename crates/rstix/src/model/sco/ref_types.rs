//! Typed reference enums for SCO union ref targets.

use crate::core::{
    ArtifactId, DirectoryId, DomainNameId, FileId, Ipv4AddrId, Ipv6AddrId, MacAddrId, StixId,
};
#[cfg(feature = "serde")]
use crate::model::ModelError;

/// Domain-name `resolves_to_refs` target (STIX §6.4.1).
#[derive(Clone, Debug, PartialEq)]
pub enum DomainNameResolvesToRef {
    /// An `ipv4-addr` reference.
    Ipv4Addr(Ipv4AddrId),
    /// An `ipv6-addr` reference.
    Ipv6Addr(Ipv6AddrId),
    /// A `domain-name` reference.
    DomainName(DomainNameId),
}

impl DomainNameResolvesToRef {
    /// Borrow the underlying STIX id.
    pub fn as_stix_id(&self) -> &StixId {
        match self {
            Self::Ipv4Addr(id) => id.as_stix_id(),
            Self::Ipv6Addr(id) => id.as_stix_id(),
            Self::DomainName(id) => id.as_stix_id(),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for DomainNameResolvesToRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_stix_id().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DomainNameResolvesToRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let id = <StixId as serde::Deserialize>::deserialize(deserializer)?;
        match id.type_name() {
            "ipv4-addr" => Ipv4AddrId::from_stix_id(id)
                .map(Self::Ipv4Addr)
                .map_err(serde::de::Error::custom),
            "ipv6-addr" => Ipv6AddrId::from_stix_id(id)
                .map(Self::Ipv6Addr)
                .map_err(serde::de::Error::custom),
            "domain-name" => DomainNameId::from_stix_id(id)
                .map(Self::DomainName)
                .map_err(serde::de::Error::custom),
            _ => Err(ModelError::DomainNameResolvesToRefInvalid.into_de_custom()),
        }
    }
}

/// Directory `contains_refs` target (STIX §6.3.1).
#[derive(Clone, Debug, PartialEq)]
pub enum DirectoryContainsRef {
    /// A `file` reference.
    File(FileId),
    /// A `directory` reference.
    Directory(DirectoryId),
}

impl DirectoryContainsRef {
    /// Borrow the underlying STIX id.
    pub fn as_stix_id(&self) -> &StixId {
        match self {
            Self::File(id) => id.as_stix_id(),
            Self::Directory(id) => id.as_stix_id(),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for DirectoryContainsRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_stix_id().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DirectoryContainsRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let id = <StixId as serde::Deserialize>::deserialize(deserializer)?;
        match id.type_name() {
            "file" => FileId::from_stix_id(id)
                .map(Self::File)
                .map_err(serde::de::Error::custom),
            "directory" => DirectoryId::from_stix_id(id)
                .map(Self::Directory)
                .map_err(serde::de::Error::custom),
            _ => Err(ModelError::DirectoryContainsRefInvalid.into_de_custom()),
        }
    }
}

/// Network-traffic endpoint ref (STIX §6.12.1).
#[derive(Clone, Debug, PartialEq)]
pub enum NetworkTrafficEndpointRef {
    /// An `ipv4-addr` reference.
    Ipv4Addr(Ipv4AddrId),
    /// An `ipv6-addr` reference.
    Ipv6Addr(Ipv6AddrId),
    /// A `mac-addr` reference.
    MacAddr(MacAddrId),
    /// A `domain-name` reference.
    DomainName(DomainNameId),
}

impl NetworkTrafficEndpointRef {
    /// Borrow the underlying STIX id.
    pub fn as_stix_id(&self) -> &StixId {
        match self {
            Self::Ipv4Addr(id) => id.as_stix_id(),
            Self::Ipv6Addr(id) => id.as_stix_id(),
            Self::MacAddr(id) => id.as_stix_id(),
            Self::DomainName(id) => id.as_stix_id(),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for NetworkTrafficEndpointRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_stix_id().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for NetworkTrafficEndpointRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let id = <StixId as serde::Deserialize>::deserialize(deserializer)?;
        match id.type_name() {
            "ipv4-addr" => Ipv4AddrId::from_stix_id(id)
                .map(Self::Ipv4Addr)
                .map_err(serde::de::Error::custom),
            "ipv6-addr" => Ipv6AddrId::from_stix_id(id)
                .map(Self::Ipv6Addr)
                .map_err(serde::de::Error::custom),
            "mac-addr" => MacAddrId::from_stix_id(id)
                .map(Self::MacAddr)
                .map_err(serde::de::Error::custom),
            "domain-name" => DomainNameId::from_stix_id(id)
                .map(Self::DomainName)
                .map_err(serde::de::Error::custom),
            _ => Err(ModelError::NetworkTrafficEndpointRefInvalid.into_de_custom()),
        }
    }
}

/// Email MIME part raw body ref (STIX §6.6.2).
#[derive(Clone, Debug, PartialEq)]
pub enum EmailMimeBodyRawRef {
    /// An `artifact` reference.
    Artifact(ArtifactId),
    /// A `file` reference.
    File(FileId),
}

impl EmailMimeBodyRawRef {
    /// Borrow the underlying STIX id.
    pub fn as_stix_id(&self) -> &StixId {
        match self {
            Self::Artifact(id) => id.as_stix_id(),
            Self::File(id) => id.as_stix_id(),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for EmailMimeBodyRawRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_stix_id().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EmailMimeBodyRawRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let id = <StixId as serde::Deserialize>::deserialize(deserializer)?;
        match id.type_name() {
            "artifact" => ArtifactId::from_stix_id(id)
                .map(Self::Artifact)
                .map_err(serde::de::Error::custom),
            "file" => FileId::from_stix_id(id)
                .map(Self::File)
                .map_err(serde::de::Error::custom),
            _ => Err(ModelError::EmailMimeBodyRawRefInvalid.into_de_custom()),
        }
    }
}
