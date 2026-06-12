//! STIX identifier types and object-kind discriminants.

use std::fmt;
use std::str::FromStr;

use crate::core::error::StixIdError;

/// A STIX object ID in the form `{type}--{uuid}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StixId(String);

impl StixId {
    /// Parse from `"{type}--{uuid}"`.
    pub fn parse(s: &str) -> Result<Self, StixIdError> {
        let (type_name, uuid_str) = s.split_once("--").ok_or(StixIdError::MissingDelimiter)?;
        if type_name.is_empty() {
            return Err(StixIdError::EmptyTypeName);
        }
        let _ = uuid::Uuid::parse_str(uuid_str)?;
        Ok(Self(s.to_owned()))
    }

    /// Generate a new random UUIDv4 ID for the given type name.
    pub fn generate(type_name: &str) -> Self {
        let prefix = if type_name.is_empty() {
            "unknown"
        } else {
            type_name
        };
        let id = format!("{prefix}--{}", uuid::Uuid::new_v4());
        Self(id)
    }

    /// The object type prefix (for example `"indicator"`).
    pub fn type_name(&self) -> &str {
        self.0.split_once("--").map_or("", |(prefix, _)| prefix)
    }

    /// The UUID portion.
    pub fn uuid(&self) -> uuid::Uuid {
        let (_, uuid_str) = self
            .0
            .split_once("--")
            .expect("StixId invariant violated: missing delimiter");
        uuid::Uuid::parse_str(uuid_str).expect("StixId invariant violated: invalid UUID")
    }

    /// Full string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StixId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for StixId {
    type Err = StixIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Discriminant for all STIX object classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StixObjectKind {
    /// STIX Domain Object.
    Sdo(SdoKind),
    /// STIX Cyber-observable Object.
    Sco(ScoKind),
    /// STIX Relationship Object.
    Sro(SroKind),
    /// STIX Meta Object.
    Meta(MetaKind),
}

impl StixObjectKind {
    /// Parse kind from a STIX `type` string.
    pub fn from_type_str(value: &str) -> Option<Self> {
        SdoKind::from_type_str(value)
            .map(Self::Sdo)
            .or_else(|| ScoKind::from_type_str(value).map(Self::Sco))
            .or_else(|| SroKind::from_type_str(value).map(Self::Sro))
            .or_else(|| MetaKind::from_type_str(value).map(Self::Meta))
    }
}

/// All STIX Domain Object discriminants in STIX 2.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SdoKind {
    /// `attack-pattern`.
    AttackPattern,
    /// `campaign`.
    Campaign,
    /// `course-of-action`.
    CourseOfAction,
    /// `grouping`.
    Grouping,
    /// `identity`.
    Identity,
    /// `incident`.
    Incident,
    /// `indicator`.
    Indicator,
    /// `infrastructure`.
    Infrastructure,
    /// `intrusion-set`.
    IntrusionSet,
    /// `location`.
    Location,
    /// `malware`.
    Malware,
    /// `malware-analysis`.
    MalwareAnalysis,
    /// `note`.
    Note,
    /// `observed-data`.
    ObservedData,
    /// `opinion`.
    Opinion,
    /// `report`.
    Report,
    /// `threat-actor`.
    ThreatActor,
    /// `tool`.
    Tool,
    /// `vulnerability`.
    Vulnerability,
}

impl SdoKind {
    /// Returns the STIX `type` string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AttackPattern => "attack-pattern",
            Self::Campaign => "campaign",
            Self::CourseOfAction => "course-of-action",
            Self::Grouping => "grouping",
            Self::Identity => "identity",
            Self::Incident => "incident",
            Self::Indicator => "indicator",
            Self::Infrastructure => "infrastructure",
            Self::IntrusionSet => "intrusion-set",
            Self::Location => "location",
            Self::Malware => "malware",
            Self::MalwareAnalysis => "malware-analysis",
            Self::Note => "note",
            Self::ObservedData => "observed-data",
            Self::Opinion => "opinion",
            Self::Report => "report",
            Self::ThreatActor => "threat-actor",
            Self::Tool => "tool",
            Self::Vulnerability => "vulnerability",
        }
    }

    /// Parse from STIX `type` string.
    pub fn from_type_str(value: &str) -> Option<Self> {
        match value {
            "attack-pattern" => Some(Self::AttackPattern),
            "campaign" => Some(Self::Campaign),
            "course-of-action" => Some(Self::CourseOfAction),
            "grouping" => Some(Self::Grouping),
            "identity" => Some(Self::Identity),
            "incident" => Some(Self::Incident),
            "indicator" => Some(Self::Indicator),
            "infrastructure" => Some(Self::Infrastructure),
            "intrusion-set" => Some(Self::IntrusionSet),
            "location" => Some(Self::Location),
            "malware" => Some(Self::Malware),
            "malware-analysis" => Some(Self::MalwareAnalysis),
            "note" => Some(Self::Note),
            "observed-data" => Some(Self::ObservedData),
            "opinion" => Some(Self::Opinion),
            "report" => Some(Self::Report),
            "threat-actor" => Some(Self::ThreatActor),
            "tool" => Some(Self::Tool),
            "vulnerability" => Some(Self::Vulnerability),
            _ => None,
        }
    }
}

/// All STIX Cyber-observable Object discriminants in STIX 2.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScoKind {
    /// `artifact`.
    Artifact,
    /// `autonomous-system`.
    AutonomousSystem,
    /// `directory`.
    Directory,
    /// `domain-name`.
    DomainName,
    /// `email-addr`.
    EmailAddr,
    /// `email-message`.
    EmailMessage,
    /// `file`.
    File,
    /// `ipv4-addr`.
    Ipv4Addr,
    /// `ipv6-addr`.
    Ipv6Addr,
    /// `mac-addr`.
    MacAddr,
    /// `mutex`.
    Mutex,
    /// `network-traffic`.
    NetworkTraffic,
    /// `process`.
    Process,
    /// `software`.
    Software,
    /// `url`.
    Url,
    /// `user-account`.
    UserAccount,
    /// `windows-registry-key`.
    WindowsRegistryKey,
    /// `x509-certificate`.
    X509Certificate,
}

impl ScoKind {
    /// Returns the STIX `type` string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Artifact => "artifact",
            Self::AutonomousSystem => "autonomous-system",
            Self::Directory => "directory",
            Self::DomainName => "domain-name",
            Self::EmailAddr => "email-addr",
            Self::EmailMessage => "email-message",
            Self::File => "file",
            Self::Ipv4Addr => "ipv4-addr",
            Self::Ipv6Addr => "ipv6-addr",
            Self::MacAddr => "mac-addr",
            Self::Mutex => "mutex",
            Self::NetworkTraffic => "network-traffic",
            Self::Process => "process",
            Self::Software => "software",
            Self::Url => "url",
            Self::UserAccount => "user-account",
            Self::WindowsRegistryKey => "windows-registry-key",
            Self::X509Certificate => "x509-certificate",
        }
    }

    /// Parse from STIX `type` string.
    pub fn from_type_str(value: &str) -> Option<Self> {
        match value {
            "artifact" => Some(Self::Artifact),
            "autonomous-system" => Some(Self::AutonomousSystem),
            "directory" => Some(Self::Directory),
            "domain-name" => Some(Self::DomainName),
            "email-addr" => Some(Self::EmailAddr),
            "email-message" => Some(Self::EmailMessage),
            "file" => Some(Self::File),
            "ipv4-addr" => Some(Self::Ipv4Addr),
            "ipv6-addr" => Some(Self::Ipv6Addr),
            "mac-addr" => Some(Self::MacAddr),
            "mutex" => Some(Self::Mutex),
            "network-traffic" => Some(Self::NetworkTraffic),
            "process" => Some(Self::Process),
            "software" => Some(Self::Software),
            "url" => Some(Self::Url),
            "user-account" => Some(Self::UserAccount),
            "windows-registry-key" => Some(Self::WindowsRegistryKey),
            "x509-certificate" => Some(Self::X509Certificate),
            _ => None,
        }
    }
}

/// STIX Relationship Object discriminants in STIX 2.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SroKind {
    /// `relationship`.
    Relationship,
    /// `sighting`.
    Sighting,
}

impl SroKind {
    /// Returns the STIX `type` string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Relationship => "relationship",
            Self::Sighting => "sighting",
        }
    }

    /// Parse from STIX `type` string.
    pub fn from_type_str(value: &str) -> Option<Self> {
        match value {
            "relationship" => Some(Self::Relationship),
            "sighting" => Some(Self::Sighting),
            _ => None,
        }
    }
}

/// STIX Meta object discriminants in STIX 2.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MetaKind {
    /// `marking-definition`.
    MarkingDefinition,
    /// `language-content`.
    LanguageContent,
    /// `extension-definition`.
    ExtensionDefinition,
}

impl MetaKind {
    /// Returns the STIX `type` string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MarkingDefinition => "marking-definition",
            Self::LanguageContent => "language-content",
            Self::ExtensionDefinition => "extension-definition",
        }
    }

    /// Parse from STIX `type` string.
    pub fn from_type_str(value: &str) -> Option<Self> {
        match value {
            "marking-definition" => Some(Self::MarkingDefinition),
            "language-content" => Some(Self::LanguageContent),
            "extension-definition" => Some(Self::ExtensionDefinition),
            _ => None,
        }
    }
}

macro_rules! define_typed_id {
    ($name:ident, $type_name:literal) => {
        #[doc = "Typed ID wrapper for `"]
        #[doc = $type_name]
        #[doc = "` objects."]
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name(StixId);

        impl $name {
            /// Create from a generic `StixId` after validating the type prefix.
            pub fn from_stix_id(id: StixId) -> Result<Self, StixIdError> {
                if id.type_name() == $type_name {
                    Ok(Self(id))
                } else {
                    Err(StixIdError::TypeMismatch {
                        expected: $type_name,
                        found: id.type_name().to_owned(),
                    })
                }
            }

            /// Access the wrapped generic `StixId`.
            pub fn as_stix_id(&self) -> &StixId {
                &self.0
            }
        }

        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let id = <StixId as serde::Deserialize>::deserialize(deserializer)?;
                Self::from_stix_id(id).map_err(serde::de::Error::custom)
            }
        }
    };
}

define_typed_id!(AttackPatternId, "attack-pattern");
define_typed_id!(ArtifactId, "artifact");
define_typed_id!(AutonomousSystemId, "autonomous-system");
define_typed_id!(CampaignId, "campaign");
define_typed_id!(CourseOfActionId, "course-of-action");
define_typed_id!(DirectoryId, "directory");
define_typed_id!(DomainNameId, "domain-name");
define_typed_id!(EmailAddrId, "email-addr");
define_typed_id!(EmailMessageId, "email-message");
define_typed_id!(GroupingId, "grouping");
define_typed_id!(IdentityId, "identity");
define_typed_id!(IncidentId, "incident");
define_typed_id!(IndicatorId, "indicator");
define_typed_id!(InfrastructureId, "infrastructure");
define_typed_id!(IntrusionSetId, "intrusion-set");
define_typed_id!(FileId, "file");
define_typed_id!(Ipv4AddrId, "ipv4-addr");
define_typed_id!(Ipv6AddrId, "ipv6-addr");
define_typed_id!(MacAddrId, "mac-addr");
define_typed_id!(LocationId, "location");
define_typed_id!(MalwareId, "malware");
define_typed_id!(MalwareAnalysisId, "malware-analysis");
define_typed_id!(MutexId, "mutex");
define_typed_id!(NetworkTrafficId, "network-traffic");
define_typed_id!(NoteId, "note");
define_typed_id!(ObservedDataId, "observed-data");
define_typed_id!(OpinionId, "opinion");
define_typed_id!(ProcessId, "process");
define_typed_id!(ReportId, "report");
define_typed_id!(SoftwareId, "software");
define_typed_id!(ThreatActorId, "threat-actor");
define_typed_id!(ToolId, "tool");
define_typed_id!(UrlId, "url");
define_typed_id!(UserAccountId, "user-account");
define_typed_id!(VulnerabilityId, "vulnerability");
define_typed_id!(WindowsRegistryKeyId, "windows-registry-key");
define_typed_id!(X509CertificateId, "x509-certificate");
define_typed_id!(RelationshipId, "relationship");
define_typed_id!(SightingId, "sighting");
define_typed_id!(MarkingDefinitionId, "marking-definition");
define_typed_id!(LanguageContentId, "language-content");
define_typed_id!(ExtensionDefinitionId, "extension-definition");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_stix_id() {
        let id = StixId::parse("attack-pattern--550e8400-e29b-41d4-a716-446655440000")
            .expect("valid id must parse");
        assert_eq!(id.type_name(), "attack-pattern");
        assert_eq!(
            id.uuid(),
            uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid")
        );
        assert_eq!(
            id.as_str(),
            "attack-pattern--550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn rejects_missing_delimiter() {
        let err = StixId::parse("notanid").expect_err("id without delimiter must fail");
        assert_eq!(err, StixIdError::MissingDelimiter);
    }

    #[test]
    fn rejects_empty_type_name() {
        let err = StixId::parse("--550e8400-e29b-41d4-a716-446655440000").expect_err("empty type");
        assert_eq!(err, StixIdError::EmptyTypeName);
    }

    #[test]
    fn rejects_invalid_uuid() {
        let err = StixId::parse("indicator--not-a-uuid").expect_err("invalid uuid");
        assert!(matches!(err, StixIdError::InvalidUuid(_)));
    }

    #[test]
    fn generates_random_id_with_type_prefix() {
        let id = StixId::generate("indicator");
        assert_eq!(id.type_name(), "indicator");
        assert!(!id.uuid().is_nil());
    }

    #[test]
    fn resolves_kind_from_type_string() {
        assert_eq!(
            StixObjectKind::from_type_str("indicator"),
            Some(StixObjectKind::Sdo(SdoKind::Indicator))
        );
        assert_eq!(
            StixObjectKind::from_type_str("file"),
            Some(StixObjectKind::Sco(ScoKind::File))
        );
        assert_eq!(
            StixObjectKind::from_type_str("relationship"),
            Some(StixObjectKind::Sro(SroKind::Relationship))
        );
        assert_eq!(
            StixObjectKind::from_type_str("marking-definition"),
            Some(StixObjectKind::Meta(MetaKind::MarkingDefinition))
        );
        assert_eq!(StixObjectKind::from_type_str("unknown"), None);
    }

    #[test]
    fn typed_id_rejects_wrong_prefix() {
        let malware_id =
            StixId::parse("malware--550e8400-e29b-41d4-a716-446655440000").expect("malware id");
        let err = IndicatorId::from_stix_id(malware_id).expect_err("must reject wrong type");
        assert_eq!(
            err,
            StixIdError::TypeMismatch {
                expected: "indicator",
                found: "malware".to_owned(),
            }
        );
    }

    #[test]
    fn typed_id_accepts_matching_prefix() {
        let indicator_id =
            StixId::parse("indicator--550e8400-e29b-41d4-a716-446655440000").expect("indicator id");
        let typed = IndicatorId::from_stix_id(indicator_id).expect("must accept matching type");
        assert_eq!(
            typed.as_stix_id().as_str(),
            "indicator--550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn stix_id_serde_is_plain_string() {
        let id =
            StixId::parse("indicator--550e8400-e29b-41d4-a716-446655440000").expect("valid id");
        let encoded = serde_json::to_string(&id).expect("serialize");
        assert_eq!(
            encoded,
            "\"indicator--550e8400-e29b-41d4-a716-446655440000\""
        );
        let decoded: StixId = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, id);
        assert!(serde_json::from_str::<StixId>("\"notanid\"").is_err());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn typed_id_serde_validates_prefix() {
        let encoded = "\"indicator--550e8400-e29b-41d4-a716-446655440000\"";
        let decoded: IndicatorId = serde_json::from_str(encoded).expect("deserialize");
        assert_eq!(serde_json::to_string(&decoded).expect("serialize"), encoded);
        assert!(
            serde_json::from_str::<IndicatorId>(
                "\"malware--550e8400-e29b-41d4-a716-446655440000\""
            )
            .is_err()
        );
    }
}
