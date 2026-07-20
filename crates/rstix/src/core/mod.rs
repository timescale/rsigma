//! Core STIX primitives (typed ids, timestamps, confidence, language tags).
//!
//! Includes [`TaxiiTimestamp`](crate::core::TaxiiTimestamp) for RFC 3339 wire
//! normalization; this crate does not implement a TAXII client.

mod confidence;
mod error;
mod id;
mod lang;
mod spec_version;
mod timestamp;
mod traits;

pub use confidence::{
    AdmiraltyScale, Confidence, ConfidenceScale, DniScale, MispScale, NiLScale, WepScale,
    ZeroToTenScale,
};
pub use error::{ConfidenceError, LanguageTagError, StixIdError, TimestampError};
pub use id::{
    ArtifactId, AttackPatternId, AutonomousSystemId, CampaignId, CourseOfActionId, DirectoryId,
    DomainNameId, EmailAddrId, EmailMessageId, ExtensionDefinitionId, FileId, GroupingId,
    IdentityId, IncidentId, IndicatorId, InfrastructureId, IntrusionSetId, Ipv4AddrId, Ipv6AddrId,
    LanguageContentId, LocationId, MacAddrId, MalwareAnalysisId, MalwareId, MarkingDefinitionId,
    MetaKind, MutexId, NetworkTrafficId, NoteId, ObservedDataId, OpinionId, ProcessId,
    RelationshipId, ReportId, ScoKind, SdoKind, SightingId, SoftwareId, SroKind, StixId,
    StixObjectKind, ThreatActorId, ToolId, UrlId, UserAccountId, VulnerabilityId,
    WindowsRegistryKeyId, X509CertificateId,
};
pub use lang::LanguageTag;
pub use spec_version::SpecVersion;
pub use timestamp::{StixTimestamp, TaxiiTimestamp};
pub use traits::{QueryValue, QueryableStixObject};
