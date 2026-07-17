//! Preserve [`ModelError`] through serde custom-error boundaries without relying
//! on lossy display-string reverse mapping.

use serde::{Deserialize, Serialize};

use super::ModelError;

/// Prefix embedded in serde custom messages; unlikely to collide with user text.
pub(crate) const TAG: &str = "\u{001e}rstix-model\u{001e}";

/// Owned wire shape for JSON round-trip of [`ModelError`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ModelErrorWire {
    ExternalReferenceMissingSourceName,
    ExternalReferenceMissingDetail,
    GranularMarkingMissingRefAndLang,
    GranularMarkingBothRefAndLang,
    GranularMarkingEmptySelectors,
    ExtensionDefinitionMissingCreatedByRef,
    UnexpectedObjectType {
        expected: String,
        actual: String,
    },
    KillChainPhaseEmptyKillChainName,
    KillChainPhaseEmptyPhaseName,
    IdTypeMismatch {
        id: String,
        expected_type: String,
        actual_type: String,
    },
    ModifiedBeforeCreated,
    MarkingDefinitionCircularRef {
        object_id: String,
    },
    InvalidReferenceKind {
        ref_id: String,
        expected: String,
    },
    SdoLastSeenBeforeFirstSeen,
    LocationMissingGeo,
    LocationLatitudeLongitudePairRequired,
    LocationLatitudeOutOfRange,
    LocationLongitudeOutOfRange,
    LocationPrecisionRequiresCoordinates,
    MalwareAnalysisResultOrScoRefsRequired,
    MalwareSampleRefInvalid,
    MalwareAnalysisSampleRefInvalid,
    RelationshipTypeInvalid,
    RelationshipStopTimeBeforeStartTime,
    SightingCountOutOfRange,
    SightingLastSeenBeforeFirstSeen,
    SightingWhereSightedRefInvalid,
    ExtensionDeserializeFailed {
        key: String,
        detail: String,
    },
    DomainNameResolvesToRefInvalid,
    DirectoryContainsRefInvalid,
    NetworkTrafficEndpointRefInvalid,
    EmailMimeBodyRawRefInvalid,
    ArtifactPayloadXorUrl,
    ArtifactHashesRequiredWhenUrl,
    ArtifactDecryptionKeyWithoutEncryption,
    DirectoryPathEmpty,
    DomainNameValueEmpty,
    EmailAddrValueEmpty,
    EmailMimePartBodyXorRawRef,
    EmailMessageBodyWithMultipart,
    EmailMessageMultipartMissing,
    EmailMessageMultipartWhenSinglePart,
    FileHashesOrNameRequired,
    Ipv4AddrValueEmpty,
    Ipv6AddrValueEmpty,
    MacAddrValueEmpty,
    MutexNameEmpty,
    NetworkTrafficProtocolsRequired,
    NetworkTrafficSrcOrDstRequired,
    NetworkTrafficEndWithActive,
    NetworkTrafficEndBeforeStart,
    ProcessNoProperties,
    SoftwareNameEmpty,
    UrlValueEmpty,
    UserAccountNoProperties,
    WindowsRegistryKeyNoProperties,
    WindowsRegistryValueNoProperties,
    X509CertificateNoProperties,
    X509V3ExtensionsNoProperties,
    ArchiveExtContainsRefsEmpty,
    NtfsExtNoProperties,
    NtfsExtAdsNameEmpty,
    PdfExtNoProperties,
    RasterImageExtNoProperties,
    WindowsPeBinaryExtPeTypeEmpty,
    WindowsPeBinaryExtNoOptionalProperties,
    WindowsPeSectionNameEmpty,
    HttpRequestExtMethodEmpty,
    HttpRequestExtValueEmpty,
    IcmpExtFieldsEmpty,
    SocketExtAddressFamilyEmpty,
    TcpExtNoProperties,
    UnixAccountExtNoProperties,
    WindowsProcessExtNoProperties,
    WindowsServiceExtNoProperties,
    LocationInsufficientProperties,
    LocationLatitudeLongitudePair,
    MalwareFamilyMissingName,
    MalwareAnalysisMissingResultOrScoRefs,
    IndicatorValidUntilBeforeValidFrom,
    ObservedDataObjectsXorObjectRefs,
    ObservedDataMissingScoContent,
    ObservedDataEmptyObjects,
    ObservedDataEmptyObjectRefs,
    ObservedDataLastObservedBeforeFirstObserved,
    ObservedDataNumberObservedOutOfRange,
    OpinionValueInvalid,
    RelationshipEndpointKindInvalid,
    SightingOfRefKindInvalid,
    BundleReferenceMissing {
        ref_id: String,
    },
    RelationshipEndpointMatrixInvalid {
        relationship_type: String,
        source_type: String,
        target_type: String,
    },
    InvalidCapecExternalReference,
    InvalidCveExternalReference,
    MalwareSampleRefsNotSameBinary,
    BundleIdPrefixInvalid,
    BundleSpecVersionNotAllowed,
    LanguageContentLangNotAllowed,
    LanguageContentObjectModifiedMismatch,
    MarkingDefinitionSpecVersionRequired,
    MarkingDefinitionLegacyPayloadRequired,
    ExtensionDefinitionForbiddenCommonProperty {
        property: String,
    },
    ExtensionTypeOnPredefinedExtension {
        key: String,
    },
    DomainNameFormatInvalid,
    EmailAddrFormatInvalid,
    UrlFormatInvalid,
    EncryptionAlgorithmInvalid,
    ScoDeterministicIdMismatch,
    ScoEncWithoutBaseProperty {
        property: String,
    },
    ScoEncInvalidCharset {
        property: String,
    },
    PropertyExtensionDefinitionMissing {
        extension_id: String,
    },
    ScoForbiddenCommonProperty {
        property: String,
    },
    LanguageContentInvalidLanguageCode,
    GranularSelectorSyntaxInvalid {
        selector: String,
    },
}

impl From<&ModelError> for ModelErrorWire {
    fn from(err: &ModelError) -> Self {
        match err {
            ModelError::ExternalReferenceMissingSourceName => {
                Self::ExternalReferenceMissingSourceName
            }
            ModelError::ExternalReferenceMissingDetail => Self::ExternalReferenceMissingDetail,
            ModelError::GranularMarkingMissingRefAndLang => Self::GranularMarkingMissingRefAndLang,
            ModelError::GranularMarkingBothRefAndLang => Self::GranularMarkingBothRefAndLang,
            ModelError::GranularMarkingEmptySelectors => Self::GranularMarkingEmptySelectors,
            ModelError::ExtensionDefinitionMissingCreatedByRef => {
                Self::ExtensionDefinitionMissingCreatedByRef
            }
            ModelError::UnexpectedObjectType { expected, actual } => Self::UnexpectedObjectType {
                expected: (*expected).to_owned(),
                actual: actual.clone(),
            },
            ModelError::KillChainPhaseEmptyKillChainName => Self::KillChainPhaseEmptyKillChainName,
            ModelError::KillChainPhaseEmptyPhaseName => Self::KillChainPhaseEmptyPhaseName,
            ModelError::IdTypeMismatch {
                id,
                expected_type,
                actual_type,
            } => Self::IdTypeMismatch {
                id: id.clone(),
                expected_type: expected_type.clone(),
                actual_type: actual_type.clone(),
            },
            ModelError::ModifiedBeforeCreated => Self::ModifiedBeforeCreated,
            ModelError::MarkingDefinitionCircularRef { object_id } => {
                Self::MarkingDefinitionCircularRef {
                    object_id: object_id.clone(),
                }
            }
            ModelError::InvalidReferenceKind { ref_id, expected } => Self::InvalidReferenceKind {
                ref_id: ref_id.clone(),
                expected: expected.clone(),
            },
            ModelError::SdoLastSeenBeforeFirstSeen => Self::SdoLastSeenBeforeFirstSeen,
            ModelError::LocationMissingGeo => Self::LocationMissingGeo,
            ModelError::LocationLatitudeLongitudePairRequired => {
                Self::LocationLatitudeLongitudePairRequired
            }
            ModelError::LocationLatitudeOutOfRange => Self::LocationLatitudeOutOfRange,
            ModelError::LocationLongitudeOutOfRange => Self::LocationLongitudeOutOfRange,
            ModelError::LocationPrecisionRequiresCoordinates => {
                Self::LocationPrecisionRequiresCoordinates
            }
            ModelError::MalwareAnalysisResultOrScoRefsRequired => {
                Self::MalwareAnalysisResultOrScoRefsRequired
            }
            ModelError::MalwareSampleRefInvalid => Self::MalwareSampleRefInvalid,
            ModelError::MalwareAnalysisSampleRefInvalid => Self::MalwareAnalysisSampleRefInvalid,
            ModelError::RelationshipTypeInvalid => Self::RelationshipTypeInvalid,
            ModelError::RelationshipStopTimeBeforeStartTime => {
                Self::RelationshipStopTimeBeforeStartTime
            }
            ModelError::SightingCountOutOfRange => Self::SightingCountOutOfRange,
            ModelError::SightingLastSeenBeforeFirstSeen => Self::SightingLastSeenBeforeFirstSeen,
            ModelError::SightingWhereSightedRefInvalid => Self::SightingWhereSightedRefInvalid,
            ModelError::ExtensionDeserializeFailed { key, detail } => {
                Self::ExtensionDeserializeFailed {
                    key: (*key).to_owned(),
                    detail: detail.clone(),
                }
            }
            ModelError::DomainNameResolvesToRefInvalid => Self::DomainNameResolvesToRefInvalid,
            ModelError::DirectoryContainsRefInvalid => Self::DirectoryContainsRefInvalid,
            ModelError::NetworkTrafficEndpointRefInvalid => Self::NetworkTrafficEndpointRefInvalid,
            ModelError::EmailMimeBodyRawRefInvalid => Self::EmailMimeBodyRawRefInvalid,
            ModelError::ArtifactPayloadXorUrl => Self::ArtifactPayloadXorUrl,
            ModelError::ArtifactHashesRequiredWhenUrl => Self::ArtifactHashesRequiredWhenUrl,
            ModelError::ArtifactDecryptionKeyWithoutEncryption => {
                Self::ArtifactDecryptionKeyWithoutEncryption
            }
            ModelError::DirectoryPathEmpty => Self::DirectoryPathEmpty,
            ModelError::DomainNameValueEmpty => Self::DomainNameValueEmpty,
            ModelError::EmailAddrValueEmpty => Self::EmailAddrValueEmpty,
            ModelError::EmailMimePartBodyXorRawRef => Self::EmailMimePartBodyXorRawRef,
            ModelError::EmailMessageBodyWithMultipart => Self::EmailMessageBodyWithMultipart,
            ModelError::EmailMessageMultipartMissing => Self::EmailMessageMultipartMissing,
            ModelError::EmailMessageMultipartWhenSinglePart => {
                Self::EmailMessageMultipartWhenSinglePart
            }
            ModelError::FileHashesOrNameRequired => Self::FileHashesOrNameRequired,
            ModelError::Ipv4AddrValueEmpty => Self::Ipv4AddrValueEmpty,
            ModelError::Ipv6AddrValueEmpty => Self::Ipv6AddrValueEmpty,
            ModelError::MacAddrValueEmpty => Self::MacAddrValueEmpty,
            ModelError::MutexNameEmpty => Self::MutexNameEmpty,
            ModelError::NetworkTrafficProtocolsRequired => Self::NetworkTrafficProtocolsRequired,
            ModelError::NetworkTrafficSrcOrDstRequired => Self::NetworkTrafficSrcOrDstRequired,
            ModelError::NetworkTrafficEndWithActive => Self::NetworkTrafficEndWithActive,
            ModelError::NetworkTrafficEndBeforeStart => Self::NetworkTrafficEndBeforeStart,
            ModelError::ProcessNoProperties => Self::ProcessNoProperties,
            ModelError::SoftwareNameEmpty => Self::SoftwareNameEmpty,
            ModelError::UrlValueEmpty => Self::UrlValueEmpty,
            ModelError::UserAccountNoProperties => Self::UserAccountNoProperties,
            ModelError::WindowsRegistryKeyNoProperties => Self::WindowsRegistryKeyNoProperties,
            ModelError::WindowsRegistryValueNoProperties => Self::WindowsRegistryValueNoProperties,
            ModelError::X509CertificateNoProperties => Self::X509CertificateNoProperties,
            ModelError::X509V3ExtensionsNoProperties => Self::X509V3ExtensionsNoProperties,
            ModelError::ArchiveExtContainsRefsEmpty => Self::ArchiveExtContainsRefsEmpty,
            ModelError::NtfsExtNoProperties => Self::NtfsExtNoProperties,
            ModelError::NtfsExtAdsNameEmpty => Self::NtfsExtAdsNameEmpty,
            ModelError::PdfExtNoProperties => Self::PdfExtNoProperties,
            ModelError::RasterImageExtNoProperties => Self::RasterImageExtNoProperties,
            ModelError::WindowsPeBinaryExtPeTypeEmpty => Self::WindowsPeBinaryExtPeTypeEmpty,
            ModelError::WindowsPeBinaryExtNoOptionalProperties => {
                Self::WindowsPeBinaryExtNoOptionalProperties
            }
            ModelError::WindowsPeSectionNameEmpty => Self::WindowsPeSectionNameEmpty,
            ModelError::HttpRequestExtMethodEmpty => Self::HttpRequestExtMethodEmpty,
            ModelError::HttpRequestExtValueEmpty => Self::HttpRequestExtValueEmpty,
            ModelError::IcmpExtFieldsEmpty => Self::IcmpExtFieldsEmpty,
            ModelError::SocketExtAddressFamilyEmpty => Self::SocketExtAddressFamilyEmpty,
            ModelError::TcpExtNoProperties => Self::TcpExtNoProperties,
            ModelError::UnixAccountExtNoProperties => Self::UnixAccountExtNoProperties,
            ModelError::WindowsProcessExtNoProperties => Self::WindowsProcessExtNoProperties,
            ModelError::WindowsServiceExtNoProperties => Self::WindowsServiceExtNoProperties,
            ModelError::LocationInsufficientProperties => Self::LocationInsufficientProperties,
            ModelError::LocationLatitudeLongitudePair => Self::LocationLatitudeLongitudePair,
            ModelError::MalwareFamilyMissingName => Self::MalwareFamilyMissingName,
            ModelError::MalwareAnalysisMissingResultOrScoRefs => {
                Self::MalwareAnalysisMissingResultOrScoRefs
            }
            ModelError::IndicatorValidUntilBeforeValidFrom => {
                Self::IndicatorValidUntilBeforeValidFrom
            }
            ModelError::ObservedDataObjectsXorObjectRefs => Self::ObservedDataObjectsXorObjectRefs,
            ModelError::ObservedDataMissingScoContent => Self::ObservedDataMissingScoContent,
            ModelError::ObservedDataEmptyObjects => Self::ObservedDataEmptyObjects,
            ModelError::ObservedDataEmptyObjectRefs => Self::ObservedDataEmptyObjectRefs,
            ModelError::ObservedDataLastObservedBeforeFirstObserved => {
                Self::ObservedDataLastObservedBeforeFirstObserved
            }
            ModelError::ObservedDataNumberObservedOutOfRange => {
                Self::ObservedDataNumberObservedOutOfRange
            }
            ModelError::OpinionValueInvalid => Self::OpinionValueInvalid,
            ModelError::RelationshipEndpointKindInvalid => Self::RelationshipEndpointKindInvalid,
            ModelError::SightingOfRefKindInvalid => Self::SightingOfRefKindInvalid,
            ModelError::BundleReferenceMissing { ref_id } => Self::BundleReferenceMissing {
                ref_id: ref_id.clone(),
            },
            ModelError::RelationshipEndpointMatrixInvalid {
                relationship_type,
                source_type,
                target_type,
            } => Self::RelationshipEndpointMatrixInvalid {
                relationship_type: relationship_type.clone(),
                source_type: source_type.clone(),
                target_type: target_type.clone(),
            },
            ModelError::InvalidCapecExternalReference => Self::InvalidCapecExternalReference,
            ModelError::InvalidCveExternalReference => Self::InvalidCveExternalReference,
            ModelError::MalwareSampleRefsNotSameBinary => Self::MalwareSampleRefsNotSameBinary,
            ModelError::BundleIdPrefixInvalid => Self::BundleIdPrefixInvalid,
            ModelError::BundleSpecVersionNotAllowed => Self::BundleSpecVersionNotAllowed,
            ModelError::LanguageContentLangNotAllowed => Self::LanguageContentLangNotAllowed,
            ModelError::LanguageContentObjectModifiedMismatch => {
                Self::LanguageContentObjectModifiedMismatch
            }
            ModelError::MarkingDefinitionSpecVersionRequired => {
                Self::MarkingDefinitionSpecVersionRequired
            }
            ModelError::MarkingDefinitionLegacyPayloadRequired => {
                Self::MarkingDefinitionLegacyPayloadRequired
            }
            ModelError::ExtensionDefinitionForbiddenCommonProperty { property } => {
                Self::ExtensionDefinitionForbiddenCommonProperty {
                    property: property.clone(),
                }
            }
            ModelError::ExtensionTypeOnPredefinedExtension { key } => {
                Self::ExtensionTypeOnPredefinedExtension { key: key.clone() }
            }
            ModelError::DomainNameFormatInvalid => Self::DomainNameFormatInvalid,
            ModelError::EmailAddrFormatInvalid => Self::EmailAddrFormatInvalid,
            ModelError::UrlFormatInvalid => Self::UrlFormatInvalid,
            ModelError::EncryptionAlgorithmInvalid => Self::EncryptionAlgorithmInvalid,
            ModelError::ScoDeterministicIdMismatch => Self::ScoDeterministicIdMismatch,
            ModelError::ScoEncWithoutBaseProperty { property } => Self::ScoEncWithoutBaseProperty {
                property: property.clone(),
            },
            ModelError::ScoEncInvalidCharset { property } => Self::ScoEncInvalidCharset {
                property: property.clone(),
            },
            ModelError::PropertyExtensionDefinitionMissing { extension_id } => {
                Self::PropertyExtensionDefinitionMissing {
                    extension_id: extension_id.clone(),
                }
            }
            ModelError::ScoForbiddenCommonProperty { property } => {
                Self::ScoForbiddenCommonProperty {
                    property: property.clone(),
                }
            }
            ModelError::LanguageContentInvalidLanguageCode => {
                Self::LanguageContentInvalidLanguageCode
            }
            ModelError::GranularSelectorSyntaxInvalid { selector } => {
                Self::GranularSelectorSyntaxInvalid {
                    selector: selector.clone(),
                }
            }
        }
    }
}

impl From<ModelErrorWire> for ModelError {
    fn from(wire: ModelErrorWire) -> Self {
        match wire {
            ModelErrorWire::ExternalReferenceMissingSourceName => {
                Self::ExternalReferenceMissingSourceName
            }
            ModelErrorWire::ExternalReferenceMissingDetail => Self::ExternalReferenceMissingDetail,
            ModelErrorWire::GranularMarkingMissingRefAndLang => {
                Self::GranularMarkingMissingRefAndLang
            }
            ModelErrorWire::GranularMarkingBothRefAndLang => Self::GranularMarkingBothRefAndLang,
            ModelErrorWire::GranularMarkingEmptySelectors => Self::GranularMarkingEmptySelectors,
            ModelErrorWire::ExtensionDefinitionMissingCreatedByRef => {
                Self::ExtensionDefinitionMissingCreatedByRef
            }
            ModelErrorWire::UnexpectedObjectType { expected, actual } => {
                Self::UnexpectedObjectType {
                    expected: Box::leak(expected.into_boxed_str()),
                    actual,
                }
            }
            ModelErrorWire::KillChainPhaseEmptyKillChainName => {
                Self::KillChainPhaseEmptyKillChainName
            }
            ModelErrorWire::KillChainPhaseEmptyPhaseName => Self::KillChainPhaseEmptyPhaseName,
            ModelErrorWire::IdTypeMismatch {
                id,
                expected_type,
                actual_type,
            } => Self::IdTypeMismatch {
                id,
                expected_type,
                actual_type,
            },
            ModelErrorWire::ModifiedBeforeCreated => Self::ModifiedBeforeCreated,
            ModelErrorWire::MarkingDefinitionCircularRef { object_id } => {
                Self::MarkingDefinitionCircularRef { object_id }
            }
            ModelErrorWire::InvalidReferenceKind { ref_id, expected } => {
                Self::InvalidReferenceKind { ref_id, expected }
            }
            ModelErrorWire::SdoLastSeenBeforeFirstSeen => Self::SdoLastSeenBeforeFirstSeen,
            ModelErrorWire::LocationMissingGeo => Self::LocationMissingGeo,
            ModelErrorWire::LocationLatitudeLongitudePairRequired => {
                Self::LocationLatitudeLongitudePairRequired
            }
            ModelErrorWire::LocationLatitudeOutOfRange => Self::LocationLatitudeOutOfRange,
            ModelErrorWire::LocationLongitudeOutOfRange => Self::LocationLongitudeOutOfRange,
            ModelErrorWire::LocationPrecisionRequiresCoordinates => {
                Self::LocationPrecisionRequiresCoordinates
            }
            ModelErrorWire::MalwareAnalysisResultOrScoRefsRequired => {
                Self::MalwareAnalysisResultOrScoRefsRequired
            }
            ModelErrorWire::MalwareSampleRefInvalid => Self::MalwareSampleRefInvalid,
            ModelErrorWire::MalwareAnalysisSampleRefInvalid => {
                Self::MalwareAnalysisSampleRefInvalid
            }
            ModelErrorWire::RelationshipTypeInvalid => Self::RelationshipTypeInvalid,
            ModelErrorWire::RelationshipStopTimeBeforeStartTime => {
                Self::RelationshipStopTimeBeforeStartTime
            }
            ModelErrorWire::SightingCountOutOfRange => Self::SightingCountOutOfRange,
            ModelErrorWire::SightingLastSeenBeforeFirstSeen => {
                Self::SightingLastSeenBeforeFirstSeen
            }
            ModelErrorWire::SightingWhereSightedRefInvalid => Self::SightingWhereSightedRefInvalid,
            ModelErrorWire::ExtensionDeserializeFailed { key, detail } => {
                Self::ExtensionDeserializeFailed {
                    key: Box::leak(key.into_boxed_str()),
                    detail,
                }
            }
            ModelErrorWire::DomainNameResolvesToRefInvalid => Self::DomainNameResolvesToRefInvalid,
            ModelErrorWire::DirectoryContainsRefInvalid => Self::DirectoryContainsRefInvalid,
            ModelErrorWire::NetworkTrafficEndpointRefInvalid => {
                Self::NetworkTrafficEndpointRefInvalid
            }
            ModelErrorWire::EmailMimeBodyRawRefInvalid => Self::EmailMimeBodyRawRefInvalid,
            ModelErrorWire::ArtifactPayloadXorUrl => Self::ArtifactPayloadXorUrl,
            ModelErrorWire::ArtifactHashesRequiredWhenUrl => Self::ArtifactHashesRequiredWhenUrl,
            ModelErrorWire::ArtifactDecryptionKeyWithoutEncryption => {
                Self::ArtifactDecryptionKeyWithoutEncryption
            }
            ModelErrorWire::DirectoryPathEmpty => Self::DirectoryPathEmpty,
            ModelErrorWire::DomainNameValueEmpty => Self::DomainNameValueEmpty,
            ModelErrorWire::EmailAddrValueEmpty => Self::EmailAddrValueEmpty,
            ModelErrorWire::EmailMimePartBodyXorRawRef => Self::EmailMimePartBodyXorRawRef,
            ModelErrorWire::EmailMessageBodyWithMultipart => Self::EmailMessageBodyWithMultipart,
            ModelErrorWire::EmailMessageMultipartMissing => Self::EmailMessageMultipartMissing,
            ModelErrorWire::EmailMessageMultipartWhenSinglePart => {
                Self::EmailMessageMultipartWhenSinglePart
            }
            ModelErrorWire::FileHashesOrNameRequired => Self::FileHashesOrNameRequired,
            ModelErrorWire::Ipv4AddrValueEmpty => Self::Ipv4AddrValueEmpty,
            ModelErrorWire::Ipv6AddrValueEmpty => Self::Ipv6AddrValueEmpty,
            ModelErrorWire::MacAddrValueEmpty => Self::MacAddrValueEmpty,
            ModelErrorWire::MutexNameEmpty => Self::MutexNameEmpty,
            ModelErrorWire::NetworkTrafficProtocolsRequired => {
                Self::NetworkTrafficProtocolsRequired
            }
            ModelErrorWire::NetworkTrafficSrcOrDstRequired => Self::NetworkTrafficSrcOrDstRequired,
            ModelErrorWire::NetworkTrafficEndWithActive => Self::NetworkTrafficEndWithActive,
            ModelErrorWire::NetworkTrafficEndBeforeStart => Self::NetworkTrafficEndBeforeStart,
            ModelErrorWire::ProcessNoProperties => Self::ProcessNoProperties,
            ModelErrorWire::SoftwareNameEmpty => Self::SoftwareNameEmpty,
            ModelErrorWire::UrlValueEmpty => Self::UrlValueEmpty,
            ModelErrorWire::UserAccountNoProperties => Self::UserAccountNoProperties,
            ModelErrorWire::WindowsRegistryKeyNoProperties => Self::WindowsRegistryKeyNoProperties,
            ModelErrorWire::WindowsRegistryValueNoProperties => {
                Self::WindowsRegistryValueNoProperties
            }
            ModelErrorWire::X509CertificateNoProperties => Self::X509CertificateNoProperties,
            ModelErrorWire::X509V3ExtensionsNoProperties => Self::X509V3ExtensionsNoProperties,
            ModelErrorWire::ArchiveExtContainsRefsEmpty => Self::ArchiveExtContainsRefsEmpty,
            ModelErrorWire::NtfsExtNoProperties => Self::NtfsExtNoProperties,
            ModelErrorWire::NtfsExtAdsNameEmpty => Self::NtfsExtAdsNameEmpty,
            ModelErrorWire::PdfExtNoProperties => Self::PdfExtNoProperties,
            ModelErrorWire::RasterImageExtNoProperties => Self::RasterImageExtNoProperties,
            ModelErrorWire::WindowsPeBinaryExtPeTypeEmpty => Self::WindowsPeBinaryExtPeTypeEmpty,
            ModelErrorWire::WindowsPeBinaryExtNoOptionalProperties => {
                Self::WindowsPeBinaryExtNoOptionalProperties
            }
            ModelErrorWire::WindowsPeSectionNameEmpty => Self::WindowsPeSectionNameEmpty,
            ModelErrorWire::HttpRequestExtMethodEmpty => Self::HttpRequestExtMethodEmpty,
            ModelErrorWire::HttpRequestExtValueEmpty => Self::HttpRequestExtValueEmpty,
            ModelErrorWire::IcmpExtFieldsEmpty => Self::IcmpExtFieldsEmpty,
            ModelErrorWire::SocketExtAddressFamilyEmpty => Self::SocketExtAddressFamilyEmpty,
            ModelErrorWire::TcpExtNoProperties => Self::TcpExtNoProperties,
            ModelErrorWire::UnixAccountExtNoProperties => Self::UnixAccountExtNoProperties,
            ModelErrorWire::WindowsProcessExtNoProperties => Self::WindowsProcessExtNoProperties,
            ModelErrorWire::WindowsServiceExtNoProperties => Self::WindowsServiceExtNoProperties,
            ModelErrorWire::LocationInsufficientProperties => Self::LocationInsufficientProperties,
            ModelErrorWire::LocationLatitudeLongitudePair => Self::LocationLatitudeLongitudePair,
            ModelErrorWire::MalwareFamilyMissingName => Self::MalwareFamilyMissingName,
            ModelErrorWire::MalwareAnalysisMissingResultOrScoRefs => {
                Self::MalwareAnalysisMissingResultOrScoRefs
            }
            ModelErrorWire::IndicatorValidUntilBeforeValidFrom => {
                Self::IndicatorValidUntilBeforeValidFrom
            }
            ModelErrorWire::ObservedDataObjectsXorObjectRefs => {
                Self::ObservedDataObjectsXorObjectRefs
            }
            ModelErrorWire::ObservedDataMissingScoContent => Self::ObservedDataMissingScoContent,
            ModelErrorWire::ObservedDataEmptyObjects => Self::ObservedDataEmptyObjects,
            ModelErrorWire::ObservedDataEmptyObjectRefs => Self::ObservedDataEmptyObjectRefs,
            ModelErrorWire::ObservedDataLastObservedBeforeFirstObserved => {
                Self::ObservedDataLastObservedBeforeFirstObserved
            }
            ModelErrorWire::ObservedDataNumberObservedOutOfRange => {
                Self::ObservedDataNumberObservedOutOfRange
            }
            ModelErrorWire::OpinionValueInvalid => Self::OpinionValueInvalid,
            ModelErrorWire::RelationshipEndpointKindInvalid => {
                Self::RelationshipEndpointKindInvalid
            }
            ModelErrorWire::SightingOfRefKindInvalid => Self::SightingOfRefKindInvalid,
            ModelErrorWire::BundleReferenceMissing { ref_id } => {
                Self::BundleReferenceMissing { ref_id }
            }
            ModelErrorWire::RelationshipEndpointMatrixInvalid {
                relationship_type,
                source_type,
                target_type,
            } => Self::RelationshipEndpointMatrixInvalid {
                relationship_type,
                source_type,
                target_type,
            },
            ModelErrorWire::InvalidCapecExternalReference => Self::InvalidCapecExternalReference,
            ModelErrorWire::InvalidCveExternalReference => Self::InvalidCveExternalReference,
            ModelErrorWire::MalwareSampleRefsNotSameBinary => Self::MalwareSampleRefsNotSameBinary,
            ModelErrorWire::BundleIdPrefixInvalid => Self::BundleIdPrefixInvalid,
            ModelErrorWire::BundleSpecVersionNotAllowed => Self::BundleSpecVersionNotAllowed,
            ModelErrorWire::LanguageContentLangNotAllowed => Self::LanguageContentLangNotAllowed,
            ModelErrorWire::LanguageContentObjectModifiedMismatch => {
                Self::LanguageContentObjectModifiedMismatch
            }
            ModelErrorWire::MarkingDefinitionSpecVersionRequired => {
                Self::MarkingDefinitionSpecVersionRequired
            }
            ModelErrorWire::MarkingDefinitionLegacyPayloadRequired => {
                Self::MarkingDefinitionLegacyPayloadRequired
            }
            ModelErrorWire::ExtensionDefinitionForbiddenCommonProperty { property } => {
                Self::ExtensionDefinitionForbiddenCommonProperty { property }
            }
            ModelErrorWire::ExtensionTypeOnPredefinedExtension { key } => {
                Self::ExtensionTypeOnPredefinedExtension { key }
            }
            ModelErrorWire::DomainNameFormatInvalid => Self::DomainNameFormatInvalid,
            ModelErrorWire::EmailAddrFormatInvalid => Self::EmailAddrFormatInvalid,
            ModelErrorWire::UrlFormatInvalid => Self::UrlFormatInvalid,
            ModelErrorWire::EncryptionAlgorithmInvalid => Self::EncryptionAlgorithmInvalid,
            ModelErrorWire::ScoDeterministicIdMismatch => Self::ScoDeterministicIdMismatch,
            ModelErrorWire::ScoEncWithoutBaseProperty { property } => {
                Self::ScoEncWithoutBaseProperty {
                    property: property.clone(),
                }
            }
            ModelErrorWire::ScoEncInvalidCharset { property } => Self::ScoEncInvalidCharset {
                property: property.clone(),
            },
            ModelErrorWire::PropertyExtensionDefinitionMissing { extension_id } => {
                Self::PropertyExtensionDefinitionMissing { extension_id }
            }
            ModelErrorWire::ScoForbiddenCommonProperty { property } => {
                Self::ScoForbiddenCommonProperty { property }
            }
            ModelErrorWire::LanguageContentInvalidLanguageCode => {
                Self::LanguageContentInvalidLanguageCode
            }
            ModelErrorWire::GranularSelectorSyntaxInvalid { selector } => {
                Self::GranularSelectorSyntaxInvalid { selector }
            }
        }
    }
}

/// Encode a model error for embedding in a serde custom message.
///
/// Wire format is `{TAG}{payload}{TAG}{display}` so decode never scans attacker-controlled
/// display text for the delimiter (see `decode_from_serde`).
pub(crate) fn encode_for_serde(err: &ModelError) -> String {
    let payload = serde_json::to_string(&ModelErrorWire::from(err)).expect("model error wire json");
    format!("{TAG}{payload}{TAG}{err}")
}

/// Decode a model error from a serde custom message, if tagged.
pub(crate) fn decode_from_serde(message: &str) -> Option<ModelError> {
    let rest = message.strip_prefix(TAG)?;
    let json_end = rest.find(TAG)?;
    let json = &rest[..json_end];
    serde_json::from_str::<ModelErrorWire>(json)
        .ok()
        .map(Into::into)
}

/// Map a model validation failure into a serde deserialize error that round-trips.
pub(crate) fn model_de_custom<E: serde::de::Error>(err: ModelError) -> E {
    E::custom(encode_for_serde(&err))
}

impl ModelError {
    /// Map this model error into a serde deserialize error that round-trips.
    pub(crate) fn into_de_custom<E: serde::de::Error>(self) -> E {
        model_de_custom(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_roundtrip_preserves_human_readable_display_suffix() {
        let err = ModelError::UnexpectedObjectType {
            expected: "indicator",
            actual: "malware".into(),
        };
        let message = encode_for_serde(&err);
        assert!(message.contains("expected STIX type `indicator`, got `malware`"));
        let recovered = decode_from_serde(&message).expect("decode");
        assert_eq!(recovered, err);
    }

    #[test]
    fn decode_ignores_tag_sequence_embedded_in_display_fields() {
        let forged_payload =
            serde_json::to_string(&ModelErrorWire::OpinionValueInvalid).expect("wire json");
        let malicious_err = ModelError::ExtensionDeserializeFailed {
            key: "test-ext",
            detail: format!("detail{TAG}{forged_payload}"),
        };
        let message = encode_for_serde(&malicious_err);
        let recovered = decode_from_serde(&message).expect("decode");
        assert_eq!(recovered, malicious_err);
        assert!(!matches!(recovered, ModelError::OpinionValueInvalid));
    }

    #[test]
    fn tagged_roundtrip_recovers_unexpected_object_type() {
        let err = ModelError::UnexpectedObjectType {
            expected: "indicator",
            actual: "malware".into(),
        };
        let message = encode_for_serde(&err);
        let recovered = decode_from_serde(&message).expect("decode");
        assert_eq!(recovered, err);
    }

    #[test]
    fn tagged_roundtrip_recovers_extension_deserialize_failed() {
        let err = ModelError::ExtensionDeserializeFailed {
            key: "archive-ext",
            detail: "missing field".into(),
        };
        let message = encode_for_serde(&err);
        let recovered = decode_from_serde(&message).expect("decode");
        assert_eq!(recovered, err);
    }
}
