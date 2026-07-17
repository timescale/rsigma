//! Map [`crate::model::ModelError`] variants to pipeline [`DiagnosticCode`]s.

use crate::model::ModelError;

use super::diagnostic::DiagnosticCode;

/// Structured pipeline code and default property path for a model error.
pub(crate) fn model_error_pipeline_mapping(
    err: &ModelError,
) -> (DiagnosticCode, Option<&'static str>) {
    match err {
        ModelError::ExternalReferenceMissingSourceName => {
            (DiagnosticCode::E0003, Some("source_name"))
        }
        ModelError::ExternalReferenceMissingDetail => {
            (DiagnosticCode::E0003, Some("external_references"))
        }
        ModelError::ExtensionDefinitionMissingCreatedByRef => {
            (DiagnosticCode::E0005, Some("created_by_ref"))
        }
        ModelError::UnexpectedObjectType { .. } => (DiagnosticCode::E0002, Some("type")),
        ModelError::ObservedDataObjectsXorObjectRefs => (DiagnosticCode::E0007, Some("objects")),
        ModelError::ObservedDataMissingScoContent => (DiagnosticCode::E0008, Some("object_refs")),
        ModelError::ObservedDataEmptyObjects => (DiagnosticCode::E0008, Some("objects")),
        ModelError::ObservedDataEmptyObjectRefs => (DiagnosticCode::E0008, Some("object_refs")),
        ModelError::EmailMessageBodyWithMultipart
        | ModelError::EmailMessageMultipartMissing
        | ModelError::EmailMessageMultipartWhenSinglePart => (DiagnosticCode::E0009, Some("body")),
        ModelError::EmailMimePartBodyXorRawRef => (DiagnosticCode::E0009, Some("body_multipart")),
        ModelError::MalwareFamilyMissingName => (DiagnosticCode::E0004, Some("name")),
        ModelError::GranularMarkingMissingRefAndLang => (DiagnosticCode::E0040, None),
        ModelError::GranularMarkingBothRefAndLang => (DiagnosticCode::E0041, None),
        ModelError::GranularMarkingEmptySelectors => (DiagnosticCode::E0024, Some("selectors")),
        ModelError::GranularSelectorSyntaxInvalid { .. } => {
            (DiagnosticCode::E0024, Some("selectors"))
        }
        ModelError::IdTypeMismatch { .. } | ModelError::BundleIdPrefixInvalid => {
            (DiagnosticCode::E0003, Some("id"))
        }
        ModelError::ModifiedBeforeCreated
        | ModelError::SdoLastSeenBeforeFirstSeen
        | ModelError::SightingLastSeenBeforeFirstSeen
        | ModelError::ObservedDataLastObservedBeforeFirstObserved
        | ModelError::RelationshipStopTimeBeforeStartTime
        | ModelError::NetworkTrafficEndBeforeStart
        | ModelError::IndicatorValidUntilBeforeValidFrom => (DiagnosticCode::E0015, None),
        ModelError::OpinionValueInvalid | ModelError::EncryptionAlgorithmInvalid => {
            (DiagnosticCode::E0013, None)
        }
        ModelError::DomainNameFormatInvalid
        | ModelError::EmailAddrFormatInvalid
        | ModelError::UrlFormatInvalid
        | ModelError::LocationLatitudeOutOfRange
        | ModelError::LocationLongitudeOutOfRange
        | ModelError::RelationshipTypeInvalid => (DiagnosticCode::I0002, Some("relationship_type")),
        ModelError::SightingCountOutOfRange
        | ModelError::ObservedDataNumberObservedOutOfRange
        | ModelError::LanguageContentInvalidLanguageCode => (DiagnosticCode::E0013, None),
        ModelError::SightingOfRefKindInvalid => (DiagnosticCode::E0020, Some("sighting_of_ref")),
        ModelError::InvalidReferenceKind { .. }
        | ModelError::RelationshipEndpointKindInvalid
        | ModelError::MalwareSampleRefInvalid
        | ModelError::MalwareAnalysisSampleRefInvalid
        | ModelError::DomainNameResolvesToRefInvalid
        | ModelError::DirectoryContainsRefInvalid
        | ModelError::NetworkTrafficEndpointRefInvalid
        | ModelError::EmailMimeBodyRawRefInvalid
        | ModelError::SightingWhereSightedRefInvalid
        | ModelError::MalwareSampleRefsNotSameBinary => (DiagnosticCode::E0021, None),
        ModelError::MarkingDefinitionCircularRef { .. } => {
            (DiagnosticCode::E0022, Some("object_marking_refs"))
        }
        ModelError::BundleReferenceMissing { .. } => (DiagnosticCode::W0010, None),
        ModelError::PropertyExtensionDefinitionMissing { .. } => (DiagnosticCode::E0030, None),
        ModelError::ExtensionDeserializeFailed { .. }
        | ModelError::ExtensionDefinitionForbiddenCommonProperty { .. }
        | ModelError::ExtensionTypeOnPredefinedExtension { .. } => (DiagnosticCode::E0030, None),
        ModelError::ScoDeterministicIdMismatch => (DiagnosticCode::W0002, Some("id")),
        ModelError::ScoEncWithoutBaseProperty { .. } => (DiagnosticCode::E0003, None),
        ModelError::ScoEncInvalidCharset { .. } => (DiagnosticCode::E0013, None),
        ModelError::ScoForbiddenCommonProperty { .. } => (DiagnosticCode::W0040, None),
        ModelError::RelationshipEndpointMatrixInvalid { .. } => (DiagnosticCode::I0002, None),
        ModelError::InvalidCapecExternalReference | ModelError::InvalidCveExternalReference => {
            (DiagnosticCode::W0010, Some("external_references"))
        }
        ModelError::LanguageContentObjectModifiedMismatch => {
            (DiagnosticCode::E0024, Some("object_modified"))
        }
        ModelError::LanguageContentLangNotAllowed => (DiagnosticCode::E0003, Some("lang")),
        ModelError::KillChainPhaseEmptyKillChainName => {
            (DiagnosticCode::E0003, Some("kill_chain_name"))
        }
        ModelError::KillChainPhaseEmptyPhaseName => (DiagnosticCode::E0003, Some("phase_name")),
        ModelError::LocationMissingGeo
        | ModelError::LocationInsufficientProperties
        | ModelError::LocationLatitudeLongitudePairRequired
        | ModelError::LocationLatitudeLongitudePair
        | ModelError::LocationPrecisionRequiresCoordinates => (DiagnosticCode::E0003, None),
        ModelError::MalwareAnalysisResultOrScoRefsRequired
        | ModelError::MalwareAnalysisMissingResultOrScoRefs => (DiagnosticCode::E0003, None),
        ModelError::ArtifactPayloadXorUrl => (DiagnosticCode::E0007, None),
        ModelError::ArtifactHashesRequiredWhenUrl => (DiagnosticCode::E0003, Some("hashes")),
        ModelError::ArtifactDecryptionKeyWithoutEncryption => {
            (DiagnosticCode::E0003, Some("encryption_algorithm"))
        }
        ModelError::DirectoryPathEmpty => (DiagnosticCode::E0003, Some("path")),
        ModelError::DomainNameValueEmpty => (DiagnosticCode::E0003, Some("value")),
        ModelError::EmailAddrValueEmpty => (DiagnosticCode::E0003, Some("value")),
        ModelError::UrlValueEmpty => (DiagnosticCode::E0003, Some("value")),
        ModelError::FileHashesOrNameRequired => (DiagnosticCode::E0003, None),
        ModelError::Ipv4AddrValueEmpty
        | ModelError::Ipv6AddrValueEmpty
        | ModelError::MacAddrValueEmpty => (DiagnosticCode::E0003, Some("value")),
        ModelError::MutexNameEmpty | ModelError::SoftwareNameEmpty => {
            (DiagnosticCode::E0003, Some("name"))
        }
        ModelError::NetworkTrafficProtocolsRequired => (DiagnosticCode::E0003, Some("protocols")),
        ModelError::NetworkTrafficSrcOrDstRequired => (DiagnosticCode::E0003, None),
        ModelError::NetworkTrafficEndWithActive => (DiagnosticCode::E0003, Some("end")),
        ModelError::ProcessNoProperties
        | ModelError::UserAccountNoProperties
        | ModelError::WindowsRegistryKeyNoProperties
        | ModelError::WindowsRegistryValueNoProperties
        | ModelError::X509CertificateNoProperties
        | ModelError::X509V3ExtensionsNoProperties
        | ModelError::ArchiveExtContainsRefsEmpty
        | ModelError::NtfsExtNoProperties
        | ModelError::PdfExtNoProperties
        | ModelError::RasterImageExtNoProperties
        | ModelError::WindowsPeBinaryExtNoOptionalProperties
        | ModelError::TcpExtNoProperties
        | ModelError::UnixAccountExtNoProperties
        | ModelError::WindowsProcessExtNoProperties
        | ModelError::WindowsServiceExtNoProperties => (DiagnosticCode::E0003, None),
        ModelError::NtfsExtAdsNameEmpty
        | ModelError::WindowsPeSectionNameEmpty
        | ModelError::WindowsPeBinaryExtPeTypeEmpty
        | ModelError::HttpRequestExtMethodEmpty
        | ModelError::HttpRequestExtValueEmpty
        | ModelError::IcmpExtFieldsEmpty
        | ModelError::SocketExtAddressFamilyEmpty => (DiagnosticCode::E0003, None),
        ModelError::BundleSpecVersionNotAllowed => (DiagnosticCode::E0003, Some("spec_version")),
        ModelError::MarkingDefinitionSpecVersionRequired => {
            (DiagnosticCode::E0003, Some("spec_version"))
        }
        ModelError::MarkingDefinitionLegacyPayloadRequired => {
            (DiagnosticCode::E0003, Some("definition_type"))
        }
    }
}
