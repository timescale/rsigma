//! Model-level validation errors raised when constructing or validating STIX
//! values whose invariants cannot be expressed in the type system alone.

/// Errors raised while constructing or validating STIX model values.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModelError {
    /// An `external-reference` was missing the required `source_name`.
    #[error("external reference requires a non-empty source_name")]
    ExternalReferenceMissingSourceName,
    /// An `external-reference` must set at least one of `description`, `url`,
    /// or `external_id` (STIX §2.5.2).
    #[error("external reference requires at least one of description, url, or external_id")]
    ExternalReferenceMissingDetail,
    /// A `granular-marking` must set exactly one of `marking_ref` or `lang`.
    #[error("granular marking must set exactly one of marking_ref or lang")]
    GranularMarkingExclusivity,
    /// A `granular-marking` must name at least one selector.
    #[error("granular marking requires at least one selector")]
    GranularMarkingEmptySelectors,
    /// An `extension-definition` requires `created_by_ref` (STIX §7.2.2).
    #[error("extension definition requires created_by_ref")]
    ExtensionDefinitionMissingCreatedByRef,
    /// JSON `type` does not match the struct being deserialized.
    #[error("expected STIX type `{expected}`, got `{actual}`")]
    UnexpectedObjectType {
        /// Expected STIX `type` string.
        expected: &'static str,
        /// `type` value from the JSON document.
        actual: String,
    },
    /// A `relationship` `relationship_type` contains characters outside `[a-z0-9-]`.
    #[error("relationship type must contain only lowercase ASCII letters, digits, and hyphens")]
    RelationshipTypeInvalid,
    /// A `relationship` `stop_time` is not later than `start_time` when both are set.
    #[error("relationship stop_time must be later than start_time")]
    RelationshipStopTimeBeforeStartTime,
    /// A `sighting` `count` is outside `0..=999_999_999`.
    #[error("sighting count must be between 0 and 999_999_999 inclusive")]
    SightingCountOutOfRange,
    /// A `sighting` `last_seen` is earlier than `first_seen` when both are set.
    #[error("sighting last_seen must be greater than or equal to first_seen")]
    SightingLastSeenBeforeFirstSeen,
    /// A `sighting` `where_sighted_refs` entry is not an identity or location id.
    #[error("where_sighted_refs must reference identity or location objects")]
    SightingWhereSightedRefInvalid,
    /// An embedded SCO extension object failed to deserialize.
    #[error("SCO extension failed to deserialize")]
    ExtensionDeserializeFailed,
    /// `domain-name` `resolves_to_refs` entry is not ipv4-addr, ipv6-addr, or domain-name.
    #[error("domain-name resolves_to_refs must reference ipv4-addr, ipv6-addr, or domain-name")]
    DomainNameResolvesToRefInvalid,
    /// `directory` `contains_refs` entry is not file or directory.
    #[error("directory contains_refs must reference file or directory")]
    DirectoryContainsRefInvalid,
    /// Network-traffic endpoint ref is not a supported SCO type.
    #[error(
        "network-traffic endpoint ref must reference ipv4-addr, ipv6-addr, mac-addr, or domain-name"
    )]
    NetworkTrafficEndpointRefInvalid,
    /// Email MIME part `body_raw_ref` is not artifact or file.
    #[error("email MIME body_raw_ref must reference artifact or file")]
    EmailMimeBodyRawRefInvalid,
    /// `artifact` must set exactly one of payload_bin or url.
    #[error("artifact requires exactly one of payload_bin or url")]
    ArtifactPayloadXorUrl,
    /// `artifact` url requires hashes.
    #[error("artifact url requires hashes")]
    ArtifactHashesRequiredWhenUrl,
    /// `artifact` decryption_key requires encryption_algorithm.
    #[error("artifact decryption_key requires encryption_algorithm")]
    ArtifactDecryptionKeyWithoutEncryption,
    /// `directory` path is empty.
    #[error("directory path must be non-empty")]
    DirectoryPathEmpty,
    /// `domain-name` value is empty.
    #[error("domain-name value must be non-empty")]
    DomainNameValueEmpty,
    /// `email-addr` value is empty.
    #[error("email-addr value must be non-empty")]
    EmailAddrValueEmpty,
    /// Email MIME part must set exactly one of body or body_raw_ref.
    #[error("email MIME part requires exactly one of body or body_raw_ref")]
    EmailMimePartBodyXorRawRef,
    /// `email-message` body must not be set when is_multipart is true.
    #[error("email-message body must not be set when is_multipart is true")]
    EmailMessageBodyWithMultipart,
    /// `email-message` is_multipart true requires body_multipart.
    #[error("email-message is_multipart true requires body_multipart")]
    EmailMessageMultipartMissing,
    /// `email-message` is_multipart false must not set body_multipart.
    #[error("email-message is_multipart false must not set body_multipart")]
    EmailMessageMultipartWhenSinglePart,
    /// `file` requires at least one of hashes or name.
    #[error("file requires at least one of hashes or name")]
    FileHashesOrNameRequired,
    /// `ipv4-addr` value is empty.
    #[error("ipv4-addr value must be non-empty")]
    Ipv4AddrValueEmpty,
    /// `ipv6-addr` value is empty.
    #[error("ipv6-addr value must be non-empty")]
    Ipv6AddrValueEmpty,
    /// `mac-addr` value is empty.
    #[error("mac-addr value must be non-empty")]
    MacAddrValueEmpty,
    /// `mutex` name is empty.
    #[error("mutex name must be non-empty")]
    MutexNameEmpty,
    /// `network-traffic` requires protocols.
    #[error("network-traffic requires at least one protocol")]
    NetworkTrafficProtocolsRequired,
    /// `network-traffic` requires src_ref or dst_ref.
    #[error("network-traffic requires src_ref or dst_ref")]
    NetworkTrafficSrcOrDstRequired,
    /// `network-traffic` is_active true must not set end.
    #[error("network-traffic is_active true must not set end")]
    NetworkTrafficEndWithActive,
    /// `network-traffic` end is before start.
    #[error("network-traffic end must be greater than or equal to start")]
    NetworkTrafficEndBeforeStart,
    /// `process` has no specific properties.
    #[error("process requires at least one specific property or extension")]
    ProcessNoProperties,
    /// `software` name is empty.
    #[error("software name must be non-empty")]
    SoftwareNameEmpty,
    /// `url` value is empty.
    #[error("url value must be non-empty")]
    UrlValueEmpty,
    /// `user-account` has no specific properties.
    #[error("user-account requires at least one specific property or extension")]
    UserAccountNoProperties,
    /// `windows-registry-key` has no specific properties.
    #[error("windows-registry-key requires at least one specific property")]
    WindowsRegistryKeyNoProperties,
    /// Windows registry value has no properties.
    #[error("windows-registry-value requires at least one property")]
    WindowsRegistryValueNoProperties,
    /// `x509-certificate` has no specific properties.
    #[error("x509-certificate requires at least one specific property")]
    X509CertificateNoProperties,
    /// X.509 v3 extensions block has no properties.
    #[error("x509-v3-extensions requires at least one property")]
    X509V3ExtensionsNoProperties,
    /// `archive-ext` requires non-empty contains_refs.
    #[error("archive-ext requires at least one contains_refs entry")]
    ArchiveExtContainsRefsEmpty,
    /// `ntfs-ext` has no properties.
    #[error("ntfs-ext requires at least one property")]
    NtfsExtNoProperties,
    /// NTFS alternate data stream name is empty.
    #[error("ntfs alternate data stream name must be non-empty")]
    NtfsExtAdsNameEmpty,
    /// `pdf-ext` has no properties.
    #[error("pdf-ext requires at least one property")]
    PdfExtNoProperties,
    /// `raster-image-ext` has no properties.
    #[error("raster-image-ext requires at least one property")]
    RasterImageExtNoProperties,
    /// `windows-pebinary-ext` pe_type is empty.
    #[error("windows-pebinary-ext pe_type must be non-empty")]
    WindowsPeBinaryExtPeTypeEmpty,
    /// `windows-pebinary-ext` lacks optional properties besides pe_type.
    #[error("windows-pebinary-ext requires at least one property besides pe_type")]
    WindowsPeBinaryExtNoOptionalProperties,
    /// Windows PE section name is empty.
    #[error("windows PE section name must be non-empty")]
    WindowsPeSectionNameEmpty,
    /// `http-request-ext` request_method is empty.
    #[error("http-request-ext request_method must be non-empty")]
    HttpRequestExtMethodEmpty,
    /// `http-request-ext` request_value is empty.
    #[error("http-request-ext request_value must be non-empty")]
    HttpRequestExtValueEmpty,
    /// `icmp-ext` type or code hex is empty.
    #[error("icmp-ext icmp_type_hex and icmp_code_hex must be non-empty")]
    IcmpExtFieldsEmpty,
    /// `socket-ext` address_family is empty.
    #[error("socket-ext address_family must be non-empty")]
    SocketExtAddressFamilyEmpty,
    /// `tcp-ext` has no properties.
    #[error("tcp-ext requires at least one property")]
    TcpExtNoProperties,
    /// `unix-account-ext` has no properties.
    #[error("unix-account-ext requires at least one property")]
    UnixAccountExtNoProperties,
    /// `windows-process-ext` has no properties.
    #[error("windows-process-ext requires at least one property")]
    WindowsProcessExtNoProperties,
    /// `windows-service-ext` has no properties.
    #[error("windows-service-ext requires at least one property")]
    WindowsServiceExtNoProperties,
}
