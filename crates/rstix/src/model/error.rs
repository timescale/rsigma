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
    /// A `granular-marking` must set exactly one of `marking_ref` or `lang` (both absent).
    #[error("granular marking must set marking_ref or lang")]
    GranularMarkingMissingRefAndLang,
    /// A `granular-marking` must set exactly one of `marking_ref` or `lang` (both present).
    #[error("granular marking must not set both marking_ref and lang")]
    GranularMarkingBothRefAndLang,
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
    /// A kill-chain phase `kill_chain_name` is empty.
    #[error("kill chain phase kill_chain_name must be non-empty")]
    KillChainPhaseEmptyKillChainName,
    /// A kill-chain phase `phase_name` is empty.
    #[error("kill chain phase phase_name must be non-empty")]
    KillChainPhaseEmptyPhaseName,
    /// Object `id` prefix does not match the declared STIX `type`.
    #[error(
        "STIX id `{id}` type prefix `{actual_type}` does not match object type `{expected_type}`"
    )]
    IdTypeMismatch {
        /// Full STIX id string.
        id: String,
        /// Expected type prefix from the object.
        expected_type: String,
        /// Actual type prefix parsed from the id.
        actual_type: String,
    },
    /// `modified` is earlier than `created`.
    #[error("modified must be greater than or equal to created")]
    ModifiedBeforeCreated,
    /// A marking reference points at the same object id (circular reference).
    #[error(
        "object `{object_id}` must not reference itself in object_marking_refs or granular_markings"
    )]
    MarkingDefinitionCircularRef {
        /// Object id that circularly references itself.
        object_id: String,
    },
    /// A STIX reference id prefix is not an allowed target type.
    #[error("reference `{ref_id}` has invalid kind; expected {expected}")]
    InvalidReferenceKind {
        /// Referenced STIX id.
        ref_id: String,
        /// Human-readable list of expected type prefixes.
        expected: String,
    },
    /// An SDO `last_seen` is earlier than `first_seen` when both are set.
    #[error("SDO last_seen must be greater than or equal to first_seen")]
    SdoLastSeenBeforeFirstSeen,
    /// A `location` lacks region, country, and latitude/longitude pair.
    #[error("location requires region, country, or both latitude and longitude")]
    LocationMissingGeo,
    /// A `location` sets latitude without longitude or vice versa.
    #[error("location latitude and longitude must both be set or both be absent")]
    LocationLatitudeLongitudePairRequired,
    /// A `location` latitude is outside `-90.0..=90.0`.
    #[error("location latitude must be between -90.0 and 90.0 inclusive")]
    LocationLatitudeOutOfRange,
    /// A `location` longitude is outside `-180.0..=180.0`.
    #[error("location longitude must be between -180.0 and 180.0 inclusive")]
    LocationLongitudeOutOfRange,
    /// A `location` `precision` is set without latitude and longitude.
    #[error("location precision requires latitude and longitude")]
    LocationPrecisionRequiresCoordinates,
    /// A `malware-analysis` lacks both `result` and `analysis_sco_refs`.
    #[error("malware-analysis requires result or at least one analysis_sco_refs entry")]
    MalwareAnalysisResultOrScoRefsRequired,
    /// A `malware` `sample_refs` entry is not file or artifact.
    #[error("malware sample_refs must reference file or artifact")]
    MalwareSampleRefInvalid,
    /// A `malware-analysis` `sample_ref` is not file, network-traffic, or artifact.
    #[error("malware-analysis sample_ref must reference file, network-traffic, or artifact")]
    MalwareAnalysisSampleRefInvalid,
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
    #[error("SCO extension `{key}` failed to deserialize: {detail}")]
    ExtensionDeserializeFailed {
        /// Extension dictionary key (for example `archive-ext`).
        key: &'static str,
        /// Underlying serde error message.
        detail: String,
    },
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
    /// A `location` lacks region, country, or latitude/longitude.
    #[error("location requires region, country, or both latitude and longitude")]
    LocationInsufficientProperties,
    /// A `location` sets only one of latitude and longitude.
    #[error("location latitude and longitude must both be present")]
    LocationLatitudeLongitudePair,
    /// A `malware` family is missing the required `name`.
    #[error("malware family requires name")]
    MalwareFamilyMissingName,
    /// A `malware-analysis` must set `result` or `analysis_sco_refs`.
    #[error("malware-analysis requires result or analysis_sco_refs")]
    MalwareAnalysisMissingResultOrScoRefs,
    /// An `indicator` `valid_until` is not later than `valid_from`.
    #[error("indicator valid_until must be later than valid_from")]
    IndicatorValidUntilBeforeValidFrom,
    /// An `observed-data` sets both `objects` and `object_refs`.
    #[error("observed-data requires exactly one of objects or object_refs")]
    ObservedDataObjectsXorObjectRefs,
    /// An `observed-data` sets neither `objects` nor `object_refs`.
    #[error("observed-data requires objects or object_refs")]
    ObservedDataMissingScoContent,
    /// An `observed-data` `objects` map is empty.
    #[error("observed-data objects must contain at least one SCO")]
    ObservedDataEmptyObjects,
    /// An `observed-data` `object_refs` is empty.
    #[error("observed-data object_refs must contain at least one reference")]
    ObservedDataEmptyObjectRefs,
    /// An `observed-data` `last_observed` is earlier than `first_observed`.
    #[error("observed-data last_observed must be greater than or equal to first_observed")]
    ObservedDataLastObservedBeforeFirstObserved,
    /// An `observed-data` `number_observed` is outside `1..=999_999_999`.
    #[error("observed-data number_observed must be between 1 and 999_999_999 inclusive")]
    ObservedDataNumberObservedOutOfRange,
    /// An `opinion` value is not in the opinion-enum vocabulary.
    #[error("unknown opinion value")]
    OpinionValueInvalid,
    /// A `relationship` endpoint reference is not an SDO or SCO id prefix.
    #[error("relationship source_ref and target_ref must reference SDO or SCO objects")]
    RelationshipEndpointKindInvalid,
    /// A `sighting` `sighting_of_ref` is not an SDO id prefix.
    #[error("sighting_of_ref must reference an SDO object")]
    SightingOfRefKindInvalid,
    /// A bundle object reference does not resolve to an object in the bundle.
    #[error("bundle reference `{ref_id}` not found in bundle")]
    BundleReferenceMissing {
        /// Referenced STIX id missing from the bundle.
        ref_id: String,
    },
    /// Relationship endpoints violate the STIX 2.1 relationship matrix.
    #[error(
        "relationship `{relationship_type}` from `{source_type}` to `{target_type}` is not allowed"
    )]
    RelationshipEndpointMatrixInvalid {
        /// Relationship type string.
        relationship_type: String,
        /// Source object type prefix.
        source_type: String,
        /// Target object type prefix.
        target_type: String,
    },
    /// CAPEC external reference is malformed on attack-pattern.
    #[error("attack-pattern CAPEC external reference requires external_id prefixed with CAPEC-")]
    InvalidCapecExternalReference,
    /// CVE external reference is malformed on vulnerability.
    #[error("vulnerability CVE external reference requires external_id prefixed with CVE-")]
    InvalidCveExternalReference,
    /// Multiple malware sample_refs must reference the same binary when is_family is false.
    #[error("malware sample_refs must reference the same binary when is_family is false")]
    MalwareSampleRefsNotSameBinary,
    /// Bundle id prefix is not `bundle`.
    #[error("bundle id must use the bundle type prefix")]
    BundleIdPrefixInvalid,
    /// Bundle must not carry spec_version (STIX §8).
    #[error("bundle must not include spec_version")]
    BundleSpecVersionNotAllowed,
    /// language-content must not set lang on common properties.
    #[error("language-content must not set lang")]
    LanguageContentLangNotAllowed,
    /// language-content object_modified does not match the target object's modified time.
    #[error("language-content object_modified does not match target object modified time")]
    LanguageContentObjectModifiedMismatch,
    /// marking-definition requires spec_version.
    #[error("marking-definition requires spec_version")]
    MarkingDefinitionSpecVersionRequired,
    /// marking-definition requires legacy definition payload when extensions are empty.
    #[error("marking-definition requires definition_type and definition when extensions are empty")]
    MarkingDefinitionLegacyPayloadRequired,
    /// extension-definition must not carry forbidden common properties on the wire.
    #[error("extension-definition must not set {property}")]
    ExtensionDefinitionForbiddenCommonProperty {
        /// Forbidden property name.
        property: String,
    },
    /// Predefined extension keys must not include extension_type.
    #[error("predefined extension `{key}` must not include extension_type")]
    ExtensionTypeOnPredefinedExtension {
        /// Extension dictionary key.
        key: String,
    },
    /// Domain name value failed basic format validation.
    #[error("domain-name value has invalid format")]
    DomainNameFormatInvalid,
    /// Email address value failed basic format validation.
    #[error("email-addr value has invalid format")]
    EmailAddrFormatInvalid,
    /// URL value failed basic format validation.
    #[error("url value has invalid format")]
    UrlFormatInvalid,
    /// Encryption algorithm is not in the STIX closed vocabulary.
    #[error("artifact encryption_algorithm is not in the STIX closed vocabulary")]
    EncryptionAlgorithmInvalid,
    /// SCO id does not match deterministic id generation from contributing properties.
    #[error("SCO id does not match deterministic id from contributing properties")]
    ScoDeterministicIdMismatch,
    /// Property-extension references an extension-definition id missing from the bundle.
    #[error("property-extension references missing extension-definition `{extension_id}`")]
    PropertyExtensionDefinitionMissing {
        /// Referenced extension-definition id.
        extension_id: String,
    },
    /// SCO JSON includes SDO-only common properties.
    #[error("SCO must not include SDO common property `{property}`")]
    ScoForbiddenCommonProperty {
        /// Forbidden property name.
        property: String,
    },
    /// language-content `contents` key is not a valid RFC 5646 language tag.
    #[error("language-content contents key is not a valid RFC 5646 language tag")]
    LanguageContentInvalidLanguageCode,
    /// granular-marking selector syntax is invalid (STIX §7.2.3.1).
    #[error("granular marking selector syntax is invalid: `{selector}`")]
    GranularSelectorSyntaxInvalid {
        /// Invalid selector string.
        selector: String,
    },
}
