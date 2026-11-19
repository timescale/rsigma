#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! STIX 2.1 library for Rust.

/// Core types shared across the crate.
pub mod core;

/// Deterministic SCO ID generation helpers.
pub mod id;

/// STIX vocabulary tables.
pub mod vocab;

/// STIX 2.1 patterning engine (STIX Specification §9).
#[cfg(feature = "pattern")]
pub mod pattern;

/// STIX 2.1 data model: typed objects and common properties.
pub mod model;

/// Profile-based STIX 2.1 validation pipeline.
#[cfg(feature = "validate")]
pub mod validate;

/// STIX property graph construction and traversal.
#[cfg(feature = "graph")]
pub mod graph;

/// STIX marking resolution (TLP + granular + statement).
#[cfg(feature = "marking")]
pub mod marking;

/// STIX object store trait and in-memory implementation.
#[cfg(feature = "store")]
pub mod store;

/// TAXII 2.1 HTTP client (OASIS TAXII 2.1).
#[cfg(feature = "taxii")]
pub mod taxii;

#[cfg(feature = "serde")]
mod serde_impls;

/// Top-level parse error.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// Invalid JSON at the wire boundary.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Model validation failed during parse.
    #[error(transparent)]
    Model(#[from] model::ModelError),
    /// The document root is not a STIX bundle.
    #[error("expected STIX type `bundle`, got `{actual_type}`")]
    NotABundle {
        /// `type` value from the JSON document.
        actual_type: String,
    },
    /// Bundle is missing the required `id` property.
    #[error("bundle missing required id")]
    MissingBundleId,
    /// A bundle object is missing the required `id` property.
    #[error("bundle object missing required id")]
    MissingObjectId,
    /// Two objects in the same bundle share an `id`.
    #[error("duplicate bundle object id `{0}`")]
    DuplicateObjectId(String),
    /// Bundle exceeds the configured object limit.
    #[error("bundle object count {count} exceeds limit {max}")]
    ObjectLimitExceeded {
        /// Number of objects in the bundle.
        count: usize,
        /// Configured maximum object count.
        max: usize,
    },
    /// Object `type` is not recognized and custom types are disabled.
    #[error("unknown STIX object type `{0}`")]
    UnknownObjectType(String),
    /// Bundle JSON exceeds the configured byte limit while streaming.
    #[error("bundle exceeds max_bundle_bytes limit ({max} bytes)")]
    BundleByteLimitExceeded {
        /// Configured byte limit.
        max: usize,
    },
    /// JSON nesting exceeds `ParseOptions::max_nesting_depth`.
    #[error("JSON nesting exceeds max_nesting_depth ({max})")]
    JsonNestingTooDeep {
        /// Configured nesting limit.
        max: usize,
    },
    /// A JSON string exceeds `ParseOptions::max_string_length`.
    #[error("JSON string length {len} exceeds max_string_length ({max})")]
    JsonStringTooLong {
        /// Observed string length.
        len: usize,
        /// Configured limit.
        max: usize,
    },
    /// A STIX id string failed to parse (`type--uuid` / UUID shape).
    #[error(transparent)]
    InvalidStixId(#[from] core::StixIdError),
}

#[cfg(feature = "pattern")]
pub use pattern::{
    ObservableExtraction, ObservableKind, Pattern, PatternAst, PatternError, PatternMatchError,
    PatternScoType, SimpleObservable, UnsupportedReason,
};

#[cfg(feature = "validate")]
pub use validate::{
    Diagnostic, DiagnosticCode, Leniency, Severity, SourceSpan, ValidationPhase,
    ValidationReport as PipelineValidationReport, Validator, ValidatorBuilder,
};

#[cfg(feature = "graph")]
pub use graph::{
    AttackPatternSummary, CampaignSummary, CoaSummary, Edge, EdgePredicate, EdgeTraversal,
    ExpansionResult, GraphError, IdentitySummary, IndicatorSummary, InfrastructureSummary,
    MalwareSummary, PredicateFn, RelationshipExpander, SroEdgePayload, StixGraph,
    ThreatActorSummary, TraversalBuilder, VulnerabilitySummary,
};

#[cfg(feature = "marking")]
#[allow(deprecated)]
pub use marking::{
    DisclosureContext, EffectiveMarking, MarkingResolver, StatementMarking, TlpV1Level, TlpV2Level,
};

#[cfg(feature = "store-fs")]
pub use store::FsStore;
#[cfg(feature = "store")]
pub use store::{
    FingerprintConflict, ImportReport, MemoryStore, QueryCursor, QueryResult, StixQuery, StixStore,
    StoreError, StoredSco,
};

#[cfg(feature = "serde")]
pub use model::{
    Bundle, BundleObjectCast, CustomStixObject, ParseOptions, QueryableContainer, SdoObject,
    StixObject, TypeRegistry, ValidationCode, ValidationFinding, ValidationReport,
};

#[cfg(feature = "taxii")]
pub use taxii::{
    ApiKeyHeader, AuthChallenge, BasicAuth, BearerAuth, CapabilityPolicy, ClientCertificate,
    DeleteObjectFilter, DnsLookupOptions, HttpsPolicy, ManifestRecord, ManifestResponse,
    ObjectByIdFilter, ObjectVersion, PollBudget, PollStop, PolledPage, PostSubmitPolicy,
    PreflightPolicy, RetryPolicy, ServerTrustPolicy, SpkiPin, StatusDetail, StatusState,
    TAXII2_SRV_SERVICE, TaxiiApiRoot, TaxiiAuthProvider, TaxiiClient, TaxiiClientConfig,
    TaxiiCollection, TaxiiDiscovery, TaxiiEnvelope, TaxiiError, TaxiiFilter, TaxiiPageHeaders,
    TaxiiPaged, TaxiiStatus, TlsaCache, TlsaRecord, VersionFilter, VersionSelector,
    VersionsQueryFilter, VersionsResponse, build_rustls_config, parse_envelope,
    parse_www_authenticate, resolve_taxii_srv, resolve_taxii_srv_with_options, resolve_tlsa,
    resolve_tlsa_with_options,
};
#[cfg(all(feature = "taxii", feature = "store"))]
pub use taxii::{
    DEFAULT_INGEST_BUNDLE_ID, IngestError, IngestOptions, IngestReport, ingest_collection,
    ingest_collection_with_bundle_id,
};
#[cfg(all(feature = "taxii", feature = "store", feature = "validate"))]
pub use taxii::{IngestValidationFailure, IngestValidationReport};

/// Parse a STIX bundle from a JSON string using default options.
#[cfg(feature = "serde")]
pub fn parse_bundle(json: &str) -> Result<Bundle, ParseError> {
    Bundle::parse(json)
}

/// Parse a single STIX object with the same wire capture rules as [`Bundle::parse`].
///
/// Unmodeled top-level keys and `x_*` custom properties are returned in the side map
/// (and drained from typed `common.extra` / meta `extra`, matching bundle ingest).
#[cfg(feature = "serde")]
pub fn parse_object_with_extras(
    json: &str,
) -> Result<
    (
        StixObject,
        std::collections::BTreeMap<String, serde_json::Value>,
    ),
    ParseError,
> {
    parse_object_with_extras_and_options(json, &ParseOptions::default())
}

/// Parse a single STIX object with explicit [`ParseOptions`].
#[cfg(feature = "serde")]
pub fn parse_object_with_extras_and_options(
    json: &str,
    opts: &ParseOptions,
) -> Result<
    (
        StixObject,
        std::collections::BTreeMap<String, serde_json::Value>,
    ),
    ParseError,
> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    model::deserialize_stix_object_from_value(value, opts)
}

/// Parse a single STIX object using default options (extras discarded).
#[cfg(feature = "serde")]
pub fn parse_object(json: &str) -> Result<StixObject, ParseError> {
    parse_object_with_extras(json).map(|(object, _)| object)
}
