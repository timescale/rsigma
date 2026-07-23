//! TAXII 2.1 HTTP client (OASIS TAXII 2.1).
//!
//! All wire payloads use [`TaxiiEnvelope`] — not [`crate::model::Bundle`]. Requests use
//! `Accept: application/taxii+json;version=2.1` and endpoint paths **must** end with `/`.

#![allow(clippy::result_large_err)]

mod capability;
mod client;
mod dane;
mod dns;
mod envelope;
mod error;
mod filter;
mod headers;
mod media;
mod pagination;
mod policy;
mod request;
mod resources;
mod retry;
mod server_trust;
mod tls;
mod url;
mod www_authenticate;

pub mod auth;

pub use auth::{ApiKeyHeader, AuthError, BasicAuth, BearerAuth, TaxiiAuthProvider};
pub use client::{TaxiiClient, TaxiiClientConfig};
pub use dane::TlsaRecord;
pub use dns::{
    DnsLookupOptions, TAXII2_SRV_SERVICE, resolve_taxii_srv, resolve_taxii_srv_with,
    resolve_taxii_srv_with_options, resolve_tlsa, resolve_tlsa_with, resolve_tlsa_with_options,
};
pub use envelope::{
    ManifestRecord, ManifestResponse, StatusDetail, StatusState, TaxiiEnvelope, TaxiiStatus,
};
pub use error::TaxiiError;
pub use filter::{
    DeleteObjectFilter, ObjectByIdFilter, ObjectVersion, TaxiiFilter, VersionFilter,
    VersionSelector, VersionsQueryFilter,
};
pub use headers::{TaxiiPageHeaders, TaxiiPaged};
pub use policy::{CapabilityPolicy, PostSubmitPolicy, PreflightPolicy};
pub use resources::{TaxiiApiRoot, TaxiiCollection, TaxiiDiscovery, VersionsResponse};
pub use retry::RetryPolicy;
pub use server_trust::{ServerTrustPolicy, SpkiPin, TlsaCache, build_rustls_config};
pub use tls::ClientCertificate;
pub use url::HttpsPolicy;
pub use www_authenticate::{AuthChallenge, parse_www_authenticate};
