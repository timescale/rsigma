//! TAXII discovery, API Root, and collection resources.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::TaxiiError;
use super::url::resolve_against;
/// Discovery resource (spec section 4.1.1).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct TaxiiDiscovery {
    /// Human-readable server title.
    pub title: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional contact information.
    #[serde(default)]
    pub contact: Option<String>,
    /// Default API Root URL when present.
    #[serde(default)]
    pub default: Option<String>,
    /// Advertised API Root URLs (absolute or relative).
    #[serde(default, rename = "api_roots")]
    pub api_roots: Vec<String>,
    /// Unmodeled discovery properties.
    #[serde(flatten)]
    pub custom: BTreeMap<String, serde_json::Value>,
}

impl TaxiiDiscovery {
    /// Return the default API Root URL when advertised.
    pub fn default_api_root(&self) -> Option<&str> {
        self.default.as_deref()
    }

    /// Resolve advertised API Root URLs against `discovery_base`.
    pub fn resolved_api_roots(
        &self,
        discovery_base: &url::Url,
        policy: super::url::HttpsPolicy,
    ) -> Result<Vec<url::Url>, TaxiiError> {
        self.api_roots
            .iter()
            .map(|root| resolve_against(discovery_base, root, policy))
            .collect()
    }
}

/// API Root resource (spec section 4.2.1).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct TaxiiApiRoot {
    /// Human-readable API Root title.
    pub title: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
    /// Supported TAXII media types (must include 2.1).
    pub versions: Vec<String>,
    /// Maximum POST body size in octets (TAXII 2.1 §4.2.1 — MUST be a positive integer).
    pub max_content_length: u64,
    /// Unmodeled API Root properties.
    #[serde(flatten)]
    pub custom: BTreeMap<String, serde_json::Value>,
}

/// Collection resource (spec section 5.2.1).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct TaxiiCollection {
    /// Collection identifier.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional alias unique within the API Root.
    #[serde(default)]
    pub alias: Option<String>,
    /// Whether the authenticated client may read.
    pub can_read: bool,
    /// Whether the authenticated client may write.
    pub can_write: bool,
    /// Supported media types for objects in this collection.
    ///
    /// When omitted on the wire, TAXII 2.1 §5.2.1 treats the collection as if this were
    /// `["application/stix+json"]`.
    #[serde(default = "default_collection_media_types")]
    pub media_types: Vec<String>,
    /// Unmodeled collection properties.
    #[serde(flatten)]
    pub custom: BTreeMap<String, serde_json::Value>,
}

/// Default collection `media_types` when the property is absent (TAXII 2.1 §5.2.1).
pub(crate) fn default_collection_media_types() -> Vec<String> {
    vec!["application/stix+json".to_string()]
}

impl TaxiiCollection {
    /// Media types used for capability checks and POST validation.
    ///
    /// When the wire value is absent or an empty list, returns `["application/stix+json"]`
    /// (TAXII 2.1 §5.2.1).
    pub fn effective_media_types(&self) -> Vec<String> {
        if self.media_types.is_empty() {
            default_collection_media_types()
        } else {
            self.media_types.clone()
        }
    }
}

/// Versions resource (spec section 5.8.1).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct VersionsResponse {
    /// Whether more versions are available.
    #[serde(default)]
    pub more: bool,
    /// Opaque pagination cursor when present.
    #[serde(default)]
    pub next: Option<String>,
    /// Version strings when present.
    #[serde(default)]
    pub versions: Vec<String>,
    /// Unmodeled versions properties.
    #[serde(flatten)]
    pub custom: std::collections::BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
pub(crate) struct CollectionsResponse {
    #[serde(default)]
    pub collections: Vec<TaxiiCollection>,
}
