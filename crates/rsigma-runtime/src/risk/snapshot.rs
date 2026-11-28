//! Versioned persistence snapshot for the per-entity risk accumulator.
//!
//! Saved to the daemon's SQLite store on the periodic and shutdown hooks, beside
//! the correlation and alert-pipeline snapshots, and restored on boot with
//! window-aware pruning. A version mismatch starts fresh rather than erroring.

use serde::{Deserialize, Serialize};

use rsigma_eval::TenantId;

use super::accumulator::Contribution;

/// Snapshot format version. Bump on any breaking change to the layout below; a
/// loaded snapshot whose version is newer is discarded and the accumulator
/// starts empty. Versions 1 and 2 hold no window aggregates and are rebuilt
/// from their contributions.
pub const SNAPSHOT_VERSION: u32 = 3;

/// A point-in-time capture of the whole accumulator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskStateSnapshot {
    /// Snapshot layout version.
    pub version: u32,
    /// One entry per tracked entity.
    pub entities: Vec<EntitySnapshot>,
}

/// One tracked entity's window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySnapshot {
    /// Tenant that owns this entity, when tenancy is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<TenantId>,
    /// The risk-object type.
    pub entity_type: String,
    /// The entity value.
    pub entity_value: String,
    /// When this entity last fired an incident, if ever (unix seconds).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_fired: Option<i64>,
    /// When this entity was last seen (unix seconds).
    pub last_seen: i64,
    /// The sample contributions kept for embedding in incidents.
    pub contributions: Vec<Contribution>,
    /// The window aggregates, oldest bucket first. Empty in version 1 and 2
    /// snapshots.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub buckets: Vec<BucketSnapshot>,
}

/// The aggregates of the contributions in one time bucket of an entity's
/// window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketSnapshot {
    /// Bucket start (unix seconds).
    pub start: i64,
    /// Oldest contribution time in the bucket (unix seconds).
    pub first: i64,
    /// Newest contribution time in the bucket (unix seconds). The bucket
    /// leaves the window when this does.
    pub last: i64,
    /// Risk sum of the bucket's contributions.
    pub score: i64,
    /// Number of contributions in the bucket.
    pub count: u64,
    /// Contributions per canonical ATT&CK tactic slug.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tactics: Vec<(String, u32)>,
    /// Contributions per source (rule identity).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<(String, u32)>,
}
