//! Versioned persistence snapshot for the per-entity risk accumulator.
//!
//! Saved to the daemon's SQLite store on the periodic and shutdown hooks, beside
//! the correlation and alert-pipeline snapshots, and restored on boot with
//! window-aware pruning. A version mismatch starts fresh rather than erroring.

use serde::{Deserialize, Serialize};

use super::accumulator::Contribution;

/// Snapshot format version. Bump on any breaking change to the layout below; a
/// loaded snapshot whose version differs is discarded and the accumulator
/// starts empty.
pub const SNAPSHOT_VERSION: u32 = 1;

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
    /// The risk-object type.
    pub entity_type: String,
    /// The entity value.
    pub entity_value: String,
    /// When this entity last fired an incident, if ever (unix seconds).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_fired: Option<i64>,
    /// When this entity was last seen (unix seconds).
    pub last_seen: i64,
    /// The retained window of contributions.
    pub contributions: Vec<Contribution>,
}
