//! Versioned persistence snapshot for the alert pipeline.
//!
//! Captures the four pieces of mutable state (dedup active alerts, open
//! incidents, dynamic silences, inhibition active sources) in a single
//! serializable struct. The entity index and cardinality counters are not
//! persisted; the index is rebuilt from the restored incidents on boot.

use serde::{Deserialize, Serialize};

use super::dedup::ActiveAlert;
use super::grouping::Incident;
use super::inhibit::InhibitSourceSnap;
use super::silence::SilenceSnap;

/// Bumped when the snapshot layout changes incompatibly; a mismatch on load
/// logs a warning and the daemon starts with fresh state.
pub const SNAPSHOT_VERSION: u32 = 2;

/// A point-in-time snapshot of the alert pipeline's mutable state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertPipelineSnapshot {
    /// Snapshot layout version.
    pub version: u32,
    /// Active dedup alerts as `(fingerprint, alert)` pairs.
    #[serde(default)]
    pub(crate) dedup: Vec<(String, ActiveAlert)>,
    /// Open incidents.
    #[serde(default)]
    pub(crate) incidents: Vec<Incident>,
    /// Dynamic (API) silences; static ones are re-seeded from config.
    #[serde(default)]
    pub(crate) silences: Vec<SilenceSnap>,
    /// Inhibition active sources.
    #[serde(default)]
    pub(crate) inhibit_sources: Vec<InhibitSourceSnap>,
}
