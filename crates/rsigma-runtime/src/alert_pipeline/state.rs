//! The alert pipeline's mutable runtime state.
//!
//! Bundles the per-stage stores so the sink task owns one value (and shares one
//! `RwLock` with the admin API) rather than threading a store per stage. The
//! dedup store is sink-task-private in practice, but lives here so it persists
//! alongside the incident and silence state.

use super::dedup::DedupStore;
use super::grouping::IncidentStore;
use super::inhibit::InhibitStore;
use super::silence::SilenceStore;

/// All mutable alert-pipeline state, owned by the sink task and shared behind
/// an `RwLock` with the `/api/v1/incidents` and `/api/v1/silences` handlers.
#[derive(Debug, Default)]
pub struct AlertPipelineState {
    /// Active-alert dedup store.
    pub dedup: DedupStore,
    /// Open incidents from the grouping stage.
    pub incidents: IncidentStore,
    /// Operator silences (static + API).
    pub silences: SilenceStore,
    /// Inhibition active-source index.
    pub inhibit: InhibitStore,
}
