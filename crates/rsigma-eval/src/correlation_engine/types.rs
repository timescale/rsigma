use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::correlation::EventBuffer;
use crate::correlation::{EventRefBuffer, GroupKey, WindowState};
use crate::result::EvaluationResult;
use crate::tenant::TenantId;

// =============================================================================
// Configuration
// =============================================================================

/// What to do with window state after a correlation fires.
///
/// This is an engine-level default that can be overridden per-correlation
/// via the `rsigma.action` custom attribute set in processing pipelines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationAction {
    /// Keep window state as-is after firing (current / default behavior).
    /// Subsequent events that still satisfy the condition will re-fire.
    #[default]
    Alert,
    /// Clear the window state for the firing group key after emitting the alert.
    /// The threshold must be met again from scratch before the next alert.
    Reset,
}

impl std::str::FromStr for CorrelationAction {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "alert" => Ok(CorrelationAction::Alert),
            "reset" => Ok(CorrelationAction::Reset),
            _ => Err(format!(
                "Unknown correlation action: {s} (expected 'alert' or 'reset')"
            )),
        }
    }
}

/// How to include events in correlation results.
///
/// Can be overridden per-correlation via the `rsigma.correlation_event_mode`
/// custom attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationEventMode {
    /// Don't include events (default). Zero memory overhead.
    #[default]
    None,
    /// Include full event bodies, individually compressed with deflate.
    /// Typical cost: 100–1000 bytes per event.
    Full,
    /// Include only event references (timestamp + optional ID).
    /// Minimal memory: ~40 bytes per event.
    Refs,
}

impl std::str::FromStr for CorrelationEventMode {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" | "off" | "false" => Ok(CorrelationEventMode::None),
            "full" | "true" => Ok(CorrelationEventMode::Full),
            "refs" | "references" => Ok(CorrelationEventMode::Refs),
            _ => Err(format!(
                "Unknown correlation event mode: {s} (expected 'none', 'full', or 'refs')"
            )),
        }
    }
}

impl std::fmt::Display for CorrelationEventMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorrelationEventMode::None => write!(f, "none"),
            CorrelationEventMode::Full => write!(f, "full"),
            CorrelationEventMode::Refs => write!(f, "refs"),
        }
    }
}

/// Behavior when no timestamp field is found or parseable in an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimestampFallback {
    /// Use wall-clock time (`Utc::now()`). Good for real-time streaming.
    #[default]
    WallClock,
    /// Skip the event from correlation processing. Detections still fire,
    /// but the event does not update any correlation state. Recommended for
    /// batch/replay of historical logs where wall-clock time is meaningless.
    Skip,
}

/// Configuration for the correlation engine.
///
/// Provides engine-level defaults that mirror pySigma backend optional arguments.
/// Per-correlation overrides can be set via `SetCustomAttribute` pipeline
/// transformations using the `rsigma.*` attribute namespace.
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    /// Field names to try for timestamp extraction, in order of priority.
    ///
    /// The engine will try each field until one yields a parseable timestamp.
    /// If none succeed, the `timestamp_fallback` policy applies.
    pub timestamp_fields: Vec<String>,

    /// What to do when no timestamp can be extracted from an event.
    ///
    /// Default: `WallClock` (use `Utc::now()`).
    pub timestamp_fallback: TimestampFallback,

    /// Maximum number of state entries (across all correlations and groups)
    /// before aggressive eviction is triggered. Prevents unbounded memory growth.
    ///
    /// Default: 100_000.
    pub max_state_entries: usize,

    /// Maximum number of retained entries within a single group's window
    /// state (timestamps for `event_count`, `(timestamp, value)` pairs for
    /// `value_count` and the numeric aggregations, per-rule hits for
    /// temporal types). Bounds the within-window growth that
    /// `max_state_entries` does not: a group's deque otherwise grows with
    /// `timespan` x event rate.
    ///
    /// When the cap is exceeded the oldest entries are dropped, which can
    /// only under-count (aggregates saturate; correlations that would have
    /// fired on evicted entries may not). Session windows always keep their
    /// oldest entry as the span anchor so truncation cannot silently extend
    /// the `timespan` cap.
    ///
    /// `None` (default) means unbounded, preserving existing behavior.
    /// Can be overridden per-correlation via `rsigma.max_group_entries`.
    pub max_group_entries: Option<usize>,

    /// Default suppression window in seconds.
    ///
    /// After a correlation fires for a `(correlation, group_key)`, suppress
    /// re-alerts for this duration. `None` means no suppression (every
    /// condition-satisfying event produces an alert).
    ///
    /// Can be overridden per-correlation via the `rsigma.suppress` custom attribute.
    pub suppress: Option<u64>,

    /// Default action to take after a correlation fires.
    ///
    /// Can be overridden per-correlation via the `rsigma.action` custom attribute.
    pub action_on_match: CorrelationAction,

    /// Whether to emit matches for rules that are only referenced by
    /// correlations (where `generate: false`). This covers detection rules
    /// and correlations referenced by another correlation in a chain.
    ///
    /// Default: `false`, following Sigma's correlation-only output semantics.
    /// Set to `true` to emit every detection and correlation match.
    pub emit_detections: bool,

    /// How to include contributing events in correlation results.
    ///
    /// - `None` (default): no event storage, zero overhead.
    /// - `Full`: events are deflate-compressed and decompressed on output.
    /// - `Refs`: only timestamps + event IDs are stored (minimal memory).
    ///
    /// Can be overridden per-correlation via `rsigma.correlation_event_mode`.
    pub correlation_event_mode: CorrelationEventMode,

    /// Maximum number of events to store per (correlation, group_key) window
    /// when `correlation_event_mode` is not `None`.
    ///
    /// Bounds memory at: `max_correlation_events × cost_per_event × active_groups`.
    /// Default: 10.
    pub max_correlation_events: usize,

    /// Maximum state entries per tenant. At a tenant's cap, that tenant's own
    /// expired entries are evicted first, then its stalest entries down to 90%
    /// of the cap. `None` leaves only the global [`Self::max_state_entries`]
    /// bound in force.
    pub max_state_entries_per_tenant: Option<usize>,

    /// Skip correlation for events that carry no tenant, counting them in
    /// [`crate::CorrelationEngine::untenanted_skipped`].
    ///
    /// Set when tenancy is enabled so a bug that lets an untenanted event
    /// through cannot form a shared `None` bucket. Default: `false`.
    pub require_tenant: bool,
}

/// Key identifying one correlation window: tenant, correlation index, and the
/// resolved group values.
///
/// Tenants never share a window even when their group keys are identical.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct StateKey {
    pub(crate) tenant: Option<TenantId>,
    pub(crate) corr_idx: usize,
    pub(crate) group_key: GroupKey,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        CorrelationConfig {
            timestamp_fields: vec![
                "@timestamp".to_string(),
                "timestamp".to_string(),
                "EventTime".to_string(),
                "TimeCreated".to_string(),
                "eventTime".to_string(),
            ],
            timestamp_fallback: TimestampFallback::default(),
            max_state_entries: 100_000,
            max_group_entries: None,
            suppress: None,
            action_on_match: CorrelationAction::default(),
            emit_detections: false,
            correlation_event_mode: CorrelationEventMode::default(),
            max_correlation_events: 10,
            max_state_entries_per_tenant: None,
            require_tenant: false,
        }
    }
}

// =============================================================================
// Result types
// =============================================================================

/// All [`EvaluationResult`]s produced for a single input event.
///
/// Detection results come first (in evaluation order), followed by any
/// correlation results that fired on this event. Iterate the vec to
/// process every result uniformly; use [`EvaluationResult::is_detection`]
/// / [`EvaluationResult::is_correlation`] (or `as_detection` /
/// `as_correlation`) to dispatch on the body kind when needed.
pub type ProcessResult = Vec<EvaluationResult>;

/// Serializable snapshot of all mutable correlation state.
///
/// Uses stable string identifiers (correlation id/name/title) as keys so the
/// snapshot can be restored after a rule reload, even if internal indices change.
/// Inner maps use `Vec<(GroupKey, T)>` instead of `HashMap<GroupKey, T>` because
/// `GroupKey` cannot be used as a JSON object key.
///
/// Version 2 nests state under [`Self::tenants`]; the top-level maps hold the
/// version 1 layout and are read as tenant `None` but never written.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CorrelationSnapshot {
    /// Schema version — used to detect incompatible snapshots on load.
    #[serde(default = "default_snapshot_version")]
    pub version: u32,
    /// Version 1 layout: per-correlation, per-group window state, read as
    /// tenant `None`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub windows: HashMap<String, Vec<(GroupKey, WindowState)>>,
    /// Version 1 layout: per-correlation, per-group last alert timestamp.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub last_alert: HashMap<String, Vec<(GroupKey, i64)>>,
    /// Version 1 layout: per-correlation, per-group compressed event buffers.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub event_buffers: HashMap<String, Vec<(GroupKey, EventBuffer)>>,
    /// Version 1 layout: per-correlation, per-group event reference buffers.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub event_ref_buffers: HashMap<String, Vec<(GroupKey, EventRefBuffer)>>,
    /// Version 2 layout: one entry per tenant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tenants: Vec<TenantStateSnapshot>,
    /// Per-ruleset snapshots, keyed by ruleset name. Empty for a single
    /// collection.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rulesets: BTreeMap<String, CorrelationSnapshot>,
}

/// State belonging to one tenant in a version 2 snapshot.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct TenantStateSnapshot {
    /// Tenant that owns this state. `None` for the untenanted bucket.
    pub tenant: Option<TenantId>,
    /// Per-correlation, per-group window state.
    pub windows: HashMap<String, Vec<(GroupKey, WindowState)>>,
    /// Per-correlation, per-group last alert timestamp.
    pub last_alert: HashMap<String, Vec<(GroupKey, i64)>>,
    /// Per-correlation, per-group compressed event buffers.
    pub event_buffers: HashMap<String, Vec<(GroupKey, EventBuffer)>>,
    /// Per-correlation, per-group event reference buffers.
    pub event_ref_buffers: HashMap<String, Vec<(GroupKey, EventRefBuffer)>>,
}

impl TenantStateSnapshot {
    /// An empty snapshot for `tenant`.
    pub fn empty(tenant: Option<TenantId>) -> Self {
        TenantStateSnapshot {
            tenant,
            windows: HashMap::new(),
            last_alert: HashMap::new(),
            event_buffers: HashMap::new(),
            event_ref_buffers: HashMap::new(),
        }
    }

    /// Number of window-state entries in this tenant's snapshot.
    pub fn window_entries(&self) -> usize {
        self.windows.values().map(Vec::len).sum::<usize>()
    }
}

/// Outcome of importing a snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportStats {
    /// Window-state entries restored.
    pub restored: usize,
    /// Window-state entries discarded because they had no tenant while
    /// tenancy requires one.
    pub discarded_untenanted: usize,
    /// Window-state entries discarded because they carried a tenant while
    /// tenancy is disabled.
    pub discarded_tenanted: usize,
}

impl std::ops::AddAssign for ImportStats {
    fn add_assign(&mut self, other: Self) {
        self.restored += other.restored;
        self.discarded_untenanted += other.discarded_untenanted;
        self.discarded_tenanted += other.discarded_tenanted;
    }
}

impl CorrelationSnapshot {
    /// Whether the snapshot carries state outside the per-ruleset map.
    pub fn has_collection_state(&self) -> bool {
        !self.windows.is_empty()
            || !self.last_alert.is_empty()
            || !self.event_buffers.is_empty()
            || !self.event_ref_buffers.is_empty()
            || !self.tenants.is_empty()
    }

    /// Window entries in the snapshot and every per-ruleset snapshot.
    pub fn window_entries(&self) -> usize {
        self.windows.values().map(Vec::len).sum::<usize>()
            + self
                .tenants
                .iter()
                .map(TenantStateSnapshot::window_entries)
                .sum::<usize>()
            + self
                .rulesets
                .values()
                .map(CorrelationSnapshot::window_entries)
                .sum::<usize>()
    }
}

fn default_snapshot_version() -> u32 {
    1
}
