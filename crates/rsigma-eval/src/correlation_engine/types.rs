use std::collections::HashMap;

use serde::Serialize;

use crate::correlation::EventBuffer;
use crate::correlation::{EventRefBuffer, GroupKey, WindowState};
use crate::result::EvaluationResult;

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

/// What to do when an event lacks the configured tenant field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MissingTenantPolicy {
    /// Reject the event from correlation (detections still fire).
    #[default]
    Reject,
    /// Assign to a synthetic "__default__" tenant.
    DefaultTenant,
}

impl std::str::FromStr for MissingTenantPolicy {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "reject" => Ok(MissingTenantPolicy::Reject),
            "default" => Ok(MissingTenantPolicy::DefaultTenant),
            _ => Err(format!(
                "Unknown missing tenant policy: {s} (expected 'reject' or 'default')"
            )),
        }
    }
}

/// Multi-tenancy configuration for correlation isolation.
#[derive(Debug, Clone, Default)]
pub struct TenantConfig {
    /// Event field name from which to extract the tenant identifier.
    /// When `None`, multi-tenancy is disabled (single-tenant mode).
    pub tenant_field: Option<String>,

    /// Policy when the tenant field is missing from an event.
    pub missing_tenant_policy: MissingTenantPolicy,
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

    /// Whether to emit detection-level matches for rules that are only
    /// referenced by correlations (where `generate: false`).
    ///
    /// Default: `true` (emit all detection matches).
    /// Set to `false` to suppress detection output for correlation-only rules.
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

    /// Multi-tenancy configuration. When `tenant.tenant_field` is set,
    /// correlation state is partitioned by tenant — events from different
    /// tenants never share correlation windows.
    pub tenant: TenantConfig,
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
            suppress: None,
            action_on_match: CorrelationAction::default(),
            emit_detections: true,
            correlation_event_mode: CorrelationEventMode::default(),
            max_correlation_events: 10,
            tenant: TenantConfig::default(),
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
/// Each entry is a tuple of `(Option<tenant_id>, GroupKey, T)`.
/// The `Option<String>` is the serialized tenant ID (`None` in single-tenant mode).
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CorrelationSnapshot {
    /// Schema version — used to detect incompatible snapshots on load.
    #[serde(default = "default_snapshot_version")]
    pub version: u32,
    /// Per-correlation, per-(tenant, group) window state.
    pub windows: HashMap<String, Vec<(Option<String>, GroupKey, WindowState)>>,
    /// Per-correlation, per-(tenant, group) last alert timestamp (for suppression).
    pub last_alert: HashMap<String, Vec<(Option<String>, GroupKey, i64)>>,
    /// Per-correlation, per-(tenant, group) compressed event buffers.
    pub event_buffers: HashMap<String, Vec<(Option<String>, GroupKey, EventBuffer)>>,
    /// Per-correlation, per-(tenant, group) event reference buffers.
    pub event_ref_buffers: HashMap<String, Vec<(Option<String>, GroupKey, EventRefBuffer)>>,
}

fn default_snapshot_version() -> u32 {
    2
}
