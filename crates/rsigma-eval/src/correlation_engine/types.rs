use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;

use rsigma_parser::{CorrelationType, Level};

use crate::correlation::EventBuffer;
use crate::correlation::{EventRef, EventRefBuffer, GroupKey, WindowState};
use crate::result::MatchResult;

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
        }
    }
}

// =============================================================================
// Result types
// =============================================================================

/// Combined result from processing a single event.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessResult {
    /// Detection rule matches (stateless, immediate).
    pub detections: Vec<MatchResult>,
    /// Correlation rule matches (stateful, accumulated).
    pub correlations: Vec<CorrelationResult>,
}

/// The result of a correlation rule firing.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationResult {
    /// Title of the correlation rule.
    pub rule_title: String,
    /// ID of the correlation rule (if present).
    pub rule_id: Option<String>,
    /// Severity level.
    pub level: Option<Level>,
    /// Tags from the correlation rule.
    pub tags: Vec<String>,
    /// Type of correlation.
    pub correlation_type: CorrelationType,
    /// Group-by field names and their values for this match.
    pub group_key: Vec<(String, String)>,
    /// The aggregated value that triggered the condition (count, sum, avg, etc.).
    pub aggregated_value: f64,
    /// The time window in seconds.
    pub timespan_secs: u64,
    /// Full event bodies, included when `correlation_event_mode` is `Full`.
    ///
    /// Contains up to `max_correlation_events` recently stored window events.
    /// Events are decompressed from deflate storage on output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<serde_json::Value>>,
    /// Lightweight event references, included when `correlation_event_mode` is `Refs`.
    ///
    /// Contains up to `max_correlation_events` timestamp + optional ID pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_refs: Option<Vec<EventRef>>,
    /// Custom attributes from the original Sigma correlation rule (merged
    /// view of arbitrary top-level keys, the `custom_attributes:` block, and
    /// any pipeline-applied overrides).
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub custom_attributes: Arc<HashMap<String, serde_json::Value>>,
}

/// Serializable snapshot of all mutable correlation state.
///
/// Uses stable string identifiers (correlation id/name/title) as keys so the
/// snapshot can be restored after a rule reload, even if internal indices change.
/// Inner maps use `Vec<(GroupKey, T)>` instead of `HashMap<GroupKey, T>` because
/// `GroupKey` cannot be used as a JSON object key.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CorrelationSnapshot {
    /// Schema version — used to detect incompatible snapshots on load.
    #[serde(default = "default_snapshot_version")]
    pub version: u32,
    /// Per-correlation, per-group window state.
    pub windows: HashMap<String, Vec<(GroupKey, WindowState)>>,
    /// Per-correlation, per-group last alert timestamp (for suppression).
    pub last_alert: HashMap<String, Vec<(GroupKey, i64)>>,
    /// Per-correlation, per-group compressed event buffers.
    pub event_buffers: HashMap<String, Vec<(GroupKey, EventBuffer)>>,
    /// Per-correlation, per-group event reference buffers.
    pub event_ref_buffers: HashMap<String, Vec<(GroupKey, EventRefBuffer)>>,
}

fn default_snapshot_version() -> u32 {
    1
}
