//! The risk-incident wire shape and the open-entity admin view.

use serde::Serialize;
use serde_json::Value;

/// How much contributing-detection detail to embed in a [`RiskIncidentResult`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncludeMode {
    /// Lightweight references (rule, level, score, timestamp) only.
    Refs,
    /// Full (event-stripped) contributing results.
    Results,
}

/// A lightweight reference to a contributing detection.
#[derive(Debug, Clone, Serialize)]
pub struct RiskRef {
    /// Rule id, falling back to the rule title.
    pub rule: String,
    /// Severity, lowercased.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// The risk score this firing contributed.
    pub score: i64,
    /// Contributing-detection timestamp (unix seconds).
    pub timestamp: i64,
}

/// The wire shape emitted when an entity crosses a risk threshold. One flat
/// NDJSON object, disambiguated downstream by the presence of `risk_incident_id`.
#[derive(Debug, Clone, Serialize)]
pub struct RiskIncidentResult {
    /// Surrogate UUIDv4 identity for this incident.
    pub risk_incident_id: String,
    /// The risk-object type, e.g. `user`.
    pub entity_type: String,
    /// The entity value, e.g. `alice`.
    pub entity_value: String,
    /// What crossed the threshold: `score` or `tactic_count`.
    pub trigger: &'static str,
    /// The accumulated risk score over the window.
    pub score: i64,
    /// The configured score threshold, when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_threshold: Option<i64>,
    /// The distinct ATT&CK tactic count over the window.
    pub tactic_count: u64,
    /// The configured tactic-count threshold, when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tactic_count_threshold: Option<u64>,
    /// The distinct ATT&CK tactics contributing over the window.
    pub tactics: Vec<String>,
    /// The distinct contributing sources (rule identities) over the window,
    /// bounded by `max_sources_per_entity`.
    pub sources: Vec<String>,
    /// The distinct contributing-source count over the window.
    pub source_count: u64,
    /// First and last contributing-detection timestamps (unix seconds).
    pub window_start: i64,
    pub window_end: i64,
    /// Number of contributing detections retained over the window.
    pub result_count: u64,
    /// Contributing references (`include: refs`), bounded by
    /// `max_results_per_incident`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refs: Option<Vec<RiskRef>>,
    /// Contributing results (`include: results`), event payloads stripped and
    /// stored as serialized JSON values, bounded by `max_results_per_incident`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<Value>>,
}

/// A read-only view of one open entity, served by `GET /api/v1/risk`.
#[derive(Debug, Clone, Serialize)]
pub struct RiskEntityView {
    /// The risk-object type.
    pub entity_type: String,
    /// The entity value.
    pub entity_value: String,
    /// The accumulated risk score over the window.
    pub score: i64,
    /// The distinct ATT&CK tactic count over the window.
    pub tactic_count: u64,
    /// The distinct contributing-source count over the window.
    pub source_count: u64,
    /// Number of contributing detections retained over the window.
    pub result_count: u64,
    /// First and last contributing-detection timestamps (unix seconds).
    pub window_start: i64,
    pub window_end: i64,
    /// When this entity last fired an incident, if ever (unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_fired: Option<i64>,
}
