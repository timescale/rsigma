//! Match result types for rule evaluation.

use std::collections::HashMap;
use std::sync::Arc;

use rsigma_parser::Level;
use serde::Serialize;

/// The result of a rule matching an event.
///
/// Contains the matched rule metadata plus details about which
/// selections and fields triggered the match.
#[derive(Debug, Clone, Serialize)]
pub struct MatchResult {
    /// Title of the matched rule.
    pub rule_title: String,
    /// ID of the matched rule (if present).
    pub rule_id: Option<String>,
    /// Severity level.
    pub level: Option<Level>,
    /// Tags from the matched rule.
    pub tags: Vec<String>,
    /// Which named detections (selections) matched.
    pub matched_selections: Vec<String>,
    /// Specific field matches that triggered the detection.
    pub matched_fields: Vec<FieldMatch>,
    /// The full event that triggered the match, included when the
    /// `rsigma.include_event` custom attribute is set to `"true"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<serde_json::Value>,
    /// Custom attributes carried from the original Sigma rule.
    ///
    /// Contains the merged view of (a) arbitrary non-standard top-level keys,
    /// (b) the explicit `custom_attributes:` block, and (c) anything added by
    /// pipeline `SetCustomAttribute` transformations.
    /// Wrapped in `Arc` so that per-match cloning is a pointer bump.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub custom_attributes: Arc<HashMap<String, serde_json::Value>>,
}

/// A specific field match within a detection.
#[derive(Debug, Clone, Serialize)]
pub struct FieldMatch {
    /// The field name that matched.
    pub field: String,
    /// The event value that triggered the match.
    pub value: serde_json::Value,
}
