//! Pipeline state tracking.
//!
//! Tracks which transformations have been applied (per-pipeline and per-rule),
//! stores key-value state set by `SetState` transformations, and holds pipeline
//! variables used for placeholder expansion.

use std::collections::{HashMap, HashSet};

use super::sources::SourceStatus;

/// Mutable state carried through a pipeline's application to one or more rules.
#[derive(Debug, Clone, Default)]
pub struct PipelineState {
    /// IDs of transformations that have been applied globally (across all rules).
    pub applied_items: HashSet<String>,

    /// IDs of transformations applied to the current rule being processed.
    /// Reset between rules.
    pub rule_applied: HashSet<String>,

    /// IDs of transformations applied to the current detection item being processed.
    /// Reset between detection items.
    pub detection_item_applied: HashSet<String>,

    /// Arbitrary key-value state set by `SetState` transformations.
    pub state: HashMap<String, serde_json::Value>,

    /// Pipeline variables from the `vars` section, used for placeholder expansion.
    pub vars: HashMap<String, Vec<String>>,

    /// Resolution status of each dynamic source (keyed by source ID).
    pub source_status: HashMap<String, SourceStatus>,
}

impl PipelineState {
    /// Create a new state initialized with the given pipeline variables.
    pub fn new(vars: HashMap<String, Vec<String>>) -> Self {
        Self {
            vars,
            ..Default::default()
        }
    }

    /// Record that a transformation with the given ID was applied.
    pub fn mark_applied(&mut self, id: &str) {
        self.applied_items.insert(id.to_string());
        self.rule_applied.insert(id.to_string());
        self.detection_item_applied.insert(id.to_string());
    }

    /// Check if a transformation with the given ID was applied (globally or to current rule).
    pub fn was_applied(&self, id: &str) -> bool {
        self.applied_items.contains(id) || self.rule_applied.contains(id)
    }

    /// Check if a transformation was applied to the current detection item.
    pub fn was_applied_to_detection_item(&self, id: &str) -> bool {
        self.detection_item_applied.contains(id)
    }

    /// Get a state value.
    pub fn get_state(&self, key: &str) -> Option<&serde_json::Value> {
        self.state.get(key)
    }

    /// Set a state value.
    pub fn set_state(&mut self, key: String, val: serde_json::Value) {
        self.state.insert(key, val);
    }

    /// Check if a state key has a specific string value.
    pub fn state_matches(&self, key: &str, val: &str) -> bool {
        self.state
            .get(key)
            .and_then(|v| v.as_str())
            .is_some_and(|s| s == val)
    }

    /// Reset per-rule tracking (called before processing each rule).
    pub fn reset_rule(&mut self) {
        self.rule_applied.clear();
        self.detection_item_applied.clear();
    }

    /// Reset per-detection-item tracking.
    pub fn reset_detection_item(&mut self) {
        self.detection_item_applied.clear();
    }

    /// Initialize source status tracking for a set of source IDs.
    /// All sources start in `Pending` state.
    pub fn init_sources(&mut self, source_ids: impl IntoIterator<Item = String>) {
        for id in source_ids {
            self.source_status.insert(id, SourceStatus::Pending);
        }
    }

    /// Mark a source as successfully resolved.
    pub fn mark_source_resolved(&mut self, id: &str) {
        self.source_status
            .insert(id.to_string(), SourceStatus::Resolved);
    }

    /// Mark a source as failed.
    pub fn mark_source_failed(&mut self, id: &str) {
        self.source_status
            .insert(id.to_string(), SourceStatus::Failed);
    }

    /// Get the resolution status of a source.
    pub fn source_status(&self, id: &str) -> Option<SourceStatus> {
        self.source_status.get(id).copied()
    }

    /// Returns `true` if all tracked sources have been resolved.
    pub fn all_sources_resolved(&self) -> bool {
        self.source_status
            .values()
            .all(|s| *s == SourceStatus::Resolved)
    }

    /// Returns source IDs that are still pending resolution.
    pub fn pending_sources(&self) -> Vec<&str> {
        self.source_status
            .iter()
            .filter(|(_, status)| **status == SourceStatus::Pending)
            .map(|(id, _)| id.as_str())
            .collect()
    }
}
