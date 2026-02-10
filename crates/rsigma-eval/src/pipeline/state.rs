//! Pipeline state tracking.
//!
//! Tracks which transformations have been applied (per-pipeline and per-rule),
//! stores key-value state set by `SetState` transformations, and holds pipeline
//! variables used for placeholder expansion.

use std::collections::{HashMap, HashSet};

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
}
