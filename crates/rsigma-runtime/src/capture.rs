//! Capture hook types for admitted detection evidence.
//!
//! The alert pipeline offers detections that survived inhibition and silencing
//! to a [`CaptureSink`] before dedup folds them. The sink is optional; when it
//! is absent, [`AlertPipeline::process`](crate::AlertPipeline::process) output
//! is unchanged.
//!
//! ```
//! use rsigma_runtime::{AdmittedEvent, CaptureReject, CaptureSink};
//!
//! #[derive(Default)]
//! struct Recorder {
//!     admitted: usize,
//! }
//!
//! impl CaptureSink for Recorder {
//!     fn admit(&mut self, _event: AdmittedEvent, _now: i64) {
//!         self.admitted += 1;
//!     }
//!     fn reject(&mut self, _reason: CaptureReject) {}
//! }
//!
//! let mut sink = Recorder::default();
//! sink.reject(CaptureReject::MissingEvent);
//! assert_eq!(sink.admitted, 0);
//! ```

use std::collections::HashMap;
use std::fmt;

use serde_json::Value;

/// One source-event payload admitted for a `group_by` incident, with every
/// detection that matched it in the same processing call.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmittedEvent {
    /// Deterministic `group_by` incident id.
    pub incident_id: String,
    /// True when this incident id is not currently open in the incident store.
    pub is_fresh_generation: bool,
    /// The retained source-event payload.
    pub event: Value,
    /// Every detection that matched this payload in the same processing call.
    pub matches: Vec<AdmittedMatch>,
}

/// A single rule match contributing to an [`AdmittedEvent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedMatch {
    /// Rule id, falling back to the rule title.
    pub rule_id: String,
    /// Rule title as loaded.
    pub rule_title: String,
    /// Dedup fingerprint when dedup is configured.
    pub fingerprint: Option<String>,
}

/// Why an admitted-looking result was not offered to the sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureReject {
    /// A correlation result, or any non-detection body.
    UnsupportedResultKind,
    /// The incident store cannot accept a new incident for this group id.
    NotAssignable,
    /// The detection had no retained event payload.
    MissingEvent,
}

impl CaptureReject {
    /// Stable metric label for this reject reason.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedResultKind => "unsupported_result_kind",
            Self::NotAssignable => "not_assignable",
            Self::MissingEvent => "missing_event",
        }
    }
}

/// Why an alert pipeline cannot host capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureIncompatibility {
    /// No `group:` block, or grouping is not `group_by`.
    MissingGroupBy,
    /// `group.mode` is `entity_graph`.
    EntityGraph,
    /// Dedup is configured but its fingerprint omits a `group.by` selector.
    DedupSelectorsMissing(Vec<String>),
}

impl fmt::Display for CaptureIncompatibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingGroupBy => write!(
                f,
                "capture requires an alert pipeline with group.mode: group_by"
            ),
            Self::EntityGraph => write!(f, "capture does not support group.mode: entity_graph"),
            Self::DedupSelectorsMissing(selectors) => write!(
                f,
                "dedup.fingerprint must include every group.by selector (missing: {})",
                selectors.join(", ")
            ),
        }
    }
}

impl std::error::Error for CaptureIncompatibility {}

/// Receives detections that survived inhibition and silencing, before dedup.
pub trait CaptureSink {
    /// Retain one coalesced source-event payload.
    fn admit(&mut self, event: AdmittedEvent, now: i64);
    /// Record a result that could not be captured.
    fn reject(&mut self, reason: CaptureReject);
}

/// Internal pending admit used by the pipeline before coalescing.
pub(crate) struct PendingAdmit {
    pub incident_id: String,
    pub is_fresh_generation: bool,
    pub event: Value,
    pub match_: AdmittedMatch,
}

pub(crate) enum PendingCapture {
    Admit(PendingAdmit),
    Reject(CaptureReject),
}

pub(crate) fn flush_pending(pending: Vec<PendingCapture>, sink: &mut dyn CaptureSink, now: i64) {
    let mut admits = Vec::new();
    for item in pending {
        match item {
            PendingCapture::Admit(admit) => admits.push(admit),
            PendingCapture::Reject(reason) => sink.reject(reason),
        }
    }
    for event in coalesce_admits(admits) {
        sink.admit(event, now);
    }
}

/// Collapse equal event payloads that share an incident id into one admit
/// with a combined matches array, preserving first-seen order.
fn coalesce_admits(pending: Vec<PendingAdmit>) -> Vec<AdmittedEvent> {
    let mut order = Vec::new();
    let mut map: HashMap<(String, Vec<u8>), AdmittedEvent> = HashMap::new();
    for item in pending {
        let key_bytes = serde_json::to_vec(&item.event).unwrap_or_default();
        let key = (item.incident_id.clone(), key_bytes);
        if let Some(existing) = map.get_mut(&key) {
            existing.matches.push(item.match_);
            existing.is_fresh_generation |= item.is_fresh_generation;
        } else {
            order.push(key.clone());
            map.insert(
                key,
                AdmittedEvent {
                    incident_id: item.incident_id,
                    is_fresh_generation: item.is_fresh_generation,
                    event: item.event,
                    matches: vec![item.match_],
                },
            );
        }
    }
    order
        .into_iter()
        .filter_map(|key| map.remove(&key))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admit(incident: &str, event: Value, rule: &str) -> PendingAdmit {
        PendingAdmit {
            incident_id: incident.to_string(),
            is_fresh_generation: true,
            event,
            match_: AdmittedMatch {
                rule_id: rule.to_string(),
                rule_title: rule.to_string(),
                fingerprint: None,
            },
        }
    }

    #[test]
    fn coalesce_combines_matches_for_equal_payloads() {
        let event = serde_json::json!({"user": "alice"});
        let out = coalesce_admits(vec![
            admit("inc-1", event.clone(), "r1"),
            admit("inc-1", event, "r2"),
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].matches.len(), 2);
        assert_eq!(out[0].matches[0].rule_id, "r1");
        assert_eq!(out[0].matches[1].rule_id, "r2");
    }

    #[test]
    fn coalesce_keeps_distinct_incidents_and_payloads() {
        let out = coalesce_admits(vec![
            admit("inc-1", serde_json::json!({"n": 1}), "r1"),
            admit("inc-2", serde_json::json!({"n": 1}), "r1"),
            admit("inc-1", serde_json::json!({"n": 2}), "r1"),
        ]);
        assert_eq!(out.len(), 3);
    }
}
