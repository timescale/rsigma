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

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::Duration;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::MetricsHook;

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

/// Byte-bounded in-memory retention of admitted detection events, keyed by
/// deterministic `group_by` incident id.
///
/// ```
/// use std::time::Duration;
/// use rsigma_runtime::{AdmittedEvent, AdmittedMatch, CaptureConfig, CaptureRing, NoopMetrics};
///
/// let mut ring = CaptureRing::new(CaptureConfig {
///     max_event_bytes: 1024,
///     max_bytes_per_incident: 4096,
///     max_capture_bytes: 8192,
///     ttl: Duration::from_secs(60),
///     ..CaptureConfig::default()
/// });
/// ring.admit(
///     AdmittedEvent {
///         incident_id: "inc-1".into(),
///         is_fresh_generation: true,
///         event: serde_json::json!({"user": "alice"}),
///         matches: vec![AdmittedMatch {
///             rule_id: "r1".into(),
///             rule_title: "r1".into(),
///             fingerprint: None,
///         }],
///     },
///     0,
///     &NoopMetrics,
/// );
/// assert_eq!(ring.stats().incidents, 1);
/// ```
#[derive(Debug)]
pub struct CaptureRing {
    config: CaptureConfig,
    incidents: HashMap<String, RingIncident>,
    order: VecDeque<String>,
    fingerprint_index: HashMap<(String, String), String>,
    total_bytes: usize,
}

/// Limits for [`CaptureRing`]. Every field must be positive, and
/// `max_event_bytes <= max_bytes_per_incident <= max_capture_bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    /// Maximum simultaneously-retained incidents.
    pub max_captured_incidents: usize,
    /// Maximum events retained per incident.
    pub max_events_per_incident: usize,
    /// Maximum encoded JSON size of one event. Oversized events are dropped whole.
    pub max_event_bytes: usize,
    /// Maximum encoded JSON bytes retained for one incident.
    pub max_bytes_per_incident: usize,
    /// Maximum encoded JSON bytes retained across the ring.
    pub max_capture_bytes: usize,
    /// Idle lifetime after `last_seen` before the incident is evicted.
    pub ttl: Duration,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            max_captured_incidents: 1_000,
            max_events_per_incident: 1_000,
            max_event_bytes: 1024 * 1024,
            max_bytes_per_incident: 16 * 1024 * 1024,
            max_capture_bytes: 256 * 1024 * 1024,
            ttl: Duration::from_secs(24 * 60 * 60),
        }
    }
}

impl CaptureConfig {
    /// Reject a zero limit or an inverted byte hierarchy.
    pub fn validate(&self) -> Result<(), CaptureConfigError> {
        if self.max_captured_incidents == 0 {
            return Err(CaptureConfigError::NonPositive("max_captured_incidents"));
        }
        if self.max_events_per_incident == 0 {
            return Err(CaptureConfigError::NonPositive("max_events_per_incident"));
        }
        if self.max_event_bytes == 0 {
            return Err(CaptureConfigError::NonPositive("max_event_bytes"));
        }
        if self.max_bytes_per_incident == 0 {
            return Err(CaptureConfigError::NonPositive("max_bytes_per_incident"));
        }
        if self.max_capture_bytes == 0 {
            return Err(CaptureConfigError::NonPositive("max_capture_bytes"));
        }
        if self.ttl.as_secs() == 0 {
            return Err(CaptureConfigError::NonPositive("ttl"));
        }
        if self.max_event_bytes > self.max_bytes_per_incident
            || self.max_bytes_per_incident > self.max_capture_bytes
        {
            return Err(CaptureConfigError::InvertedBounds);
        }
        Ok(())
    }
}

/// Why a [`CaptureConfig`] was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureConfigError {
    /// A limit was zero.
    NonPositive(&'static str),
    /// `max_event_bytes <= max_bytes_per_incident <= max_capture_bytes` failed.
    InvertedBounds,
}

impl fmt::Display for CaptureConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonPositive(field) => {
                write!(f, "daemon.capture.{field} must be greater than zero")
            }
            Self::InvertedBounds => write!(
                f,
                "daemon.capture requires max_event_bytes <= max_bytes_per_incident <= max_capture_bytes"
            ),
        }
    }
}

impl std::error::Error for CaptureConfigError {}

/// One retained event plus the detections that matched it.
#[derive(Debug, Clone, PartialEq)]
pub struct CapturedEvent {
    /// SHA-256 hex digest of the encoded event JSON.
    pub event_digest: String,
    /// When the event was admitted (unix seconds).
    pub captured_at: i64,
    /// Detections that matched this payload.
    pub matches: Vec<AdmittedMatch>,
    /// Bare event object.
    pub event: Value,
    /// Encoded JSON size counted against the ring budgets.
    pub event_bytes: usize,
}

/// Read-only view of one ring incident.
#[derive(Debug, Clone, PartialEq)]
pub struct CaptureSnapshot {
    /// Deterministic `group_by` incident id.
    pub incident_id: String,
    /// First admission time for this generation.
    pub first_seen: i64,
    /// Last admission time for this generation.
    pub last_seen: i64,
    /// Retained events in admission order.
    pub events: Vec<CapturedEvent>,
    /// Sum of encoded event sizes.
    pub bytes: usize,
}

/// Point-in-time ring occupancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CaptureStats {
    /// Incidents currently held.
    pub incidents: usize,
    /// Events currently held.
    pub events: usize,
    /// Encoded JSON bytes currently held.
    pub bytes: usize,
}

#[derive(Debug)]
struct RingIncident {
    first_seen: i64,
    last_seen: i64,
    events: Vec<CapturedEvent>,
    bytes: usize,
    fingerprint_keys: Vec<(String, String)>,
}

impl CaptureRing {
    /// Build an empty ring. The caller must [`CaptureConfig::validate`] first.
    pub fn new(config: CaptureConfig) -> Self {
        Self {
            config,
            incidents: HashMap::new(),
            order: VecDeque::new(),
            fingerprint_index: HashMap::new(),
            total_bytes: 0,
        }
    }

    /// Current occupancy.
    pub fn stats(&self) -> CaptureStats {
        CaptureStats {
            incidents: self.incidents.len(),
            events: self.incidents.values().map(|inc| inc.events.len()).sum(),
            bytes: self.total_bytes,
        }
    }

    /// Snapshot one incident, if it is still held.
    pub fn snapshot_incident(&self, incident_id: &str) -> Option<CaptureSnapshot> {
        self.incidents.get(incident_id).map(|inc| CaptureSnapshot {
            incident_id: incident_id.to_string(),
            first_seen: inc.first_seen,
            last_seen: inc.last_seen,
            events: inc.events.clone(),
            bytes: inc.bytes,
        })
    }

    /// Snapshot the incident indexed by a detection-scoped fingerprint.
    pub fn snapshot_fingerprint(
        &self,
        rule_id: &str,
        fingerprint: &str,
    ) -> Option<CaptureSnapshot> {
        let incident_id = self
            .fingerprint_index
            .get(&(rule_id.to_string(), fingerprint.to_string()))?;
        self.snapshot_incident(incident_id)
    }

    /// Evict incidents whose `last_seen` is at least `ttl` in the past.
    pub fn expire(&mut self, now: i64, metrics: &dyn MetricsHook) {
        let ttl = self.config.ttl.as_secs() as i64;
        let stale: Vec<String> = self
            .incidents
            .iter()
            .filter(|(_, inc)| now.saturating_sub(inc.last_seen) >= ttl)
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            self.remove_incident(&id);
            metrics.on_capture_eviction("ttl");
        }
        self.refresh_gauges(metrics);
    }

    /// Admit one coalesced source-event payload.
    pub fn admit(&mut self, event: AdmittedEvent, now: i64, metrics: &dyn MetricsHook) {
        let encoded = encode_event(&event.event);
        let event_bytes = encoded.len();
        if event_bytes > self.config.max_event_bytes {
            metrics.on_capture_event_dropped("event_too_large");
            return;
        }

        if event.is_fresh_generation && self.incidents.contains_key(&event.incident_id) {
            self.remove_incident(&event.incident_id);
        }

        let exists = self.incidents.contains_key(&event.incident_id);
        if !exists {
            while self.incidents.len() >= self.config.max_captured_incidents {
                if !self.evict_oldest(Some(&event.incident_id), metrics) {
                    break;
                }
            }
            if self.incidents.len() >= self.config.max_captured_incidents {
                metrics.on_capture_event_dropped("global_byte_cap");
                return;
            }
        }

        if let Some(inc) = self.incidents.get(&event.incident_id) {
            if inc.events.len() >= self.config.max_events_per_incident {
                metrics.on_capture_event_dropped("incident_event_cap");
                return;
            }
            if inc.bytes.saturating_add(event_bytes) > self.config.max_bytes_per_incident {
                metrics.on_capture_event_dropped("incident_byte_cap");
                return;
            }
        } else if event_bytes > self.config.max_bytes_per_incident {
            metrics.on_capture_event_dropped("incident_byte_cap");
            return;
        }

        while self.total_bytes.saturating_add(event_bytes) > self.config.max_capture_bytes {
            if !self.evict_oldest(Some(&event.incident_id), metrics) {
                break;
            }
        }
        if self.total_bytes.saturating_add(event_bytes) > self.config.max_capture_bytes {
            metrics.on_capture_event_dropped("global_byte_cap");
            return;
        }

        let captured = CapturedEvent {
            event_digest: digest_bytes(&encoded),
            captured_at: now,
            matches: event.matches.clone(),
            event: event.event,
            event_bytes,
        };

        if let Some(inc) = self.incidents.get_mut(&event.incident_id) {
            inc.last_seen = now;
            inc.bytes += event_bytes;
            inc.events.push(captured);
            index_matches(
                &mut self.fingerprint_index,
                &mut inc.fingerprint_keys,
                &event.incident_id,
                &event.matches,
            );
        } else {
            let mut fingerprint_keys = Vec::new();
            index_matches(
                &mut self.fingerprint_index,
                &mut fingerprint_keys,
                &event.incident_id,
                &event.matches,
            );
            self.incidents.insert(
                event.incident_id.clone(),
                RingIncident {
                    first_seen: now,
                    last_seen: now,
                    events: vec![captured],
                    bytes: event_bytes,
                    fingerprint_keys,
                },
            );
            self.order.push_back(event.incident_id);
        }
        self.total_bytes += event_bytes;
        self.refresh_gauges(metrics);
    }

    /// Record a result the pipeline could not capture.
    pub fn reject(&mut self, reason: CaptureReject, metrics: &dyn MetricsHook) {
        if reason == CaptureReject::UnsupportedResultKind {
            metrics.on_capture_event_dropped(reason.as_str());
        }
    }

    fn evict_oldest(&mut self, except: Option<&str>, metrics: &dyn MetricsHook) -> bool {
        let Some(position) = self
            .order
            .iter()
            .position(|id| except.is_none_or(|skip| id != skip))
        else {
            return false;
        };
        let Some(id) = self.order.remove(position) else {
            return false;
        };
        self.remove_incident_at(&id);
        metrics.on_capture_eviction("ring_full");
        true
    }

    fn remove_incident(&mut self, id: &str) {
        if let Some(position) = self.order.iter().position(|existing| existing == id) {
            self.order.remove(position);
        }
        self.remove_incident_at(id);
    }

    fn remove_incident_at(&mut self, id: &str) {
        let Some(inc) = self.incidents.remove(id) else {
            return;
        };
        self.total_bytes = self.total_bytes.saturating_sub(inc.bytes);
        for key in inc.fingerprint_keys {
            if self
                .fingerprint_index
                .get(&key)
                .is_some_and(|held| held == id)
            {
                self.fingerprint_index.remove(&key);
            }
        }
    }

    fn refresh_gauges(&self, metrics: &dyn MetricsHook) {
        let stats = self.stats();
        metrics.set_capture_incidents_open(stats.incidents as i64);
        metrics.set_capture_events_held(stats.events as i64);
        metrics.set_capture_bytes_held(stats.bytes as i64);
    }
}

/// [`CaptureSink`] adapter that records ring metrics.
pub struct CaptureRingSink<'ring, 'metrics> {
    /// Mutable ring.
    pub ring: &'ring mut CaptureRing,
    /// Metrics backend.
    pub metrics: &'metrics dyn MetricsHook,
}

impl CaptureSink for CaptureRingSink<'_, '_> {
    fn admit(&mut self, event: AdmittedEvent, now: i64) {
        self.ring.admit(event, now, self.metrics);
    }

    fn reject(&mut self, reason: CaptureReject) {
        self.ring.reject(reason, self.metrics);
    }
}

/// SHA-256 hex digest of a bare event's encoded JSON.
pub fn event_digest(event: &Value) -> String {
    digest_bytes(&encode_event(event))
}

fn encode_event(event: &Value) -> Vec<u8> {
    serde_json::to_vec(event).unwrap_or_default()
}

fn digest_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

fn index_matches(
    index: &mut HashMap<(String, String), String>,
    keys: &mut Vec<(String, String)>,
    incident_id: &str,
    matches: &[AdmittedMatch],
) {
    for matched in matches {
        let Some(fingerprint) = matched.fingerprint.as_deref() else {
            continue;
        };
        let key = (matched.rule_id.clone(), fingerprint.to_string());
        if !keys.contains(&key) {
            keys.push(key.clone());
        }
        index.insert(key, incident_id.to_string());
    }
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

    fn event(id: &str, n: u8) -> AdmittedEvent {
        AdmittedEvent {
            incident_id: id.to_string(),
            is_fresh_generation: false,
            event: serde_json::json!({"n": n}),
            matches: vec![AdmittedMatch {
                rule_id: "r1".into(),
                rule_title: "r1".into(),
                fingerprint: Some(format!("fp-{id}")),
            }],
        }
    }

    fn tiny_config() -> CaptureConfig {
        CaptureConfig {
            max_captured_incidents: 2,
            max_events_per_incident: 2,
            max_event_bytes: 64,
            max_bytes_per_incident: 80,
            max_capture_bytes: 160,
            ttl: Duration::from_secs(10),
        }
    }

    #[test]
    fn config_rejects_zero_and_inverted_bounds() {
        let cfg = CaptureConfig {
            max_captured_incidents: 0,
            ..CaptureConfig::default()
        };
        assert!(matches!(
            cfg.validate(),
            Err(CaptureConfigError::NonPositive("max_captured_incidents"))
        ));
        let cfg = CaptureConfig {
            max_event_bytes: 100,
            max_bytes_per_incident: 50,
            ..CaptureConfig::default()
        };
        assert_eq!(cfg.validate(), Err(CaptureConfigError::InvertedBounds));
        assert!(CaptureConfig::default().validate().is_ok());
    }

    #[test]
    fn ring_retains_and_indexes_fingerprints() {
        let mut ring = CaptureRing::new(tiny_config());
        let mut ev = event("a", 1);
        ev.is_fresh_generation = true;
        ring.admit(ev, 0, &crate::NoopMetrics);
        assert_eq!(ring.stats().incidents, 1);
        assert!(ring.snapshot_incident("a").is_some());
        assert!(ring.snapshot_fingerprint("r1", "fp-a").is_some());
    }

    #[test]
    fn ring_drops_oversized_events_whole() {
        let mut ring = CaptureRing::new(tiny_config());
        let mut ev = event("a", 1);
        ev.event = serde_json::json!({"pad": "x".repeat(200)});
        ev.is_fresh_generation = true;
        ring.admit(ev, 0, &crate::NoopMetrics);
        assert_eq!(ring.stats().events, 0);
    }

    #[test]
    fn ring_enforces_per_incident_event_and_byte_caps() {
        let mut ring = CaptureRing::new(tiny_config());
        let mut first = event("a", 1);
        first.is_fresh_generation = true;
        ring.admit(first, 0, &crate::NoopMetrics);
        ring.admit(event("a", 2), 1, &crate::NoopMetrics);
        ring.admit(event("a", 3), 2, &crate::NoopMetrics);
        assert_eq!(ring.snapshot_incident("a").unwrap().events.len(), 2);
    }

    #[test]
    fn ring_evicts_fifo_when_incident_cap_is_hit() {
        let mut ring = CaptureRing::new(tiny_config());
        let mut a = event("a", 1);
        a.is_fresh_generation = true;
        let mut b = event("b", 1);
        b.is_fresh_generation = true;
        let mut c = event("c", 1);
        c.is_fresh_generation = true;
        ring.admit(a, 0, &crate::NoopMetrics);
        ring.admit(b, 1, &crate::NoopMetrics);
        ring.admit(c, 2, &crate::NoopMetrics);
        assert!(ring.snapshot_incident("a").is_none());
        assert!(ring.snapshot_incident("b").is_some());
        assert!(ring.snapshot_incident("c").is_some());
        assert!(ring.snapshot_fingerprint("r1", "fp-a").is_none());
    }

    #[test]
    fn ring_replaces_stale_generation() {
        let mut ring = CaptureRing::new(tiny_config());
        let mut first = event("a", 1);
        first.is_fresh_generation = true;
        ring.admit(first, 0, &crate::NoopMetrics);
        ring.admit(event("a", 2), 1, &crate::NoopMetrics);
        let mut fresh = event("a", 9);
        fresh.is_fresh_generation = true;
        ring.admit(fresh, 5, &crate::NoopMetrics);
        let snap = ring.snapshot_incident("a").unwrap();
        assert_eq!(snap.events.len(), 1);
        assert_eq!(snap.first_seen, 5);
        assert_eq!(snap.events[0].event["n"], 9);
    }

    #[test]
    fn ring_expires_idle_incidents() {
        let mut ring = CaptureRing::new(tiny_config());
        let mut ev = event("a", 1);
        ev.is_fresh_generation = true;
        ring.admit(ev, 0, &crate::NoopMetrics);
        ring.expire(9, &crate::NoopMetrics);
        assert_eq!(ring.stats().incidents, 1);
        ring.expire(10, &crate::NoopMetrics);
        assert_eq!(ring.stats().incidents, 0);
    }
}
