//! Opt-in observer that records every field name seen at evaluation
//! time so consumers can report which event fields are not referenced
//! by any loaded rule (gap signal) and which rule fields have never
//! been seen in events (broken-coverage signal).
//!
//! Lives in `rsigma-eval` because the observer only depends on the
//! [`Event`] trait. The daemon (`rsigma-runtime` + `rsigma-cli`'s
//! `engine daemon`) and the one-shot evaluator (`rsigma-cli`'s
//! `engine eval`) both consume the same type so the report shape is
//! consistent across runtimes.
//!
//! # Design
//!
//! - Backed by a `std::sync::Mutex<HashMap<Arc<str>, u64>>`. The mutex
//!   is only held long enough to bump or insert a counter; the lock
//!   never wraps user code that could panic, so poisoning is
//!   effectively impossible in practice and the `lock().unwrap()`
//!   calls below treat poisoning as a programmer bug.
//! - A hard cap (`max_keys`) bounds memory. Once the cap is reached
//!   new keys are dropped and the `overflow_dropped` counter is
//!   incremented; existing counters keep updating so the observer
//!   keeps surfacing high-frequency keys even on a saturated set.
//! - The observer is opt-in: callers construct an `Arc<FieldObserver>`
//!   only when their `--observe-fields` flag is set. When unset the
//!   observation call sites stay unwired and the hot path is
//!   untouched.
//! - Keys are stored as `Arc<str>` so a snapshot only refcount-bumps
//!   each key rather than copying the string. Trade: one extra
//!   allocation per first-time-insert (Arc header) in exchange for
//!   near-free repeated snapshots.
//! - Lifetime counters (`lifetime_events_observed`,
//!   `lifetime_overflow_dropped`) are monotonic across resets so
//!   Prometheus counter bridges don't desync when the daemon resets
//!   the observer via `DELETE /api/v1/fields/observer`.
//!
//! # Coordinates
//!
//! - Iterate [`Event::field_keys`](crate::Event::field_keys) once per
//!   event before evaluation. For JSON events this is a recursive
//!   walk that allocates one `String` per leaf path (dot-joined paths
//!   are not substrings of the source value); for flat formats like
//!   `KvEvent` the override returns `Cow::Borrowed`. The cost is
//!   acceptable in the opt-in diagnostic mode but is not free.
//! - Render the gap and broken-coverage signals by joining a
//!   [`snapshot`](FieldObserver::snapshot) against a
//!   [`RuleFieldSet`](crate::RuleFieldSet).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::event::Event;
use crate::fields::{FieldOrigin, RuleFieldSet};

/// Single field-name counter as exposed via the snapshot API.
///
/// The field name is held as `Arc<str>` so snapshotting only bumps a
/// refcount rather than copying every key out of the observer's
/// internal map. Treat as a string slice for read access:
/// `entry.field.as_ref()` or `&*entry.field`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldObservationEntry {
    /// Dot-joined field path (matches what `Event::field_keys` returns).
    pub field: Arc<str>,
    /// Number of events that contained this field since the last reset.
    pub count: u64,
}

/// Immutable snapshot of an observer's state at one moment in time.
///
/// Returned by [`FieldObserver::snapshot`]; consumers (the daemon's
/// HTTP handlers, the `engine eval` report writer) render coverage
/// reports from this against a [`RuleFieldSet`](crate::RuleFieldSet).
#[derive(Debug, Clone, Default)]
pub struct FieldObservation {
    /// Per-field counters, sorted by descending count then ascending name.
    pub entries: Vec<FieldObservationEntry>,
    /// Number of events evaluated by the observer since construction or
    /// the last reset.
    pub events_observed: u64,
    /// Distinct field names tracked (saturates at `max_keys`).
    pub unique_keys: usize,
    /// Number of insert attempts dropped because the observer was at
    /// capacity since the last reset.
    pub overflow_dropped: u64,
    /// Lifetime total of events evaluated since the observer was
    /// constructed, ignoring resets. Drives Prometheus counters, which
    /// must be monotonic.
    pub lifetime_events_observed: u64,
    /// Lifetime total of insert attempts dropped because the observer
    /// was at capacity, ignoring resets. Drives Prometheus counters.
    pub lifetime_overflow_dropped: u64,
    /// Configured ceiling for distinct keys.
    pub max_keys: usize,
    /// Seconds since the observer was created (or last reset).
    pub uptime_seconds: f64,
}

/// Capped, opt-in field-name counter shared across producers (the
/// daemon's event task, the eval streaming loop) and consumers (the
/// daemon's HTTP handlers, the eval report writer).
pub struct FieldObserver {
    inner: Mutex<HashMap<Arc<str>, u64>>,
    max_keys: usize,
    /// Resets to 0 on [`reset`](Self::reset). Drives the "since-last-reset"
    /// view exposed in [`FieldObservation::overflow_dropped`].
    overflow_dropped: AtomicU64,
    /// Resets to 0 on [`reset`](Self::reset). Drives the "since-last-reset"
    /// view exposed in [`FieldObservation::events_observed`].
    events_observed: AtomicU64,
    /// Monotonic. Never reset. Drives the Prometheus counter bridge so
    /// the lifetime metric stays consistent across observer resets.
    lifetime_events_observed: AtomicU64,
    /// Monotonic. Never reset. Drives the Prometheus counter bridge.
    lifetime_overflow_dropped: AtomicU64,
    start: Mutex<Instant>,
}

impl FieldObservation {
    /// Join the snapshot against a [`RuleFieldSet`] and return the
    /// partitioned coverage view in a single pass.
    ///
    /// Returned references borrow from `self` (the entries) and the
    /// supplied `rule_field_set` (the missing entries), so this is
    /// allocation-light: one `Vec` for the unknown borrows, one `Vec`
    /// for the missing borrows, one `HashSet` for the seen lookup.
    ///
    /// Centralises the logic shared between the daemon's
    /// `GET /api/v1/fields*` handlers and the `engine eval` end-of-run
    /// report so the two surfaces cannot drift on field semantics.
    pub fn coverage<'a>(&'a self, rule_field_set: &'a RuleFieldSet) -> FieldCoverage<'a> {
        let mut unknown: Vec<&'a FieldObservationEntry> = Vec::new();
        let mut intersection_count: usize = 0;
        let mut seen: HashSet<&'a str> = HashSet::with_capacity(self.entries.len());
        for entry in &self.entries {
            let field: &str = &entry.field;
            seen.insert(field);
            if rule_field_set.contains(field) {
                intersection_count += 1;
            } else {
                unknown.push(entry);
            }
        }
        let missing: Vec<(&'a str, &'a FieldOrigin)> = rule_field_set
            .iter()
            .filter(|(name, _)| !seen.contains(name))
            .collect();
        FieldCoverage {
            unknown,
            intersection_count,
            missing,
        }
    }
}

/// Borrowed view over a [`FieldObservation`] joined against a
/// [`RuleFieldSet`]. Produced by [`FieldObservation::coverage`].
///
/// Consumers (the daemon HTTP handlers, the eval report writer) own
/// the JSON shape; this struct only provides the partitioned data.
pub struct FieldCoverage<'a> {
    /// Observed fields not referenced by any loaded rule (gap signal).
    /// Ordered the same way as [`FieldObservation::entries`]: by
    /// descending count, then ascending name.
    pub unknown: Vec<&'a FieldObservationEntry>,
    /// Count of observed fields that *are* rule-referenced.
    pub intersection_count: usize,
    /// Rule field names that have not appeared in any observed event
    /// (broken-coverage signal), paired with their [`FieldOrigin`] so
    /// consumers can render rule titles and source kinds.
    pub missing: Vec<(&'a str, &'a FieldOrigin)>,
}

impl FieldObserver {
    /// Create a new observer with the given upper bound on distinct keys.
    ///
    /// A `max_keys` of 0 is allowed and disables tracking entirely; every
    /// observed field counts as overflow. Callers wanting "no cap" should
    /// pick a large finite number (e.g. `usize::MAX / 2`).
    pub fn new(max_keys: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_keys,
            overflow_dropped: AtomicU64::new(0),
            events_observed: AtomicU64::new(0),
            lifetime_events_observed: AtomicU64::new(0),
            lifetime_overflow_dropped: AtomicU64::new(0),
            start: Mutex::new(Instant::now()),
        }
    }

    /// Walk the event's field keys and update the per-field counters.
    ///
    /// Insertion of a new key is skipped once the observer is at capacity;
    /// already-tracked keys keep counting. The method takes `&self`, so
    /// the observer can be shared behind an `Arc` without locking from
    /// the caller's side.
    pub fn observe<E: Event + ?Sized>(&self, event: &E) {
        self.events_observed.fetch_add(1, Ordering::Relaxed);
        self.lifetime_events_observed
            .fetch_add(1, Ordering::Relaxed);
        let keys = event.field_keys();
        if keys.is_empty() {
            return;
        }
        let mut overflow_local = 0u64;
        let mut counts = self.inner.lock().expect("field observer mutex poisoned");
        for key in keys {
            if let Some(slot) = counts.get_mut(key.as_ref()) {
                *slot = slot.saturating_add(1);
            } else if counts.len() < self.max_keys {
                counts.insert(Arc::<str>::from(key.as_ref()), 1);
            } else {
                overflow_local = overflow_local.saturating_add(1);
            }
        }
        drop(counts);
        if overflow_local > 0 {
            self.overflow_dropped
                .fetch_add(overflow_local, Ordering::Relaxed);
            self.lifetime_overflow_dropped
                .fetch_add(overflow_local, Ordering::Relaxed);
        }
    }

    /// Snapshot the current counts. Entries are sorted by descending
    /// count, then by ascending name for deterministic output.
    ///
    /// Cheap relative to the cardinality of the observer: each entry
    /// only refcount-clones the `Arc<str>` key rather than copying the
    /// key bytes, so a 10 000-key snapshot costs ~10 000 atomic
    /// increments plus one `Vec` allocation, not 10 000 `String`
    /// allocations.
    pub fn snapshot(&self) -> FieldObservation {
        let counts = self.inner.lock().expect("field observer mutex poisoned");
        let mut entries: Vec<FieldObservationEntry> = counts
            .iter()
            .map(|(k, v)| FieldObservationEntry {
                field: Arc::clone(k),
                count: *v,
            })
            .collect();
        let unique_keys = entries.len();
        drop(counts);
        entries.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.field.cmp(&b.field)));
        FieldObservation {
            entries,
            events_observed: self.events_observed.load(Ordering::Relaxed),
            unique_keys,
            overflow_dropped: self.overflow_dropped.load(Ordering::Relaxed),
            lifetime_events_observed: self.lifetime_events_observed.load(Ordering::Relaxed),
            lifetime_overflow_dropped: self.lifetime_overflow_dropped.load(Ordering::Relaxed),
            max_keys: self.max_keys,
            uptime_seconds: self
                .start
                .lock()
                .expect("field observer start mutex poisoned")
                .elapsed()
                .as_secs_f64(),
        }
    }

    /// Reset every counter and the overflow tally. Returns the previous
    /// `(unique_keys, events_observed)` pair so the API endpoint can
    /// report what was cleared.
    pub fn reset(&self) -> (usize, u64) {
        let mut counts = self.inner.lock().expect("field observer mutex poisoned");
        let previous_keys = counts.len();
        counts.clear();
        drop(counts);
        let previous_events = self.events_observed.swap(0, Ordering::Relaxed);
        self.overflow_dropped.store(0, Ordering::Relaxed);
        *self
            .start
            .lock()
            .expect("field observer start mutex poisoned") = Instant::now();
        (previous_keys, previous_events)
    }

    /// Total events observed since the observer was created or last reset.
    pub fn events_observed(&self) -> u64 {
        self.events_observed.load(Ordering::Relaxed)
    }

    /// Lifetime total of events observed since the observer was
    /// constructed, ignoring resets. Monotonic; suitable for driving
    /// Prometheus counters.
    pub fn lifetime_events_observed(&self) -> u64 {
        self.lifetime_events_observed.load(Ordering::Relaxed)
    }

    /// Distinct keys currently tracked (does not include overflow drops).
    pub fn unique_keys(&self) -> usize {
        self.inner
            .lock()
            .expect("field observer mutex poisoned")
            .len()
    }

    /// Insert attempts dropped because the observer was at capacity
    /// since the last reset.
    pub fn overflow_dropped(&self) -> u64 {
        self.overflow_dropped.load(Ordering::Relaxed)
    }

    /// Lifetime total of insert attempts dropped because the observer
    /// was at capacity, ignoring resets. Monotonic.
    pub fn lifetime_overflow_dropped(&self) -> u64 {
        self.lifetime_overflow_dropped.load(Ordering::Relaxed)
    }

    /// Configured per-observer ceiling for distinct keys.
    pub fn max_keys(&self) -> usize {
        self.max_keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::JsonEvent;
    use serde_json::json;

    #[test]
    fn observes_flat_json_fields() {
        let observer = FieldObserver::new(100);
        let v = json!({"CommandLine": "whoami", "User": "admin"});
        observer.observe(&JsonEvent::borrow(&v));
        let snap = observer.snapshot();
        assert_eq!(snap.events_observed, 1);
        assert_eq!(snap.unique_keys, 2);
        assert_eq!(snap.overflow_dropped, 0);
        let names: Vec<&str> = snap.entries.iter().map(|e| -> &str { &e.field }).collect();
        assert!(names.contains(&"CommandLine"));
        assert!(names.contains(&"User"));
    }

    #[test]
    fn observes_nested_json_with_dotted_leaves() {
        let observer = FieldObserver::new(100);
        let v = json!({"actor": {"id": "u1"}});
        observer.observe(&JsonEvent::borrow(&v));
        let snap = observer.snapshot();
        let names: Vec<&str> = snap.entries.iter().map(|e| -> &str { &e.field }).collect();
        // Only the leaf is observed; the intermediate `actor` is not.
        // This keeps the gap signal free of false positives on objects
        // whose children are rule-referenced.
        assert!(names.contains(&"actor.id"));
        assert!(!names.contains(&"actor"));
    }

    #[test]
    fn counts_accumulate_across_observations() {
        let observer = FieldObserver::new(100);
        for _ in 0..5 {
            let v = json!({"CommandLine": "whoami"});
            observer.observe(&JsonEvent::borrow(&v));
        }
        let snap = observer.snapshot();
        assert_eq!(snap.events_observed, 5);
        let entry = snap
            .entries
            .iter()
            .find(|e| &*e.field == "CommandLine")
            .expect("CommandLine tracked");
        assert_eq!(entry.count, 5);
    }

    #[test]
    fn cap_enforced_and_overflow_recorded() {
        let observer = FieldObserver::new(2);
        let v = json!({"a": 1, "b": 2, "c": 3, "d": 4});
        observer.observe(&JsonEvent::borrow(&v));
        let snap = observer.snapshot();
        assert_eq!(snap.unique_keys, 2);
        assert_eq!(snap.overflow_dropped, 2);
        // Existing keys keep counting after cap is hit:
        observer.observe(&JsonEvent::borrow(&v));
        let snap2 = observer.snapshot();
        assert_eq!(snap2.unique_keys, 2);
        assert_eq!(snap2.overflow_dropped, 4);
        for entry in &snap2.entries {
            assert_eq!(entry.count, 2, "tracked key counter advanced");
        }
    }

    #[test]
    fn snapshot_sorts_by_count_desc_then_name() {
        let observer = FieldObserver::new(100);
        for _ in 0..3 {
            observer.observe(&JsonEvent::borrow(&json!({"hot": 1})));
        }
        observer.observe(&JsonEvent::borrow(&json!({"warm": 1})));
        observer.observe(&JsonEvent::borrow(&json!({"chill": 1})));
        let snap = observer.snapshot();
        let order: Vec<&str> = snap.entries.iter().map(|e| -> &str { &e.field }).collect();
        assert_eq!(order, vec!["hot", "chill", "warm"]);
    }

    #[test]
    fn reset_clears_state_and_returns_previous_counts() {
        let observer = FieldObserver::new(100);
        observer.observe(&JsonEvent::borrow(&json!({"a": 1, "b": 2})));
        observer.observe(&JsonEvent::borrow(&json!({"a": 1})));
        let (prev_keys, prev_events) = observer.reset();
        assert_eq!(prev_keys, 2);
        assert_eq!(prev_events, 2);
        let snap = observer.snapshot();
        assert_eq!(snap.events_observed, 0);
        assert_eq!(snap.unique_keys, 0);
        assert_eq!(snap.overflow_dropped, 0);
        assert!(snap.entries.is_empty());
    }

    #[test]
    fn lifetime_counters_survive_reset() {
        // Regression: the Prometheus counter bridge relies on monotonic
        // lifetime totals. Resetting the observer must not lose data
        // points that the next /metrics scrape needs to see.
        let observer = FieldObserver::new(2);
        // 3 events, 4 unique fields => 2 fit, 2 overflow per event.
        for _ in 0..3 {
            observer.observe(&JsonEvent::borrow(&json!({"a": 1, "b": 2, "c": 3, "d": 4})));
        }
        let before = observer.snapshot();
        assert_eq!(before.events_observed, 3);
        assert_eq!(before.lifetime_events_observed, 3);
        assert_eq!(before.overflow_dropped, 6);
        assert_eq!(before.lifetime_overflow_dropped, 6);

        observer.reset();
        let after_reset = observer.snapshot();
        assert_eq!(after_reset.events_observed, 0);
        assert_eq!(after_reset.overflow_dropped, 0);
        // Lifetime totals MUST NOT reset:
        assert_eq!(after_reset.lifetime_events_observed, 3);
        assert_eq!(after_reset.lifetime_overflow_dropped, 6);

        // Continue observing; lifetime keeps climbing from where it was.
        observer.observe(&JsonEvent::borrow(&json!({"a": 1, "b": 2, "c": 3, "d": 4})));
        let after = observer.snapshot();
        assert_eq!(after.events_observed, 1);
        assert_eq!(after.lifetime_events_observed, 4);
        assert_eq!(after.overflow_dropped, 2);
        assert_eq!(after.lifetime_overflow_dropped, 8);
    }

    #[test]
    fn plain_event_observation_is_a_noop_for_counters() {
        let observer = FieldObserver::new(100);
        let plain = crate::event::PlainEvent::new("disk full".into());
        observer.observe(&plain);
        let snap = observer.snapshot();
        // events_observed still ticks: the observer saw the event but it had
        // no structured fields to record.
        assert_eq!(snap.events_observed, 1);
        assert_eq!(snap.unique_keys, 0);
        assert_eq!(snap.overflow_dropped, 0);
    }

    #[test]
    fn coverage_partitions_observed_against_rule_set() {
        // Two rules: one references CommandLine (also matches the event),
        // the other references ProcessGuid (never appears in the event).
        // Event carries CommandLine plus two unrelated fields.
        let yaml = r#"
title: Whoami
status: test
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
---
title: Process Tampering
status: test
logsource:
    category: test
detection:
    selection:
        ProcessGuid: "{abc}"
    condition: selection
"#;
        let collection = rsigma_parser::parse_sigma_yaml(yaml).expect("parse");
        let rule_field_set = crate::fields::RuleFieldSet::collect(&collection, &[], true);
        let observer = FieldObserver::new(100);
        observer.observe(&JsonEvent::borrow(
            &json!({"CommandLine":"whoami","User":"alice","src_ip":"10.0.0.1"}),
        ));

        let snap = observer.snapshot();
        let coverage = snap.coverage(&rule_field_set);

        assert_eq!(coverage.intersection_count, 1, "CommandLine intersects");
        let unknown: Vec<&str> = coverage
            .unknown
            .iter()
            .map(|e| -> &str { &e.field })
            .collect();
        assert!(unknown.contains(&"User"));
        assert!(unknown.contains(&"src_ip"));
        assert!(!unknown.contains(&"CommandLine"));
        let missing: Vec<&str> = coverage.missing.iter().map(|(n, _)| *n).collect();
        assert!(
            missing.contains(&"ProcessGuid"),
            "ProcessGuid was rule-referenced but never observed"
        );
        assert!(!missing.contains(&"CommandLine"));
    }

    #[test]
    fn coverage_empty_observer_yields_only_missing() {
        let yaml = r#"
title: A
status: test
logsource:
    category: test
detection:
    selection:
        FieldA: x
    condition: selection
"#;
        let collection = rsigma_parser::parse_sigma_yaml(yaml).expect("parse");
        let rule_field_set = crate::fields::RuleFieldSet::collect(&collection, &[], true);
        let observer = FieldObserver::new(100);

        let snap = observer.snapshot();
        let coverage = snap.coverage(&rule_field_set);
        assert_eq!(coverage.intersection_count, 0);
        assert!(coverage.unknown.is_empty());
        assert_eq!(coverage.missing.len(), 1);
        assert_eq!(coverage.missing[0].0, "FieldA");
    }

    #[test]
    fn coverage_unknown_preserves_snapshot_ordering() {
        let observer = FieldObserver::new(100);
        for _ in 0..3 {
            observer.observe(&JsonEvent::borrow(&json!({"hot": 1})));
        }
        observer.observe(&JsonEvent::borrow(&json!({"warm": 1})));
        let empty_rule_set = crate::fields::RuleFieldSet::default();

        let snap = observer.snapshot();
        let coverage = snap.coverage(&empty_rule_set);
        let order: Vec<&str> = coverage
            .unknown
            .iter()
            .map(|e| -> &str { &e.field })
            .collect();
        // Snapshot is already sorted by descending count then ascending
        // name; coverage's filter-only pass must preserve that order.
        assert_eq!(order, vec!["hot", "warm"]);
    }
}
