//! Opt-in observer that records every field name seen on the daemon's hot
//! path so the field-observability endpoints can report which event fields
//! are not referenced by any loaded rule (gap signal) and which rule
//! fields have never been seen in events (broken-coverage signal).
//!
//! # Design
//!
//! - Backed by a `parking_lot::Mutex<HashMap<String, u64>>`. The mutex is
//!   only held long enough to bump or insert a counter; the daemon's
//!   engine task is the sole writer in the current architecture, so
//!   contention is bounded by event throughput rather than worker count.
//! - A hard cap (`max_keys`) bounds memory. Once the cap is reached new
//!   keys are dropped and the `overflow_dropped` counter is incremented;
//!   existing counters keep updating so the observer keeps surfacing
//!   high-frequency keys even on a saturated set.
//! - The observer is opt-in: the daemon constructs an `Arc<FieldObserver>`
//!   only when `--observe-fields` is set. When the feature is off the
//!   engine task never calls `observe`, so the hot path stays untouched.
//!
//! # Coordinates
//!
//! - The daemon iterates [`Event::field_keys`](rsigma_eval::Event::field_keys)
//!   once per event before evaluation. For JSON events this is a
//!   recursive walk that allocates one `String` per leaf path
//!   (dot-joined paths do not exist as substrings of the source value);
//!   for flat formats like `KvEvent` the override returns
//!   `Cow::Borrowed`. The cost is acceptable in the opt-in diagnostic
//!   mode but is not free.
//! - The HTTP API takes [`snapshot`](FieldObserver::snapshot) and joins it
//!   against `RuntimeEngine::rule_field_set` to compute the
//!   unknown / missing / intersection sets per request.
//! - The Prometheus counter bridge in the CLI metrics module reads
//!   `lifetime_events_observed` / `lifetime_overflow_dropped` rather
//!   than the resettable views, so `DELETE /api/v1/fields/observer`
//!   does not desync the monotonic counters.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::Mutex;
use rsigma_eval::event::Event;

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
/// Returned by [`FieldObserver::snapshot`]; the daemon's HTTP handlers
/// consume this to render the `/api/v1/fields/*` endpoints.
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

/// Capped, opt-in field-name counter shared across the daemon's event task
/// and the HTTP API handlers.
///
/// Keys are stored as `Arc<str>` rather than `String` so a snapshot
/// only refcount-bumps each key instead of allocating a fresh
/// `String` per entry. The trade is one extra allocation per
/// first-time-insert (Arc header) in exchange for cheap snapshots,
/// which is the right side of the trade because the metrics handler
/// scrapes every 15-30 s while new-key insertions happen at most once
/// per unique field across the whole observation window.
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
        let mut counts = self.inner.lock();
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
        let counts = self.inner.lock();
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
            uptime_seconds: self.start.lock().elapsed().as_secs_f64(),
        }
    }

    /// Reset every counter and the overflow tally. Returns the previous
    /// `(unique_keys, events_observed)` pair so the API endpoint can
    /// report what was cleared.
    pub fn reset(&self) -> (usize, u64) {
        let mut counts = self.inner.lock();
        let previous_keys = counts.len();
        counts.clear();
        drop(counts);
        let previous_events = self.events_observed.swap(0, Ordering::Relaxed);
        self.overflow_dropped.store(0, Ordering::Relaxed);
        *self.start.lock() = Instant::now();
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
        self.inner.lock().len()
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
    use rsigma_eval::event::JsonEvent;
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
        let plain = rsigma_eval::event::PlainEvent::new("disk full".into());
        observer.observe(&plain);
        let snap = observer.snapshot();
        // events_observed still ticks: the observer saw the event but it had
        // no structured fields to record.
        assert_eq!(snap.events_observed, 1);
        assert_eq!(snap.unique_keys, 0);
        assert_eq!(snap.overflow_dropped, 0);
    }
}
