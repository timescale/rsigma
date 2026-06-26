//! Fingerprint deduplication with an Alertmanager-style active-alert lifecycle.
//!
//! Each in-scope result is reduced to a fingerprint (the rule identity plus the
//! configured selector values). The first fire for a fingerprint passes through
//! unchanged and opens an *active alert*; subsequent fires within the window
//! fold into that alert (incrementing the count and `last_seen`) instead of
//! being emitted again. A periodic tick re-emits a still-active alert every
//! `repeat_interval` (carrying the accumulated fire count) and emits a final
//! `resolved` record once `resolve_timeout` elapses with no further fires.
//!
//! Re-emit and resolved records are ordinary [`EvaluationResult`]s carrying a
//! `dedup_state` key in `header.enrichments`, so they ride the existing sink
//! path and wire shape.

use std::collections::HashMap;
use std::time::Duration;

use rsigma_eval::EvaluationResult;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::selector::Selector;
use super::strip_event_payloads;

/// Validated dedup configuration.
#[derive(Debug, Clone)]
pub struct DedupConfig {
    /// Selectors hashed (with the rule identity) into the fingerprint.
    pub fingerprint: Vec<Selector>,
    /// Re-emit cadence for a still-active alert. `0` disables re-emits
    /// (pure suppression with a single resolved summary on expiry).
    pub repeat_interval: Duration,
    /// Idle timeout after which an active alert resolves and is evicted.
    pub resolve_timeout: Duration,
    /// Ceiling on concurrently-active alerts. Once reached, a first-fire for a
    /// new fingerprint passes through un-deduped rather than opening another
    /// alert, so a high-cardinality fingerprint cannot grow the store without
    /// bound between resolve windows.
    pub max_active_alerts: usize,
}

/// One fingerprint's active-alert state.
///
/// `sample` is the event-stripped first-fire result as a JSON [`Value`] (rather
/// than an [`EvaluationResult`], which is serialize-only), so the active-alert
/// store round-trips through the persistence snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ActiveAlert {
    first_seen: i64,
    last_seen: i64,
    last_emitted: i64,
    fire_count: u64,
    /// `fire_count` as of the last emission, so a repeat tick is a no-op when
    /// nothing new folded in since the previous re-emit.
    emitted_count: u64,
    /// Representative result (event payloads stripped) used to build the
    /// `repeat` / `resolved` records.
    sample: Value,
    /// Resolved fingerprint selector values, surfaced on the summary records.
    fields: Vec<(String, Value)>,
}

/// In-memory active-alert store, owned single-threaded by the sink task.
#[derive(Debug, Default)]
pub struct DedupStore {
    alerts: HashMap<String, ActiveAlert>,
}

/// A summary record produced by the periodic tick, tagged with its state so
/// the driver can record the matching metric.
pub(crate) struct DedupRecord {
    /// `repeat` or `resolved`.
    pub state: &'static str,
    /// The summary line to emit (a serialized result with `dedup_*` keys).
    pub json: Value,
}

impl DedupStore {
    /// Number of active alerts currently tracked.
    pub fn len(&self) -> usize {
        self.alerts.len()
    }

    /// True when no active alerts are tracked.
    pub fn is_empty(&self) -> bool {
        self.alerts.is_empty()
    }

    /// True when a fingerprint already has an active alert.
    pub(crate) fn contains(&self, fingerprint: &str) -> bool {
        self.alerts.contains_key(fingerprint)
    }

    /// Fold a duplicate into the existing active alert.
    pub(crate) fn fold(&mut self, fingerprint: &str, now: i64) {
        if let Some(alert) = self.alerts.get_mut(fingerprint) {
            alert.fire_count += 1;
            alert.last_seen = now;
        }
    }

    /// Open a new active alert for a first-fire result.
    pub(crate) fn insert(
        &mut self,
        fingerprint: String,
        now: i64,
        sample: Value,
        fields: Vec<(String, Value)>,
    ) {
        self.alerts.insert(
            fingerprint,
            ActiveAlert {
                first_seen: now,
                last_seen: now,
                last_emitted: now,
                fire_count: 1,
                emitted_count: 1,
                sample,
                fields,
            },
        );
    }

    /// Advance time: emit repeat records for due alerts and resolved records
    /// for idle alerts, evicting the latter.
    pub(crate) fn tick(&mut self, cfg: &DedupConfig, now: i64) -> Vec<DedupRecord> {
        let resolve_secs = cfg.resolve_timeout.as_secs() as i64;
        let repeat_secs = cfg.repeat_interval.as_secs() as i64;
        let mut out = Vec::new();
        let mut resolved = Vec::new();

        for (fingerprint, alert) in self.alerts.iter_mut() {
            if now - alert.last_seen >= resolve_secs {
                out.push(DedupRecord {
                    state: "resolved",
                    json: build_record(alert, fingerprint, "resolved"),
                });
                resolved.push(fingerprint.clone());
            } else if repeat_secs > 0
                && now - alert.last_emitted >= repeat_secs
                && alert.fire_count > alert.emitted_count
            {
                out.push(DedupRecord {
                    state: "repeat",
                    json: build_record(alert, fingerprint, "repeat"),
                });
                alert.last_emitted = now;
                alert.emitted_count = alert.fire_count;
            }
        }

        for key in resolved {
            self.alerts.remove(&key);
        }
        out
    }

    /// Snapshot the active alerts (fingerprint -> alert) for persistence.
    pub(crate) fn snapshot(&self) -> Vec<(String, ActiveAlert)> {
        self.alerts
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Restore active alerts, dropping any already past `resolve_timeout` at
    /// `now`.
    pub(crate) fn restore(
        &mut self,
        alerts: Vec<(String, ActiveAlert)>,
        now: i64,
        resolve_secs: i64,
    ) {
        for (fingerprint, alert) in alerts {
            if now - alert.last_seen < resolve_secs {
                self.alerts.insert(fingerprint, alert);
            }
        }
    }
}

/// Compute the fingerprint for a result under `selectors`.
///
/// The rule identity is always part of the fingerprint; each selector
/// contributes its resolved value or an explicit null marker. The canonical
/// string is reduced to a compact, stable 64-bit FNV-1a hex digest so the same
/// logical alert keeps one fingerprint across restarts.
pub(crate) fn fingerprint(selectors: &[Selector], result: &EvaluationResult) -> String {
    let rule = result
        .header
        .rule_id
        .as_deref()
        .unwrap_or(result.header.rule_title.as_str());

    let mut buf = String::with_capacity(64);
    buf.push_str("rule=");
    buf.push_str(rule);
    for sel in selectors {
        buf.push('\u{1f}');
        buf.push_str(&sel.as_str());
        buf.push('=');
        match sel.resolve(result) {
            Some(value) => buf.push_str(&canonical(&value)),
            None => buf.push_str("\u{0}null"),
        }
    }
    format!("{:016x}", fnv1a64(buf.as_bytes()))
}

/// Resolve the selector values once, for storage on the active alert and
/// surfacing on the summary records.
pub(crate) fn resolve_fields(
    selectors: &[Selector],
    result: &EvaluationResult,
) -> Vec<(String, Value)> {
    selectors
        .iter()
        .map(|sel| (sel.as_str(), sel.resolve(result).unwrap_or(Value::Null)))
        .collect()
}

/// Canonical string form of a resolved value for fingerprinting. Strings use
/// their raw text; everything else uses compact JSON.
fn canonical(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Build a `repeat` / `resolved` summary line (a JSON [`Value`]) from an active
/// alert by injecting the `dedup_*` keys into the sample's `enrichments` object.
fn build_record(alert: &ActiveAlert, fingerprint: &str, state: &'static str) -> Value {
    let mut result = alert.sample.clone();
    if !result.is_object() {
        result = Value::Object(serde_json::Map::new());
    }
    let obj = result.as_object_mut().expect("result is an object");
    let enrichments = obj
        .entry("enrichments")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if !enrichments.is_object() {
        *enrichments = Value::Object(serde_json::Map::new());
    }
    let map = enrichments
        .as_object_mut()
        .expect("enrichments is an object");
    map.insert("dedup_state".to_string(), Value::String(state.to_string()));
    map.insert(
        "dedup_fingerprint".to_string(),
        Value::String(fingerprint.to_string()),
    );
    map.insert(
        "dedup_fire_count".to_string(),
        Value::from(alert.fire_count),
    );
    map.insert(
        "dedup_first_seen".to_string(),
        Value::from(alert.first_seen),
    );
    map.insert("dedup_last_seen".to_string(), Value::from(alert.last_seen));
    let fields: serde_json::Map<String, Value> = alert.fields.iter().cloned().collect();
    map.insert("dedup_fields".to_string(), Value::Object(fields));
    result
}

/// The event-stripped, serialized form of a result, retained as a long-lived
/// sample. A `Value` (not an [`EvaluationResult`]) so the store is persistable.
pub(crate) fn sample_of(result: &EvaluationResult) -> Value {
    let mut sample = result.clone();
    strip_event_payloads(&mut sample);
    serde_json::to_value(&sample).unwrap_or(Value::Null)
}

/// FNV-1a 64-bit. Inlined so the digest is stable across toolchains and crate
/// versions (unlike `DefaultHasher`), which matters for persisted fingerprints.
pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
    use rsigma_parser::Level;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn result(ip: &str) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: "Brute force".to_string(),
                rule_id: Some("rule-1".to_string()),
                level: Some(Level::High),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: vec![FieldMatch::new("SourceIp", serde_json::json!(ip))],
                event: Some(serde_json::json!({"big": "payload"})),
            }),
        }
    }

    fn cfg(repeat: u64, resolve: u64) -> DedupConfig {
        DedupConfig {
            fingerprint: vec![Selector::parse("match.SourceIp").unwrap()],
            repeat_interval: Duration::from_secs(repeat),
            resolve_timeout: Duration::from_secs(resolve),
            max_active_alerts: 100_000,
        }
    }

    #[test]
    fn fingerprint_is_stable_and_value_sensitive() {
        let c = cfg(0, 60);
        let a = fingerprint(&c.fingerprint, &result("10.0.0.1"));
        let b = fingerprint(&c.fingerprint, &result("10.0.0.1"));
        let d = fingerprint(&c.fingerprint, &result("10.0.0.2"));
        assert_eq!(a, b, "same inputs must hash identically");
        assert_ne!(a, d, "different selector values must differ");
    }

    #[test]
    fn first_fire_opens_alert_then_folds() {
        let c = cfg(0, 60);
        let mut store = DedupStore::default();
        let r = result("10.0.0.1");
        let fp = fingerprint(&c.fingerprint, &r);

        assert!(!store.contains(&fp));
        store.insert(
            fp.clone(),
            100,
            sample_of(&r),
            resolve_fields(&c.fingerprint, &r),
        );
        assert_eq!(store.len(), 1);

        // The stored sample has no raw event payload.
        // (Folding does not re-store the sample.)
        store.fold(&fp, 105);
        store.fold(&fp, 110);
        // Three fires total: one insert + two folds.
        let records = {
            // Force resolution by jumping past resolve_timeout.
            store.tick(&c, 200)
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, "resolved");
        let enr = &records[0].json["enrichments"];
        assert_eq!(enr["dedup_state"], serde_json::json!("resolved"));
        assert_eq!(enr["dedup_fire_count"], serde_json::json!(3));
        assert!(records[0].json.get("event").is_none());
        assert!(store.is_empty(), "resolved alert is evicted");
    }

    #[test]
    fn repeat_emits_only_when_new_fires_accumulate() {
        let c = cfg(10, 600);
        let mut store = DedupStore::default();
        let r = result("10.0.0.1");
        let fp = fingerprint(&c.fingerprint, &r);
        store.insert(
            fp.clone(),
            0,
            sample_of(&r),
            resolve_fields(&c.fingerprint, &r),
        );

        // No new fires since insert: a repeat tick is a no-op.
        assert!(store.tick(&c, 20).is_empty());

        // A fold then a due tick emits one repeat carrying the new count.
        store.fold(&fp, 25);
        let records = store.tick(&c, 40);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, "repeat");
        assert_eq!(
            records[0].json["enrichments"]["dedup_fire_count"],
            serde_json::json!(2)
        );

        // Immediately after a repeat, with no new fires, the next tick is a no-op.
        assert!(store.tick(&c, 55).is_empty());
        assert_eq!(store.len(), 1, "still active, not resolved");
    }

    #[test]
    fn repeat_interval_zero_is_pure_suppression() {
        let c = cfg(0, 100);
        let mut store = DedupStore::default();
        let r = result("10.0.0.1");
        let fp = fingerprint(&c.fingerprint, &r);
        store.insert(
            fp.clone(),
            0,
            sample_of(&r),
            resolve_fields(&c.fingerprint, &r),
        );
        store.fold(&fp, 10);
        // No repeats ever, even with new fires.
        assert!(store.tick(&c, 50).is_empty());
        // Only a resolved record on expiry.
        let records = store.tick(&c, 200);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, "resolved");
    }
}
