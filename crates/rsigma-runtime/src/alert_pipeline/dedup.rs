//! Fingerprint deduplication with an Alertmanager-style active-alert lifecycle.
//!
//! Each in-scope result is reduced to its exact identity (the tenant, the rule
//! identity, and the configured selector values; see [`IdentityKey`]). The
//! first fire for an identity passes through unchanged and opens an *active
//! alert*; subsequent fires within the window fold into that alert
//! (incrementing the count and `last_seen`) instead of being emitted again. A
//! periodic tick re-emits a still-active alert every `repeat_interval`
//! (carrying the accumulated fire count) and emits a final `resolved` record
//! once `resolve_timeout` elapses with no further fires.
//!
//! Re-emit and resolved records are ordinary [`EvaluationResult`]s carrying a
//! `dedup_state` key in `header.enrichments`, so they ride the existing sink
//! path and wire shape. Their `dedup_fingerprint` is the alert's display id,
//! unique among active alerts.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use rsigma_eval::EvaluationResult;
use rsigma_eval::TenantId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::identity::{self, IdentityKey};
use super::strip_event_payloads;
use crate::selector::Selector;

/// Validated dedup configuration.
#[derive(Debug, Clone)]
pub struct DedupConfig {
    /// Selectors that, with the tenant and rule identity, form the alert
    /// identity.
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

/// One identity's active-alert state.
///
/// `sample` is the event-stripped first-fire result as a JSON [`Value`] (rather
/// than an [`EvaluationResult`], which is serialize-only), so the active-alert
/// store round-trips through the persistence snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ActiveAlert {
    /// Display id surfaced as `dedup_fingerprint`. Persisted beside the alert
    /// in [`DedupSnap`].
    #[serde(skip)]
    fingerprint: String,
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
    /// Tenant that owns this alert, when tenancy is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tenant: Option<TenantId>,
}

/// One persisted active alert. Snapshots before version 3 hold bare
/// `(fingerprint, alert)` pairs, whose key is rebuilt on restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum DedupSnap {
    Keyed {
        fingerprint: String,
        key: IdentityKey,
        alert: ActiveAlert,
    },
    Legacy(String, ActiveAlert),
}

impl DedupSnap {
    /// Tenant that owns the persisted alert.
    pub(crate) fn tenant(&self) -> Option<&TenantId> {
        match self {
            DedupSnap::Keyed { alert, .. } | DedupSnap::Legacy(_, alert) => alert.tenant.as_ref(),
        }
    }
}

/// In-memory active-alert store, owned single-threaded by the sink task.
#[derive(Debug, Default)]
pub struct DedupStore {
    alerts: HashMap<Arc<IdentityKey>, ActiveAlert>,
    /// Display id to key, kept in step with `alerts`.
    fingerprints: HashMap<String, Arc<IdentityKey>>,
    /// Display ids per tenant, kept in step with `alerts`.
    tenant_fingerprints: HashMap<Option<TenantId>, HashSet<String>>,
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

    /// True when an identity already has an active alert.
    #[cfg(test)]
    pub(crate) fn contains(&self, key: &IdentityKey) -> bool {
        self.alerts.contains_key(key)
    }

    /// The display id of the active alert for `key`, if one is open.
    pub(crate) fn fingerprint_of(&self, key: &IdentityKey) -> Option<&str> {
        self.alerts.get(key).map(|alert| alert.fingerprint.as_str())
    }

    /// The display id a new alert for `key` would take: its natural id, or
    /// the next candidate when another key holds that one.
    pub(crate) fn allocate_fingerprint(&self, key: &IdentityKey) -> String {
        key.allocate_id(|id| self.fingerprints.contains_key(id))
    }

    /// Fold a duplicate into the active alert for `key`. Returns whether one
    /// was open.
    pub(crate) fn fold(&mut self, key: &IdentityKey, now: i64) -> bool {
        match self.alerts.get_mut(key) {
            Some(alert) => {
                alert.fire_count += 1;
                alert.last_seen = now;
                true
            }
            None => false,
        }
    }

    /// Open a new active alert for a first-fire result, under `fingerprint`
    /// when it is still free (see [`Self::allocate_fingerprint`]).
    pub(crate) fn insert(
        &mut self,
        key: IdentityKey,
        fingerprint: String,
        now: i64,
        sample: Value,
        fields: Vec<(String, Value)>,
    ) {
        let fingerprint = match self.fingerprints.get(&fingerprint) {
            Some(holder) if **holder != key => self.allocate_fingerprint(&key),
            _ => fingerprint,
        };
        let tenant = key.tenant().cloned();
        self.insert_alert(
            Arc::new(key),
            ActiveAlert {
                fingerprint,
                first_seen: now,
                last_seen: now,
                last_emitted: now,
                fire_count: 1,
                emitted_count: 1,
                sample,
                fields,
                tenant,
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

        for (key, alert) in self.alerts.iter_mut() {
            if now - alert.last_seen >= resolve_secs {
                out.push(DedupRecord {
                    state: "resolved",
                    json: build_record(alert, "resolved"),
                });
                resolved.push(key.clone());
            } else if repeat_secs > 0
                && now - alert.last_emitted >= repeat_secs
                && alert.fire_count > alert.emitted_count
            {
                out.push(DedupRecord {
                    state: "repeat",
                    json: build_record(alert, "repeat"),
                });
                alert.last_emitted = now;
                alert.emitted_count = alert.fire_count;
            }
        }

        for key in resolved {
            self.remove_alert(&key);
        }
        out
    }

    fn insert_alert(&mut self, key: Arc<IdentityKey>, alert: ActiveAlert) {
        self.remove_alert(&key);
        self.fingerprints
            .insert(alert.fingerprint.clone(), key.clone());
        self.tenant_fingerprints
            .entry(alert.tenant.clone())
            .or_default()
            .insert(alert.fingerprint.clone());
        self.alerts.insert(key, alert);
    }

    fn remove_alert(&mut self, key: &IdentityKey) -> Option<ActiveAlert> {
        let alert = self.alerts.remove(key)?;
        self.fingerprints.remove(&alert.fingerprint);
        if let Some(fingerprints) = self.tenant_fingerprints.get_mut(&alert.tenant) {
            fingerprints.remove(&alert.fingerprint);
            if fingerprints.is_empty() {
                self.tenant_fingerprints.remove(&alert.tenant);
            }
        }
        Some(alert)
    }

    /// Count of active alerts owned by `tenant`.
    pub(crate) fn count_for_tenant(&self, tenant: Option<&TenantId>) -> usize {
        self.tenant_fingerprints
            .get(&tenant.cloned())
            .map_or(0, HashSet::len)
    }

    /// Evict the least recently seen alert owned by `tenant`. Returns whether
    /// one was evicted.
    pub(crate) fn evict_tenant_oldest(&mut self, tenant: Option<&TenantId>) -> bool {
        let victim = self
            .tenant_fingerprints
            .get(&tenant.cloned())
            .into_iter()
            .flatten()
            .filter_map(|fingerprint| self.fingerprints.get(fingerprint))
            .filter_map(|key| {
                self.alerts
                    .get(key.as_ref())
                    .map(|alert| (key, alert.last_seen))
            })
            .min_by_key(|(_, last_seen)| *last_seen)
            .map(|(key, _)| Arc::clone(key));
        match victim {
            Some(key) => self.remove_alert(&key).is_some(),
            None => false,
        }
    }

    /// Evict each tenant's least recently seen alerts until it holds at most
    /// `max`, returning how many were evicted.
    pub(crate) fn enforce_tenant_cap(&mut self, max: usize) -> usize {
        let over: Vec<Option<TenantId>> = self
            .tenant_fingerprints
            .iter()
            .filter(|(_, fingerprints)| fingerprints.len() > max)
            .map(|(tenant, _)| tenant.clone())
            .collect();
        let mut evicted = 0;
        for tenant in over {
            while self.count_for_tenant(tenant.as_ref()) > max
                && self.evict_tenant_oldest(tenant.as_ref())
            {
                evicted += 1;
            }
        }
        evicted
    }

    /// Snapshot the active alerts with their keys for persistence.
    pub(crate) fn snapshot(&self) -> Vec<DedupSnap> {
        self.alerts
            .iter()
            .map(|(key, alert)| DedupSnap::Keyed {
                fingerprint: alert.fingerprint.clone(),
                key: IdentityKey::clone(key),
                alert: alert.clone(),
            })
            .collect()
    }

    /// Restore active alerts, dropping any already past `resolve_timeout` at
    /// `now`. An alert keeps its persisted display id unless another restored
    /// alert already holds it. Returns how many legacy entries were dropped
    /// because their key could not be rebuilt.
    pub(crate) fn restore(&mut self, alerts: Vec<DedupSnap>, now: i64, resolve_secs: i64) -> usize {
        let mut unrebuildable = 0;
        for entry in alerts {
            let (fingerprint, key, mut alert) = match entry {
                DedupSnap::Keyed {
                    fingerprint,
                    key,
                    alert,
                } => (fingerprint, key, alert),
                DedupSnap::Legacy(fingerprint, alert) => {
                    match identity::rebuild_dedup_key(
                        &fingerprint,
                        alert.tenant.as_ref(),
                        &alert.sample,
                        &alert.fields,
                    ) {
                        Some(key) => (fingerprint, key, alert),
                        None => {
                            unrebuildable += 1;
                            continue;
                        }
                    }
                }
            };
            if now - alert.last_seen >= resolve_secs
                || self
                    .alerts
                    .get(&key)
                    .is_some_and(|held| held.last_seen >= alert.last_seen)
            {
                continue;
            }
            alert.tenant = key.tenant().cloned();
            alert.fingerprint = match self.fingerprints.get(&fingerprint) {
                Some(holder) if **holder != key => self.allocate_fingerprint(&key),
                _ => fingerprint,
            };
            self.insert_alert(Arc::new(key), alert);
        }
        unrebuildable
    }

    /// Evict the least recently seen alerts until at most `max` remain,
    /// returning how many were evicted. Evicted alerts emit no `resolved`
    /// record. The live path never exceeds the cap; this bounds a store
    /// restored or carried across a reload under a lower one.
    pub(crate) fn enforce_cap(&mut self, max: usize) -> usize {
        let excess = self.alerts.len().saturating_sub(max);
        if excess == 0 {
            return 0;
        }
        let mut by_age: Vec<(i64, &str)> = self
            .alerts
            .values()
            .map(|alert| (alert.last_seen, alert.fingerprint.as_str()))
            .collect();
        by_age.sort_unstable();
        let victims: Vec<Arc<IdentityKey>> = by_age
            .into_iter()
            .take(excess)
            .filter_map(|(_, fingerprint)| self.fingerprints.get(fingerprint).cloned())
            .collect();
        for key in victims {
            self.remove_alert(&key);
        }
        excess
    }
}

/// Build a `repeat` / `resolved` summary line (a JSON [`Value`]) from an active
/// alert by injecting the `dedup_*` keys into the sample's `enrichments` object.
fn build_record(alert: &ActiveAlert, state: &'static str) -> Value {
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
        Value::String(alert.fingerprint.clone()),
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

#[cfg(test)]
mod tests {
    use super::super::identity::{colliding_display_id, display_values, force_display_id};
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
                tenant_id: None,
                level: Some(Level::High),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
                ruleset: None,
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

    /// Open an alert for `r` the way the pipeline does, returning its key.
    fn open(
        store: &mut DedupStore,
        c: &DedupConfig,
        r: &EvaluationResult,
        now: i64,
    ) -> IdentityKey {
        let key = IdentityKey::dedup(&c.fingerprint, r);
        let fingerprint = store.allocate_fingerprint(&key);
        store.insert(
            key.clone(),
            fingerprint,
            now,
            sample_of(r),
            display_values(key.names(), &c.fingerprint, r),
        );
        key
    }

    #[test]
    fn identity_is_stable_and_value_sensitive() {
        let c = cfg(0, 60);
        let a = IdentityKey::dedup(&c.fingerprint, &result("10.0.0.1"));
        let b = IdentityKey::dedup(&c.fingerprint, &result("10.0.0.1"));
        let d = IdentityKey::dedup(&c.fingerprint, &result("10.0.0.2"));
        assert_eq!(a, b, "same inputs must yield the same identity");
        assert_ne!(a, d, "different selector values must differ");
        let store = DedupStore::default();
        assert_eq!(
            store.allocate_fingerprint(&a),
            store.allocate_fingerprint(&b)
        );
        assert_ne!(
            store.allocate_fingerprint(&a),
            store.allocate_fingerprint(&d)
        );
    }

    #[test]
    fn first_fire_opens_alert_then_folds() {
        let c = cfg(0, 60);
        let mut store = DedupStore::default();
        let r = result("10.0.0.1");
        let key = IdentityKey::dedup(&c.fingerprint, &r);

        assert!(!store.contains(&key));
        assert!(!store.fold(&key, 99), "nothing to fold into yet");
        open(&mut store, &c, &r, 100);
        assert_eq!(store.len(), 1);

        assert!(store.fold(&key, 105));
        assert!(store.fold(&key, 110));
        // Three fires total: one insert + two folds. Jump past resolve_timeout.
        let records = store.tick(&c, 200);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, "resolved");
        let enr = &records[0].json["enrichments"];
        assert_eq!(enr["dedup_state"], serde_json::json!("resolved"));
        assert_eq!(enr["dedup_fire_count"], serde_json::json!(3));
        assert_eq!(
            enr["dedup_fingerprint"],
            serde_json::json!(store.allocate_fingerprint(&key))
        );
        assert!(records[0].json.get("event").is_none());
        assert!(store.is_empty(), "resolved alert is evicted");
    }

    #[test]
    fn repeat_emits_only_when_new_fires_accumulate() {
        let c = cfg(10, 600);
        let mut store = DedupStore::default();
        let key = open(&mut store, &c, &result("10.0.0.1"), 0);

        // No new fires since insert: a repeat tick is a no-op.
        assert!(store.tick(&c, 20).is_empty());

        // A fold then a due tick emits one repeat carrying the new count.
        store.fold(&key, 25);
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
        let key = open(&mut store, &c, &result("10.0.0.1"), 0);
        store.fold(&key, 10);
        // No repeats ever, even with new fires.
        assert!(store.tick(&c, 50).is_empty());
        // Only a resolved record on expiry.
        let records = store.tick(&c, 200);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, "resolved");
    }

    fn tenant_result(ip: &str, tenant: &str) -> EvaluationResult {
        let mut r = result(ip);
        r.header.tenant_id = Some(TenantId::new(tenant).unwrap());
        r
    }

    #[test]
    fn the_same_value_in_two_tenants_is_two_alerts() {
        let c = cfg(0, 60);
        let mut store = DedupStore::default();
        let ka = open(&mut store, &c, &tenant_result("10.0.0.1", "a"), 0);
        let kb = open(&mut store, &c, &tenant_result("10.0.0.1", "b"), 0);
        assert_ne!(ka, kb, "tenant is part of the identity");
        assert_eq!(store.len(), 2);
        assert_ne!(store.fingerprint_of(&ka), store.fingerprint_of(&kb));
        assert_eq!(store.count_for_tenant(ka.tenant()), 1);
        assert_eq!(store.count_for_tenant(kb.tenant()), 1);
    }

    #[test]
    fn colliding_display_ids_stay_separate_alerts() {
        let _forced = force_display_id(colliding_display_id);
        let c = cfg(0, 60);
        let mut store = DedupStore::default();
        let ka = open(&mut store, &c, &result("10.0.0.1"), 0);
        let kb = open(&mut store, &c, &result("10.0.0.2"), 1);
        assert_eq!(store.len(), 2, "a shared display id does not merge alerts");
        let (fa, fb) = (
            store.fingerprint_of(&ka).unwrap().to_string(),
            store.fingerprint_of(&kb).unwrap().to_string(),
        );
        assert_ne!(fa, fb, "the second alert takes the next candidate id");

        assert!(store.fold(&kb, 2));
        let records = store.tick(&c, 100);
        let mut seen: Vec<(String, u64)> = records
            .iter()
            .map(|r| {
                let e = &r.json["enrichments"];
                (
                    e["dedup_fingerprint"].as_str().unwrap().to_string(),
                    e["dedup_fire_count"].as_u64().unwrap(),
                )
            })
            .collect();
        seen.sort();
        let mut expected = vec![(fa, 1), (fb, 2)];
        expected.sort();
        assert_eq!(seen, expected);
    }

    #[test]
    fn insert_never_reuses_a_display_id_held_by_another_key() {
        let _forced = force_display_id(colliding_display_id);
        let c = cfg(0, 60);
        let mut store = DedupStore::default();
        let ka = open(&mut store, &c, &result("10.0.0.1"), 0);
        let held = store.fingerprint_of(&ka).unwrap().to_string();
        let r = result("10.0.0.2");
        let kb = IdentityKey::dedup(&c.fingerprint, &r);
        store.insert(kb.clone(), held.clone(), 1, sample_of(&r), vec![]);
        assert_eq!(store.fingerprint_of(&ka), Some(held.as_str()));
        assert_ne!(store.fingerprint_of(&kb), Some(held.as_str()));
    }

    #[test]
    fn a_snapshot_round_trips_keys_and_display_ids() {
        let _forced = force_display_id(colliding_display_id);
        let c = cfg(0, 600);
        let mut store = DedupStore::default();
        let ka = open(&mut store, &c, &result("10.0.0.1"), 0);
        let kb = open(&mut store, &c, &result("10.0.0.2"), 0);
        let json = serde_json::to_string(&store.snapshot()).unwrap();

        let mut restored = DedupStore::default();
        let snaps: Vec<DedupSnap> = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.restore(snaps, 10, 600), 0);
        assert_eq!(restored.fingerprint_of(&ka), store.fingerprint_of(&ka));
        assert_eq!(restored.fingerprint_of(&kb), store.fingerprint_of(&kb));
    }

    #[test]
    fn a_legacy_entry_restores_under_its_old_fingerprint() {
        let c = cfg(0, 600);
        let r = result("10.0.0.1");
        let legacy_fingerprint = "c1a5d5a9b8d5c9a3";
        let legacy = serde_json::json!([[
            legacy_fingerprint,
            {
                "first_seen": 0,
                "last_seen": 5,
                "last_emitted": 0,
                "fire_count": 2,
                "emitted_count": 1,
                "sample": sample_of(&r),
                "fields": [["match.SourceIp", "10.0.0.1"]],
            }
        ]]);
        let snaps: Vec<DedupSnap> = serde_json::from_value(legacy).unwrap();
        let mut store = DedupStore::default();
        assert_eq!(store.restore(snaps, 10, 600), 0);
        let key = IdentityKey::dedup(&c.fingerprint, &r);
        assert_eq!(store.fingerprint_of(&key), Some(legacy_fingerprint));
        assert!(
            store.fold(&key, 11),
            "a live fire folds into the restored alert"
        );
    }
}
