//! Incident grouping, modeled on Alertmanager.
//!
//! Two modes:
//!
//! - `group_by` (default): group results by equality on an ordered selector
//!   list. The incident identity is a deterministic fingerprint of the
//!   `(selector -> value)` pairs, stable across restarts and re-emissions.
//! - `entity_graph` (opt-in): union-find over `(selector, value)` entity pairs.
//!   A result joins (and merges) any open incident sharing an entity value.
//!   Guarded against the giant-component failure by a `stop_values` list and a
//!   per-value `max_value_cardinality` ceiling above which a value stops acting
//!   as a join key.
//!
//! Incidents follow the Alertmanager timers: `group_wait` (initial batching
//! delay before the first emission), `group_interval` (minimum delay before
//! emitting an updated incident), and `repeat_interval` (re-emit cadence for a
//! still-open incident). An incident resolves and is evicted once
//! `resolve_timeout` elapses with no new results.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use rsigma_eval::EvaluationResult;
use rsigma_parser::Level;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::dedup::fnv1a64;
use super::strip_event_payloads;
use crate::selector::Selector;

/// Whether the layer groups by key equality or by entity union-find.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMode {
    /// Group by equality on the `by` selectors (deterministic incident id).
    GroupBy,
    /// Union-find over `entities` selector values (surrogate UUID id).
    EntityGraph,
}

/// How much contributing-result detail to embed in an `IncidentResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncludeMode {
    /// Lightweight references (rule + level) only.
    Refs,
    /// Full (event-stripped) contributing results.
    Results,
}

/// Bounds on incident growth, with eviction metrics when exceeded.
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    /// Maximum simultaneously-open incidents.
    pub max_open_incidents: usize,
    /// Maximum distinct entity values retained per incident (entity_graph).
    pub max_entities_per_incident: usize,
    /// Maximum contributing results/refs retained per incident.
    pub max_results_per_incident: usize,
    /// Per-value occurrence ceiling above which an entity value stops joining
    /// (entity_graph giant-component guard).
    pub max_value_cardinality: u64,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            max_open_incidents: 10_000,
            max_entities_per_incident: 1_000,
            max_results_per_incident: 1_000,
            max_value_cardinality: 10_000,
        }
    }
}

/// Validated grouping configuration.
#[derive(Debug, Clone)]
pub struct GroupConfig {
    pub mode: GroupMode,
    /// `group_by` mode: selectors whose values form the group key.
    pub by: Vec<Selector>,
    /// `entity_graph` mode: selectors whose values form join edges.
    pub entities: Vec<Selector>,
    pub group_wait: Duration,
    pub group_interval: Duration,
    pub repeat_interval: Duration,
    pub resolve_timeout: Duration,
    pub include: IncludeMode,
    pub caps: Caps,
    /// Entity values that never form a join edge (entity_graph).
    pub stop_values: BTreeSet<String>,
    /// Optional NATS subject override for emitted incidents.
    pub nats_subject: Option<String>,
}

/// A lightweight reference to a contributing result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRef {
    /// Rule id, falling back to the rule title.
    pub rule: String,
    /// Severity, lowercased.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
}

/// The wire shape emitted for an incident. One flat NDJSON object,
/// disambiguated downstream by the presence of `incident_id`.
#[derive(Debug, Clone, Serialize)]
pub struct IncidentResult {
    /// Deterministic group fingerprint (group_by) or surrogate UUIDv4
    /// (entity_graph). Stable across restarts in group_by mode.
    pub incident_id: String,
    /// `open` or `resolved`.
    pub state: &'static str,
    /// What produced this emission: `group_wait` / `group_interval` /
    /// `repeat` / `resolved`.
    pub trigger: &'static str,
    /// First and last contributing-result timestamps (unix seconds).
    pub first_seen: i64,
    pub last_seen: i64,
    /// Highest severity seen across contributing results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_level: Option<String>,
    /// Number of contributing results.
    pub result_count: u64,
    /// Per-rule contributing-result counts.
    pub rule_counts: BTreeMap<String, u64>,
    /// group_by mode: the group key field values.
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    pub group_by: serde_json::Map<String, Value>,
    /// entity_graph mode: the entity values that bind the incident.
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    pub entities: serde_json::Map<String, Value>,
    /// Contributing references (`include: refs`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refs: Option<Vec<IncidentRef>>,
    /// Contributing results (`include: results`), event payloads stripped and
    /// stored as serialized JSON values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<Value>>,
}

/// Internal per-incident state.
///
/// Serializable for persistence: contributing `results` are stored as
/// serialized JSON values (since [`EvaluationResult`] is serialize-only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Incident {
    id: String,
    first_seen: i64,
    last_seen: i64,
    last_emitted: i64,
    emitted_count: u64,
    opened: bool,
    dirty: bool,
    group_by: Vec<(String, Value)>,
    entities: BTreeMap<String, BTreeSet<String>>,
    max_level: Option<Level>,
    rule_counts: BTreeMap<String, u64>,
    result_count: u64,
    refs: Vec<IncidentRef>,
    results: Vec<Value>,
}

/// A grouping outcome the driver records a metric for.
pub(crate) struct IncidentEmission {
    pub trigger: &'static str,
    pub result: IncidentResult,
}

/// In-memory incident store, owned single-threaded by the sink task (or shared
/// behind an `RwLock` so the HTTP API can read open incidents).
#[derive(Debug, Default)]
pub struct IncidentStore {
    incidents: HashMap<String, Incident>,
    /// entity_graph: `(selector, value)` -> incident id.
    entity_index: HashMap<(String, String), String>,
    /// entity_graph: per-value occurrence count for the cardinality guard.
    value_counts: HashMap<(String, String), u64>,
}

/// A value the cardinality guard or stop-list suppressed, reported via a
/// metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OvermergeGuard {
    StopValue,
    CardinalityCeiling,
}

impl IncidentStore {
    /// Number of open incidents.
    pub fn len(&self) -> usize {
        self.incidents.len()
    }

    /// True when no incidents are open.
    pub fn is_empty(&self) -> bool {
        self.incidents.is_empty()
    }

    /// A snapshot of every open incident, for the admin API.
    pub fn snapshot(&self, include: IncludeMode) -> Vec<IncidentResult> {
        self.incidents
            .values()
            .map(|inc| inc.to_result("open", "snapshot", include))
            .collect()
    }

    /// Assign a result to an incident, returning the incident id to annotate
    /// the pass-through result with. Records guard hits via `on_guard`.
    pub(crate) fn assign(
        &mut self,
        cfg: &GroupConfig,
        result: &EvaluationResult,
        now: i64,
        mut on_guard: impl FnMut(OvermergeGuard),
    ) -> Option<String> {
        match cfg.mode {
            GroupMode::GroupBy => self.assign_group_by(cfg, result, now),
            GroupMode::EntityGraph => self.assign_entity_graph(cfg, result, now, &mut on_guard),
        }
    }

    fn assign_group_by(
        &mut self,
        cfg: &GroupConfig,
        result: &EvaluationResult,
        now: i64,
    ) -> Option<String> {
        let (id, key) = group_fingerprint(&cfg.by, result);
        let exists = self.incidents.contains_key(&id);
        if !exists && self.incidents.len() >= cfg.caps.max_open_incidents {
            return None;
        }
        let incident = self
            .incidents
            .entry(id.clone())
            .or_insert_with(|| Incident::new(id.clone(), now, key.clone()));
        incident.absorb(result, now, cfg);
        Some(id)
    }

    fn assign_entity_graph(
        &mut self,
        cfg: &GroupConfig,
        result: &EvaluationResult,
        now: i64,
        on_guard: &mut impl FnMut(OvermergeGuard),
    ) -> Option<String> {
        // Extract joinable entity pairs, applying the stop-list and
        // per-value cardinality ceiling.
        let mut pairs: Vec<(String, String)> = Vec::new();
        for sel in &cfg.entities {
            let Some(value) = sel.resolve(result) else {
                continue;
            };
            let value = match value {
                Value::String(s) => s,
                other => other.to_string(),
            };
            if cfg.stop_values.contains(&value) {
                on_guard(OvermergeGuard::StopValue);
                continue;
            }
            let key = (sel.as_str(), value);
            let count = self.value_counts.entry(key.clone()).or_insert(0);
            *count += 1;
            if *count > cfg.caps.max_value_cardinality {
                on_guard(OvermergeGuard::CardinalityCeiling);
                continue;
            }
            pairs.push(key);
        }

        // Incidents already touched by any of these entity values.
        let mut touched: Vec<String> = Vec::new();
        for pair in &pairs {
            if let Some(id) = self.entity_index.get(pair)
                && !touched.contains(id)
            {
                touched.push(id.clone());
            }
        }

        let survivor_id = match touched.first().cloned() {
            None => {
                if self.incidents.len() >= cfg.caps.max_open_incidents {
                    return None;
                }
                let id = uuid::Uuid::new_v4().to_string();
                self.incidents
                    .insert(id.clone(), Incident::new(id.clone(), now, Vec::new()));
                id
            }
            Some(survivor) => {
                // Merge any other touched incidents into the survivor.
                for other in touched.iter().skip(1) {
                    self.merge(&survivor, other, cfg.caps.max_results_per_incident);
                }
                survivor
            }
        };

        // Register the entity values and absorb the result.
        if let Some(incident) = self.incidents.get_mut(&survivor_id) {
            for (sel, value) in &pairs {
                let set = incident.entities.entry(sel.clone()).or_default();
                if set.len() < cfg.caps.max_entities_per_incident {
                    set.insert(value.clone());
                }
            }
            incident.absorb(result, now, cfg);
        }
        for pair in pairs {
            self.entity_index.insert(pair, survivor_id.clone());
        }
        Some(survivor_id)
    }

    /// Merge incident `other` into `survivor`, repointing its entity index.
    fn merge(&mut self, survivor: &str, other: &str, max_results: usize) {
        if survivor == other {
            return;
        }
        let Some(mut victim) = self.incidents.remove(other) else {
            return;
        };
        // Repoint entity-index entries from the victim to the survivor.
        for (sel, values) in &victim.entities {
            for value in values {
                self.entity_index
                    .insert((sel.clone(), value.clone()), survivor.to_string());
            }
        }
        if let Some(inc) = self.incidents.get_mut(survivor) {
            inc.first_seen = inc.first_seen.min(victim.first_seen);
            inc.last_seen = inc.last_seen.max(victim.last_seen);
            inc.result_count += victim.result_count;
            inc.dirty = true;
            inc.max_level = max_level(inc.max_level, victim.max_level);
            for (rule, count) in victim.rule_counts {
                *inc.rule_counts.entry(rule).or_insert(0) += count;
            }
            for (sel, values) in victim.entities {
                inc.entities.entry(sel).or_default().extend(values);
            }
            inc.refs.append(&mut victim.refs);
            inc.results.append(&mut victim.results);
            // Keep the per-incident cap after merging two incidents' samples.
            inc.refs.truncate(max_results);
            inc.results.truncate(max_results);
        }
    }

    /// Advance time: emit incidents due per the Alertmanager timers and evict
    /// resolved ones.
    pub(crate) fn tick(&mut self, cfg: &GroupConfig, now: i64) -> Vec<IncidentEmission> {
        let group_wait = cfg.group_wait.as_secs() as i64;
        let group_interval = cfg.group_interval.as_secs() as i64;
        let repeat = cfg.repeat_interval.as_secs() as i64;
        let resolve = cfg.resolve_timeout.as_secs() as i64;

        let mut out = Vec::new();
        let mut resolved = Vec::new();
        for (id, inc) in self.incidents.iter_mut() {
            if !inc.opened {
                if now - inc.first_seen >= group_wait {
                    out.push(IncidentEmission {
                        trigger: "group_wait",
                        result: inc.to_result("open", "group_wait", cfg.include),
                    });
                    inc.opened = true;
                    inc.dirty = false;
                    inc.last_emitted = now;
                    inc.emitted_count = inc.result_count;
                }
                continue;
            }
            if now - inc.last_seen >= resolve {
                out.push(IncidentEmission {
                    trigger: "resolved",
                    result: inc.to_result("resolved", "resolved", cfg.include),
                });
                resolved.push(id.clone());
            } else if inc.dirty && now - inc.last_emitted >= group_interval {
                out.push(IncidentEmission {
                    trigger: "group_interval",
                    result: inc.to_result("open", "group_interval", cfg.include),
                });
                inc.dirty = false;
                inc.last_emitted = now;
                inc.emitted_count = inc.result_count;
            } else if repeat > 0 && now - inc.last_emitted >= repeat {
                out.push(IncidentEmission {
                    trigger: "repeat",
                    result: inc.to_result("open", "repeat", cfg.include),
                });
                inc.last_emitted = now;
            }
        }
        for id in resolved {
            if let Some(inc) = self.incidents.remove(&id) {
                // Drop the resolved incident's entity values from both the index
                // and the cardinality counters so neither grows unbounded with
                // distinct entity values over time.
                for (sel, values) in inc.entities {
                    for value in values {
                        let key = (sel.clone(), value);
                        self.entity_index.remove(&key);
                        self.value_counts.remove(&key);
                    }
                }
            }
        }
        out
    }

    /// Export open incidents for persistence.
    pub(crate) fn export(&self) -> Vec<Incident> {
        self.incidents.values().cloned().collect()
    }

    /// Restore incidents, dropping any already past `resolve_timeout` at `now`,
    /// and rebuild the entity index from the restored incidents' entity values
    /// (the index and cardinality counters are not themselves persisted).
    pub(crate) fn restore(&mut self, incidents: Vec<Incident>, now: i64, resolve_secs: i64) {
        for inc in incidents {
            if now - inc.last_seen >= resolve_secs {
                continue;
            }
            for (sel, values) in &inc.entities {
                for value in values {
                    self.entity_index
                        .insert((sel.clone(), value.clone()), inc.id.clone());
                }
            }
            self.incidents.insert(inc.id.clone(), inc);
        }
    }
}

impl Incident {
    fn new(id: String, now: i64, group_by: Vec<(String, Value)>) -> Self {
        Incident {
            id,
            first_seen: now,
            last_seen: now,
            last_emitted: now,
            emitted_count: 0,
            opened: false,
            dirty: true,
            group_by,
            entities: BTreeMap::new(),
            max_level: None,
            rule_counts: BTreeMap::new(),
            result_count: 0,
            refs: Vec::new(),
            results: Vec::new(),
        }
    }

    fn absorb(&mut self, result: &EvaluationResult, now: i64, cfg: &GroupConfig) {
        self.last_seen = now;
        self.dirty = true;
        self.result_count += 1;
        self.max_level = max_level(self.max_level, result.header.level);
        let rule = result
            .header
            .rule_id
            .clone()
            .unwrap_or_else(|| result.header.rule_title.clone());
        *self.rule_counts.entry(rule.clone()).or_insert(0) += 1;
        match cfg.include {
            IncludeMode::Refs => {
                if self.refs.len() < cfg.caps.max_results_per_incident {
                    self.refs.push(IncidentRef {
                        rule,
                        level: result.header.level.map(|l| l.as_str().to_string()),
                    });
                }
            }
            IncludeMode::Results => {
                if self.results.len() < cfg.caps.max_results_per_incident {
                    let mut sample = result.clone();
                    strip_event_payloads(&mut sample);
                    self.results
                        .push(serde_json::to_value(&sample).unwrap_or(Value::Null));
                }
            }
        }
    }

    fn to_result(
        &self,
        state: &'static str,
        trigger: &'static str,
        include: IncludeMode,
    ) -> IncidentResult {
        let group_by: serde_json::Map<String, Value> = self.group_by.iter().cloned().collect();
        let entities: serde_json::Map<String, Value> = self
            .entities
            .iter()
            .map(|(sel, values)| {
                (
                    sel.clone(),
                    Value::Array(values.iter().cloned().map(Value::String).collect()),
                )
            })
            .collect();
        let (refs, results) = match include {
            IncludeMode::Refs => (Some(self.refs.clone()), None),
            IncludeMode::Results => (None, Some(self.results.clone())),
        };
        IncidentResult {
            incident_id: self.id.clone(),
            state,
            trigger,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            max_level: self.max_level.map(|l| l.as_str().to_string()),
            result_count: self.result_count,
            rule_counts: self.rule_counts.clone(),
            group_by,
            entities,
            refs,
            results,
        }
    }
}

/// The deterministic group fingerprint and the resolved key values for a
/// `group_by`-mode result. The rule identity is deliberately excluded so an
/// incident can span rules that share the group key.
pub(crate) fn group_fingerprint(
    selectors: &[Selector],
    result: &EvaluationResult,
) -> (String, Vec<(String, Value)>) {
    let mut buf = String::with_capacity(64);
    let mut key = Vec::with_capacity(selectors.len());
    for sel in selectors {
        let value = sel.resolve(result).unwrap_or(Value::Null);
        buf.push('\u{1f}');
        buf.push_str(&sel.as_str());
        buf.push('=');
        match &value {
            Value::String(s) => buf.push_str(s),
            other => buf.push_str(&other.to_string()),
        }
        key.push((sel.as_str(), value));
    }
    (format!("{:016x}", fnv1a64(buf.as_bytes())), key)
}

/// Rank for severity comparison (`Level` is not `Ord`).
fn level_rank(level: Level) -> u8 {
    match level {
        Level::Informational => 0,
        Level::Low => 1,
        Level::Medium => 2,
        Level::High => 3,
        Level::Critical => 4,
    }
}

/// The higher-severity of two optional levels.
fn max_level(a: Option<Level>, b: Option<Level>) -> Option<Level> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if level_rank(x) >= level_rank(y) { x } else { y }),
        (Some(x), None) => Some(x),
        (None, b) => b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn detection(rule: &str, ip: &str, user: &str, level: Level) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: rule.to_string(),
                rule_id: Some(rule.to_string()),
                level: Some(level),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: vec![
                    FieldMatch::new("SourceIp", serde_json::json!(ip)),
                    FieldMatch::new("User", serde_json::json!(user)),
                ],
                event: None,
            }),
        }
    }

    fn group_by_cfg() -> GroupConfig {
        GroupConfig {
            mode: GroupMode::GroupBy,
            by: vec![Selector::parse("match.SourceIp").unwrap()],
            entities: vec![],
            group_wait: Duration::from_secs(30),
            group_interval: Duration::from_secs(300),
            repeat_interval: Duration::from_secs(0),
            resolve_timeout: Duration::from_secs(3600),
            include: IncludeMode::Refs,
            caps: Caps::default(),
            stop_values: BTreeSet::new(),
            nats_subject: None,
        }
    }

    #[test]
    fn group_by_assigns_same_key_to_one_incident() {
        let cfg = group_by_cfg();
        let mut store = IncidentStore::default();
        let a = store.assign(
            &cfg,
            &detection("r1", "10.0.0.1", "alice", Level::High),
            0,
            |_| {},
        );
        let b = store.assign(
            &cfg,
            &detection("r2", "10.0.0.1", "bob", Level::Low),
            1,
            |_| {},
        );
        let c = store.assign(
            &cfg,
            &detection("r1", "10.0.0.2", "carol", Level::High),
            2,
            |_| {},
        );
        assert_eq!(a, b, "same SourceIp groups together across rules");
        assert_ne!(a, c, "different SourceIp is a separate incident");
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn group_by_fingerprint_is_deterministic() {
        let cfg = group_by_cfg();
        let mut s1 = IncidentStore::default();
        let mut s2 = IncidentStore::default();
        let id1 = s1.assign(
            &cfg,
            &detection("r", "1.2.3.4", "x", Level::High),
            0,
            |_| {},
        );
        let id2 = s2.assign(&cfg, &detection("r", "1.2.3.4", "y", Level::Low), 9, |_| {});
        assert_eq!(id1, id2, "same key yields the same id across stores");
    }

    #[test]
    fn group_wait_then_resolve() {
        let cfg = group_by_cfg();
        let mut store = IncidentStore::default();
        store.assign(
            &cfg,
            &detection("r", "10.0.0.1", "a", Level::High),
            0,
            |_| {},
        );
        assert!(store.tick(&cfg, 10).is_empty(), "before group_wait");
        let opened = store.tick(&cfg, 40);
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].trigger, "group_wait");
        assert_eq!(opened[0].result.state, "open");
        let resolved = store.tick(&cfg, 40 + 3600);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].trigger, "resolved");
        assert!(store.is_empty());
    }

    fn entity_cfg() -> GroupConfig {
        GroupConfig {
            mode: GroupMode::EntityGraph,
            by: vec![],
            entities: vec![
                Selector::parse("match.SourceIp").unwrap(),
                Selector::parse("match.User").unwrap(),
            ],
            group_wait: Duration::from_secs(0),
            group_interval: Duration::from_secs(300),
            repeat_interval: Duration::from_secs(0),
            resolve_timeout: Duration::from_secs(3600),
            include: IncludeMode::Refs,
            caps: Caps::default(),
            stop_values: BTreeSet::new(),
            nats_subject: None,
        }
    }

    #[test]
    fn entity_graph_merges_via_shared_value() {
        let cfg = entity_cfg();
        let mut store = IncidentStore::default();
        // A: ip1 + alice
        let a = store
            .assign(
                &cfg,
                &detection("r", "10.0.0.1", "alice", Level::High),
                0,
                |_| {},
            )
            .unwrap();
        // B: ip2 + bob (separate)
        let b = store
            .assign(
                &cfg,
                &detection("r", "10.0.0.2", "bob", Level::Low),
                1,
                |_| {},
            )
            .unwrap();
        assert_ne!(a, b);
        assert_eq!(store.len(), 2);
        // C: ip2 + alice -> bridges A and B into one incident.
        let c = store
            .assign(
                &cfg,
                &detection("r", "10.0.0.2", "alice", Level::Medium),
                2,
                |_| {},
            )
            .unwrap();
        assert_eq!(store.len(), 1, "the bridge merged the two incidents");
        assert!(c == a || c == b);
    }

    #[test]
    fn entity_graph_stop_value_does_not_join() {
        let mut cfg = entity_cfg();
        cfg.stop_values.insert("0.0.0.0".to_string());
        let mut store = IncidentStore::default();
        let mut guards = 0;
        // Two results sharing only the stop value 0.0.0.0 must NOT merge.
        store.assign(
            &cfg,
            &detection("r", "0.0.0.0", "alice", Level::High),
            0,
            |_| guards += 1,
        );
        store.assign(
            &cfg,
            &detection("r", "0.0.0.0", "bob", Level::High),
            1,
            |_| guards += 1,
        );
        assert_eq!(store.len(), 2, "stop value must not bridge incidents");
        assert!(guards >= 2, "stop-value guard fired");
    }

    #[test]
    fn cardinality_counter_freed_after_resolve() {
        // A value's occurrence counter must not leak: once its incident
        // resolves, the counter is dropped so the value can join fresh.
        let mut cfg = entity_cfg();
        cfg.caps.max_value_cardinality = 2;
        cfg.entities = vec![Selector::parse("match.SourceIp").unwrap()];
        let mut store = IncidentStore::default();
        let mut guards = 0;
        store.assign(
            &cfg,
            &detection("r", "10.0.0.9", "a", Level::High),
            0,
            |_| guards += 1,
        );
        store.assign(
            &cfg,
            &detection("r", "10.0.0.9", "b", Level::High),
            1,
            |_| guards += 1,
        );
        assert_eq!(guards, 0, "two occurrences are within the ceiling");
        store.tick(&cfg, 0); // group_wait 0 opens the incident
        store.tick(&cfg, 5000); // past resolve_timeout
        assert!(store.is_empty());
        // The counter for 10.0.0.9 was freed on resolve, so a new occurrence
        // joins fresh rather than tripping the ceiling.
        store.assign(
            &cfg,
            &detection("r", "10.0.0.9", "c", Level::High),
            6000,
            |_| guards += 1,
        );
        assert_eq!(guards, 0, "counter reset after resolve");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn entity_graph_cardinality_ceiling_stops_joining() {
        let mut cfg = entity_cfg();
        cfg.caps.max_value_cardinality = 1;
        cfg.entities = vec![Selector::parse("match.SourceIp").unwrap()];
        let mut store = IncidentStore::default();
        let mut guards = 0;
        // First occurrence joins; subsequent ones exceed the ceiling and stop.
        store.assign(
            &cfg,
            &detection("r", "10.0.0.9", "a", Level::High),
            0,
            |_| guards += 1,
        );
        store.assign(
            &cfg,
            &detection("r", "10.0.0.9", "b", Level::High),
            1,
            |_| guards += 1,
        );
        store.assign(
            &cfg,
            &detection("r", "10.0.0.9", "c", Level::High),
            2,
            |_| guards += 1,
        );
        assert!(guards >= 2, "cardinality guard fired after the ceiling");
        // The 2nd and 3rd did not join the 1st, so they each opened their own.
        assert_eq!(store.len(), 3);
    }
}
