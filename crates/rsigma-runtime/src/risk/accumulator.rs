//! Per-entity sliding-window risk accumulator (stage two).
//!
//! Keyed by `(entity_type, entity_value)`, each entity keeps a time-ordered
//! window of contributions. On every new contribution the window is pruned to
//! the configured duration, the risk sum and the distinct-tactic and
//! distinct-source modifiers are recomputed, and a [`RiskIncidentResult`] fires
//! when the entity crosses the score or tactic-count threshold, subject to a
//! per-entity cooldown.
//!
//! State ownership is single-threaded (the sink task), mirroring the alert
//! pipeline; the only shared access is the read-only `GET /api/v1/risk` view
//! behind an `RwLock`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use rsigma_eval::TenantId;

use super::incident::{IncludeMode, RiskEntityView, RiskIncidentResult, RiskRef};
use super::snapshot::{EntitySnapshot, RiskStateSnapshot, SNAPSHOT_VERSION};

/// Default ceiling on concurrently-tracked entities. Once full, contributions
/// for a new entity are not accumulated (bounding memory), reported as an
/// eviction so the saturation is visible.
pub const DEFAULT_MAX_OPEN_ENTITIES: usize = 100_000;
/// Default ceiling on distinct sources listed in an emitted incident.
pub const DEFAULT_MAX_SOURCES_PER_ENTITY: usize = 1_000;
/// Default ceiling on contributions retained per entity (also the embedded
/// refs/results bound). Older contributions are dropped FIFO once exceeded.
pub const DEFAULT_MAX_RESULTS_PER_INCIDENT: usize = 1_000;

/// Bounds on accumulator growth, with an eviction metric when exceeded.
#[derive(Debug, Clone, Copy)]
pub struct RiskCaps {
    /// Maximum simultaneously-tracked entities.
    pub max_open_entities: usize,
    /// Maximum distinct sources listed per emitted incident.
    pub max_sources_per_entity: usize,
    /// Maximum contributions retained per entity (and embedded per incident).
    pub max_results_per_incident: usize,
    /// Maximum simultaneously-tracked entities per tenant. At the cap, that
    /// tenant's stalest entity is dropped. `None` leaves only the global cap.
    pub max_open_entities_per_tenant: Option<usize>,
}

impl Default for RiskCaps {
    fn default() -> Self {
        RiskCaps {
            max_open_entities: DEFAULT_MAX_OPEN_ENTITIES,
            max_sources_per_entity: DEFAULT_MAX_SOURCES_PER_ENTITY,
            max_results_per_incident: DEFAULT_MAX_RESULTS_PER_INCIDENT,
            max_open_entities_per_tenant: None,
        }
    }
}

/// Validated risk-incident configuration.
#[derive(Debug, Clone)]
pub struct IncidentConfig {
    /// Accumulation window.
    pub window: Duration,
    /// Score threshold (window risk sum). `None` disables the score trigger.
    pub score_threshold: Option<i64>,
    /// Distinct-tactic threshold. `None` disables the tactic trigger.
    pub tactic_count_threshold: Option<u64>,
    /// Per-entity cooldown after a fire.
    pub cooldown: Duration,
    /// How much contributing detail to embed in an incident.
    pub include: IncludeMode,
    /// Optional NATS subject override for emitted incidents.
    pub nats_subject: Option<String>,
    /// Growth bounds.
    pub caps: RiskCaps,
}

impl IncidentConfig {
    fn window_secs(&self) -> i64 {
        self.window.as_secs() as i64
    }
}

/// One contribution from a firing detection to an entity's risk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contribution {
    /// Contribution timestamp (unix seconds).
    pub ts: i64,
    /// The risk score this firing contributed.
    pub score: i64,
    /// Canonical ATT&CK tactic slugs this firing touched.
    pub tactics: Vec<String>,
    /// Rule identity (rule id, falling back to the title).
    pub rule: String,
    /// Severity, lowercased.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub level: Option<String>,
    /// The event-stripped serialized result, retained only for `include: results`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub result: Option<Value>,
    /// OCSF `finding_info.uid` of the Detection Finding minted for this
    /// firing, when known. In memory only: never persisted.
    #[serde(skip)]
    pub finding_uid: Option<String>,
}

/// Per-entity sliding-window state.
#[derive(Debug, Default)]
struct EntityWindow {
    contributions: VecDeque<Contribution>,
    last_fired: Option<i64>,
    last_seen: i64,
}

impl EntityWindow {
    /// Drop contributions older than the window.
    fn prune(&mut self, cutoff: i64) {
        while let Some(front) = self.contributions.front() {
            if front.ts <= cutoff {
                self.contributions.pop_front();
            } else {
                break;
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.contributions.is_empty()
    }
}

/// Aggregate statistics over a window of contributions.
struct WindowStats {
    score: i64,
    tactics: Vec<String>,
    sources: Vec<String>,
    source_count: u64,
    result_count: u64,
    window_start: i64,
    window_end: i64,
}

/// Compute aggregate statistics over a set of contributions, listing at most
/// `max_sources` distinct sources (the count is the true distinct total).
fn window_stats<'a>(
    contributions: impl Iterator<Item = &'a Contribution>,
    max_sources: usize,
) -> WindowStats {
    let mut score: i64 = 0;
    let mut tactics: Vec<String> = Vec::new();
    let mut sources: Vec<String> = Vec::new();
    let mut result_count: u64 = 0;
    let mut window_start = i64::MAX;
    let mut window_end = i64::MIN;
    for c in contributions {
        score += c.score;
        result_count += 1;
        window_start = window_start.min(c.ts);
        window_end = window_end.max(c.ts);
        for t in &c.tactics {
            if !tactics.contains(t) {
                tactics.push(t.clone());
            }
        }
        if !sources.contains(&c.rule) {
            sources.push(c.rule.clone());
        }
    }
    let source_count = sources.len() as u64;
    if sources.len() > max_sources {
        sources.truncate(max_sources);
    }
    if result_count == 0 {
        window_start = 0;
        window_end = 0;
    }
    WindowStats {
        score,
        tactics,
        sources,
        source_count,
        result_count,
        window_start,
        window_end,
    }
}

/// The in-memory accumulator, owned single-threaded by the sink task (shared
/// behind an `RwLock` so `GET /api/v1/risk` can read it).
#[derive(Debug, Default)]
pub struct RiskState {
    entities: HashMap<(Option<TenantId>, String, String), EntityWindow>,
    /// `(entity_type, entity_value)` per tenant, kept in step with `entities`.
    tenant_entities: HashMap<Option<TenantId>, HashSet<(String, String)>>,
}

/// The outcome of recording one contribution.
pub struct RecordOutcome {
    /// An incident, when the entity crossed a threshold and was not cooling down.
    pub incident: Option<RiskIncidentResult>,
    /// Detection Finding uids for `incident`, when one was emitted.
    pub links: crate::FindingLinks,
    /// True when a new entity could not be tracked because the store was full.
    pub evicted: bool,
    /// True when a tenant's own stalest entity was evicted to make room under
    /// its per-tenant cap.
    pub quota_evicted: bool,
}

impl RiskState {
    /// Number of tracked entities.
    pub fn len(&self) -> usize {
        self.entities.len()
    }

    /// True when no entities are tracked.
    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    /// Count of tracked entities owned by `tenant`.
    pub fn count_for_tenant(&self, tenant: Option<&TenantId>) -> usize {
        self.tenant_entities
            .get(&tenant.cloned())
            .map_or(0, HashSet::len)
    }

    fn insert_entity(&mut self, key: (Option<TenantId>, String, String), window: EntityWindow) {
        self.tenant_entities
            .entry(key.0.clone())
            .or_default()
            .insert((key.1.clone(), key.2.clone()));
        self.entities.insert(key, window);
    }

    fn remove_entity(&mut self, key: &(Option<TenantId>, String, String)) -> bool {
        if self.entities.remove(key).is_none() {
            return false;
        }
        if let Some(entities) = self.tenant_entities.get_mut(&key.0) {
            entities.remove(&(key.1.clone(), key.2.clone()));
            if entities.is_empty() {
                self.tenant_entities.remove(&key.0);
            }
        }
        true
    }

    /// Whether `(tenant, entity_type, entity_value)` is already tracked.
    pub fn contains_entity(
        &self,
        tenant: Option<&TenantId>,
        entity_type: &str,
        entity_value: &str,
    ) -> bool {
        self.entities.contains_key(&(
            tenant.cloned(),
            entity_type.to_string(),
            entity_value.to_string(),
        ))
    }

    /// Evict the stalest entity owned by `tenant`. Returns whether one was
    /// evicted.
    pub fn evict_tenant_oldest(&mut self, tenant: Option<&TenantId>) -> bool {
        let tenant = tenant.cloned();
        let victim = self
            .tenant_entities
            .get(&tenant)
            .into_iter()
            .flatten()
            .filter_map(|(entity_type, entity_value)| {
                let key = (tenant.clone(), entity_type.clone(), entity_value.clone());
                self.entities
                    .get(&key)
                    .map(|window| (window.last_seen, key))
            })
            .min_by_key(|(last_seen, _)| *last_seen)
            .map(|(_, key)| key);
        match victim {
            Some(key) => self.remove_entity(&key),
            None => false,
        }
    }

    /// Evict each tenant's stalest entities until it holds at most `max`,
    /// returning how many were evicted.
    pub fn enforce_tenant_cap(&mut self, max: usize) -> usize {
        let over: Vec<Option<TenantId>> = self
            .tenant_entities
            .iter()
            .filter(|(_, entities)| entities.len() > max)
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

    /// Total retained contributions across all entities (for the state gauge).
    pub fn total_entries(&self) -> usize {
        self.entities.values().map(|e| e.contributions.len()).sum()
    }

    /// Record a contribution for an entity, returning an incident when a
    /// threshold is crossed outside the cooldown.
    pub fn record(
        &mut self,
        cfg: &IncidentConfig,
        tenant: Option<&TenantId>,
        entity_type: &str,
        entity_value: &str,
        contribution: Contribution,
        now: i64,
    ) -> RecordOutcome {
        let key = (
            tenant.cloned(),
            entity_type.to_string(),
            entity_value.to_string(),
        );
        let cutoff = now - cfg.window_secs();

        let mut quota_evicted = false;
        if !self.entities.contains_key(&key)
            && let Some(cap) = cfg.caps.max_open_entities_per_tenant
            && self.count_for_tenant(tenant) >= cap
        {
            quota_evicted = self.evict_tenant_oldest(tenant);
        }

        if !self.entities.contains_key(&key) && self.entities.len() >= cfg.caps.max_open_entities {
            // At capacity: a brand-new entity is not tracked, bounding memory.
            // The firing still passes through annotated; the saturation shows
            // up as an eviction and the entities gauge plateauing at the cap.
            return RecordOutcome {
                incident: None,
                links: crate::FindingLinks::default(),
                evicted: true,
                quota_evicted,
            };
        }

        if !self.entities.contains_key(&key) {
            self.insert_entity(key.clone(), EntityWindow::default());
        }
        let entity = self.entities.get_mut(&key).expect("inserted above");
        entity.prune(cutoff);
        entity.last_seen = now;
        entity.contributions.push_back(contribution);
        while entity.contributions.len() > cfg.caps.max_results_per_incident {
            entity.contributions.pop_front();
        }

        let stats = window_stats(entity.contributions.iter(), cfg.caps.max_sources_per_entity);
        let tactic_count = stats.tactics.len() as u64;

        let trigger = if cfg.score_threshold.is_some_and(|t| stats.score >= t) {
            Some("score")
        } else if cfg
            .tactic_count_threshold
            .is_some_and(|t| tactic_count >= t)
        {
            Some("tactic_count")
        } else {
            None
        };

        let built = trigger.and_then(|trigger| {
            let cooling = entity
                .last_fired
                .is_some_and(|lf| now - lf < cfg.cooldown.as_secs() as i64);
            if cooling {
                return None;
            }
            entity.last_fired = Some(now);
            Some(build_incident(
                cfg,
                tenant,
                entity_type,
                entity_value,
                trigger,
                tactic_count,
                &stats,
                entity.contributions.iter(),
            ))
        });
        let (incident, links) = match built {
            Some((incident, links)) => (Some(incident), links),
            None => (None, crate::FindingLinks::default()),
        };

        RecordOutcome {
            incident,
            links,
            evicted: false,
            quota_evicted,
        }
    }

    /// Prune entities whose windows have fully aged out at `now`, returning the
    /// number removed (for eviction accounting).
    pub fn tick(&mut self, cfg: &IncidentConfig, now: i64) -> usize {
        let cutoff = now - cfg.window_secs();
        let mut emptied = Vec::new();
        for (key, entity) in self.entities.iter_mut() {
            entity.prune(cutoff);
            if entity.is_empty() {
                emptied.push(key.clone());
            }
        }
        for key in &emptied {
            self.remove_entity(key);
        }
        emptied.len()
    }

    /// Capture the accumulator into a versioned persistence snapshot.
    pub fn snapshot(&self) -> RiskStateSnapshot {
        let entities = self
            .entities
            .iter()
            .map(
                |((tenant, entity_type, entity_value), window)| EntitySnapshot {
                    tenant: tenant.clone(),
                    entity_type: entity_type.clone(),
                    entity_value: entity_value.clone(),
                    last_fired: window.last_fired,
                    last_seen: window.last_seen,
                    contributions: window.contributions.iter().cloned().collect(),
                },
            )
            .collect();
        RiskStateSnapshot {
            version: SNAPSHOT_VERSION,
            entities,
        }
    }

    /// Restore a snapshot, dropping contributions already past the window at
    /// `now`, skipping entities left empty, and honoring `max_open_entities` so a
    /// restore cannot load more entities than the live cap allows. Returns
    /// `false` on a version mismatch (the caller starts fresh).
    pub fn restore(
        &mut self,
        snap: RiskStateSnapshot,
        window_secs: i64,
        max_open_entities: usize,
        now: i64,
        tenancy: bool,
    ) -> bool {
        self.restore_detailed(snap, window_secs, max_open_entities, now, tenancy)
            .is_some()
    }

    /// Like [`restore`](Self::restore), returning the restored and discarded
    /// counts. Accepts versions 1 and 2 and applies the tenant attribution rule:
    /// with `tenancy`, untenanted entities are discarded; without it, tenanted
    /// ones are.
    pub fn restore_detailed(
        &mut self,
        snap: RiskStateSnapshot,
        window_secs: i64,
        max_open_entities: usize,
        now: i64,
        tenancy: bool,
    ) -> Option<rsigma_eval::ImportStats> {
        if !matches!(snap.version, 1 | 2) {
            return None;
        }
        let mut stats = rsigma_eval::ImportStats::default();
        let cutoff = now - window_secs;
        for entity in snap.entities {
            let keep = if tenancy {
                entity.tenant.is_some()
            } else {
                entity.tenant.is_none()
            };
            if !keep {
                if entity.tenant.is_none() {
                    stats.discarded_untenanted += 1;
                } else {
                    stats.discarded_tenanted += 1;
                }
                continue;
            }
            if self.entities.len() >= max_open_entities {
                break;
            }
            let contributions: VecDeque<Contribution> = entity
                .contributions
                .into_iter()
                .filter(|c| c.ts > cutoff)
                .collect();
            if contributions.is_empty() {
                continue;
            }
            self.insert_entity(
                (entity.tenant, entity.entity_type, entity.entity_value),
                EntityWindow {
                    contributions,
                    last_fired: entity.last_fired,
                    last_seen: entity.last_seen,
                },
            );
            stats.restored += 1;
        }
        Some(stats)
    }

    /// A read-only view of every open entity at `now`, for the admin API.
    pub fn views(&self, cfg: &IncidentConfig, now: i64) -> Vec<RiskEntityView> {
        let cutoff = now - cfg.window_secs();
        let mut out = Vec::new();
        for ((tenant, entity_type, entity_value), entity) in &self.entities {
            let live = entity.contributions.iter().filter(|c| c.ts > cutoff);
            let stats = window_stats(live, cfg.caps.max_sources_per_entity);
            if stats.result_count == 0 {
                continue;
            }
            out.push(RiskEntityView {
                tenant_id: tenant.clone(),
                entity_type: entity_type.clone(),
                entity_value: entity_value.clone(),
                score: stats.score,
                tactic_count: stats.tactics.len() as u64,
                source_count: stats.source_count,
                result_count: stats.result_count,
                window_start: stats.window_start,
                window_end: stats.window_end,
                last_fired: entity.last_fired,
            });
        }
        out
    }
}

/// Build a [`RiskIncidentResult`] from the current window state.
#[allow(clippy::too_many_arguments)]
fn build_incident<'a>(
    cfg: &IncidentConfig,
    tenant: Option<&TenantId>,
    entity_type: &str,
    entity_value: &str,
    trigger: &'static str,
    tactic_count: u64,
    stats: &WindowStats,
    contributions: impl Iterator<Item = &'a Contribution>,
) -> (RiskIncidentResult, crate::FindingLinks) {
    let recent: Vec<&Contribution> = {
        let all: Vec<&Contribution> = contributions.collect();
        let take = cfg.caps.max_results_per_incident.min(all.len());
        all[all.len() - take..].to_vec()
    };

    let (refs, results, links) = match cfg.include {
        IncludeMode::Refs => {
            let refs: Vec<RiskRef> = recent
                .iter()
                .map(|c| RiskRef {
                    rule: c.rule.clone(),
                    level: c.level.clone(),
                    score: c.score,
                    timestamp: c.ts,
                })
                .collect();
            let links = crate::FindingLinks {
                refs: recent.iter().map(|c| c.finding_uid.clone()).collect(),
                results: Vec::new(),
            };
            (Some(refs), None, links)
        }
        IncludeMode::Results => {
            let (results, uids): (Vec<Value>, Vec<Option<String>>) = recent
                .iter()
                .filter_map(|c| Some((c.result.clone()?, c.finding_uid.clone())))
                .unzip();
            (
                None,
                Some(results),
                crate::FindingLinks {
                    refs: Vec::new(),
                    results: uids,
                },
            )
        }
    };

    (
        RiskIncidentResult {
            risk_incident_id: Uuid::new_v4().to_string(),
            tenant_id: tenant.cloned(),
            entity_type: entity_type.to_string(),
            entity_value: entity_value.to_string(),
            trigger,
            score: stats.score,
            score_threshold: cfg.score_threshold,
            tactic_count,
            tactic_count_threshold: cfg.tactic_count_threshold,
            tactics: stats.tactics.clone(),
            sources: stats.sources.clone(),
            source_count: stats.source_count,
            window_start: stats.window_start,
            window_end: stats.window_end,
            result_count: stats.result_count,
            refs,
            results,
        },
        links,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(score: Option<i64>, tactics: Option<u64>) -> IncidentConfig {
        IncidentConfig {
            window: Duration::from_secs(3600),
            score_threshold: score,
            tactic_count_threshold: tactics,
            cooldown: Duration::from_secs(600),
            include: IncludeMode::Refs,
            nats_subject: None,
            caps: RiskCaps::default(),
        }
    }

    fn contrib(ts: i64, score: i64, tactics: &[&str], rule: &str) -> Contribution {
        Contribution {
            ts,
            score,
            tactics: tactics.iter().map(|s| s.to_string()).collect(),
            rule: rule.to_string(),
            level: Some("high".to_string()),
            result: None,
            finding_uid: None,
        }
    }

    #[test]
    fn fires_on_score_threshold() {
        let mut st = RiskState::default();
        let c = cfg(Some(100), None);
        let a = st.record(
            &c,
            None,
            "user",
            "alice",
            contrib(0, 60, &["execution"], "r1"),
            0,
        );
        assert!(a.incident.is_none());
        let b = st.record(
            &c,
            None,
            "user",
            "alice",
            contrib(10, 60, &["persistence"], "r2"),
            10,
        );
        let inc = b.incident.expect("threshold crossed");
        assert_eq!(inc.trigger, "score");
        assert_eq!(inc.score, 120);
        assert_eq!(inc.entity_value, "alice");
        assert_eq!(inc.source_count, 2);
    }

    #[test]
    fn fires_on_tactic_count_threshold() {
        let mut st = RiskState::default();
        let c = cfg(None, Some(3));
        st.record(
            &c,
            None,
            "host",
            "dc01",
            contrib(0, 1, &["execution"], "r1"),
            0,
        );
        st.record(
            &c,
            None,
            "host",
            "dc01",
            contrib(1, 1, &["persistence"], "r2"),
            1,
        );
        let third = st.record(
            &c,
            None,
            "host",
            "dc01",
            contrib(2, 1, &["impact"], "r3"),
            2,
        );
        let inc = third.incident.expect("three distinct tactics");
        assert_eq!(inc.trigger, "tactic_count");
        assert_eq!(inc.tactic_count, 3);
    }

    #[test]
    fn cooldown_suppresses_refire() {
        let mut st = RiskState::default();
        let c = cfg(Some(50), None);
        let first = st.record(
            &c,
            None,
            "user",
            "bob",
            contrib(0, 50, &["execution"], "r1"),
            0,
        );
        assert!(first.incident.is_some());
        // Within cooldown: no re-fire even though still over threshold.
        let second = st.record(
            &c,
            None,
            "user",
            "bob",
            contrib(100, 50, &["execution"], "r1"),
            100,
        );
        assert!(second.incident.is_none());
        // After cooldown: fires again.
        let third = st.record(
            &c,
            None,
            "user",
            "bob",
            contrib(700, 50, &["execution"], "r1"),
            700,
        );
        assert!(third.incident.is_some());
    }

    #[test]
    fn window_prunes_old_contributions() {
        let mut st = RiskState::default();
        let c = cfg(Some(100), None);
        st.record(
            &c,
            None,
            "user",
            "carol",
            contrib(0, 60, &["execution"], "r1"),
            0,
        );
        // The first contribution ages out of the 3600s window by t=4000.
        let later = st.record(
            &c,
            None,
            "user",
            "carol",
            contrib(4000, 60, &["execution"], "r1"),
            4000,
        );
        assert!(
            later.incident.is_none(),
            "old contribution pruned, sum is 60"
        );
    }

    #[test]
    fn at_capacity_new_entity_is_not_tracked() {
        let mut st = RiskState::default();
        let mut c = cfg(Some(1), None);
        c.caps.max_open_entities = 1;
        let a = st.record(&c, None, "user", "a", contrib(0, 1, &[], "r1"), 0);
        assert!(a.incident.is_some());
        let b = st.record(&c, None, "user", "b", contrib(0, 1, &[], "r1"), 0);
        assert!(b.evicted, "second distinct entity rejected at capacity");
        assert_eq!(st.len(), 1);
    }

    #[test]
    fn tick_evicts_fully_aged_entities() {
        let mut st = RiskState::default();
        let c = cfg(Some(1000), None);
        st.record(
            &c,
            None,
            "user",
            "dan",
            contrib(0, 10, &["execution"], "r1"),
            0,
        );
        assert_eq!(st.len(), 1);
        let removed = st.tick(&c, 4000);
        assert_eq!(removed, 1);
        assert!(st.is_empty());
    }

    #[test]
    fn snapshot_round_trips_and_prunes() {
        let mut st = RiskState::default();
        let c = cfg(Some(100), None);
        st.record(
            &c,
            None,
            "user",
            "erin",
            contrib(100, 50, &["execution"], "r1"),
            100,
        );

        // Round-trip through JSON.
        let json = serde_json::to_string(&st.snapshot()).unwrap();
        let snap: RiskStateSnapshot = serde_json::from_str(&json).unwrap();

        // Restore within the window: the entity comes back and keeps accruing.
        let mut fresh = RiskState::default();
        assert!(fresh.restore(
            snap,
            c.window.as_secs() as i64,
            c.caps.max_open_entities,
            200,
            false
        ));
        assert_eq!(fresh.len(), 1);
        let again = fresh.record(
            &c,
            None,
            "user",
            "erin",
            contrib(200, 50, &["execution"], "r1"),
            200,
        );
        assert_eq!(again.incident.unwrap().score, 100, "restored 50 + new 50");

        // Restore far past the window: the stale contribution is pruned away.
        let snap2: RiskStateSnapshot =
            serde_json::from_str(&serde_json::to_string(&st.snapshot()).unwrap()).unwrap();
        let mut aged = RiskState::default();
        assert!(aged.restore(
            snap2,
            c.window.as_secs() as i64,
            c.caps.max_open_entities,
            100 + 3600 + 5,
            false
        ));
        assert!(aged.is_empty(), "stale entity pruned on restore");
    }

    #[test]
    fn restore_honors_max_open_entities() {
        let mut src = RiskState::default();
        let c = cfg(Some(1_000_000), None);
        for i in 0..5 {
            src.record(
                &c,
                None,
                "user",
                &format!("u{i}"),
                contrib(0, 10, &["execution"], "r1"),
                0,
            );
        }
        let snap = src.snapshot();

        let mut restored = RiskState::default();
        // Cap the restore at 3; the remaining snapshot entities are dropped.
        assert!(restored.restore(snap, c.window.as_secs() as i64, 3, 0, false));
        assert_eq!(restored.len(), 3);
    }

    #[test]
    fn restore_rejects_version_mismatch() {
        let mut st = RiskState::default();
        let snap = RiskStateSnapshot {
            version: SNAPSHOT_VERSION + 1,
            entities: vec![],
        };
        assert!(!st.restore(snap, 3600, usize::MAX, 0, false));
    }

    #[test]
    fn the_same_entity_in_two_tenants_is_two_entities() {
        let c = cfg(Some(100), None);
        let mut st = RiskState::default();
        let a = TenantId::new("a").unwrap();
        let b = TenantId::new("b").unwrap();
        st.record(
            &c,
            Some(&a),
            "user",
            "alice",
            contrib(0, 60, &["execution"], "r1"),
            0,
        );
        st.record(
            &c,
            Some(&b),
            "user",
            "alice",
            contrib(0, 60, &["execution"], "r1"),
            0,
        );
        assert_eq!(st.len(), 2);
        let views = st.views(&c, 0);
        assert_eq!(views.len(), 2);
        assert!(views.iter().all(|v| v.tenant_id.is_some()));
    }

    #[test]
    fn a_tenanted_incident_carries_the_tenant() {
        let c = cfg(Some(50), None);
        let mut st = RiskState::default();
        let a = TenantId::new("a").unwrap();
        let out = st.record(
            &c,
            Some(&a),
            "user",
            "bob",
            contrib(0, 50, &["execution"], "r1"),
            0,
        );
        assert_eq!(out.incident.unwrap().tenant_id.as_ref(), Some(&a));
    }

    #[test]
    fn snapshot_attribution_discards_the_other_mode() {
        let c = cfg(Some(1000), None);
        let mut st = RiskState::default();
        let a = TenantId::new("a").unwrap();
        st.record(
            &c,
            Some(&a),
            "user",
            "alice",
            contrib(0, 10, &["execution"], "r1"),
            0,
        );
        st.record(
            &c,
            None,
            "user",
            "bob",
            contrib(0, 10, &["execution"], "r1"),
            0,
        );
        let snap = st.snapshot();

        let mut tenanted = RiskState::default();
        let stats = tenanted
            .restore_detailed(snap.clone(), 3600, usize::MAX, 0, true)
            .unwrap();
        assert_eq!(stats.restored, 1);
        assert_eq!(stats.discarded_untenanted, 1);
        assert_eq!(tenanted.len(), 1);

        let mut untenanted = RiskState::default();
        let stats = untenanted
            .restore_detailed(snap, 3600, usize::MAX, 0, false)
            .unwrap();
        assert_eq!(stats.restored, 1);
        assert_eq!(stats.discarded_tenanted, 1);
        assert_eq!(untenanted.len(), 1);
    }

    #[test]
    fn a_tenant_quota_evicts_only_its_own_entities() {
        let mut c = cfg(Some(1_000), None);
        c.caps.max_open_entities_per_tenant = Some(2);
        let mut st = RiskState::default();
        let a = TenantId::new("a").unwrap();
        let b = TenantId::new("b").unwrap();
        for i in 0..3 {
            st.record(
                &c,
                Some(&a),
                "user",
                &format!("a{i}"),
                contrib(i as i64, 10, &["execution"], "r1"),
                i as i64,
            );
        }
        st.record(
            &c,
            Some(&b),
            "user",
            "quiet",
            contrib(0, 10, &["execution"], "r1"),
            0,
        );

        assert_eq!(st.count_for_tenant(Some(&a)), 2);
        assert_eq!(st.count_for_tenant(Some(&b)), 1);
        assert_eq!(st.len(), 3);
        assert!(
            !st.contains_entity(Some(&a), "user", "a0"),
            "the stalest entity went first"
        );
    }

    #[test]
    fn restored_entities_are_trimmed_to_the_tenant_cap_and_indexed() {
        let c = cfg(Some(1_000), None);
        let mut st = RiskState::default();
        let a = TenantId::new("a").unwrap();
        for i in 0..3 {
            st.record(
                &c,
                Some(&a),
                "user",
                &format!("a{i}"),
                contrib(i as i64, 10, &["execution"], "r1"),
                i as i64,
            );
        }
        let mut restored = RiskState::default();
        restored
            .restore_detailed(st.snapshot(), 3600, usize::MAX, 3, true)
            .unwrap();
        assert_eq!(restored.count_for_tenant(Some(&a)), 3);
        assert_eq!(restored.enforce_tenant_cap(2), 1);
        assert_eq!(restored.count_for_tenant(Some(&a)), 2);
        assert!(!restored.contains_entity(Some(&a), "user", "a0"));

        assert_eq!(restored.tick(&c, 10_000), 2);
        assert_eq!(restored.count_for_tenant(Some(&a)), 0);
    }
}
