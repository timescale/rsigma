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

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use serde_json::Value;
use uuid::Uuid;

use super::incident::{IncludeMode, RiskEntityView, RiskIncidentResult, RiskRef};

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
}

impl Default for RiskCaps {
    fn default() -> Self {
        RiskCaps {
            max_open_entities: DEFAULT_MAX_OPEN_ENTITIES,
            max_sources_per_entity: DEFAULT_MAX_SOURCES_PER_ENTITY,
            max_results_per_incident: DEFAULT_MAX_RESULTS_PER_INCIDENT,
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
#[derive(Debug, Clone)]
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
    pub level: Option<String>,
    /// The event-stripped serialized result, retained only for `include: results`.
    pub result: Option<Value>,
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
    entities: HashMap<(String, String), EntityWindow>,
}

/// The outcome of recording one contribution.
pub struct RecordOutcome {
    /// An incident, when the entity crossed a threshold and was not cooling down.
    pub incident: Option<RiskIncidentResult>,
    /// True when a new entity could not be tracked because the store was full.
    pub evicted: bool,
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

    /// Total retained contributions across all entities (for the state gauge).
    pub fn total_entries(&self) -> usize {
        self.entities.values().map(|e| e.contributions.len()).sum()
    }

    /// Record a contribution for an entity, returning an incident when a
    /// threshold is crossed outside the cooldown.
    pub fn record(
        &mut self,
        cfg: &IncidentConfig,
        entity_type: &str,
        entity_value: &str,
        contribution: Contribution,
        now: i64,
    ) -> RecordOutcome {
        let key = (entity_type.to_string(), entity_value.to_string());
        let cutoff = now - cfg.window_secs();

        if !self.entities.contains_key(&key) && self.entities.len() >= cfg.caps.max_open_entities {
            // At capacity: a brand-new entity is not tracked, bounding memory.
            // The firing still passes through annotated; the saturation shows
            // up as an eviction and the entities gauge plateauing at the cap.
            return RecordOutcome {
                incident: None,
                evicted: true,
            };
        }

        let entity = self.entities.entry(key.clone()).or_default();
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

        let incident = trigger.and_then(|trigger| {
            let cooling = entity
                .last_fired
                .is_some_and(|lf| now - lf < cfg.cooldown.as_secs() as i64);
            if cooling {
                return None;
            }
            entity.last_fired = Some(now);
            Some(build_incident(
                cfg,
                entity_type,
                entity_value,
                trigger,
                tactic_count,
                &stats,
                entity.contributions.iter(),
            ))
        });

        RecordOutcome {
            incident,
            evicted: false,
        }
    }

    /// Prune entities whose windows have fully aged out at `now`, returning the
    /// number removed (for eviction accounting).
    pub fn tick(&mut self, cfg: &IncidentConfig, now: i64) -> usize {
        let cutoff = now - cfg.window_secs();
        let before = self.entities.len();
        self.entities.retain(|_, entity| {
            entity.prune(cutoff);
            !entity.is_empty()
        });
        before - self.entities.len()
    }

    /// A read-only view of every open entity at `now`, for the admin API.
    pub fn views(&self, cfg: &IncidentConfig, now: i64) -> Vec<RiskEntityView> {
        let cutoff = now - cfg.window_secs();
        let mut out = Vec::new();
        for ((entity_type, entity_value), entity) in &self.entities {
            let live = entity.contributions.iter().filter(|c| c.ts > cutoff);
            let stats = window_stats(live, cfg.caps.max_sources_per_entity);
            if stats.result_count == 0 {
                continue;
            }
            out.push(RiskEntityView {
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
fn build_incident<'a>(
    cfg: &IncidentConfig,
    entity_type: &str,
    entity_value: &str,
    trigger: &'static str,
    tactic_count: u64,
    stats: &WindowStats,
    contributions: impl Iterator<Item = &'a Contribution>,
) -> RiskIncidentResult {
    let recent: Vec<&Contribution> = {
        let all: Vec<&Contribution> = contributions.collect();
        let take = cfg.caps.max_results_per_incident.min(all.len());
        all[all.len() - take..].to_vec()
    };

    let (refs, results) = match cfg.include {
        IncludeMode::Refs => {
            let refs = recent
                .iter()
                .map(|c| RiskRef {
                    rule: c.rule.clone(),
                    level: c.level.clone(),
                    score: c.score,
                    timestamp: c.ts,
                })
                .collect();
            (Some(refs), None)
        }
        IncludeMode::Results => {
            let results = recent.iter().filter_map(|c| c.result.clone()).collect();
            (None, Some(results))
        }
    };

    RiskIncidentResult {
        risk_incident_id: Uuid::new_v4().to_string(),
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
    }
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
        }
    }

    #[test]
    fn fires_on_score_threshold() {
        let mut st = RiskState::default();
        let c = cfg(Some(100), None);
        let a = st.record(&c, "user", "alice", contrib(0, 60, &["execution"], "r1"), 0);
        assert!(a.incident.is_none());
        let b = st.record(
            &c,
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
        st.record(&c, "host", "dc01", contrib(0, 1, &["execution"], "r1"), 0);
        st.record(&c, "host", "dc01", contrib(1, 1, &["persistence"], "r2"), 1);
        let third = st.record(&c, "host", "dc01", contrib(2, 1, &["impact"], "r3"), 2);
        let inc = third.incident.expect("three distinct tactics");
        assert_eq!(inc.trigger, "tactic_count");
        assert_eq!(inc.tactic_count, 3);
    }

    #[test]
    fn cooldown_suppresses_refire() {
        let mut st = RiskState::default();
        let c = cfg(Some(50), None);
        let first = st.record(&c, "user", "bob", contrib(0, 50, &["execution"], "r1"), 0);
        assert!(first.incident.is_some());
        // Within cooldown: no re-fire even though still over threshold.
        let second = st.record(
            &c,
            "user",
            "bob",
            contrib(100, 50, &["execution"], "r1"),
            100,
        );
        assert!(second.incident.is_none());
        // After cooldown: fires again.
        let third = st.record(
            &c,
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
        st.record(&c, "user", "carol", contrib(0, 60, &["execution"], "r1"), 0);
        // The first contribution ages out of the 3600s window by t=4000.
        let later = st.record(
            &c,
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
        let a = st.record(&c, "user", "a", contrib(0, 1, &[], "r1"), 0);
        assert!(a.incident.is_some());
        let b = st.record(&c, "user", "b", contrib(0, 1, &[], "r1"), 0);
        assert!(b.evicted, "second distinct entity rejected at capacity");
        assert_eq!(st.len(), 1);
    }

    #[test]
    fn tick_evicts_fully_aged_entities() {
        let mut st = RiskState::default();
        let c = cfg(Some(1000), None);
        st.record(&c, "user", "dan", contrib(0, 10, &["execution"], "r1"), 0);
        assert_eq!(st.len(), 1);
        let removed = st.tick(&c, 4000);
        assert_eq!(removed, 1);
        assert!(st.is_empty());
    }
}
