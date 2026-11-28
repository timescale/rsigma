//! Per-entity sliding-window risk accumulator (stage two).
//!
//! Keyed by `(tenant, entity_type, entity_value)`, each entity keeps exact
//! window aggregates (the risk sum, the contribution count, and per-tactic and
//! per-source counts) in time buckets, plus a bounded list of sample
//! contributions used only to embed refs or results in an incident. Dropping a
//! sample never changes the aggregates. A [`RiskIncidentResult`] fires when an
//! entity crosses the score or tactic-count threshold, subject to a per-entity
//! cooldown.
//!
//! At `max_open_entities` a new entity reclaims the tracked entity with the
//! lowest window score (then fewest tactics, then least recently seen). An
//! entity at or above a threshold is reclaimed only when every tracked entity
//! is. Expired buckets leave the aggregates before a victim is chosen, so the
//! choice is made on current window scores.
//!
//! State ownership is single-threaded (the sink task), mirroring the alert
//! pipeline; the only shared access is the read-only `GET /api/v1/risk` view
//! behind an `RwLock`.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use rsigma_eval::TenantId;

use super::incident::{IncludeMode, RiskEntityView, RiskIncidentResult, RiskRef};
use super::snapshot::{BucketSnapshot, EntitySnapshot, RiskStateSnapshot, SNAPSHOT_VERSION};
use super::tactics;
use crate::log_throttle::WarnThrottle;

/// Default ceiling on concurrently-tracked entities. Once full, a new entity
/// reclaims the tracked entity with the lowest window score.
pub const DEFAULT_MAX_OPEN_ENTITIES: usize = 100_000;
/// Default ceiling on distinct sources listed in an emitted incident.
pub const DEFAULT_MAX_SOURCES_PER_ENTITY: usize = 1_000;
/// Default ceiling on sample contributions kept per entity (also the embedded
/// refs/results bound). Past it the lowest-score sample is dropped; the window
/// aggregates still count it.
pub const DEFAULT_MAX_RESULTS_PER_INCIDENT: usize = 1_000;
/// Most time buckets one entity's window is split into. A window of up to this
/// many seconds gets one-second buckets, so its edge is exact; a longer window
/// gets `window / MAX_WINDOW_BUCKETS` second buckets, and a bucket leaves the
/// window when its newest contribution does.
const MAX_WINDOW_BUCKETS: i64 = 1_440;

/// Bounds on accumulator growth, with an eviction metric when exceeded.
#[derive(Debug, Clone, Copy)]
pub struct RiskCaps {
    /// Maximum simultaneously-tracked entities. At the cap a new entity
    /// reclaims the tracked entity with the lowest window score. Values below
    /// 1 act as 1.
    pub max_open_entities: usize,
    /// Maximum distinct sources listed per emitted incident.
    pub max_sources_per_entity: usize,
    /// Maximum sample contributions kept per entity (and embedded per
    /// incident). Past it the lowest-score older sample is dropped; the window
    /// score, tactic, source, and result counts are unaffected.
    pub max_results_per_incident: usize,
    /// Maximum simultaneously-tracked entities per tenant. At the cap, that
    /// tenant's lowest-scoring entity is reclaimed. `None` leaves only the
    /// global cap.
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
    pub(crate) fn window_secs(&self) -> i64 {
        i64::try_from(self.window.as_secs()).unwrap_or(i64::MAX)
    }

    /// Contributions at or before the returned second are outside the window
    /// at `now`.
    fn cutoff(&self, now: i64) -> i64 {
        now.saturating_sub(self.window_secs())
    }

    fn bucket_secs(&self) -> i64 {
        let window = self.window_secs();
        (window / MAX_WINDOW_BUCKETS + i64::from(window % MAX_WINDOW_BUCKETS != 0)).max(1)
    }

    fn cooldown_secs(&self) -> i64 {
        i64::try_from(self.cooldown.as_secs()).unwrap_or(i64::MAX)
    }

    fn thresholds(&self) -> Thresholds {
        Thresholds {
            score: self.score_threshold,
            tactics: self.tactic_count_threshold,
        }
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

/// The configured triggers, which decide whether an entity is protected from
/// reclamation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Thresholds {
    score: Option<i64>,
    tactics: Option<u64>,
}

impl Thresholds {
    fn trigger(&self, score: i64, tactics: u64) -> Option<&'static str> {
        if self.score.is_some_and(|t| score >= t) {
            Some("score")
        } else if self.tactics.is_some_and(|t| tactics >= t) {
            Some("tactic_count")
        } else {
            None
        }
    }
}

type EntityKey = (Option<TenantId>, String, String);
type EntityId = u64;
type TacticCounts<T> = [T; tactics::COUNT];

/// Reclamation order: the smallest rank is reclaimed first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Rank {
    protected: bool,
    score: i64,
    tactics: u64,
    last_seen: i64,
    id: EntityId,
}

/// Aggregates of the contributions that fell in one time bucket. Buckets of an
/// entity are ordered and never overlap: each bucket's `first` is after the
/// previous bucket's `last`.
#[derive(Debug, Clone)]
struct Bucket {
    start: i64,
    first: i64,
    last: i64,
    score: i64,
    count: u64,
    tactics: TacticCounts<u32>,
    sources: Vec<(Arc<str>, u32)>,
}

impl Bucket {
    fn new(start: i64, ts: i64) -> Self {
        Bucket {
            start,
            first: ts,
            last: ts,
            score: 0,
            count: 0,
            tactics: [0; tactics::COUNT],
            sources: Vec::new(),
        }
    }
}

/// Per-rule window count and the order the rule first appeared in.
#[derive(Debug)]
struct Source {
    count: u64,
    seen: u64,
}

/// Bounded sample contributions, kept in arrival order with a score index.
#[derive(Debug, Default)]
struct Samples {
    by_seq: BTreeMap<u64, Contribution>,
    by_score: BTreeSet<(i64, u64)>,
}

impl Samples {
    fn len(&self) -> usize {
        self.by_seq.len()
    }

    /// Keep `c`, then drop the lowest-score older samples (the oldest first on
    /// ties) until at most `cap` remain. The newest sample is always kept so
    /// an incident lists the firing that triggered it.
    fn push(&mut self, seq: u64, c: Contribution, cap: usize) {
        if cap == 0 {
            return;
        }
        self.by_score.insert((c.score, seq));
        self.by_seq.insert(seq, c);
        self.trim(cap, Some(seq));
    }

    fn trim(&mut self, cap: usize, keep: Option<u64>) {
        while self.by_seq.len() > cap {
            let Some(victim) = self
                .by_score
                .iter()
                .find(|(_, seq)| Some(*seq) != keep)
                .copied()
            else {
                break;
            };
            self.by_score.remove(&victim);
            self.by_seq.remove(&victim.1);
        }
    }

    fn prune(&mut self, cutoff: i64) {
        while let Some(entry) = self.by_seq.first_entry() {
            if entry.get().ts > cutoff {
                break;
            }
            let (seq, c) = entry.remove_entry();
            self.by_score.remove(&(c.score, seq));
        }
    }

    fn iter(&self) -> impl DoubleEndedIterator<Item = &Contribution> + ExactSizeIterator {
        self.by_seq.values()
    }
}

/// Window statistics of one entity at a cutoff.
struct LiveStats {
    score: i64,
    count: u64,
    tactic_count: u64,
    source_count: u64,
    window_start: i64,
    window_end: i64,
}

/// Per-entity window state.
#[derive(Debug)]
struct Entity {
    id: EntityId,
    buckets: VecDeque<Bucket>,
    score: i64,
    count: u64,
    tactics: TacticCounts<u64>,
    tactic_seen: TacticCounts<u64>,
    sources: HashMap<Arc<str>, Source>,
    samples: Samples,
    seq: u64,
    last_fired: Option<i64>,
    last_seen: i64,
    rank: Rank,
}

impl Entity {
    fn new(id: EntityId, last_seen: i64) -> Self {
        Entity {
            id,
            buckets: VecDeque::new(),
            score: 0,
            count: 0,
            tactics: [0; tactics::COUNT],
            tactic_seen: [0; tactics::COUNT],
            sources: HashMap::new(),
            samples: Samples::default(),
            seq: 0,
            last_fired: None,
            last_seen,
            rank: Rank {
                protected: false,
                score: 0,
                tactics: 0,
                last_seen,
                id,
            },
        }
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// The newest contribution time of the oldest bucket: the entity next
    /// changes when the cutoff reaches it.
    fn expiry(&self) -> Option<i64> {
        self.buckets.front().map(|b| b.last)
    }

    fn tactic_count(&self) -> u64 {
        self.tactics.iter().filter(|&&n| n > 0).count() as u64
    }

    /// Index of the bucket `ts` belongs to, creating it when needed.
    fn bucket_index(&mut self, ts: i64, width: i64) -> usize {
        let start = ts - ts.rem_euclid(width);
        if let Some(back) = self.buckets.back_mut() {
            if ts <= back.last {
                // Out of order: join the latest bucket that starts at or
                // before `ts` (the first one when none does), which keeps
                // the buckets ordered and disjoint.
                let i = self
                    .buckets
                    .partition_point(|b| b.first <= ts)
                    .saturating_sub(1);
                let bucket = &mut self.buckets[i];
                bucket.first = bucket.first.min(ts);
                bucket.last = bucket.last.max(ts);
                return i;
            }
            if start <= back.start {
                back.last = ts;
                return self.buckets.len() - 1;
            }
        }
        self.buckets.push_back(Bucket::new(start, ts));
        self.buckets.len() - 1
    }

    /// Count `n` contributions of `rule`, returning its shared name.
    fn count_source(&mut self, rule: &str, n: u64, seq: u64) -> Arc<str> {
        if let Some((name, _)) = self.sources.get_key_value(rule) {
            let name = name.clone();
            if let Some(source) = self.sources.get_mut(rule) {
                source.count += n;
            }
            return name;
        }
        let name: Arc<str> = Arc::from(rule);
        self.sources.insert(
            name.clone(),
            Source {
                count: n,
                seen: seq,
            },
        );
        name
    }

    fn count_tactic(&mut self, tactic: usize, n: u64, seq: u64) {
        if self.tactics[tactic] == 0 {
            self.tactic_seen[tactic] = seq;
        }
        self.tactics[tactic] += n;
    }

    /// Add one contribution to the window aggregates.
    fn add(&mut self, c: &Contribution, width: i64) {
        let seq = self.next_seq();
        let rule = self.count_source(&c.rule, 1, seq);
        let mut touched = [false; tactics::COUNT];
        for slug in &c.tactics {
            if let Some(t) = tactics::index(slug)
                && !touched[t]
            {
                touched[t] = true;
                self.count_tactic(t, 1, seq);
            }
        }
        self.score = self.score.wrapping_add(c.score);
        self.count += 1;

        let i = self.bucket_index(c.ts, width);
        let bucket = &mut self.buckets[i];
        bucket.score = bucket.score.wrapping_add(c.score);
        bucket.count += 1;
        for (t, hit) in touched.into_iter().enumerate() {
            bucket.tactics[t] += u32::from(hit);
        }
        match bucket
            .sources
            .iter_mut()
            .find(|(name, _)| Arc::ptr_eq(name, &rule))
        {
            Some((_, n)) => *n += 1,
            None => bucket.sources.push((rule, 1)),
        }
    }

    /// Add a persisted bucket to the window aggregates. Buckets must arrive
    /// ordered by `first`; one that overlaps the previous bucket is merged
    /// into it.
    fn add_bucket(&mut self, snap: BucketSnapshot) {
        let seq = self.next_seq();
        let mut bucket = Bucket::new(snap.start, snap.first);
        bucket.last = snap.last;
        bucket.score = snap.score;
        bucket.count = snap.count;
        for (slug, n) in &snap.tactics {
            if let Some(t) = tactics::index(slug) {
                bucket.tactics[t] = bucket.tactics[t].saturating_add(*n);
            }
        }
        for (rule, n) in &snap.sources {
            let name = self.count_source(rule, u64::from(*n), seq);
            match bucket
                .sources
                .iter_mut()
                .find(|(existing, _)| Arc::ptr_eq(existing, &name))
            {
                Some((_, count)) => *count = count.saturating_add(*n),
                None => bucket.sources.push((name, *n)),
            }
        }
        for t in 0..tactics::COUNT {
            if bucket.tactics[t] > 0 {
                self.count_tactic(t, u64::from(bucket.tactics[t]), seq);
            }
        }
        self.score = self.score.wrapping_add(bucket.score);
        self.count += bucket.count;

        match self.buckets.back_mut() {
            Some(back) if bucket.first <= back.last => {
                back.last = back.last.max(bucket.last);
                back.score = back.score.wrapping_add(bucket.score);
                back.count += bucket.count;
                for t in 0..tactics::COUNT {
                    back.tactics[t] = back.tactics[t].saturating_add(bucket.tactics[t]);
                }
                for (name, n) in bucket.sources {
                    match back
                        .sources
                        .iter_mut()
                        .find(|(existing, _)| Arc::ptr_eq(existing, &name))
                    {
                        Some((_, count)) => *count = count.saturating_add(n),
                        None => back.sources.push((name, n)),
                    }
                }
            }
            _ => self.buckets.push_back(bucket),
        }
    }

    /// Drop buckets whose newest contribution is at or before `cutoff`, and
    /// the samples older than the window.
    fn expire(&mut self, cutoff: i64) {
        while let Some(bucket) = self.buckets.pop_front() {
            if bucket.last > cutoff {
                self.buckets.push_front(bucket);
                break;
            }
            self.score = self.score.wrapping_sub(bucket.score);
            self.count = self.count.saturating_sub(bucket.count);
            for t in 0..tactics::COUNT {
                self.tactics[t] = self.tactics[t].saturating_sub(u64::from(bucket.tactics[t]));
            }
            for (name, n) in bucket.sources {
                if let Some(source) = self.sources.get_mut(&*name) {
                    source.count = source.count.saturating_sub(u64::from(n));
                    if source.count == 0 {
                        self.sources.remove(&*name);
                    }
                }
            }
        }
        self.samples.prune(cutoff);
    }

    /// The window statistics at `cutoff`, leaving out buckets that have
    /// expired but not been dropped yet. `None` when nothing is left.
    fn live(&self, cutoff: i64) -> Option<LiveStats> {
        let expired = self.buckets.iter().take_while(|b| b.last <= cutoff);
        let mut score = self.score;
        let mut count = self.count;
        let mut tactics = self.tactics;
        let mut gone: HashMap<&str, u64> = HashMap::new();
        let mut dropped = 0;
        for bucket in expired {
            dropped += 1;
            score = score.wrapping_sub(bucket.score);
            count = count.saturating_sub(bucket.count);
            for t in 0..tactics::COUNT {
                tactics[t] = tactics[t].saturating_sub(u64::from(bucket.tactics[t]));
            }
            for (name, n) in &bucket.sources {
                *gone.entry(&**name).or_default() += u64::from(*n);
            }
        }
        let first = self.buckets.get(dropped)?;
        let source_count = if gone.is_empty() {
            self.sources.len() as u64
        } else {
            self.sources
                .iter()
                .filter(|(name, s)| s.count > gone.get(&***name).copied().unwrap_or(0))
                .count() as u64
        };
        Some(LiveStats {
            score,
            count,
            tactic_count: tactics.iter().filter(|&&n| n > 0).count() as u64,
            source_count,
            window_start: first.first,
            window_end: self.buckets.back().map_or(first.last, |b| b.last),
        })
    }

    /// The window's distinct tactics, in the order they first appeared.
    fn tactic_list(&self) -> Vec<String> {
        let mut live: Vec<usize> = (0..tactics::COUNT)
            .filter(|&t| self.tactics[t] > 0)
            .collect();
        live.sort_by_key(|&t| (self.tactic_seen[t], t));
        live.into_iter()
            .map(|t| tactics::slug(t).to_string())
            .collect()
    }

    /// Up to `max` distinct sources in first-seen order, and the true total.
    fn source_list(&self, max: usize) -> (Vec<String>, u64) {
        let mut names: Vec<(&Arc<str>, u64)> = self
            .sources
            .iter()
            .map(|(name, s)| (name, s.seen))
            .collect();
        names.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(b.0)));
        let total = names.len() as u64;
        let listed = names
            .into_iter()
            .take(max)
            .map(|(name, _)| name.to_string())
            .collect();
        (listed, total)
    }
}

/// Entities reclaimed to bring the store within its caps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CapTrim {
    /// Entities reclaimed because their tenant was over
    /// `max_open_entities_per_tenant`.
    pub tenant: usize,
    /// Entities reclaimed because the store was over `max_open_entities`.
    pub global: usize,
}

/// The in-memory accumulator, owned single-threaded by the sink task (shared
/// behind an `RwLock` so `GET /api/v1/risk` can read it).
#[derive(Debug, Default)]
pub struct RiskState {
    entities: HashMap<EntityKey, Entity>,
    keys: HashMap<EntityId, EntityKey>,
    /// Reclamation order per tenant, kept in step with `entities`.
    ranks: HashMap<Option<TenantId>, BTreeSet<Rank>>,
    /// Each entity's next bucket expiry.
    expiry: BTreeSet<(i64, EntityId)>,
    /// The triggers `ranks` was computed with.
    thresholds: Thresholds,
    next_id: EntityId,
    samples: usize,
    cap_warn: WarnThrottle,
    cap_warn_protected: usize,
}

/// The outcome of recording one contribution.
pub struct RecordOutcome {
    /// An incident, when the entity crossed a threshold and was not cooling down.
    pub incident: Option<RiskIncidentResult>,
    /// Detection Finding uids for `incident`, when one was emitted.
    pub links: crate::FindingLinks,
    /// Tracked entities reclaimed to make room for a new entity under
    /// `max_open_entities`.
    pub cap_evicted: usize,
    /// Entities dropped because their whole window aged out.
    pub aged_evicted: usize,
    /// True when a tenant's own lowest-scoring entity was reclaimed to make
    /// room under its per-tenant cap.
    pub quota_evicted: bool,
}

fn rank_of(thresholds: Thresholds, entity: &Entity) -> Rank {
    let tactics = entity.tactic_count();
    Rank {
        protected: thresholds.trigger(entity.score, tactics).is_some(),
        score: entity.score,
        tactics,
        last_seen: entity.last_seen,
        id: entity.id,
    }
}

fn rerank(
    ranks: &mut HashMap<Option<TenantId>, BTreeSet<Rank>>,
    thresholds: Thresholds,
    tenant: &Option<TenantId>,
    entity: &mut Entity,
) {
    let next = rank_of(thresholds, entity);
    if next == entity.rank {
        return;
    }
    let set = ranks.entry(tenant.clone()).or_default();
    set.remove(&entity.rank);
    set.insert(next);
    entity.rank = next;
}

fn move_expiry(
    expiry: &mut BTreeSet<(i64, EntityId)>,
    id: EntityId,
    before: Option<i64>,
    after: Option<i64>,
) {
    if before == after {
        return;
    }
    if let Some(ts) = before {
        expiry.remove(&(ts, id));
    }
    if let Some(ts) = after {
        expiry.insert((ts, id));
    }
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
        self.ranks.get(&tenant.cloned()).map_or(0, BTreeSet::len)
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

    /// Total sample contributions kept across all entities (for the state
    /// gauge).
    pub fn total_entries(&self) -> usize {
        self.samples
    }

    /// Recompute every rank when the triggers changed (a reload).
    fn sync(&mut self, cfg: &IncidentConfig) {
        let thresholds = cfg.thresholds();
        if thresholds == self.thresholds {
            return;
        }
        self.thresholds = thresholds;
        self.ranks.clear();
        for (key, entity) in &mut self.entities {
            entity.rank = rank_of(thresholds, entity);
            self.ranks
                .entry(key.0.clone())
                .or_default()
                .insert(entity.rank);
        }
    }

    fn insert_entity(&mut self, key: EntityKey, mut entity: Entity) {
        entity.rank = rank_of(self.thresholds, &entity);
        self.ranks
            .entry(key.0.clone())
            .or_default()
            .insert(entity.rank);
        if let Some(ts) = entity.expiry() {
            self.expiry.insert((ts, entity.id));
        }
        self.samples += entity.samples.len();
        self.keys.insert(entity.id, key.clone());
        self.entities.insert(key, entity);
    }

    fn remove_entity(&mut self, id: EntityId) -> bool {
        let Some(key) = self.keys.remove(&id) else {
            return false;
        };
        let Some(entity) = self.entities.remove(&key) else {
            return false;
        };
        if let Some(set) = self.ranks.get_mut(&key.0) {
            set.remove(&entity.rank);
            if set.is_empty() {
                self.ranks.remove(&key.0);
            }
        }
        if let Some(ts) = entity.expiry() {
            self.expiry.remove(&(ts, id));
        }
        self.samples -= entity.samples.len();
        true
    }

    fn allocate_id(&mut self) -> EntityId {
        self.next_id += 1;
        self.next_id
    }

    /// Drop expired buckets from every entity they belong to and remove the
    /// entities left empty, returning how many were removed.
    fn advance(&mut self, cutoff: i64) -> usize {
        let mut aged = 0;
        while let Some(&(ts, id)) = self.expiry.first() {
            if ts > cutoff {
                break;
            }
            self.expiry.pop_first();
            let Some(key) = self.keys.get(&id) else {
                continue;
            };
            let Some(entity) = self.entities.get_mut(key) else {
                continue;
            };
            let before = entity.samples.len();
            entity.expire(cutoff);
            self.samples = self.samples - before + entity.samples.len();
            match entity.expiry() {
                Some(next) => {
                    self.expiry.insert((next, id));
                    rerank(&mut self.ranks, self.thresholds, &key.0, entity);
                }
                None => {
                    // `expiry` no longer holds this entity's entry.
                    let key = key.clone();
                    if let Some(entity) = self.entities.remove(&key) {
                        self.keys.remove(&id);
                        if let Some(set) = self.ranks.get_mut(&key.0) {
                            set.remove(&entity.rank);
                            if set.is_empty() {
                                self.ranks.remove(&key.0);
                            }
                        }
                        self.samples -= entity.samples.len();
                    }
                    aged += 1;
                }
            }
        }
        aged
    }

    /// The lowest-ranked entity, within `tenant` when given.
    fn lowest(&self, tenant: Option<&Option<TenantId>>) -> Option<Rank> {
        match tenant {
            Some(tenant) => self.ranks.get(tenant)?.first().copied(),
            None => self
                .ranks
                .values()
                .filter_map(BTreeSet::first)
                .min()
                .copied(),
        }
    }

    /// Reclaim the lowest-ranked entity, within `tenant` when given.
    fn evict_lowest(&mut self, tenant: Option<&Option<TenantId>>) -> Option<Rank> {
        let rank = self.lowest(tenant)?;
        self.remove_entity(rank.id).then_some(rank)
    }

    fn warn_cap_evictions(&mut self, victims: &[Rank], cap: usize) {
        self.cap_warn_protected += victims.iter().filter(|r| r.protected).count();
        let mut warn = None;
        for _ in victims {
            if let Some(n) = self.cap_warn.record(Instant::now()) {
                warn = Some(n);
            }
        }
        if let Some(evicted) = warn {
            tracing::warn!(
                evicted,
                above_threshold = std::mem::take(&mut self.cap_warn_protected),
                max_open_entities = cap,
                "Risk accumulator is at max_open_entities; reclaimed the lowest-scoring entities"
            );
        }
    }

    /// Reclaim entities until every tenant is within
    /// `max_open_entities_per_tenant`, the store is within
    /// `max_open_entities`, and each entity keeps at most
    /// `max_results_per_incident` samples. Lowering a cap on reload takes
    /// effect at once through this.
    pub fn enforce_caps(&mut self, cfg: &IncidentConfig) -> CapTrim {
        self.sync(cfg);
        let mut trim = CapTrim::default();
        if let Some(max) = cfg.caps.max_open_entities_per_tenant {
            let max = max.max(1);
            let over: Vec<Option<TenantId>> = self
                .ranks
                .iter()
                .filter(|(_, set)| set.len() > max)
                .map(|(tenant, _)| tenant.clone())
                .collect();
            for tenant in over {
                while self.ranks.get(&tenant).is_some_and(|set| set.len() > max)
                    && self.evict_lowest(Some(&tenant)).is_some()
                {
                    trim.tenant += 1;
                }
            }
        }
        let cap = cfg.caps.max_open_entities.max(1);
        let mut victims = Vec::new();
        while self.entities.len() > cap {
            match self.evict_lowest(None) {
                Some(rank) => victims.push(rank),
                None => break,
            }
        }
        trim.global = victims.len();
        if !victims.is_empty() {
            self.warn_cap_evictions(&victims, cap);
        }
        let max_samples = cfg.caps.max_results_per_incident;
        let mut samples = 0;
        for entity in self.entities.values_mut() {
            entity.samples.trim(max_samples, None);
            samples += entity.samples.len();
        }
        self.samples = samples;
        trim
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
        self.sync(cfg);
        let cutoff = cfg.cutoff(now);
        let aged_evicted = self.advance(cutoff);
        let key = (
            tenant.cloned(),
            entity_type.to_string(),
            entity_value.to_string(),
        );

        let mut quota_evicted = false;
        let mut cap_evicted = 0;
        if !self.entities.contains_key(&key) {
            if let Some(cap) = cfg.caps.max_open_entities_per_tenant
                && self.count_for_tenant(tenant) >= cap.max(1)
            {
                quota_evicted = self.evict_lowest(Some(&key.0)).is_some();
            }
            let cap = cfg.caps.max_open_entities.max(1);
            let mut victims = Vec::new();
            while self.entities.len() >= cap {
                match self.evict_lowest(None) {
                    Some(rank) => victims.push(rank),
                    None => break,
                }
            }
            cap_evicted = victims.len();
            if !victims.is_empty() {
                self.warn_cap_evictions(&victims, cap);
            }
            let id = self.allocate_id();
            self.insert_entity(key.clone(), Entity::new(id, now));
        }

        let Some(entity) = self.entities.get_mut(&key) else {
            return RecordOutcome {
                incident: None,
                links: crate::FindingLinks::default(),
                cap_evicted,
                aged_evicted,
                quota_evicted,
            };
        };
        let expiry_before = entity.expiry();
        let samples_before = entity.samples.len();
        entity.add(&contribution, cfg.bucket_secs());
        entity.last_seen = entity.last_seen.max(now);
        let seq = entity.seq;
        entity
            .samples
            .push(seq, contribution, cfg.caps.max_results_per_incident);
        entity.samples.prune(cutoff);
        self.samples = self.samples - samples_before + entity.samples.len();
        move_expiry(&mut self.expiry, entity.id, expiry_before, entity.expiry());

        let tactic_count = entity.tactic_count();
        let built = self
            .thresholds
            .trigger(entity.score, tactic_count)
            .and_then(|trigger| {
                let cooling = entity
                    .last_fired
                    .is_some_and(|lf| now.saturating_sub(lf) < cfg.cooldown_secs());
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
                    entity,
                ))
            });
        rerank(&mut self.ranks, self.thresholds, &key.0, entity);
        let (incident, links) = match built {
            Some((incident, links)) => (Some(incident), links),
            None => (None, crate::FindingLinks::default()),
        };

        RecordOutcome {
            incident,
            links,
            cap_evicted,
            aged_evicted,
            quota_evicted,
        }
    }

    /// Drop expired buckets and remove entities whose windows have fully aged
    /// out at `now`, returning the number removed (for eviction accounting).
    pub fn tick(&mut self, cfg: &IncidentConfig, now: i64) -> usize {
        self.sync(cfg);
        self.advance(cfg.cutoff(now))
    }

    /// Capture the accumulator into a versioned persistence snapshot.
    pub fn snapshot(&self) -> RiskStateSnapshot {
        let entities = self
            .entities
            .iter()
            .map(
                |((tenant, entity_type, entity_value), entity)| EntitySnapshot {
                    tenant: tenant.clone(),
                    entity_type: entity_type.clone(),
                    entity_value: entity_value.clone(),
                    last_fired: entity.last_fired,
                    last_seen: entity.last_seen,
                    contributions: entity.samples.iter().cloned().collect(),
                    buckets: entity
                        .buckets
                        .iter()
                        .map(|b| BucketSnapshot {
                            start: b.start,
                            first: b.first,
                            last: b.last,
                            score: b.score,
                            count: b.count,
                            tactics: (0..tactics::COUNT)
                                .filter(|&t| b.tactics[t] > 0)
                                .map(|t| (tactics::slug(t).to_string(), b.tactics[t]))
                                .collect(),
                            sources: b
                                .sources
                                .iter()
                                .map(|(name, n)| (name.to_string(), *n))
                                .collect(),
                        })
                        .collect(),
                },
            )
            .collect();
        RiskStateSnapshot {
            version: SNAPSHOT_VERSION,
            entities,
        }
    }

    /// Restore a snapshot, dropping contributions already past the window at
    /// `now`, skipping entities left empty, and then reclaiming the
    /// lowest-scoring entities beyond the configured caps. Returns `false` on
    /// a version mismatch (the caller starts fresh).
    pub fn restore(
        &mut self,
        cfg: &IncidentConfig,
        snap: RiskStateSnapshot,
        now: i64,
        tenancy: bool,
    ) -> bool {
        self.restore_detailed(cfg, snap, now, tenancy).is_some()
    }

    /// Like [`restore`](Self::restore), returning the restored and discarded
    /// counts. Accepts versions 1 to 3 and applies the tenant attribution
    /// rule: with `tenancy`, untenanted entities are discarded; without it,
    /// tenanted ones are. Version 1 and 2 snapshots hold no window
    /// aggregates, so they are rebuilt from the saved contributions.
    pub fn restore_detailed(
        &mut self,
        cfg: &IncidentConfig,
        snap: RiskStateSnapshot,
        now: i64,
        tenancy: bool,
    ) -> Option<rsigma_eval::ImportStats> {
        if !(1..=SNAPSHOT_VERSION).contains(&snap.version) {
            return None;
        }
        self.sync(cfg);
        let mut stats = rsigma_eval::ImportStats::default();
        let cutoff = cfg.cutoff(now);
        let width = cfg.bucket_secs();
        let max_samples = cfg.caps.max_results_per_incident;
        for saved in snap.entities {
            let keep = if tenancy {
                saved.tenant.is_some()
            } else {
                saved.tenant.is_none()
            };
            if !keep {
                if saved.tenant.is_none() {
                    stats.discarded_untenanted += 1;
                } else {
                    stats.discarded_tenanted += 1;
                }
                continue;
            }
            let key = (saved.tenant, saved.entity_type, saved.entity_value);
            if self.entities.contains_key(&key) {
                continue;
            }
            let id = self.allocate_id();
            let mut entity = Entity::new(id, saved.last_seen);
            entity.last_fired = saved.last_fired;
            if saved.buckets.is_empty() {
                for c in saved.contributions.iter().filter(|c| c.ts > cutoff) {
                    entity.add(c, width);
                }
            } else {
                let mut buckets = saved.buckets;
                buckets.sort_by_key(|b| (b.first, b.last));
                for bucket in buckets {
                    if bucket.last > cutoff && bucket.count > 0 && bucket.first <= bucket.last {
                        entity.add_bucket(bucket);
                    }
                }
            }
            if entity.buckets.is_empty() {
                continue;
            }
            for c in saved.contributions.into_iter().filter(|c| c.ts > cutoff) {
                let seq = entity.next_seq();
                entity.samples.push(seq, c, max_samples);
            }
            self.insert_entity(key, entity);
            stats.restored += 1;
        }
        let trim = self.enforce_caps(cfg);
        let trimmed = trim.tenant + trim.global;
        if trimmed > 0 {
            tracing::warn!(
                tenant = trim.tenant,
                global = trim.global,
                "Reclaimed the lowest-scoring restored risk entities to fit the configured caps"
            );
        }
        stats.restored = stats.restored.saturating_sub(trimmed);
        Some(stats)
    }

    /// A read-only view of every open entity at `now`, for the admin API.
    pub fn views(&self, cfg: &IncidentConfig, now: i64) -> Vec<RiskEntityView> {
        let cutoff = cfg.cutoff(now);
        let mut out = Vec::new();
        for ((tenant, entity_type, entity_value), entity) in &self.entities {
            let Some(live) = entity.live(cutoff) else {
                continue;
            };
            out.push(RiskEntityView {
                tenant_id: tenant.clone(),
                entity_type: entity_type.clone(),
                entity_value: entity_value.clone(),
                score: live.score,
                tactic_count: live.tactic_count,
                source_count: live.source_count,
                result_count: live.count,
                window_start: live.window_start,
                window_end: live.window_end,
                last_fired: entity.last_fired,
            });
        }
        out
    }
}

/// Build a [`RiskIncidentResult`] from the entity's current window.
fn build_incident(
    cfg: &IncidentConfig,
    tenant: Option<&TenantId>,
    entity_type: &str,
    entity_value: &str,
    trigger: &'static str,
    entity: &Entity,
) -> (RiskIncidentResult, crate::FindingLinks) {
    let samples = entity.samples.iter();
    let skip = samples
        .len()
        .saturating_sub(cfg.caps.max_results_per_incident);
    let recent: Vec<&Contribution> = samples.skip(skip).collect();

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

    let tactics = entity.tactic_list();
    let (sources, source_count) = entity.source_list(cfg.caps.max_sources_per_entity);
    let window_start = entity.buckets.front().map_or(0, |b| b.first);
    let window_end = entity.buckets.back().map_or(0, |b| b.last);
    (
        RiskIncidentResult {
            risk_incident_id: Uuid::new_v4().to_string(),
            tenant_id: tenant.cloned(),
            entity_type: entity_type.to_string(),
            entity_value: entity_value.to_string(),
            trigger,
            score: entity.score,
            score_threshold: cfg.score_threshold,
            tactic_count: tactics.len() as u64,
            tactic_count_threshold: cfg.tactic_count_threshold,
            tactics,
            sources,
            source_count,
            window_start,
            window_end,
            result_count: entity.count,
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

    fn record(
        st: &mut RiskState,
        c: &IncidentConfig,
        value: &str,
        ts: i64,
        score: i64,
        tactics: &[&str],
    ) -> RecordOutcome {
        st.record(
            c,
            None,
            "user",
            value,
            contrib(ts, score, tactics, "r1"),
            ts,
        )
    }

    fn view(st: &RiskState, c: &IncidentConfig, value: &str, now: i64) -> Option<RiskEntityView> {
        st.views(c, now)
            .into_iter()
            .find(|v| v.entity_value == value)
    }

    /// Every index agrees with the entities, and every entity's aggregates
    /// equal the sum of its buckets.
    fn assert_consistent(st: &RiskState) {
        assert_eq!(st.keys.len(), st.entities.len());
        let ranked: usize = st.ranks.values().map(BTreeSet::len).sum();
        assert_eq!(ranked, st.entities.len());
        assert_eq!(st.expiry.len(), st.entities.len());
        let mut samples = 0;
        for (key, entity) in &st.entities {
            assert_eq!(st.keys[&entity.id], *key);
            assert!(st.ranks[&key.0].contains(&entity.rank));
            assert_eq!(entity.rank, rank_of(st.thresholds, entity));
            assert!(st.expiry.contains(&(entity.expiry().unwrap(), entity.id)));
            let score: i64 = entity.buckets.iter().map(|b| b.score).sum();
            let count: u64 = entity.buckets.iter().map(|b| b.count).sum();
            assert_eq!(entity.score, score);
            assert_eq!(entity.count, count);
            for t in 0..tactics::COUNT {
                let n: u64 = entity.buckets.iter().map(|b| u64::from(b.tactics[t])).sum();
                assert_eq!(entity.tactics[t], n);
            }
            for window in entity.buckets.iter().collect::<Vec<_>>().windows(2) {
                assert!(window[0].last < window[1].first, "buckets overlap");
            }
            samples += entity.samples.len();
            assert_eq!(entity.samples.len(), entity.samples.by_score.len());
        }
        assert_eq!(st.total_entries(), samples);
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
        assert_eq!(inc.sources, ["r1", "r2"]);
        assert_eq!(inc.tactics, ["execution", "persistence"]);
        assert_eq!((inc.window_start, inc.window_end), (0, 10));
        assert_eq!(inc.result_count, 2);
        assert_consistent(&st);
    }

    #[test]
    fn fires_on_tactic_count_threshold() {
        let mut st = RiskState::default();
        let c = cfg(None, Some(3));
        record(&mut st, &c, "dc01", 0, 1, &["execution"]);
        record(&mut st, &c, "dc01", 1, 1, &["persistence"]);
        let third = record(&mut st, &c, "dc01", 2, 1, &["impact"]);
        let inc = third.incident.expect("three distinct tactics");
        assert_eq!(inc.trigger, "tactic_count");
        assert_eq!(inc.tactic_count, 3);
    }

    #[test]
    fn cooldown_suppresses_refire() {
        let mut st = RiskState::default();
        let c = cfg(Some(50), None);
        assert!(
            record(&mut st, &c, "bob", 0, 50, &["execution"])
                .incident
                .is_some()
        );
        // Within cooldown: no re-fire even though still over threshold.
        assert!(
            record(&mut st, &c, "bob", 100, 50, &["execution"])
                .incident
                .is_none()
        );
        // After cooldown: fires again.
        assert!(
            record(&mut st, &c, "bob", 700, 50, &["execution"])
                .incident
                .is_some()
        );
    }

    #[test]
    fn window_prunes_old_contributions() {
        let mut st = RiskState::default();
        let c = cfg(Some(100), None);
        record(&mut st, &c, "carol", 0, 60, &["execution"]);
        // The first contribution ages out of the 3600s window by t=4000.
        let later = record(&mut st, &c, "carol", 4000, 60, &["execution"]);
        assert!(
            later.incident.is_none(),
            "old contribution pruned, sum is 60"
        );
        assert_consistent(&st);
    }

    #[test]
    fn a_short_window_edge_is_exact() {
        let mut st = RiskState::default();
        let mut c = cfg(Some(1_000), None);
        c.window = Duration::from_secs(60);
        record(&mut st, &c, "edge", 0, 10, &[]);
        record(&mut st, &c, "edge", 1, 20, &[]);
        assert_eq!(view(&st, &c, "edge", 59).unwrap().score, 30);
        assert_eq!(view(&st, &c, "edge", 60).unwrap().score, 20);
        assert!(view(&st, &c, "edge", 61).is_none());
        assert_eq!(st.tick(&c, 60), 0);
        assert_eq!(st.tick(&c, 61), 1);
        assert_consistent(&st);
    }

    #[test]
    fn a_long_window_bucket_leaves_with_its_newest_contribution() {
        let mut st = RiskState::default();
        let mut c = cfg(Some(1_000_000), None);
        c.window = Duration::from_secs(24 * 3600);
        assert_eq!(c.bucket_secs(), 60);
        record(&mut st, &c, "edge", 0, 10, &[]);
        record(&mut st, &c, "edge", 59, 20, &[]);
        record(&mut st, &c, "edge", 60, 40, &[]);
        let window = 24 * 3600;
        assert_eq!(view(&st, &c, "edge", window).unwrap().score, 70);
        assert_eq!(view(&st, &c, "edge", window + 59).unwrap().score, 40);
        assert!(view(&st, &c, "edge", window + 60).is_none());
    }

    #[test]
    fn a_clock_step_back_keeps_the_aggregates_consistent() {
        let mut st = RiskState::default();
        let c = cfg(Some(1_000), None);
        record(&mut st, &c, "skew", 100, 10, &["execution"]);
        record(&mut st, &c, "skew", 200, 10, &["impact"]);
        record(&mut st, &c, "skew", 50, 10, &["discovery"]);
        record(&mut st, &c, "skew", 150, 10, &["execution"]);
        assert_consistent(&st);
        let v = view(&st, &c, "skew", 200).unwrap();
        assert_eq!((v.score, v.tactic_count, v.result_count), (40, 3, 4));
        assert_eq!((v.window_start, v.window_end), (50, 200));
        assert_eq!(st.tick(&c, 200 + 3600), 1);
        assert_consistent(&st);
    }

    /// One high-score firing followed by more zero-score firings than the
    /// sample cap: the score and tactic count must hold while the high firing
    /// is in the window.
    #[test]
    fn sample_eviction_does_not_change_the_window_aggregates() {
        let mut st = RiskState::default();
        let mut c = cfg(Some(100), Some(4));
        c.caps.max_results_per_incident = 5;
        c.cooldown = Duration::ZERO;
        let first = st.record(
            &c,
            None,
            "user",
            "mallory",
            contrib(0, 90, &["execution", "persistence"], "high"),
            0,
        );
        assert!(first.incident.is_none());
        for ts in 1..=20 {
            let out = st.record(
                &c,
                None,
                "user",
                "mallory",
                contrib(ts, 0, &["discovery"], &format!("noise-{ts}")),
                ts,
            );
            assert!(out.incident.is_none());
            let v = view(&st, &c, "mallory", ts).unwrap();
            assert_eq!(v.score, 90, "after {ts} zero-score firings");
            assert_eq!(v.tactic_count, 3, "after {ts} zero-score firings");
            assert_eq!(v.result_count, ts as u64 + 1);
            assert_eq!(v.source_count, ts as u64 + 1);
        }
        let last = st.record(
            &c,
            None,
            "user",
            "mallory",
            contrib(21, 10, &["impact"], "closer"),
            21,
        );
        let inc = last.incident.expect("90 + 10 crosses 100");
        assert_eq!(inc.score, 100);
        assert_eq!(inc.tactic_count, 4);
        assert_eq!(inc.result_count, 22);
        let refs = inc.refs.unwrap();
        assert_eq!(refs.len(), 5);
        assert_eq!(refs[0].rule, "high", "the high-score sample is kept");
        assert_eq!(refs[4].rule, "closer", "the newest sample is kept");
        assert_consistent(&st);
    }

    #[test]
    fn sample_eviction_drops_the_lowest_score_then_the_oldest() {
        let mut samples = Samples::default();
        for (seq, score) in [(1, 5), (2, 1), (3, 9), (4, 1)] {
            samples.push(seq, contrib(seq as i64, score, &[], "r"), 3);
        }
        let kept: Vec<i64> = samples.iter().map(|c| c.ts).collect();
        assert_eq!(kept, [1, 3, 4], "the oldest score-1 sample went first");
        samples.push(5, contrib(5, 0, &[], "r"), 3);
        let kept: Vec<i64> = samples.iter().map(|c| c.ts).collect();
        assert_eq!(kept, [1, 3, 5], "the newest sample stays even at score 0");
    }

    #[test]
    fn at_capacity_a_new_entity_reclaims_the_lowest_scoring_one() {
        let mut st = RiskState::default();
        let mut c = cfg(Some(100), None);
        c.caps.max_open_entities = 3;
        record(&mut st, &c, "a", 0, 30, &[]);
        record(&mut st, &c, "b", 1, 10, &[]);
        record(&mut st, &c, "c", 2, 20, &[]);
        let out = record(&mut st, &c, "d", 3, 5, &[]);
        assert_eq!((out.cap_evicted, out.aged_evicted), (1, 0));
        assert_eq!(st.len(), 3);
        assert!(!st.contains_entity(None, "user", "b"), "lowest score went");
        assert!(st.contains_entity(None, "user", "d"));
        // Ties on score go to the least recently seen.
        let out = record(&mut st, &c, "e", 4, 1, &[]);
        assert_eq!(out.cap_evicted, 1);
        assert!(!st.contains_entity(None, "user", "d"));
        assert_consistent(&st);
    }

    /// The store is full of single low-score entities; a fresh entity that
    /// crosses a threshold on its first contribution still fires, and the
    /// room it takes is a cap eviction, not ageing.
    #[test]
    fn a_fresh_entity_crossing_a_threshold_at_the_cap_still_fires() {
        for (c, tactics) in [
            (cfg(Some(100), None), vec![]),
            (
                cfg(None, Some(3)),
                vec!["execution", "persistence", "impact"],
            ),
        ] {
            let mut c = c;
            c.caps.max_open_entities = 50;
            let mut st = RiskState::default();
            for i in 0..50 {
                let out = record(&mut st, &c, &format!("cheap-{i}"), i, 1, &[]);
                assert_eq!(out.cap_evicted, 0);
            }
            let out = record(&mut st, &c, "real", 60, 100, &tactics);
            let incident = out.incident.expect("the fresh entity fires");
            assert_eq!(incident.entity_value, "real");
            assert_eq!((out.cap_evicted, out.aged_evicted), (1, 0));
            assert!(st.contains_entity(None, "user", "real"));
            assert!(!st.contains_entity(None, "user", "cheap-0"));
            assert_eq!(st.len(), 50);
            assert_consistent(&st);
        }
    }

    #[test]
    fn an_entity_above_a_threshold_is_reclaimed_only_when_all_are() {
        let mut st = RiskState::default();
        let mut c = cfg(Some(50), None);
        c.caps.max_open_entities = 2;
        record(&mut st, &c, "hot", 0, 60, &[]);
        record(&mut st, &c, "cold", 1, 40, &[]);
        record(&mut st, &c, "new", 2, 45, &[]);
        assert!(st.contains_entity(None, "user", "hot"));
        assert!(!st.contains_entity(None, "user", "cold"));
        // Raise "new" over the threshold: both tracked entities are now
        // protected, so the lowest-scoring of them makes room.
        record(&mut st, &c, "new", 3, 10, &[]);
        let out = record(&mut st, &c, "newer", 4, 1, &[]);
        assert_eq!(out.cap_evicted, 1);
        assert!(!st.contains_entity(None, "user", "new"));
        assert!(st.contains_entity(None, "user", "hot"));
        assert_consistent(&st);
    }

    #[test]
    fn the_victim_is_chosen_on_current_window_scores() {
        let mut st = RiskState::default();
        let mut c = cfg(Some(1_000), None);
        c.caps.max_open_entities = 2;
        record(&mut st, &c, "faded", 0, 90, &[]);
        record(&mut st, &c, "faded", 3_000, 1, &[]);
        record(&mut st, &c, "steady", 3_000, 50, &[]);
        // At 3_700 the 90 has left the window, so "faded" scores 1.
        let out = record(&mut st, &c, "new", 3_700, 5, &[]);
        assert_eq!(out.cap_evicted, 1);
        assert!(!st.contains_entity(None, "user", "faded"));
        assert!(st.contains_entity(None, "user", "steady"));
        assert_consistent(&st);
    }

    #[test]
    fn a_fully_aged_entity_makes_room_as_ageing_not_as_a_cap_eviction() {
        let mut st = RiskState::default();
        let mut c = cfg(Some(1_000), None);
        c.caps.max_open_entities = 1;
        record(&mut st, &c, "old", 0, 500, &[]);
        let out = record(&mut st, &c, "new", 4_000, 1, &[]);
        assert_eq!((out.cap_evicted, out.aged_evicted), (0, 1));
        assert_eq!(st.len(), 1);
        assert_consistent(&st);
    }

    #[test]
    fn a_threshold_change_reranks_the_entities() {
        let mut st = RiskState::default();
        let mut by_score = cfg(Some(60), None);
        by_score.caps.max_open_entities = 2;
        record(&mut st, &by_score, "x", 0, 70, &[]);
        record(
            &mut st,
            &by_score,
            "y",
            1,
            10,
            &["execution", "persistence", "impact"],
        );
        // Under a tactic-only trigger "y" is protected and "x" is not.
        let mut by_tactics = cfg(None, Some(3));
        by_tactics.caps.max_open_entities = 2;
        let out = record(&mut st, &by_tactics, "z", 2, 1, &[]);
        assert_eq!(out.cap_evicted, 1);
        assert!(!st.contains_entity(None, "user", "x"));
        assert!(st.contains_entity(None, "user", "y"));
        assert_consistent(&st);
    }

    #[test]
    fn enforce_caps_applies_lowered_caps() {
        let mut st = RiskState::default();
        let c = cfg(Some(1_000), None);
        for i in 0..5 {
            for ts in 0..4 {
                record(&mut st, &c, &format!("u{i}"), ts, i, &[]);
            }
        }
        assert_eq!(st.total_entries(), 20);
        let mut lower = c.clone();
        lower.caps.max_open_entities = 3;
        lower.caps.max_results_per_incident = 2;
        let trim = st.enforce_caps(&lower);
        assert_eq!(
            trim,
            CapTrim {
                tenant: 0,
                global: 2
            }
        );
        assert!(!st.contains_entity(None, "user", "u0"));
        assert!(!st.contains_entity(None, "user", "u1"));
        assert_eq!(st.total_entries(), 6);
        assert_eq!(view(&st, &lower, "u4", 3).unwrap().score, 16);
        assert_consistent(&st);
    }

    #[test]
    fn tick_evicts_fully_aged_entities() {
        let mut st = RiskState::default();
        let c = cfg(Some(1000), None);
        record(&mut st, &c, "dan", 0, 10, &["execution"]);
        assert_eq!(st.len(), 1);
        let removed = st.tick(&c, 4000);
        assert_eq!(removed, 1);
        assert!(st.is_empty());
        assert_eq!(st.total_entries(), 0);
        assert_consistent(&st);
    }

    #[test]
    fn views_leave_out_buckets_that_expired_before_a_tick() {
        let mut st = RiskState::default();
        let c = cfg(Some(1_000), None);
        record(&mut st, &c, "v", 0, 10, &["execution"]);
        record(&mut st, &c, "v", 100, 5, &["impact"]);
        let v = view(&st, &c, "v", 3_650).unwrap();
        assert_eq!((v.score, v.tactic_count, v.result_count), (5, 1, 1));
        assert_eq!(v.window_start, 100);
    }

    #[test]
    fn snapshot_round_trips_and_prunes() {
        let mut st = RiskState::default();
        let c = cfg(Some(100), None);
        record(&mut st, &c, "erin", 100, 50, &["execution"]);

        // Round-trip through JSON.
        let json = serde_json::to_string(&st.snapshot()).unwrap();
        let snap: RiskStateSnapshot = serde_json::from_str(&json).unwrap();

        // Restore within the window: the entity comes back and keeps accruing.
        let mut fresh = RiskState::default();
        assert!(fresh.restore(&c, snap, 200, false));
        assert_eq!(fresh.len(), 1);
        let again = record(&mut fresh, &c, "erin", 200, 50, &["execution"]);
        assert_eq!(again.incident.unwrap().score, 100, "restored 50 + new 50");

        // Restore far past the window: the stale contribution is pruned away.
        let snap2: RiskStateSnapshot =
            serde_json::from_str(&serde_json::to_string(&st.snapshot()).unwrap()).unwrap();
        let mut aged = RiskState::default();
        assert!(aged.restore(&c, snap2, 100 + 3600 + 5, false));
        assert!(aged.is_empty(), "stale entity pruned on restore");
    }

    #[test]
    fn a_restore_keeps_the_aggregates_beyond_the_samples() {
        let mut st = RiskState::default();
        let mut c = cfg(Some(1_000), None);
        c.caps.max_results_per_incident = 2;
        record(&mut st, &c, "deep", 0, 90, &["execution", "persistence"]);
        for ts in 1..10 {
            record(&mut st, &c, "deep", ts, 0, &["discovery"]);
        }
        let json = serde_json::to_string(&st.snapshot()).unwrap();
        let snap: RiskStateSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap.version, 3);
        let mut restored = RiskState::default();
        restored.restore(&c, snap, 10, false);
        let before = view(&st, &c, "deep", 10).unwrap();
        let after = view(&restored, &c, "deep", 10).unwrap();
        assert_eq!(after.score, 90);
        assert_eq!(after.tactic_count, 3);
        assert_eq!(after.result_count, 10);
        assert_eq!(
            (after.window_start, after.window_end, after.source_count),
            (before.window_start, before.window_end, before.source_count)
        );
        assert_eq!(restored.total_entries(), 2);
        assert_consistent(&restored);
    }

    #[test]
    fn a_version_two_snapshot_rebuilds_its_aggregates_from_the_contributions() {
        let snap: RiskStateSnapshot = serde_json::from_value(serde_json::json!({
            "version": 2,
            "entities": [{
                "entity_type": "user",
                "entity_value": "legacy",
                "last_seen": 20,
                "contributions": [
                    {"ts": 10, "score": 30, "tactics": ["execution"], "rule": "r1"},
                    {"ts": 20, "score": 40, "tactics": ["impact"], "rule": "r2"}
                ]
            }]
        }))
        .unwrap();
        let c = cfg(Some(1_000), None);
        let mut st = RiskState::default();
        let stats = st.restore_detailed(&c, snap, 30, false).unwrap();
        assert_eq!(stats.restored, 1);
        let v = view(&st, &c, "legacy", 30).unwrap();
        assert_eq!((v.score, v.tactic_count, v.source_count), (70, 2, 2));
        assert_consistent(&st);
    }

    #[test]
    fn restore_keeps_the_highest_scoring_entities_within_the_cap() {
        let mut src = RiskState::default();
        let c = cfg(Some(1_000_000), None);
        for i in 0..5 {
            record(
                &mut src,
                &c,
                &format!("u{i}"),
                0,
                10 * (i + 1),
                &["execution"],
            );
        }
        let snap = src.snapshot();

        let mut capped = c.clone();
        capped.caps.max_open_entities = 3;
        let mut restored = RiskState::default();
        let stats = restored.restore_detailed(&capped, snap, 0, false).unwrap();
        assert_eq!(stats.restored, 3);
        assert_eq!(restored.len(), 3);
        for kept in ["u2", "u3", "u4"] {
            assert!(restored.contains_entity(None, "user", kept), "{kept}");
        }
        assert_consistent(&restored);
    }

    #[test]
    fn restore_rejects_version_mismatch() {
        let mut st = RiskState::default();
        let snap = RiskStateSnapshot {
            version: SNAPSHOT_VERSION + 1,
            entities: vec![],
        };
        assert!(!st.restore(&cfg(Some(1), None), snap, 0, false));
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
        assert_consistent(&st);
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
            .restore_detailed(&c, snap.clone(), 0, true)
            .unwrap();
        assert_eq!(stats.restored, 1);
        assert_eq!(stats.discarded_untenanted, 1);
        assert_eq!(tenanted.len(), 1);

        let mut untenanted = RiskState::default();
        let stats = untenanted.restore_detailed(&c, snap, 0, false).unwrap();
        assert_eq!(stats.restored, 1);
        assert_eq!(stats.discarded_tenanted, 1);
        assert_eq!(untenanted.len(), 1);
    }

    #[test]
    fn a_tenant_quota_reclaims_only_its_own_lowest_scoring_entity() {
        let mut c = cfg(Some(1_000), None);
        c.caps.max_open_entities_per_tenant = Some(2);
        let mut st = RiskState::default();
        let a = TenantId::new("a").unwrap();
        let b = TenantId::new("b").unwrap();
        for (i, score) in [(0, 50), (1, 10), (2, 30)] {
            st.record(
                &c,
                Some(&a),
                "user",
                &format!("a{i}"),
                contrib(i, score, &["execution"], "r1"),
                i,
            );
        }
        st.record(
            &c,
            Some(&b),
            "user",
            "quiet",
            contrib(0, 1, &["execution"], "r1"),
            0,
        );

        assert_eq!(st.count_for_tenant(Some(&a)), 2);
        assert_eq!(st.count_for_tenant(Some(&b)), 1);
        assert_eq!(st.len(), 3);
        assert!(
            !st.contains_entity(Some(&a), "user", "a1"),
            "the lowest-scoring entity went first"
        );
        assert!(st.contains_entity(Some(&a), "user", "a0"));
        assert_consistent(&st);
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
                contrib(i, 10, &["execution"], "r1"),
                i,
            );
        }
        let mut restored = RiskState::default();
        restored
            .restore_detailed(&c, st.snapshot(), 3, true)
            .unwrap();
        assert_eq!(restored.count_for_tenant(Some(&a)), 3);
        let mut quota = c.clone();
        quota.caps.max_open_entities_per_tenant = Some(2);
        assert_eq!(restored.enforce_caps(&quota).tenant, 1);
        assert_eq!(restored.count_for_tenant(Some(&a)), 2);
        assert!(!restored.contains_entity(Some(&a), "user", "a0"));

        let mut capped = RiskState::default();
        let stats = capped
            .restore_detailed(&quota, st.snapshot(), 3, true)
            .unwrap();
        assert_eq!(stats.restored, 2);

        assert_eq!(restored.tick(&c, 10_000), 2);
        assert_eq!(restored.count_for_tenant(Some(&a)), 0);
        assert_consistent(&restored);
    }

    /// Against a model that keeps every contribution, the window aggregates
    /// match after every step (one-second buckets make the edge exact).
    #[test]
    fn aggregates_match_a_model_that_keeps_every_contribution() {
        const TACTIC_POOL: [&str; 5] = [
            "execution",
            "persistence",
            "impact",
            "discovery",
            "collection",
        ];
        let mut c = cfg(Some(i64::MAX), None);
        c.window = Duration::from_secs(300);
        c.caps.max_results_per_incident = 3;
        let mut st = RiskState::default();
        let mut model: HashMap<String, Vec<Contribution>> = HashMap::new();
        let mut seed: u64 = 0x5eed;
        let mut next = move || {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            seed >> 33
        };
        let mut now = 0i64;
        for _ in 0..3_000 {
            now += (next() % 7) as i64;
            let entity = format!("e{}", next() % 6);
            let tactic = TACTIC_POOL[(next() % 5) as usize];
            let rule = format!("r{}", next() % 4);
            let c_ = contrib(now, (next() % 50) as i64 - 10, &[tactic], &rule);
            model.entry(entity.clone()).or_default().push(c_.clone());
            st.record(&c, None, "user", &entity, c_, now);
            if next() % 10 == 0 {
                st.tick(&c, now);
            }
            let cutoff = now - 300;
            for (name, all) in &model {
                let live: Vec<&Contribution> = all.iter().filter(|c| c.ts > cutoff).collect();
                let got = view(&st, &c, name, now);
                if live.is_empty() {
                    assert!(got.is_none());
                    continue;
                }
                let got = got.expect("live entity has a view");
                let tactics: std::collections::HashSet<&String> =
                    live.iter().flat_map(|c| &c.tactics).collect();
                let rules: std::collections::HashSet<&String> =
                    live.iter().map(|c| &c.rule).collect();
                assert_eq!(got.score, live.iter().map(|c| c.score).sum::<i64>());
                assert_eq!(got.result_count, live.len() as u64);
                assert_eq!(got.tactic_count, tactics.len() as u64);
                assert_eq!(got.source_count, rules.len() as u64);
                assert_eq!(got.window_start, live.first().unwrap().ts);
                assert_eq!(got.window_end, live.last().unwrap().ts);
            }
        }
        assert_consistent(&st);
    }
}
