//! The rolling per-rule disposition store and the false-positive ratio.
//!
//! Verdict counts are kept in fixed-width time buckets (daily by default)
//! across a rolling window, so memory is bounded at rules times buckets rather
//! than growing with disposition volume. The per-rule false-positive ratio is
//! recomputed from the retained buckets, suppressed until a rule reaches a
//! minimum sample so a single false positive cannot publish a misleading 100%.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Duration;

use super::record::{Disposition, Verdict};
use super::snapshot::{DispositionSnapshot, RuleBucketsSnapshot};
use rsigma_eval::TenantId;

/// Default rolling window over which dispositions are counted.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Default bucket width (one day).
pub const DEFAULT_BUCKET: Duration = Duration::from_secs(24 * 60 * 60);
/// Default minimum dispositions before a rule's ratio is published.
pub const DEFAULT_MIN_SAMPLE: u64 = 5;
/// Default ceiling on the idempotency seen-id set.
pub const DEFAULT_MAX_SEEN_IDS: usize = 100_000;
/// Default ceiling on the `(tenant, rule)` pairs the store counts.
pub const DEFAULT_MAX_RULES: usize = 10_000;

/// Whether the false-positive ratio numerator counts false positives only or
/// also benign true positives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Numerator {
    /// `false_positive` only (the default).
    #[default]
    FpOnly,
    /// `false_positive` + `benign_true_positive`.
    FpAndBtp,
}

impl Numerator {
    /// Parse the config string form.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "fp_only" => Ok(Self::FpOnly),
            "fp_and_btp" => Ok(Self::FpAndBtp),
            other => Err(format!(
                "unknown numerator '{other}' (expected 'fp_only' or 'fp_and_btp')"
            )),
        }
    }

    /// The config string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FpOnly => "fp_only",
            Self::FpAndBtp => "fp_and_btp",
        }
    }
}

/// Configuration for the rolling disposition store.
#[derive(Debug, Clone)]
pub struct DispositionConfig {
    /// The rolling window over which dispositions are counted.
    pub window: Duration,
    /// The bucket width (counts are aggregated per bucket).
    pub bucket: Duration,
    /// Whether benign true positives count toward the ratio numerator.
    pub numerator: Numerator,
    /// Minimum dispositions in the window before the ratio is published.
    pub min_sample: u64,
    /// Ceiling on the idempotency seen-id set of each tenant (and of the
    /// untenanted set), so one tenant's volume cannot evict another's ids.
    pub max_seen_ids: usize,
    /// Ceiling on the `(tenant, rule)` pairs counted. A disposition for a new
    /// pair is refused once it is reached; pairs already counted keep
    /// counting.
    pub max_rules: usize,
}

impl Default for DispositionConfig {
    fn default() -> Self {
        Self {
            window: DEFAULT_WINDOW,
            bucket: DEFAULT_BUCKET,
            numerator: Numerator::FpOnly,
            min_sample: DEFAULT_MIN_SAMPLE,
            max_seen_ids: DEFAULT_MAX_SEEN_IDS,
            max_rules: DEFAULT_MAX_RULES,
        }
    }
}

impl DispositionConfig {
    fn bucket_secs(&self) -> i64 {
        (self.bucket.as_secs() as i64).max(1)
    }

    fn window_secs(&self) -> i64 {
        self.window.as_secs() as i64
    }
}

/// Verdict counts within a single bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerdictCounts {
    pub true_positive: u64,
    pub false_positive: u64,
    pub benign_true_positive: u64,
}

impl VerdictCounts {
    fn add(&mut self, verdict: Verdict) {
        match verdict {
            Verdict::TruePositive => self.true_positive += 1,
            Verdict::FalsePositive => self.false_positive += 1,
            Verdict::BenignTruePositive => self.benign_true_positive += 1,
        }
    }

    fn total(&self) -> u64 {
        self.true_positive + self.false_positive + self.benign_true_positive
    }

    fn merge(&mut self, other: &VerdictCounts) {
        self.true_positive += other.true_positive;
        self.false_positive += other.false_positive;
        self.benign_true_positive += other.benign_true_positive;
    }
}

/// The outcome of applying one disposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    /// The disposition was counted.
    Accepted,
    /// A record with the same idempotency key was already counted.
    Duplicate,
    /// The disposition could not be counted; carries a reason.
    Rejected(String),
    /// The disposition names a `(tenant, rule)` pair the store does not count
    /// yet, and it already counts [`DispositionConfig::max_rules`] pairs.
    RuleCapReached,
}

/// A per-rule rolling summary for the `GET` view and the scorecard feed.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleSummary {
    /// Tenant that owns these counts, when tenancy is enabled.
    pub tenant: Option<TenantId>,
    pub rule_id: String,
    pub true_positives: u64,
    pub false_positives: u64,
    pub benign_true_positives: u64,
    pub total: u64,
    /// `None` when the rule has fewer than `min_sample` dispositions.
    pub fp_ratio: Option<f64>,
}

/// The rolling per-rule disposition store.
///
/// Updated only by the ingestion paths (it never sits in the eval or sink
/// path), so it is strictly additive and cannot affect detection throughput.
#[derive(Debug)]
pub struct DispositionStore {
    config: DispositionConfig,
    /// Per-rule bucketed counts, keyed by `(tenant, rule_id)` then bucket index.
    rules: HashMap<(Option<TenantId>, String), BTreeMap<i64, VerdictCounts>>,
    /// The tenants with counts for each rule id, so a cross-tenant ratio
    /// reads only that rule's entries.
    rule_tenants: HashMap<String, HashSet<Option<TenantId>>>,
    /// Idempotency sets keyed by the tenant prefix of the dedup key.
    seen: HashMap<String, SeenIds>,
    /// `(tenant, rule)` entries read by aggregations, for tests that check
    /// how the work scales.
    #[cfg(test)]
    entries_read: std::cell::Cell<usize>,
}

/// One tenant's idempotency keys, with their timestamp for window pruning.
#[derive(Debug, Default)]
struct SeenIds {
    keys: HashSet<String>,
    order: VecDeque<(i64, String)>,
}

impl SeenIds {
    fn prune(&mut self, cutoff: i64, max: usize) {
        while let Some((ts, _)) = self.order.front() {
            if *ts < cutoff || self.order.len() > max {
                if let Some((_, key)) = self.order.pop_front() {
                    self.keys.remove(&key);
                }
            } else {
                break;
            }
        }
    }
}

/// The tenant part of a [`Disposition::dedup_key`], or `""` when untenanted.
fn seen_partition(key: &str) -> &str {
    if key.starts_with("tenant=")
        && let Some(end) = key.find('\u{1f}')
    {
        return &key[..end];
    }
    ""
}

impl DispositionStore {
    /// Create an empty store with the given config.
    pub fn new(config: DispositionConfig) -> Self {
        Self {
            config,
            rules: HashMap::new(),
            rule_tenants: HashMap::new(),
            seen: HashMap::new(),
            #[cfg(test)]
            entries_read: std::cell::Cell::new(0),
        }
    }

    /// Start counting `key`, keeping the per-rule tenant index in step.
    fn insert_rule(
        &mut self,
        key: (Option<TenantId>, String),
        buckets: BTreeMap<i64, VerdictCounts>,
    ) {
        self.rule_tenants
            .entry(key.1.clone())
            .or_default()
            .insert(key.0.clone());
        self.rules.insert(key, buckets);
    }

    /// The store's configuration.
    pub fn config(&self) -> &DispositionConfig {
        &self.config
    }

    fn bucket_index(&self, ts: i64) -> i64 {
        ts.div_euclid(self.config.bucket_secs())
    }

    /// Apply one disposition at `now` (epoch seconds), enforcing idempotency.
    ///
    /// Returns [`IngestOutcome::Rejected`] for an unresolved incident-scoped
    /// record (no `rule_id`) or one whose timestamp is already outside the
    /// window, [`IngestOutcome::Duplicate`] for a redelivery,
    /// [`IngestOutcome::RuleCapReached`] for a new `(tenant, rule)` pair past
    /// [`DispositionConfig::max_rules`], and [`IngestOutcome::Accepted`]
    /// otherwise. The affected rule's bucket map is pruned to the window on
    /// each apply.
    pub fn apply(&mut self, disposition: &Disposition, now: i64) -> IngestOutcome {
        let Some(rule_id) = disposition.rule_id.clone() else {
            return IngestOutcome::Rejected(
                "incident-scoped disposition could not be resolved to a rule_id".to_string(),
            );
        };
        let idx = self.bucket_index(disposition.timestamp);
        let cutoff = self.bucket_index(now - self.config.window_secs());
        if idx < cutoff {
            return IngestOutcome::Rejected(
                "timestamp is older than the rolling window".to_string(),
            );
        }

        let key = disposition.dedup_key();
        if self
            .seen
            .get(seen_partition(&key))
            .is_some_and(|ids| ids.keys.contains(&key))
        {
            return IngestOutcome::Duplicate;
        }
        let rule_key = (disposition.tenant.clone(), rule_id);
        if !self.rules.contains_key(&rule_key) && self.rules.len() >= self.config.max_rules {
            return IngestOutcome::RuleCapReached;
        }
        // Order the seen entry by the disposition's own timestamp so the
        // idempotency key lives exactly as long as its bucket can contribute to
        // the window: once a record ages out of the window its bucket is pruned
        // on apply, so a later redelivery lands in an already-pruned bucket and
        // cannot double count.
        self.remember(key, disposition.timestamp, now);

        if !self.rules.contains_key(&rule_key) {
            self.insert_rule(rule_key.clone(), BTreeMap::new());
        }
        if let Some(buckets) = self.rules.get_mut(&rule_key) {
            buckets.entry(idx).or_default().add(disposition.verdict);
            buckets.retain(|&i, _| i >= cutoff);
        }

        IngestOutcome::Accepted
    }

    fn remember(&mut self, key: String, ts: i64, now: i64) {
        let cutoff = now - self.config.window_secs();
        let max = self.config.max_seen_ids;
        let ids = self
            .seen
            .entry(seen_partition(&key).to_string())
            .or_default();
        if ids.keys.insert(key.clone()) {
            ids.order.push_back((ts, key));
        }
        ids.prune(cutoff, max);
    }

    fn prune_seen(&mut self, now: i64) {
        let cutoff = now - self.config.window_secs();
        let max = self.config.max_seen_ids;
        self.seen.retain(|_, ids| {
            ids.prune(cutoff, max);
            !ids.order.is_empty()
        });
    }

    /// Drop buckets older than the window across every rule (called on a
    /// periodic tick). Rules left with no buckets are removed. Returns the
    /// rule ids no tenant has counts for any more.
    pub fn prune(&mut self, now: i64) -> Vec<String> {
        let cutoff = self.bucket_index(now - self.config.window_secs());
        let mut emptied = Vec::new();
        self.rules.retain(|key, buckets| {
            buckets.retain(|&i, _| i >= cutoff);
            if buckets.is_empty() {
                emptied.push(key.clone());
            }
            !buckets.is_empty()
        });
        let mut gone = Vec::new();
        for (tenant, rule_id) in emptied {
            if let Some(tenants) = self.rule_tenants.get_mut(&rule_id) {
                tenants.remove(&tenant);
                if tenants.is_empty() {
                    self.rule_tenants.remove(&rule_id);
                    gone.push(rule_id);
                }
            }
        }
        self.prune_seen(now);
        gone
    }

    fn aggregate(&self, tenant: Option<&TenantId>, rule_id: &str) -> VerdictCounts {
        let mut total = VerdictCounts::default();
        #[cfg(test)]
        self.entries_read.set(self.entries_read.get() + 1);
        if let Some(buckets) = self.rules.get(&(tenant.cloned(), rule_id.to_string())) {
            for counts in buckets.values() {
                total.merge(counts);
            }
        }
        total
    }

    fn aggregate_all_tenants(&self, rule_id: &str) -> VerdictCounts {
        let mut total = VerdictCounts::default();
        for tenant in self.rule_tenants.get(rule_id).into_iter().flatten() {
            total.merge(&self.aggregate(tenant.as_ref(), rule_id));
        }
        total
    }

    fn ratio_of(&self, counts: &VerdictCounts) -> Option<f64> {
        let total = counts.total();
        if total < self.config.min_sample || total == 0 {
            return None;
        }
        let numerator = match self.config.numerator {
            Numerator::FpOnly => counts.false_positive,
            Numerator::FpAndBtp => counts.false_positive + counts.benign_true_positive,
        };
        Some(numerator as f64 / total as f64)
    }

    /// The false-positive ratio for one rule over the window, or `None` when it
    /// has fewer than `min_sample` dispositions. Sums across tenants.
    pub fn ratio(&self, rule_id: &str) -> Option<f64> {
        self.ratio_of(&self.aggregate_all_tenants(rule_id))
    }

    /// The false-positive ratio for one rule in `tenant`, or `None` when it has
    /// fewer than `min_sample` dispositions.
    pub fn ratio_for(&self, tenant: Option<&TenantId>, rule_id: &str) -> Option<f64> {
        self.ratio_of(&self.aggregate(tenant, rule_id))
    }

    /// A per-(tenant, rule) summary for every rule with at least one
    /// disposition, sorted for stable output.
    pub fn summaries(&self) -> Vec<RuleSummary> {
        let mut out: Vec<RuleSummary> = self
            .rules
            .iter()
            .map(|((tenant, rule_id), _)| {
                let counts = self.aggregate(tenant.as_ref(), rule_id);
                RuleSummary {
                    tenant: tenant.clone(),
                    rule_id: rule_id.clone(),
                    true_positives: counts.true_positive,
                    false_positives: counts.false_positive,
                    benign_true_positives: counts.benign_true_positive,
                    total: counts.total(),
                    fp_ratio: self.ratio_of(&counts),
                }
            })
            .collect();
        out.sort_by(|a, b| {
            a.tenant
                .cmp(&b.tenant)
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });
        out
    }

    /// Number of (tenant, rule) buckets currently tracked.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Every rule id with counts in at least one tenant, in no set order.
    pub fn rule_ids(&self) -> Vec<String> {
        self.rule_tenants.keys().cloned().collect()
    }

    /// Capture the store into a versioned snapshot for persistence.
    pub fn snapshot(&self) -> DispositionSnapshot {
        DispositionSnapshot {
            version: super::snapshot::SNAPSHOT_VERSION,
            numerator: self.config.numerator.as_str().to_string(),
            rules: self
                .rules
                .iter()
                .map(|((tenant, rule_id), buckets)| RuleBucketsSnapshot {
                    tenant: tenant.clone(),
                    rule_id: rule_id.clone(),
                    buckets: buckets
                        .iter()
                        .map(|(&idx, c)| {
                            (
                                idx,
                                c.true_positive,
                                c.false_positive,
                                c.benign_true_positive,
                            )
                        })
                        .collect(),
                })
                .collect(),
            seen: {
                let mut seen: Vec<(i64, String)> = self
                    .seen
                    .values()
                    .flat_map(|ids| ids.order.iter().cloned())
                    .collect();
                seen.sort();
                seen
            },
        }
    }

    /// Restore a snapshot at `now`, pruning buckets and seen ids past the
    /// window and applying the tenant attribution rule of
    /// [`restore_detailed`](Self::restore_detailed). Returns `false` on a
    /// version mismatch (caller starts fresh).
    pub fn restore(&mut self, snapshot: DispositionSnapshot, now: i64, tenancy: bool) -> bool {
        self.restore_detailed(snapshot, now, tenancy).is_some()
    }

    /// Like [`restore`](Self::restore), returning the restored and discarded
    /// counts. Accepts versions 1 and 2 and applies the tenant attribution rule:
    /// with `tenancy`, untenanted buckets are discarded; without it, tenanted
    /// ones are.
    pub fn restore_detailed(
        &mut self,
        snapshot: DispositionSnapshot,
        now: i64,
        tenancy: bool,
    ) -> Option<rsigma_eval::ImportStats> {
        if !matches!(snapshot.version, 1 | 2) {
            return None;
        }
        let mut stats = rsigma_eval::ImportStats::default();
        let mut over_limit = 0usize;
        let cutoff = self.bucket_index(now - self.config.window_secs());
        for rule in snapshot.rules {
            let keep = if tenancy {
                rule.tenant.is_some()
            } else {
                rule.tenant.is_none()
            };
            if !keep {
                if rule.tenant.is_none() {
                    stats.discarded_untenanted += 1;
                } else {
                    stats.discarded_tenanted += 1;
                }
                continue;
            }
            let mut buckets = BTreeMap::new();
            for (idx, tp, fp, btp) in rule.buckets {
                if idx < cutoff {
                    continue;
                }
                buckets.insert(
                    idx,
                    VerdictCounts {
                        true_positive: tp,
                        false_positive: fp,
                        benign_true_positive: btp,
                    },
                );
            }
            if buckets.is_empty() {
                continue;
            }
            let key = (rule.tenant, rule.rule_id);
            if key.1.is_empty()
                || key.1.len() > super::record::MAX_DISPOSITION_ID_BYTES
                || (!self.rules.contains_key(&key) && self.rules.len() >= self.config.max_rules)
            {
                over_limit += 1;
                continue;
            }
            self.insert_rule(key, buckets);
            stats.restored += 1;
        }
        if over_limit > 0 {
            tracing::warn!(
                rules = over_limit,
                max_rules = self.config.max_rules,
                "Left out restored disposition rules over max_rules or the rule_id length limit"
            );
        }
        let seen_cutoff = now - self.config.window_secs();
        for (ts, key) in snapshot.seen {
            if ts < seen_cutoff {
                continue;
            }
            let ids = self
                .seen
                .entry(seen_partition(&key).to_string())
                .or_default();
            if ids.keys.insert(key.clone()) {
                ids.order.push_back((ts, key));
            }
        }
        self.prune_seen(now);
        Some(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispositions::record::RawDisposition;

    fn disp(rule: &str, verdict: &str, ts: i64) -> Disposition {
        let raw: RawDisposition = serde_json::from_str(&format!(
            r#"{{"rule_id": "{rule}", "verdict": "{verdict}"}}"#
        ))
        .unwrap();
        let mut d = Disposition::from_raw(raw, ts).unwrap();
        d.timestamp = ts;
        d
    }

    fn cfg(min_sample: u64) -> DispositionConfig {
        DispositionConfig {
            min_sample,
            ..Default::default()
        }
    }

    #[test]
    fn ratio_is_suppressed_below_min_sample() {
        let mut store = DispositionStore::new(cfg(5));
        store.apply(&disp("r", "false_positive", 1000), 1000);
        assert_eq!(store.ratio("r"), None);

        // Distinct timestamps so the no-identity fallback dedup key
        // (rule_id, timestamp, analyst) does not collapse them.
        for i in 1..5 {
            store.apply(&disp("r", "true_positive", 1000 + i), 1000 + i);
        }
        // Now total == 5 (1 fp + 4 tp).
        assert_eq!(store.ratio("r"), Some(1.0 / 5.0));
    }

    #[test]
    fn numerator_fp_and_btp_counts_benign() {
        let mut store = DispositionStore::new(DispositionConfig {
            min_sample: 1,
            numerator: Numerator::FpAndBtp,
            ..Default::default()
        });
        store.apply(&disp("r", "false_positive", 10), 10);
        store.apply(&disp("r", "benign_true_positive", 11), 11);
        store.apply(&disp("r", "true_positive", 12), 12);
        // (1 fp + 1 btp) / 3 total.
        assert_eq!(store.ratio("r"), Some(2.0 / 3.0));
    }

    #[test]
    fn idempotency_collapses_redelivery() {
        let mut store = DispositionStore::new(cfg(1));
        let raw: RawDisposition = serde_json::from_str(
            r#"{"rule_id": "r", "verdict": "false_positive", "fingerprint": "fp1"}"#,
        )
        .unwrap();
        let d = Disposition::from_raw(raw, 100).unwrap();
        assert_eq!(store.apply(&d, 100), IngestOutcome::Accepted);
        assert_eq!(store.apply(&d, 101), IngestOutcome::Duplicate);
        // Only counted once.
        assert_eq!(store.summaries()[0].total, 1);
    }

    fn incident_disp(rule: &str, incident: &str, ts: i64) -> Disposition {
        let raw: RawDisposition = serde_json::from_str(&format!(
            r#"{{"rule_id":"{rule}","scope":"incident","incident_id":"{incident}","verdict":"false_positive"}}"#
        ))
        .unwrap();
        let mut d = Disposition::from_raw(raw, ts).unwrap();
        d.timestamp = ts;
        d
    }

    #[test]
    fn incident_expansion_counts_every_contributing_rule() {
        // The per-rule records an incident expands into share the incident id
        // and verdict but differ by rule_id, so all of them must count rather
        // than collapsing to the first.
        let mut store = DispositionStore::new(cfg(1));
        for rule in ["r1", "r2", "r3"] {
            assert_eq!(
                store.apply(&incident_disp(rule, "inc1", 100), 100),
                IngestOutcome::Accepted
            );
        }
        assert_eq!(store.summaries().len(), 3);

        // Re-expanding the same incident (a redelivery) dedups every rule.
        for rule in ["r1", "r2", "r3"] {
            assert_eq!(
                store.apply(&incident_disp(rule, "inc1", 100), 100),
                IngestOutcome::Duplicate
            );
        }
    }

    #[test]
    fn unresolved_incident_is_rejected() {
        let raw: RawDisposition = serde_json::from_str(
            r#"{"verdict": "true_positive", "scope": "incident", "incident_id": "i1"}"#,
        )
        .unwrap();
        let d = Disposition::from_raw(raw, 1).unwrap();
        let mut store = DispositionStore::new(cfg(1));
        assert!(matches!(store.apply(&d, 1), IngestOutcome::Rejected(_)));
    }

    #[test]
    fn window_pruning_drops_old_buckets() {
        let mut store = DispositionStore::new(cfg(1));
        let day = 24 * 60 * 60;
        // An old false positive 40 days ago, then a recent true positive.
        store.apply(&disp("r", "false_positive", 1000), 1000);
        let now = 1000 + 40 * day;
        store.apply(&disp("r", "true_positive", now), now);
        // The 40-day-old bucket is outside the 30-day window.
        let summary = &store.summaries()[0];
        assert_eq!(summary.false_positives, 0);
        assert_eq!(summary.true_positives, 1);
    }

    #[test]
    fn snapshot_round_trips() {
        let mut store = DispositionStore::new(cfg(1));
        store.apply(&disp("r", "false_positive", 1000), 1000);
        store.apply(&disp("r", "true_positive", 1001), 1001);
        store.apply(&disp("s", "true_positive", 1002), 1002);
        let snap = store.snapshot();

        let mut restored = DispositionStore::new(cfg(1));
        assert!(restored.restore(snap, 1002, false));
        assert_eq!(restored.summaries(), store.summaries());
    }

    #[test]
    fn restore_rejects_version_mismatch() {
        let mut snap = DispositionStore::new(cfg(1)).snapshot();
        snap.version = 9999;
        let mut store = DispositionStore::new(cfg(1));
        assert!(!store.restore(snap, 1, false));
    }

    fn disp_tenant(rule: &str, verdict: &str, ts: i64, tenant: &str) -> Disposition {
        let raw: RawDisposition = serde_json::from_str(&format!(
            r#"{{"rule_id": "{rule}", "verdict": "{verdict}", "tenant": "{tenant}"}}"#
        ))
        .unwrap();
        let mut d = Disposition::from_raw(raw, ts).unwrap();
        d.timestamp = ts;
        d
    }

    #[test]
    fn the_same_rule_in_two_tenants_is_two_buckets() {
        let mut store = DispositionStore::new(cfg(1));
        store.apply(&disp_tenant("r", "false_positive", 1000, "a"), 1000);
        store.apply(&disp_tenant("r", "false_positive", 1000, "b"), 1000);
        assert_eq!(store.summaries().len(), 2);
        assert_eq!(store.summaries()[0].tenant.as_ref().unwrap().as_str(), "a");
        assert_eq!(store.summaries()[1].tenant.as_ref().unwrap().as_str(), "b");
        assert_eq!(
            store.ratio_for(Some(&TenantId::new("a").unwrap()), "r"),
            Some(1.0)
        );
    }

    #[test]
    fn snapshot_attribution_discards_the_other_mode() {
        let mut store = DispositionStore::new(cfg(1));
        store.apply(&disp_tenant("r", "false_positive", 1000, "a"), 1000);
        store.apply(&disp("s", "true_positive", 1000), 1000);
        let snap = store.snapshot();

        let mut tenanted = DispositionStore::new(cfg(1));
        let stats = tenanted.restore_detailed(snap.clone(), 1000, true).unwrap();
        assert_eq!(stats.restored, 1);
        assert_eq!(stats.discarded_untenanted, 1);

        let mut untenanted = DispositionStore::new(cfg(1));
        let stats = untenanted.restore_detailed(snap, 1000, false).unwrap();
        assert_eq!(stats.restored, 1);
        assert_eq!(stats.discarded_tenanted, 1);
    }

    #[test]
    fn new_rules_past_max_rules_are_refused() {
        let mut store = DispositionStore::new(DispositionConfig {
            min_sample: 1,
            max_rules: 2,
            ..Default::default()
        });
        assert_eq!(
            store.apply(&disp("a", "true_positive", 10), 10),
            IngestOutcome::Accepted
        );
        assert_eq!(
            store.apply(&disp("b", "true_positive", 11), 11),
            IngestOutcome::Accepted
        );
        assert_eq!(
            store.apply(&disp("c", "true_positive", 12), 12),
            IngestOutcome::RuleCapReached
        );
        assert_eq!(
            store.apply(&disp("a", "false_positive", 13), 13),
            IngestOutcome::Accepted,
            "a rule already counted keeps counting"
        );
        assert_eq!(store.rule_count(), 2);
        // A refused record leaves no idempotency key behind.
        let mut sorted = store.rule_ids();
        sorted.sort();
        assert_eq!(sorted, ["a", "b"]);
        let day = 24 * 60 * 60;
        let later = 12 + 40 * day;
        let gone = store.prune(later);
        assert_eq!(gone.len(), 2);
        assert!(store.rule_ids().is_empty());
        assert_eq!(
            store.apply(&disp("c", "true_positive", later), later),
            IngestOutcome::Accepted
        );
    }

    #[test]
    fn a_flood_of_distinct_rule_ids_stops_at_max_rules() {
        let mut store = DispositionStore::new(cfg(1));
        let now = 1_000_000;
        let mut refused = 0;
        for i in 0..100_000 {
            if store.apply(&disp(&format!("rule-{i}"), "false_positive", now), now)
                == IngestOutcome::RuleCapReached
            {
                refused += 1;
            }
        }
        assert_eq!(store.rule_count(), DEFAULT_MAX_RULES);
        assert_eq!(refused, 100_000 - DEFAULT_MAX_RULES);
    }

    #[test]
    fn a_timestamp_older_than_the_window_leaves_no_entry() {
        let mut store = DispositionStore::new(cfg(1));
        let day = 24 * 60 * 60;
        let now = 100 * day;
        let outcome = store.apply(&disp("r", "false_positive", now - 40 * day), now);
        assert!(matches!(outcome, IngestOutcome::Rejected(_)), "{outcome:?}");
        assert_eq!(store.rule_count(), 0);
        assert!(store.snapshot().seen.is_empty());
    }

    #[test]
    fn a_cross_tenant_ratio_reads_only_its_own_rule() {
        let ratio_reads = |other_rules: usize| {
            let mut store = DispositionStore::new(DispositionConfig {
                min_sample: 1,
                max_rules: usize::MAX,
                ..Default::default()
            });
            for tenant in ["a", "b"] {
                store.apply(&disp_tenant("r", "false_positive", 10, tenant), 10);
            }
            for i in 0..other_rules {
                store.apply(&disp(&format!("other-{i}"), "true_positive", 10), 10);
            }
            store.entries_read.set(0);
            assert_eq!(store.ratio("r"), Some(1.0));
            store.entries_read.get()
        };
        assert_eq!(ratio_reads(10), 2);
        assert_eq!(
            ratio_reads(20_000),
            2,
            "the work does not grow with other rules"
        );
    }

    #[test]
    fn restore_applies_max_rules() {
        let mut store = DispositionStore::new(cfg(1));
        for i in 0..5 {
            store.apply(&disp(&format!("r{i}"), "true_positive", 100), 100);
        }
        let mut small = DispositionStore::new(DispositionConfig {
            min_sample: 1,
            max_rules: 3,
            ..Default::default()
        });
        let stats = small
            .restore_detailed(store.snapshot(), 100, false)
            .unwrap();
        assert_eq!(stats.restored, 3);
        assert_eq!(small.rule_count(), 3);
        assert_eq!(small.rule_ids().len(), 3);
    }

    #[test]
    fn one_tenants_volume_cannot_evict_anothers_seen_ids() {
        let mut store = DispositionStore::new(DispositionConfig {
            min_sample: 1,
            max_seen_ids: 2,
            ..Default::default()
        });
        let victim = disp_tenant("r", "false_positive", 1000, "a");
        store.apply(&victim, 1000);
        for ts in 1001..1010 {
            store.apply(&disp_tenant("r", "true_positive", ts, "b"), 1010);
        }
        assert_eq!(store.apply(&victim, 1010), IngestOutcome::Duplicate);

        let mut restored = DispositionStore::new(store.config().clone());
        restored.restore(store.snapshot(), 1010, true);
        assert_eq!(restored.apply(&victim, 1010), IngestOutcome::Duplicate);
    }
}
