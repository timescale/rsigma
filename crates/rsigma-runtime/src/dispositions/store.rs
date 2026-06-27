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

/// Default rolling window over which dispositions are counted.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Default bucket width (one day).
pub const DEFAULT_BUCKET: Duration = Duration::from_secs(24 * 60 * 60);
/// Default minimum dispositions before a rule's ratio is published.
pub const DEFAULT_MIN_SAMPLE: u64 = 5;
/// Default ceiling on the idempotency seen-id set.
pub const DEFAULT_MAX_SEEN_IDS: usize = 100_000;

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
    /// Ceiling on the idempotency seen-id set.
    pub max_seen_ids: usize,
}

impl Default for DispositionConfig {
    fn default() -> Self {
        Self {
            window: DEFAULT_WINDOW,
            bucket: DEFAULT_BUCKET,
            numerator: Numerator::FpOnly,
            min_sample: DEFAULT_MIN_SAMPLE,
            max_seen_ids: DEFAULT_MAX_SEEN_IDS,
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
}

/// A per-rule rolling summary for the `GET` view and the scorecard feed.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleSummary {
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
    /// Per-rule bucketed counts, keyed by `rule_id` then bucket index.
    rules: HashMap<String, BTreeMap<i64, VerdictCounts>>,
    /// Idempotency set: keys seen, with their timestamp for window pruning.
    seen: HashSet<String>,
    seen_order: VecDeque<(i64, String)>,
}

impl DispositionStore {
    /// Create an empty store with the given config.
    pub fn new(config: DispositionConfig) -> Self {
        Self {
            config,
            rules: HashMap::new(),
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
        }
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
    /// record (no `rule_id`), [`IngestOutcome::Duplicate`] for a redelivery, and
    /// [`IngestOutcome::Accepted`] otherwise. The affected rule's bucket map is
    /// pruned to the window on each apply.
    pub fn apply(&mut self, disposition: &Disposition, now: i64) -> IngestOutcome {
        let Some(rule_id) = disposition.rule_id.clone() else {
            return IngestOutcome::Rejected(
                "incident-scoped disposition could not be resolved to a rule_id".to_string(),
            );
        };

        let key = disposition.dedup_key();
        if self.seen.contains(&key) {
            return IngestOutcome::Duplicate;
        }
        // Order the seen entry by the disposition's own timestamp so the
        // idempotency key lives exactly as long as its bucket can contribute to
        // the window: once a record ages out of the window its bucket is pruned
        // on apply, so a later redelivery lands in an already-pruned bucket and
        // cannot double count.
        self.remember(key, disposition.timestamp, now);

        let idx = self.bucket_index(disposition.timestamp);
        let cutoff = self.bucket_index(now - self.config.window_secs());
        let buckets = self.rules.entry(rule_id).or_default();
        buckets.entry(idx).or_default().add(disposition.verdict);
        buckets.retain(|&i, _| i >= cutoff);

        IngestOutcome::Accepted
    }

    fn remember(&mut self, key: String, ts: i64, now: i64) {
        self.seen.insert(key.clone());
        self.seen_order.push_back((ts, key));
        self.prune_seen(now);
    }

    fn prune_seen(&mut self, now: i64) {
        let cutoff = now - self.config.window_secs();
        while let Some((ts, _)) = self.seen_order.front() {
            let over_capacity = self.seen_order.len() > self.config.max_seen_ids;
            if *ts < cutoff || over_capacity {
                if let Some((_, key)) = self.seen_order.pop_front() {
                    self.seen.remove(&key);
                }
            } else {
                break;
            }
        }
    }

    /// Drop buckets older than the window across every rule (called on a
    /// periodic tick). Rules left with no buckets are removed.
    pub fn prune(&mut self, now: i64) {
        let cutoff = self.bucket_index(now - self.config.window_secs());
        self.rules.retain(|_, buckets| {
            buckets.retain(|&i, _| i >= cutoff);
            !buckets.is_empty()
        });
        self.prune_seen(now);
    }

    fn aggregate(&self, rule_id: &str) -> VerdictCounts {
        let mut total = VerdictCounts::default();
        if let Some(buckets) = self.rules.get(rule_id) {
            for counts in buckets.values() {
                total.merge(counts);
            }
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
    /// has fewer than `min_sample` dispositions.
    pub fn ratio(&self, rule_id: &str) -> Option<f64> {
        self.ratio_of(&self.aggregate(rule_id))
    }

    /// A per-rule summary for every rule with at least one disposition, sorted
    /// by `rule_id` for stable output.
    pub fn summaries(&self) -> Vec<RuleSummary> {
        let mut out: Vec<RuleSummary> = self
            .rules
            .keys()
            .map(|rule_id| {
                let counts = self.aggregate(rule_id);
                RuleSummary {
                    rule_id: rule_id.clone(),
                    true_positives: counts.true_positive,
                    false_positives: counts.false_positive,
                    benign_true_positives: counts.benign_true_positive,
                    total: counts.total(),
                    fp_ratio: self.ratio_of(&counts),
                }
            })
            .collect();
        out.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
        out
    }

    /// Number of rules currently tracked.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Capture the store into a versioned snapshot for persistence.
    pub fn snapshot(&self) -> DispositionSnapshot {
        DispositionSnapshot {
            version: super::snapshot::SNAPSHOT_VERSION,
            numerator: self.config.numerator.as_str().to_string(),
            rules: self
                .rules
                .iter()
                .map(|(rule_id, buckets)| RuleBucketsSnapshot {
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
            seen: self.seen_order.iter().cloned().collect(),
        }
    }

    /// Restore a snapshot at `now`, pruning buckets and seen ids past the
    /// window. Returns `false` on a version mismatch (caller starts fresh).
    pub fn restore(&mut self, snapshot: DispositionSnapshot, now: i64) -> bool {
        if snapshot.version != super::snapshot::SNAPSHOT_VERSION {
            return false;
        }
        let cutoff = self.bucket_index(now - self.config.window_secs());
        for rule in snapshot.rules {
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
            if !buckets.is_empty() {
                self.rules.insert(rule.rule_id, buckets);
            }
        }
        let seen_cutoff = now - self.config.window_secs();
        for (ts, key) in snapshot.seen {
            if ts < seen_cutoff {
                continue;
            }
            if self.seen.insert(key.clone()) {
                self.seen_order.push_back((ts, key));
            }
        }
        self.prune_seen(now);
        true
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
        assert!(restored.restore(snap, 1002));
        assert_eq!(restored.summaries(), store.summaries());
    }

    #[test]
    fn restore_rejects_version_mismatch() {
        let mut snap = DispositionStore::new(cfg(1)).snapshot();
        snap.version = 9999;
        let mut store = DispositionStore::new(cfg(1));
        assert!(!store.restore(snap, 1));
    }
}
