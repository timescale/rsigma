//! Versioned persistence snapshot for the disposition store.

use serde::{Deserialize, Serialize};

/// Snapshot format version. Bump on any incompatible layout change; a restore
/// of a mismatched version starts fresh with a warning rather than erroring.
pub const SNAPSHOT_VERSION: u32 = 1;

/// One rule's bucketed verdict counts, as `(bucket_index, tp, fp, btp)` tuples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleBucketsSnapshot {
    pub rule_id: String,
    pub buckets: Vec<(i64, u64, u64, u64)>,
}

/// A versioned snapshot of the disposition store: the per-rule buckets plus the
/// window-pruned idempotency seen-id set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispositionSnapshot {
    /// Snapshot format version.
    pub version: u32,
    /// The numerator convention in force when the snapshot was taken, recorded
    /// for diagnostics (the restoring store applies its own configured value).
    pub numerator: String,
    /// Per-rule bucketed counts.
    pub rules: Vec<RuleBucketsSnapshot>,
    /// Idempotency seen ids as `(timestamp, key)` pairs.
    pub seen: Vec<(i64, String)>,
}
