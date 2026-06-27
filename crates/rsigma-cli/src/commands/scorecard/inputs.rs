//! Typed input loaders for `rule scorecard`.
//!
//! The two required inputs (the #46 backtest report and the #47 coverage
//! report) deserialize through the shared `crate::commands::reports` structs,
//! so the consumer and the producers share one definition: a report written by
//! an incompatible build fails this typed deserialize, which is the schema
//! guard (exit `CONFIG_ERROR`). The optional triage feed deserializes through
//! typed serde as well. Only the Prometheus exposition snapshot is hand-rolled,
//! matching the repo's `DelimitedWriter` and JUnit-writer precedent (no new
//! dependency); it is the single new untrusted-input surface and is fuzzed.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::commands::reports::{BacktestReport, CoverageReport};
// The Prometheus reader and metrics loader are shared with `rule hygiene` via
// `crate::metrics_source`. Re-exported under their historical `inputs::` names
// so the rest of the scorecard (fuse/report) is untouched by the lift.
pub(crate) use crate::metrics_source::{MetricsData, unix_to_rfc3339};
use crate::metrics_source::MetricsError;

/// A failure loading or parsing an input, carrying the house exit-code intent:
/// an input that is missing or unfetchable is `Unreadable` (exit 2); an input
/// that is present but does not parse against the shipped schema is `Malformed`
/// (exit 3).
#[derive(Debug)]
pub(crate) enum InputError {
    /// The input could not be read or fetched (missing file, unreachable URL).
    Unreadable(String),
    /// The input was read but did not parse against the expected shape (a
    /// malformed or version-mismatched report).
    Malformed(String),
}

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputError::Unreadable(m) | InputError::Malformed(m) => f.write_str(m),
        }
    }
}

impl From<MetricsError> for InputError {
    fn from(e: MetricsError) -> Self {
        match e {
            MetricsError::Unreadable(m) => InputError::Unreadable(m),
            MetricsError::Malformed(m) => InputError::Malformed(m),
        }
    }
}

// ---------------------------------------------------------------------------
// Required JSON reports (shared structs from Phase 0)
// ---------------------------------------------------------------------------

/// Load and parse the #46 backtest JSON report.
pub(crate) fn load_backtest(path: &Path) -> Result<BacktestReport, InputError> {
    let raw = read_file(path)?;
    serde_json::from_str(&raw).map_err(|e| {
        InputError::Malformed(format!(
            "could not parse backtest report {} (is it a `rule backtest --report` JSON document \
             from a compatible rsigma version?): {e}",
            path.display()
        ))
    })
}

/// Load and parse the #47 coverage JSON report.
pub(crate) fn load_coverage(path: &Path) -> Result<CoverageReport, InputError> {
    let raw = read_file(path)?;
    serde_json::from_str(&raw).map_err(|e| {
        InputError::Malformed(format!(
            "could not parse coverage report {} (is it a `rule coverage --output-format json` \
             document from a compatible rsigma version?): {e}",
            path.display()
        ))
    })
}

fn read_file(path: &Path) -> Result<String, InputError> {
    std::fs::read_to_string(path)
        .map_err(|e| InputError::Unreadable(format!("could not read {}: {e}", path.display())))
}

// ---------------------------------------------------------------------------
// Optional triage disposition feed (#70)
// ---------------------------------------------------------------------------

/// Live per-rule triage dispositions. The #70 triage feedback loop owns this
/// schema; until it ships, the scorecard reads this provisional, additive
/// shape: a `rules` array keyed by `rule_id`, each carrying either an explicit
/// `fp_ratio` or the true/false-positive counts to derive it, plus optional
/// mean time-to-detect/respond in seconds.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TriageFeed {
    #[serde(default)]
    pub(crate) rules: Vec<TriageEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TriageEntry {
    pub(crate) rule_id: String,
    #[serde(default)]
    pub(crate) true_positives: Option<u64>,
    #[serde(default)]
    pub(crate) false_positives: Option<u64>,
    #[serde(default)]
    pub(crate) fp_ratio: Option<f64>,
    #[serde(default)]
    pub(crate) mttd_seconds: Option<f64>,
    #[serde(default)]
    pub(crate) mttr_seconds: Option<f64>,
}

impl TriageEntry {
    /// Effective live false-positive ratio: the explicit `fp_ratio` when set,
    /// otherwise derived from the true/false-positive counts. `None` when the
    /// entry carries neither.
    pub(crate) fn effective_fp_ratio(&self) -> Option<f64> {
        if let Some(r) = self.fp_ratio {
            return Some(r.clamp(0.0, 1.0));
        }
        match (self.true_positives, self.false_positives) {
            (Some(tp), Some(fp)) if tp + fp > 0 => Some(fp as f64 / (tp + fp) as f64),
            _ => None,
        }
    }
}

/// A per-`rule_id` index of triage dispositions for the fuse join.
pub(crate) type TriageIndex = BTreeMap<String, TriageEntry>;

/// Load the triage feed and index it by `rule_id`. A later entry for the same
/// id wins, matching the last-write semantics of a refreshed disposition feed.
pub(crate) fn load_triage(path: &Path) -> Result<TriageIndex, InputError> {
    let raw = read_file(path)?;
    let feed: TriageFeed = serde_json::from_str(&raw).map_err(|e| {
        InputError::Malformed(format!(
            "could not parse triage feed {}: {e}",
            path.display()
        ))
    })?;
    Ok(feed
        .rules
        .into_iter()
        .map(|e| (e.rule_id.clone(), e))
        .collect())
}

// ---------------------------------------------------------------------------
// Prometheus production volume (optional)
//
// The reader and loader live in the shared `crate::metrics_source` module so
// `rule scorecard` and `rule hygiene` share one parser (and one fuzz target).
// This thin wrapper preserves the scorecard's `InputError` exit-code mapping.
// ---------------------------------------------------------------------------

/// Load the Prometheus source via the shared metrics reader, mapping its error
/// into the scorecard's [`InputError`] exit-code intent.
pub(crate) fn load_metrics(spec: &str, window: Option<&str>) -> Result<MetricsData, InputError> {
    crate::metrics_source::load_metrics(spec, window).map_err(InputError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triage_effective_ratio_prefers_explicit_then_counts() {
        let explicit = TriageEntry {
            rule_id: "r".into(),
            true_positives: Some(1),
            false_positives: Some(1),
            fp_ratio: Some(0.9),
            mttd_seconds: None,
            mttr_seconds: None,
        };
        assert_eq!(explicit.effective_fp_ratio(), Some(0.9));
        let derived = TriageEntry {
            rule_id: "r".into(),
            true_positives: Some(8),
            false_positives: Some(2),
            fp_ratio: None,
            mttd_seconds: None,
            mttr_seconds: None,
        };
        assert_eq!(derived.effective_fp_ratio(), Some(0.2));
        let none = TriageEntry {
            rule_id: "r".into(),
            true_positives: None,
            false_positives: None,
            fp_ratio: None,
            mttd_seconds: None,
            mttr_seconds: None,
        };
        assert_eq!(none.effective_fp_ratio(), None);
    }
}
