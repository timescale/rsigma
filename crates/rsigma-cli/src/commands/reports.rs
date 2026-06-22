//! Shared, serializable report shapes for the detection-as-code `rule`
//! commands.
//!
//! `rule backtest` (#46) and `rule coverage` (#47) own the JSON report
//! documents the rest of the toolkit consumes. Lifting their report structs
//! here, out of the producing command modules, gives the producers and the
//! `rule scorecard` consumer a single definition that cannot drift: the
//! producers build and serialize these shapes, and the consumer deserializes
//! the very same types. A report written by an incompatible build fails the
//! consumer's typed deserialize, which is the schema/version guard.
//!
//! These are pure wire shapes. Runtime-only knobs (the backtest unexpected
//! policy, the coverage fail-on-gaps flag) are deliberately not fields here:
//! they never appear in the JSON and stay with the command logic that owns
//! the exit-code and rendering decisions. Every field is `pub(crate)` so the
//! producers can build them and the consumer can read them, and the structs
//! derive `Deserialize` (the producers only ever serialized) so the consumer
//! can load them back.

use std::collections::BTreeMap;

use rsigma_parser::LogSource;
use serde::{Deserialize, Serialize};

// ===========================================================================
// `rule backtest` report (#46)
// ===========================================================================

/// Compact logsource projection used throughout the backtest report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LogSourceView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) service: Option<String>,
}

impl LogSourceView {
    pub(crate) fn from_logsource(ls: &LogSource) -> Option<Self> {
        if ls.category.is_none() && ls.product.is_none() && ls.service.is_none() {
            return None;
        }
        Some(Self {
            category: ls.category.clone(),
            product: ls.product.clone(),
            service: ls.service.clone(),
        })
    }

    /// A stable one-line label (`product/category/service`) used for grouping
    /// and table cells. `(none)` when no component is set (e.g. correlations).
    pub(crate) fn label(view: &Option<Self>) -> String {
        let Some(v) = view else {
            return "(none)".to_string();
        };
        let parts: Vec<&str> = [
            v.product.as_deref(),
            v.category.as_deref(),
            v.service.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect();
        if parts.is_empty() {
            "(none)".to_string()
        } else {
            parts.join("/")
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BacktestSummary {
    pub(crate) corpus_files: u64,
    pub(crate) events_processed: u64,
    pub(crate) rules_loaded: u64,
    pub(crate) expectations_total: u64,
    pub(crate) expectations_passed: u64,
    pub(crate) expectations_failed: u64,
    pub(crate) unexpected_rules: u64,
    pub(crate) unexpected_fires: u64,
    pub(crate) unexpected_policy: String,
    pub(crate) duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ExpectationResult {
    /// The original reference (id or title) from the file.
    pub(crate) rule: String,
    pub(crate) rule_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) scope: Option<String>,
    pub(crate) bound: String,
    pub(crate) actual: u64,
    pub(crate) pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RuleStat {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rule_id: Option<String>,
    pub(crate) rule_title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) logsource: Option<LogSourceView>,
    pub(crate) fires: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) by_file: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UnexpectedStat {
    pub(crate) rule_key: String,
    pub(crate) rule_title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) logsource: Option<LogSourceView>,
    pub(crate) fires: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LogSourceRollup {
    pub(crate) logsource: String,
    pub(crate) unexpected_fires: u64,
    pub(crate) rules: Vec<String>,
}

/// The full `rule backtest` report document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BacktestReport {
    pub(crate) summary: BacktestSummary,
    pub(crate) expectations: Vec<ExpectationResult>,
    pub(crate) rules: Vec<RuleStat>,
    pub(crate) unexpected: Vec<UnexpectedStat>,
    pub(crate) by_logsource: Vec<LogSourceRollup>,
}

// ===========================================================================
// `rule coverage` report (#47)
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CoverageSummary {
    pub(crate) rules_total: usize,
    pub(crate) rules_tagged: usize,
    pub(crate) rules_untagged: usize,
    pub(crate) techniques: usize,
    pub(crate) subtechniques: usize,
    pub(crate) tactics: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TechniqueEntry {
    pub(crate) id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) tactics: Vec<String>,
    pub(crate) rule_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) rules: Vec<String>,
}

/// Atomic Red Team cross-reference: which techniques have atomics but no rule
/// (a detection gap) and which rules cover techniques with no atomic (a
/// validation gap).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AtomicsGap {
    pub(crate) atomics_total: usize,
    pub(crate) covered: usize,
    pub(crate) atomics_without_rule: Vec<String>,
    pub(crate) rules_without_atomic: Vec<String>,
}

/// SigmaHQ baseline cross-reference: which baseline techniques are uncovered
/// locally, and which local techniques the baseline does not carry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BaselineGap {
    pub(crate) baseline_total: usize,
    pub(crate) covered: usize,
    pub(crate) baseline_not_covered: Vec<String>,
    pub(crate) ahead_of_baseline: Vec<String>,
}

/// Target-list cross-reference: which targeted techniques are uncovered, and
/// which are only covered through a sub-technique rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TargetGap {
    pub(crate) targets_total: usize,
    pub(crate) covered: usize,
    pub(crate) uncovered: Vec<String>,
    pub(crate) covered_via_subtechnique: Vec<String>,
}

/// The full `rule coverage` report document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CoverageReport {
    pub(crate) summary: CoverageSummary,
    pub(crate) techniques: Vec<TechniqueEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) untagged_rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) atomics: Option<AtomicsGap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) baseline: Option<BaselineGap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) targets: Option<TargetGap>,
}
