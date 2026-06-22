//! Fuse the inputs into one per-rule [`ScorecardRecord`] keyed by `rule_id`.
//!
//! The canonical record set comes from the #46 backtest report's per-rule
//! stats (the authoritative `rule_id`/title/fires source). Coverage enriches
//! each record's ATT&CK context by `rule_title` (the #47 report identifies
//! covering rules by title), the Prometheus snapshot adds production volume by
//! `rule_title` (summing and flagging colliding titles), and the triage feed
//! adds the live false-positive ratio and latency by `rule_id`. Every cell
//! records which input supplied it, and an absent optional input degrades the
//! record rather than blocking it.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::inputs::{MetricsData, TriageIndex, unix_to_rfc3339};
use super::verdict::{self, Thresholds, Verdict, VerdictInput};
use crate::commands::reports::{BacktestReport, CoverageReport, LogSourceView};

/// Which input supplied a given cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Source {
    Backtest,
    Coverage,
    Metrics,
    Triage,
}

/// Per-cell provenance so an operator can tell corpus-derived numbers from
/// production-derived ones at a glance.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct Provenance {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) precision_proxy: Option<Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recall: Option<Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fp_signal: Option<Source>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) volume: Vec<Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) last_fired: Option<Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mttd: Option<Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mttr: Option<Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) live_fp_ratio: Option<Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) attack: Option<Source>,
}

/// ATT&CK context attached from the coverage report.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct AttackContext {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) techniques: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) tactics: Vec<String>,
    pub(crate) sole_coverage: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) sole_techniques: Vec<String>,
}

/// One fused per-rule scorecard row.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ScorecardRecord {
    pub(crate) rule_id: String,
    pub(crate) rule_title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) logsource: Option<LogSourceView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) precision_proxy: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recall: Option<f64>,
    pub(crate) fp_signal: u64,
    pub(crate) corpus_volume: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) production_volume: Option<u64>,
    pub(crate) volume: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) last_fired: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mttd_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mttr_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) live_fp_ratio: Option<f64>,
    pub(crate) attack: AttackContext,
    /// Set when two rules share this `rule_title` and a Prometheus counter was
    /// joined on it, so the production volume is the colliding sum.
    pub(crate) title_collision: bool,
    pub(crate) verdict: Verdict,
    pub(crate) reason: String,
    pub(crate) provenance: Provenance,
}

/// The coverage report projected into the lookups the join needs.
struct CoverageIndex {
    /// `rule_title` -> (techniques, tactics) it appears under.
    by_title: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)>,
    /// `rule_title` -> techniques for which it is the only covering rule.
    sole_by_title: BTreeMap<String, Vec<String>>,
}

impl CoverageIndex {
    fn build(coverage: &CoverageReport) -> Self {
        let mut by_title: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
        let mut sole_by_title: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for t in &coverage.techniques {
            for title in &t.rules {
                let entry = by_title.entry(title.clone()).or_default();
                entry.0.insert(t.id.clone());
                for tactic in &t.tactics {
                    entry.1.insert(tactic.clone());
                }
            }
            // A technique covered by exactly one rule makes that rule its sole
            // coverage; never silently retire it.
            if t.rule_count == 1
                && let Some(title) = t.rules.first()
            {
                sole_by_title
                    .entry(title.clone())
                    .or_default()
                    .push(t.id.clone());
            }
        }
        Self {
            by_title,
            sole_by_title,
        }
    }
}

/// Fuse the inputs into the per-rule records. `now_unix` is the reference time
/// for staleness; it is a parameter so the fusion is deterministic in tests.
pub(crate) fn fuse(
    backtest: &BacktestReport,
    coverage: &CoverageReport,
    metrics: Option<&MetricsData>,
    triage: Option<&TriageIndex>,
    thresholds: &Thresholds,
    now_unix: i64,
) -> Vec<ScorecardRecord> {
    let coverage_idx = CoverageIndex::build(coverage);

    // Per-rule corpus false-positive signal (unexpected fires) and expectation
    // pass/total, keyed the same way the backtest accumulator keys results.
    let fp_by_key: BTreeMap<&str, u64> = backtest
        .unexpected
        .iter()
        .map(|u| (u.rule_key.as_str(), u.fires))
        .collect();
    let mut exp_by_key: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for e in &backtest.expectations {
        let entry = exp_by_key.entry(e.rule_key.as_str()).or_insert((0, 0));
        entry.1 += 1;
        if e.pass {
            entry.0 += 1;
        }
    }

    // Count how many records will share each title, to flag the Prometheus
    // title-collision case.
    let mut title_counts: BTreeMap<&str, u32> = BTreeMap::new();
    for r in &backtest.rules {
        *title_counts.entry(r.rule_title.as_str()).or_insert(0) += 1;
    }

    let mut records: Vec<ScorecardRecord> = backtest
        .rules
        .iter()
        .map(|rule| {
            let key = rule
                .rule_id
                .clone()
                .unwrap_or_else(|| rule.rule_title.clone());
            let title = &rule.rule_title;

            let corpus_volume = rule.fires;
            let fp_signal = fp_by_key.get(key.as_str()).copied().unwrap_or(0);
            let tp = corpus_volume.saturating_sub(fp_signal);
            let precision_proxy = (corpus_volume > 0).then(|| tp as f64 / corpus_volume as f64);
            let recall = exp_by_key
                .get(key.as_str())
                .filter(|(_, total)| *total > 0)
                .map(|(passed, total)| *passed as f64 / *total as f64);

            // Coverage enrichment (joined by title).
            let mut attack = AttackContext::default();
            if let Some((techniques, tactics)) = coverage_idx.by_title.get(title) {
                attack.techniques = techniques.iter().cloned().collect();
                attack.tactics = tactics.iter().cloned().collect();
            }
            if let Some(sole) = coverage_idx.sole_by_title.get(title) {
                attack.sole_techniques = sole.clone();
                attack.sole_coverage = !sole.is_empty();
            }

            // Metrics enrichment (joined by title, collisions summed upstream).
            let production_volume = metrics.and_then(|m| m.by_title.get(title).copied());
            let last_fired_unix = metrics.and_then(|m| m.last_fired.get(title).copied());
            let title_collision = production_volume.is_some()
                && title_counts.get(title.as_str()).copied().unwrap_or(0) > 1;

            // Triage enrichment (joined by rule_id).
            let triage_entry = triage.and_then(|t| t.get(&key));
            let live_fp_ratio = triage_entry.and_then(|e| e.effective_fp_ratio());
            let mttd_seconds = triage_entry.and_then(|e| e.mttd_seconds);
            let mttr_seconds = triage_entry.and_then(|e| e.mttr_seconds);

            let volume = corpus_volume + production_volume.unwrap_or(0);
            let last_fired_age_days =
                last_fired_unix.map(|ts| ((now_unix - ts).max(0) / 86_400) as u64);

            let outcome = verdict::decide(
                &VerdictInput {
                    precision_proxy,
                    volume,
                    live_fp_ratio,
                    last_fired_age_days,
                    sole_coverage: attack.sole_coverage,
                    sole_techniques: attack.sole_techniques.clone(),
                },
                thresholds,
            );

            let mut provenance = Provenance {
                fp_signal: Some(Source::Backtest),
                volume: vec![Source::Backtest],
                ..Default::default()
            };
            if precision_proxy.is_some() {
                provenance.precision_proxy = Some(Source::Backtest);
            }
            if recall.is_some() {
                provenance.recall = Some(Source::Backtest);
            }
            if production_volume.is_some() {
                provenance.volume.push(Source::Metrics);
            }
            if !attack.techniques.is_empty() {
                provenance.attack = Some(Source::Coverage);
            }
            if last_fired_unix.is_some() {
                provenance.last_fired = Some(Source::Metrics);
            }
            if mttd_seconds.is_some() {
                provenance.mttd = Some(Source::Triage);
            }
            if mttr_seconds.is_some() {
                provenance.mttr = Some(Source::Triage);
            }
            if live_fp_ratio.is_some() {
                provenance.live_fp_ratio = Some(Source::Triage);
            }

            ScorecardRecord {
                rule_id: key,
                rule_title: title.clone(),
                level: rule.level.clone(),
                logsource: rule.logsource.clone(),
                precision_proxy,
                recall,
                fp_signal,
                corpus_volume,
                production_volume,
                volume,
                last_fired: last_fired_unix.map(unix_to_rfc3339),
                mttd_seconds,
                mttr_seconds,
                live_fp_ratio,
                attack,
                title_collision,
                verdict: outcome.verdict,
                reason: outcome.reason,
                provenance,
            }
        })
        .collect();

    // Stable order for golden output and deterministic rendering.
    records.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    records
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::reports::{
        BacktestReport, BacktestSummary, CoverageReport, CoverageSummary, RuleStat, TechniqueEntry,
        UnexpectedStat,
    };

    fn thresholds() -> Thresholds {
        Thresholds {
            min_precision: 0.80,
            tune_max_precision: 0.50,
            retire_max_precision: 0.10,
            min_volume: 1,
            stale_window_days: 30,
            max_fp_ratio: 0.50,
        }
    }

    fn rule(id: &str, title: &str, fires: u64) -> RuleStat {
        RuleStat {
            rule_id: Some(id.to_string()),
            rule_title: title.to_string(),
            level: Some("high".to_string()),
            logsource: None,
            fires,
            by_file: Default::default(),
        }
    }

    fn backtest(rules: Vec<RuleStat>, unexpected: Vec<UnexpectedStat>) -> BacktestReport {
        BacktestReport {
            summary: BacktestSummary {
                corpus_files: 1,
                events_processed: 1,
                rules_loaded: rules.len() as u64,
                expectations_total: 0,
                expectations_passed: 0,
                expectations_failed: 0,
                unexpected_rules: unexpected.len() as u64,
                unexpected_fires: unexpected.iter().map(|u| u.fires).sum(),
                unexpected_policy: "warn".to_string(),
                duration_ms: 0,
            },
            expectations: Vec::new(),
            rules,
            unexpected,
            by_logsource: Vec::new(),
        }
    }

    fn coverage(techniques: Vec<TechniqueEntry>) -> CoverageReport {
        CoverageReport {
            summary: CoverageSummary {
                rules_total: 0,
                rules_tagged: 0,
                rules_untagged: 0,
                techniques: techniques.len(),
                subtechniques: 0,
                tactics: 0,
            },
            techniques,
            untagged_rules: Vec::new(),
            atomics: None,
            baseline: None,
            targets: None,
        }
    }

    #[test]
    fn clean_expected_rule_keeps_with_backtest_provenance() {
        let bt = backtest(vec![rule("id-keep", "Keep Me", 10)], Vec::new());
        let cov = coverage(Vec::new());
        let records = fuse(&bt, &cov, None, None, &thresholds(), 0);
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.precision_proxy, Some(1.0));
        assert_eq!(r.verdict, Verdict::Keep);
        assert_eq!(r.provenance.precision_proxy, Some(Source::Backtest));
        // No metrics, so production volume is absent and volume is corpus-only.
        assert_eq!(r.production_volume, None);
        assert_eq!(r.volume, 10);
    }

    #[test]
    fn unexpected_rule_has_zero_precision_and_retires() {
        let bt = backtest(
            vec![rule("id-fp", "Noisy", 4)],
            vec![UnexpectedStat {
                rule_key: "id-fp".to_string(),
                rule_title: "Noisy".to_string(),
                level: Some("low".to_string()),
                logsource: None,
                fires: 4,
            }],
        );
        let cov = coverage(Vec::new());
        let records = fuse(&bt, &cov, None, None, &thresholds(), 0);
        let r = &records[0];
        assert_eq!(r.fp_signal, 4);
        assert_eq!(r.precision_proxy, Some(0.0));
        assert_eq!(r.verdict, Verdict::Retire);
    }

    #[test]
    fn sole_coverage_keeps_a_noisy_rule_as_tune() {
        let bt = backtest(
            vec![rule("id-sole", "Only Cover", 4)],
            vec![UnexpectedStat {
                rule_key: "id-sole".to_string(),
                rule_title: "Only Cover".to_string(),
                level: None,
                logsource: None,
                fires: 4,
            }],
        );
        // One technique, covered by exactly one rule (this one) -> sole coverage.
        let cov = coverage(vec![TechniqueEntry {
            id: "T1059".to_string(),
            tactics: vec!["execution".to_string()],
            rule_count: 1,
            rules: vec!["Only Cover".to_string()],
        }]);
        let records = fuse(&bt, &cov, None, None, &thresholds(), 0);
        let r = &records[0];
        assert!(r.attack.sole_coverage);
        assert_eq!(r.attack.sole_techniques, vec!["T1059".to_string()]);
        // Would be retire (precision 0) but the sole-coverage guard downgrades it.
        assert_eq!(r.verdict, Verdict::Tune);
        assert!(r.reason.contains("sole ATT&CK coverage"));
    }

    #[test]
    fn metrics_join_sums_collided_titles_and_flags() {
        // Two distinct rule ids share the title "Dup".
        let bt = backtest(
            vec![rule("id-a", "Dup", 0), rule("id-b", "Dup", 0)],
            Vec::new(),
        );
        let cov = coverage(Vec::new());
        let mut metrics = MetricsData::default();
        metrics.by_title.insert("Dup".to_string(), 12);
        let records = fuse(&bt, &cov, Some(&metrics), None, &thresholds(), 0);
        for r in &records {
            assert!(r.title_collision, "{} should be flagged", r.rule_id);
            // Both records pick up the colliding sum as production volume.
            assert_eq!(r.production_volume, Some(12));
            assert!(r.provenance.volume.contains(&Source::Metrics));
        }
    }

    #[test]
    fn triage_enriches_by_rule_id_and_can_force_tune() {
        let bt = backtest(vec![rule("id-live", "Live", 10)], Vec::new());
        let cov = coverage(Vec::new());
        let mut triage: TriageIndex = TriageIndex::new();
        triage.insert(
            "id-live".to_string(),
            super::super::inputs::TriageEntry {
                rule_id: "id-live".to_string(),
                true_positives: Some(2),
                false_positives: Some(8),
                fp_ratio: None,
                mttd_seconds: Some(1800.0),
                mttr_seconds: Some(3600.0),
            },
        );
        let records = fuse(&bt, &cov, None, Some(&triage), &thresholds(), 0);
        let r = &records[0];
        assert_eq!(r.live_fp_ratio, Some(0.8));
        assert_eq!(r.mttd_seconds, Some(1800.0));
        assert_eq!(r.provenance.live_fp_ratio, Some(Source::Triage));
        // Clean corpus precision (1.0) but a live FP ratio of 0.8 forces a tune.
        assert_eq!(r.verdict, Verdict::Tune);
    }

    #[test]
    fn missing_metrics_degrades_without_blocking() {
        let bt = backtest(vec![rule("id", "R", 5)], Vec::new());
        let cov = coverage(Vec::new());
        let records = fuse(&bt, &cov, None, None, &thresholds(), 0);
        let r = &records[0];
        assert_eq!(r.production_volume, None);
        assert!(r.last_fired.is_none());
        assert_eq!(r.provenance.volume, vec![Source::Backtest]);
    }
}
