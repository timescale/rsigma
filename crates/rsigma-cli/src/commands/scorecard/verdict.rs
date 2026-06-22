//! The keep/tune/retire verdict engine.
//!
//! Bands default to the SOC quality-metrics thresholds (the hackforlab
//! detection-quality writeup) and are fully configurable through flags and the
//! `scorecard` config section. The engine takes a primitive [`VerdictInput`] so
//! it stays decoupled from the fuse step and is exhaustively unit-testable; the
//! sole-ATT&CK-coverage guard downgrades a retire candidate to tune so the
//! program never silently drops the only rule covering a technique.

use serde::{Deserialize, Serialize};

/// The keep/tune/retire decision for a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Verdict {
    Keep,
    Tune,
    Retire,
}

impl Verdict {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Verdict::Keep => "keep",
            Verdict::Tune => "tune",
            Verdict::Retire => "retire",
        }
    }

    /// Severity rank for `--fail-on` comparison: keep `0`, tune `1`, retire `2`.
    fn rank(self) -> u8 {
        match self {
            Verdict::Keep => 0,
            Verdict::Tune => 1,
            Verdict::Retire => 2,
        }
    }
}

/// Configurable verdict thresholds (defaults from `config::defaults`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Thresholds {
    /// Keep floor: precision proxy at or above this keeps the rule.
    pub(crate) min_precision: f64,
    /// Upper edge of the core review band, used in the tune reason.
    pub(crate) tune_max_precision: f64,
    /// Retire floor: precision proxy strictly below this retires the rule.
    pub(crate) retire_max_precision: f64,
    /// Minimum total volume for a keep verdict.
    pub(crate) min_volume: u64,
    /// Staleness window in days; a rule whose last-fired is older is not kept
    /// (only enforced when last-fired is known, i.e. from a range query).
    pub(crate) stale_window_days: u64,
    /// Live false-positive-ratio ceiling; a rule above it is at best tuned.
    pub(crate) max_fp_ratio: f64,
}

/// The primitive signal the verdict engine reasons over, assembled by the fuse
/// step from the fused [`super::fuse::ScorecardRecord`].
#[derive(Debug, Clone)]
pub(crate) struct VerdictInput {
    /// Corpus precision proxy (`tp / (tp + fp)`), `None` when the rule produced
    /// no corpus signal at all.
    pub(crate) precision_proxy: Option<f64>,
    /// Total volume across the backtest corpus and the metrics window.
    pub(crate) volume: u64,
    /// Live false-positive ratio from the triage feed, when present.
    pub(crate) live_fp_ratio: Option<f64>,
    /// Age in days since the rule last fired, when a range query supplied it.
    pub(crate) last_fired_age_days: Option<u64>,
    /// Whether this rule is the sole coverage for at least one ATT&CK technique.
    pub(crate) sole_coverage: bool,
    /// The techniques this rule solely covers (for the coverage-risk note).
    pub(crate) sole_techniques: Vec<String>,
}

/// The verdict plus the human reason recorded on the record.
#[derive(Debug, Clone)]
pub(crate) struct Outcome {
    pub(crate) verdict: Verdict,
    pub(crate) reason: String,
}

/// Decide the verdict for one rule. Priority order: a dead rule (zero volume)
/// and a live false-positive breach are decided first, then the corpus
/// precision bands, then the keep gate (volume and staleness). A retire verdict
/// for the sole cover of a technique is downgraded to tune with a coverage-risk
/// note.
pub(crate) fn decide(input: &VerdictInput, t: &Thresholds) -> Outcome {
    // 1. Dead rule: no fires anywhere. Retire (subject to the sole-coverage guard).
    if input.volume == 0 {
        return guard_sole_coverage(
            Verdict::Retire,
            "no fires across the backtest corpus and the metrics window (dead rule)".to_string(),
            input,
        );
    }

    // 2. Live false-positive ratio over the ceiling: analyst feedback forces a
    //    tune even when the corpus proxy looks healthy.
    if let Some(r) = input.live_fp_ratio
        && r > t.max_fp_ratio
    {
        return Outcome {
            verdict: Verdict::Tune,
            reason: format!(
                "live false-positive ratio {r:.2} exceeds the {:.2} ceiling",
                t.max_fp_ratio
            ),
        };
    }

    // 3. Corpus precision bands.
    match input.precision_proxy {
        Some(p) if p < t.retire_max_precision => guard_sole_coverage(
            Verdict::Retire,
            format!(
                "precision proxy {p:.2} below the {:.2} retire floor",
                t.retire_max_precision
            ),
            input,
        ),
        Some(p) if p < t.min_precision => {
            let band = if p < t.tune_max_precision {
                "review band"
            } else {
                "below the keep floor"
            };
            Outcome {
                verdict: Verdict::Tune,
                reason: format!("precision proxy {p:.2} in the {band}"),
            }
        }
        Some(p) => keep_gate(p, input, t),
        // 4. No corpus precision signal but the rule has volume (e.g. it fires
        //    in production but never on the corpus). Keep only when the live
        //    ratio vouches for it; otherwise tune for review.
        None => {
            if input.live_fp_ratio.is_some_and(|r| r <= t.max_fp_ratio)
                && input.volume >= t.min_volume
                && !is_stale(input, t)
            {
                Outcome {
                    verdict: Verdict::Keep,
                    reason: "no corpus precision signal; kept on a clean live false-positive ratio"
                        .to_string(),
                }
            } else {
                Outcome {
                    verdict: Verdict::Tune,
                    reason: "fires without a corpus precision signal to score; review".to_string(),
                }
            }
        }
    }
}

/// The keep gate applied once a rule clears the keep-floor precision: it must
/// also carry enough volume and have fired recently enough.
fn keep_gate(p: f64, input: &VerdictInput, t: &Thresholds) -> Outcome {
    if input.volume < t.min_volume {
        return Outcome {
            verdict: Verdict::Tune,
            reason: format!(
                "precision proxy {p:.2} is healthy but volume {} is below the {} minimum",
                input.volume, t.min_volume
            ),
        };
    }
    if let Some(age) = input.last_fired_age_days
        && age > t.stale_window_days
    {
        return Outcome {
            verdict: Verdict::Tune,
            reason: format!(
                "precision proxy {p:.2} is healthy but the rule last fired {age}d ago, beyond the {}d window",
                t.stale_window_days
            ),
        };
    }
    Outcome {
        verdict: Verdict::Keep,
        reason: format!(
            "precision proxy {p:.2} at or above the {:.2} keep floor and firing within the window",
            t.min_precision
        ),
    }
}

fn is_stale(input: &VerdictInput, t: &Thresholds) -> bool {
    input
        .last_fired_age_days
        .is_some_and(|age| age > t.stale_window_days)
}

/// Downgrade a retire verdict to tune when the rule is the sole coverage for an
/// ATT&CK technique, appending a coverage-risk note so coverage is never
/// silently dropped. Non-retire verdicts pass through unchanged.
fn guard_sole_coverage(verdict: Verdict, reason: String, input: &VerdictInput) -> Outcome {
    if verdict == Verdict::Retire && input.sole_coverage {
        let techniques = if input.sole_techniques.is_empty() {
            String::new()
        } else {
            format!(" ({})", input.sole_techniques.join(", "))
        };
        return Outcome {
            verdict: Verdict::Tune,
            reason: format!(
                "{reason}; retained as the sole ATT&CK coverage{techniques}, tune rather than retire"
            ),
        };
    }
    Outcome { verdict, reason }
}

/// `--fail-on` policy: which verdicts trip the CI gate (exit `FINDINGS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailOn {
    /// Report only; never fail on verdicts.
    None,
    /// Fail on a tune or a retire verdict.
    Tune,
    /// Fail on a retire verdict only.
    Retire,
}

impl FailOn {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => Some(FailOn::None),
            "tune" => Some(FailOn::Tune),
            "retire" => Some(FailOn::Retire),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            FailOn::None => "none",
            FailOn::Tune => "tune",
            FailOn::Retire => "retire",
        }
    }

    /// Whether `verdict` is at or worse than this policy's threshold.
    pub(crate) fn triggers(self, verdict: Verdict) -> bool {
        match self {
            FailOn::None => false,
            FailOn::Tune => verdict.rank() >= Verdict::Tune.rank(),
            FailOn::Retire => verdict.rank() >= Verdict::Retire.rank(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn input(precision: Option<f64>, volume: u64) -> VerdictInput {
        VerdictInput {
            precision_proxy: precision,
            volume,
            live_fp_ratio: None,
            last_fired_age_days: None,
            sole_coverage: false,
            sole_techniques: Vec::new(),
        }
    }

    #[test]
    fn keep_band_clean_rule() {
        let o = decide(&input(Some(1.0), 10), &thresholds());
        assert_eq!(o.verdict, Verdict::Keep);
    }

    #[test]
    fn tune_review_band() {
        let o = decide(&input(Some(0.30), 10), &thresholds());
        assert_eq!(o.verdict, Verdict::Tune);
        assert!(o.reason.contains("review band"), "{}", o.reason);
    }

    #[test]
    fn tune_below_keep_floor_band() {
        // [tune_max, min_precision) = [0.50, 0.80) -> tune, "below the keep floor".
        let o = decide(&input(Some(0.65), 10), &thresholds());
        assert_eq!(o.verdict, Verdict::Tune);
        assert!(o.reason.contains("below the keep floor"), "{}", o.reason);
    }

    #[test]
    fn retire_below_floor() {
        let o = decide(&input(Some(0.05), 10), &thresholds());
        assert_eq!(o.verdict, Verdict::Retire);
    }

    #[test]
    fn retire_dead_rule_zero_volume() {
        let o = decide(&input(Some(1.0), 0), &thresholds());
        assert_eq!(o.verdict, Verdict::Retire);
        assert!(o.reason.contains("dead rule"), "{}", o.reason);
    }

    #[test]
    fn sole_coverage_downgrades_retire_to_tune() {
        let mut i = input(Some(0.0), 10);
        i.sole_coverage = true;
        i.sole_techniques = vec!["T1059".to_string()];
        let o = decide(&i, &thresholds());
        assert_eq!(o.verdict, Verdict::Tune);
        assert!(o.reason.contains("sole ATT&CK coverage"), "{}", o.reason);
        assert!(o.reason.contains("T1059"), "{}", o.reason);
    }

    #[test]
    fn sole_coverage_downgrades_dead_rule_too() {
        let mut i = input(Some(1.0), 0);
        i.sole_coverage = true;
        i.sole_techniques = vec!["T1003".to_string()];
        let o = decide(&i, &thresholds());
        assert_eq!(o.verdict, Verdict::Tune);
        assert!(o.reason.contains("sole ATT&CK coverage"), "{}", o.reason);
    }

    #[test]
    fn live_fp_ratio_over_ceiling_forces_tune() {
        let mut i = input(Some(1.0), 10);
        i.live_fp_ratio = Some(0.75);
        let o = decide(&i, &thresholds());
        assert_eq!(o.verdict, Verdict::Tune);
        assert!(
            o.reason.contains("live false-positive ratio"),
            "{}",
            o.reason
        );
    }

    #[test]
    fn stale_rule_is_tuned_not_kept() {
        let mut i = input(Some(1.0), 10);
        i.last_fired_age_days = Some(120);
        let o = decide(&i, &thresholds());
        assert_eq!(o.verdict, Verdict::Tune);
        assert!(o.reason.contains("beyond the 30d window"), "{}", o.reason);
    }

    #[test]
    fn no_corpus_signal_with_clean_live_ratio_keeps() {
        let mut i = input(None, 5);
        i.live_fp_ratio = Some(0.1);
        let o = decide(&i, &thresholds());
        assert_eq!(o.verdict, Verdict::Keep);
    }

    #[test]
    fn no_corpus_signal_without_triage_tunes() {
        let o = decide(&input(None, 5), &thresholds());
        assert_eq!(o.verdict, Verdict::Tune);
    }

    #[test]
    fn fail_on_policy_thresholds() {
        assert!(!FailOn::None.triggers(Verdict::Retire));
        assert!(FailOn::Tune.triggers(Verdict::Tune));
        assert!(FailOn::Tune.triggers(Verdict::Retire));
        assert!(!FailOn::Tune.triggers(Verdict::Keep));
        assert!(FailOn::Retire.triggers(Verdict::Retire));
        assert!(!FailOn::Retire.triggers(Verdict::Tune));
    }
}
