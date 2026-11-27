use std::collections::{HashMap, HashSet, VecDeque};

use rsigma_parser::{ConditionExpr, CorrelationType, WindowMode};
use serde::Serialize;

use super::CompiledCondition;

// =============================================================================
// Window State
// =============================================================================

/// Per-group mutable state within a time window.
///
/// Each variant matches the type of aggregation being performed. Every deque
/// is kept ordered by timestamp whatever the arrival order, so the front holds
/// the oldest entry and the back the newest.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub enum WindowState {
    /// For `event_count`: timestamps of matching events.
    EventCount { timestamps: VecDeque<i64> },
    /// For `value_count`: (timestamp, field_value) pairs.
    ValueCount { entries: VecDeque<(i64, String)> },
    /// For `temporal` / `temporal_ordered`: rule_ref -> list of hit timestamps.
    Temporal {
        rule_hits: HashMap<String, VecDeque<i64>>,
    },
    /// For `value_sum`, `value_avg`, `value_percentile`, `value_median`:
    /// (timestamp, numeric_value) pairs.
    NumericAgg { entries: VecDeque<(i64, f64)> },
}

impl WindowState {
    /// Create a new empty window state for the given correlation type.
    pub fn new_for(corr_type: CorrelationType) -> Self {
        match corr_type {
            CorrelationType::EventCount => WindowState::EventCount {
                timestamps: VecDeque::new(),
            },
            CorrelationType::ValueCount => WindowState::ValueCount {
                entries: VecDeque::new(),
            },
            CorrelationType::Temporal | CorrelationType::TemporalOrdered => WindowState::Temporal {
                rule_hits: HashMap::new(),
            },
            CorrelationType::ValueSum
            | CorrelationType::ValueAvg
            | CorrelationType::ValuePercentile
            | CorrelationType::ValueMedian => WindowState::NumericAgg {
                entries: VecDeque::new(),
            },
        }
    }

    /// Remove all entries older than the cutoff timestamp.
    pub fn evict(&mut self, cutoff: i64) {
        match self {
            WindowState::EventCount { timestamps } => {
                while timestamps.front().is_some_and(|&t| t < cutoff) {
                    timestamps.pop_front();
                }
            }
            WindowState::ValueCount { entries } => {
                while entries.front().is_some_and(|(t, _)| *t < cutoff) {
                    entries.pop_front();
                }
            }
            WindowState::Temporal { rule_hits } => {
                for timestamps in rule_hits.values_mut() {
                    while timestamps.front().is_some_and(|&t| t < cutoff) {
                        timestamps.pop_front();
                    }
                }
                // Remove empty rule entries
                rule_hits.retain(|_, ts| !ts.is_empty());
            }
            WindowState::NumericAgg { entries } => {
                while entries.front().is_some_and(|(t, _)| *t < cutoff) {
                    entries.pop_front();
                }
            }
        }
    }

    /// Returns true if this state has no entries.
    pub fn is_empty(&self) -> bool {
        match self {
            WindowState::EventCount { timestamps } => timestamps.is_empty(),
            WindowState::ValueCount { entries } => entries.is_empty(),
            WindowState::Temporal { rule_hits } => rule_hits.is_empty(),
            WindowState::NumericAgg { entries } => entries.is_empty(),
        }
    }

    /// Returns the most recent timestamp in this window, or `None` if empty.
    pub fn latest_timestamp(&self) -> Option<i64> {
        match self {
            WindowState::EventCount { timestamps } => timestamps.back().copied(),
            WindowState::ValueCount { entries } => entries.back().map(|(t, _)| *t),
            WindowState::Temporal { rule_hits } => {
                rule_hits.values().filter_map(|ts| ts.back().copied()).max()
            }
            WindowState::NumericAgg { entries } => entries.back().map(|(t, _)| *t),
        }
    }

    /// Returns the oldest timestamp in this window, or `None` if empty.
    ///
    /// For temporal state the minimum is taken across all per-rule deques.
    pub fn earliest_timestamp(&self) -> Option<i64> {
        match self {
            WindowState::EventCount { timestamps } => timestamps.front().copied(),
            WindowState::ValueCount { entries } => entries.front().map(|(t, _)| *t),
            WindowState::Temporal { rule_hits } => rule_hits
                .values()
                .filter_map(|ts| ts.front().copied())
                .min(),
            WindowState::NumericAgg { entries } => entries.front().map(|(t, _)| *t),
        }
    }

    /// Enforce a per-group entry cap by dropping the oldest entries.
    ///
    /// `cap` is the maximum number of retained entries (clamped to at least
    /// 1). For temporal state the cap applies to each referenced rule's hit
    /// deque independently, since the deques are what grow with event rate.
    ///
    /// When `preserve_front` is set (session windows), the oldest entry is
    /// kept and truncation happens behind it: the front entry anchors the
    /// session's total-span cap (`timespan`), so dropping it would silently
    /// let the session extend past the cap. Truncation can only under-count;
    /// it never extends a window.
    pub fn truncate_oldest(&mut self, cap: usize, preserve_front: bool) {
        let cap = cap.max(1);

        fn truncate_deque<T>(deque: &mut VecDeque<T>, cap: usize, preserve_front: bool) {
            if deque.len() <= cap {
                return;
            }
            if preserve_front {
                let anchor = deque.pop_front().expect("len > cap >= 1");
                // Keep the anchor plus the newest cap - 1 entries.
                let excess = deque.len() - (cap - 1);
                deque.drain(..excess);
                deque.push_front(anchor);
            } else {
                let excess = deque.len() - cap;
                deque.drain(..excess);
            }
        }

        match self {
            WindowState::EventCount { timestamps } => {
                truncate_deque(timestamps, cap, preserve_front);
            }
            WindowState::ValueCount { entries } => {
                truncate_deque(entries, cap, preserve_front);
            }
            WindowState::Temporal { rule_hits } => {
                for timestamps in rule_hits.values_mut() {
                    truncate_deque(timestamps, cap, preserve_front);
                }
            }
            WindowState::NumericAgg { entries } => {
                truncate_deque(entries, cap, preserve_front);
            }
        }
    }

    /// Clear all entries from the window state (used by `CorrelationAction::Reset`).
    pub fn clear(&mut self) {
        match self {
            WindowState::EventCount { timestamps } => timestamps.clear(),
            WindowState::ValueCount { entries } => entries.clear(),
            WindowState::Temporal { rule_hits } => rule_hits.clear(),
            WindowState::NumericAgg { entries } => entries.clear(),
        }
    }

    /// Record an event_count hit.
    pub fn push_event_count(&mut self, ts: i64) {
        if let WindowState::EventCount { timestamps } = self {
            insert_ordered(timestamps, ts, |&t| t);
        }
    }

    /// Record a value_count hit with the field value.
    pub fn push_value_count(&mut self, ts: i64, value: String) {
        if let WindowState::ValueCount { entries } = self {
            insert_ordered(entries, (ts, value), |(t, _)| *t);
        }
    }

    /// Record a temporal hit for a specific rule reference.
    pub fn push_temporal(&mut self, ts: i64, rule_ref: &str) {
        if let WindowState::Temporal { rule_hits } = self {
            let hits = match rule_hits.get_mut(rule_ref) {
                Some(hits) => hits,
                None => rule_hits.entry(rule_ref.to_string()).or_default(),
            };
            insert_ordered(hits, ts, |&t| t);
        }
    }

    /// Record a numeric aggregation value.
    pub fn push_numeric(&mut self, ts: i64, value: f64) {
        if let WindowState::NumericAgg { entries } = self {
            insert_ordered(entries, (ts, value), |(t, _)| *t);
        }
    }

    /// Bring restored state in line with what live processing produces:
    /// drop entries after `drop_after`, clamp entries after `clamp_to` down to
    /// it, and order every deque by timestamp. State from an older release or
    /// another host may break any of these.
    pub(crate) fn bound_restored(&mut self, clamp_to: i64, drop_after: i64) {
        fn bound<T>(
            deque: &mut VecDeque<T>,
            clamp_to: i64,
            drop_after: i64,
            ts_mut: impl Fn(&mut T) -> &mut i64,
            ts: impl Fn(&T) -> i64,
        ) {
            deque.retain_mut(|entry| {
                let t = ts_mut(entry);
                if *t > drop_after {
                    return false;
                }
                *t = (*t).min(clamp_to);
                true
            });
            deque.make_contiguous().sort_by_key(ts);
        }

        match self {
            WindowState::EventCount { timestamps } => {
                bound(timestamps, clamp_to, drop_after, |t| t, |&t| t);
            }
            WindowState::ValueCount { entries } => {
                bound(entries, clamp_to, drop_after, |(t, _)| t, |(t, _)| *t);
            }
            WindowState::Temporal { rule_hits } => {
                for hits in rule_hits.values_mut() {
                    bound(hits, clamp_to, drop_after, |t| t, |&t| t);
                }
                rule_hits.retain(|_, hits| !hits.is_empty());
            }
            WindowState::NumericAgg { entries } => {
                bound(entries, clamp_to, drop_after, |(t, _)| t, |(t, _)| *t);
            }
        }
    }

    /// Evaluate the window state against the correlation condition.
    ///
    /// Returns `Some(aggregated_value)` if the condition is satisfied,
    /// `None` otherwise.
    ///
    /// For temporal correlations with an extended expression, the expression
    /// is evaluated against the set of rules that have fired in the window.
    pub fn check_condition(
        &self,
        condition: &CompiledCondition,
        corr_type: CorrelationType,
        rule_refs: &[String],
        extended_expr: Option<&ConditionExpr>,
    ) -> Option<f64> {
        let value = match (self, corr_type) {
            (WindowState::EventCount { timestamps }, CorrelationType::EventCount) => {
                timestamps.len() as f64
            }
            (WindowState::ValueCount { entries }, CorrelationType::ValueCount) => {
                // Count distinct values
                let distinct: HashSet<&String> = entries.iter().map(|(_, v)| v).collect();
                distinct.len() as f64
            }
            (WindowState::Temporal { rule_hits }, CorrelationType::Temporal) => {
                // If an extended expression is provided, evaluate it
                if let Some(expr) = extended_expr {
                    if eval_temporal_expr(expr, rule_hits) {
                        return Some(count_fired_rules(rule_refs, rule_hits) as f64);
                    } else {
                        return None;
                    }
                }
                count_fired_rules(rule_refs, rule_hits) as f64
            }
            (WindowState::Temporal { rule_hits }, CorrelationType::TemporalOrdered) => {
                // If an extended expression is provided, evaluate it first
                if let Some(expr) = extended_expr
                    && !eval_temporal_expr(expr, rule_hits)
                {
                    return None;
                }
                // Check if all referenced rules fired in order
                if check_temporal_ordered(rule_refs, rule_hits) {
                    count_distinct_rules(rule_refs) as f64
                } else {
                    0.0
                }
            }
            (WindowState::NumericAgg { entries }, CorrelationType::ValueSum) => {
                entries.iter().map(|(_, v)| v).sum()
            }
            (WindowState::NumericAgg { entries }, CorrelationType::ValueAvg) => {
                if entries.is_empty() {
                    0.0
                } else {
                    let sum: f64 = entries.iter().map(|(_, v)| v).sum();
                    sum / entries.len() as f64
                }
            }
            (WindowState::NumericAgg { entries }, CorrelationType::ValuePercentile) => {
                // The value at the condition's percentile rank (0-100), by
                // linear interpolation; the predicates then apply to it.
                window_percentile(entries, condition.percentile)?
            }
            (WindowState::NumericAgg { entries }, CorrelationType::ValueMedian) => {
                // An empty window has no median. Returning `0.0` here would
                // spuriously satisfy predicates like `lte: 0` or `eq: 0`, so
                // match the percentile branch and skip evaluation.
                window_median(entries)?
            }
            _ => return None, // mismatched state/type
        };

        if condition.check(value) {
            Some(value)
        } else {
            None
        }
    }
}

impl WindowState {
    /// Number of retained entries in this window. For temporal state this is
    /// the total across all per-rule hit deques.
    pub fn entry_count(&self) -> usize {
        match self {
            WindowState::EventCount { timestamps } => timestamps.len(),
            WindowState::ValueCount { entries } => entries.len(),
            WindowState::Temporal { rule_hits } => rule_hits.values().map(VecDeque::len).sum(),
            WindowState::NumericAgg { entries } => entries.len(),
        }
    }

    /// Compute the current aggregate value for this window *without* applying
    /// the correlation's threshold condition.
    ///
    /// Unlike [`check_condition`](WindowState::check_condition), which returns
    /// `None` when the threshold is not met, this returns the raw "got" value
    /// the introspection surface reports so an operator can see the gap to the
    /// threshold. Returns `None` only when no value is defined (an empty
    /// percentile/median window, or a state/type mismatch).
    pub fn current_value(
        &self,
        corr_type: CorrelationType,
        rule_refs: &[String],
        percentile: Option<u64>,
    ) -> Option<f64> {
        match (self, corr_type) {
            (WindowState::EventCount { timestamps }, CorrelationType::EventCount) => {
                Some(timestamps.len() as f64)
            }
            (WindowState::ValueCount { entries }, CorrelationType::ValueCount) => {
                let distinct: HashSet<&String> = entries.iter().map(|(_, v)| v).collect();
                Some(distinct.len() as f64)
            }
            (
                WindowState::Temporal { rule_hits },
                CorrelationType::Temporal | CorrelationType::TemporalOrdered,
            ) => Some(count_fired_rules(rule_refs, rule_hits) as f64),
            (WindowState::NumericAgg { entries }, CorrelationType::ValueSum) => {
                Some(entries.iter().map(|(_, v)| v).sum())
            }
            (WindowState::NumericAgg { entries }, CorrelationType::ValueAvg) => {
                if entries.is_empty() {
                    Some(0.0)
                } else {
                    let sum: f64 = entries.iter().map(|(_, v)| v).sum();
                    Some(sum / entries.len() as f64)
                }
            }
            (WindowState::NumericAgg { entries }, CorrelationType::ValuePercentile) => {
                window_percentile(entries, percentile)
            }
            (WindowState::NumericAgg { entries }, CorrelationType::ValueMedian) => {
                window_median(entries)
            }
            _ => None,
        }
    }
}

/// Insert `entry` at its timestamp's position, after any entry with the same
/// timestamp. An in-order arrival appends in O(1).
fn insert_ordered<T>(deque: &mut VecDeque<T>, entry: T, ts: impl Fn(&T) -> i64) {
    let t = ts(&entry);
    if deque.back().is_none_or(|last| ts(last) <= t) {
        deque.push_back(entry);
    } else {
        let pos = deque.partition_point(|e| ts(e) <= t);
        deque.insert(pos, entry);
    }
}

/// Oldest timestamp a sliding window keeps when an event at `ts` arrives.
///
/// The window ends at the newer of `ts` and the group's newest entry, so a
/// late arrival neither stretches the window past `timespan_secs` nor keeps
/// entries the newest one has already aged out.
pub fn sliding_cutoff(state: &WindowState, ts: i64, timespan_secs: u64) -> i64 {
    let end = state.latest_timestamp().map_or(ts, |latest| latest.max(ts));
    end - timespan_secs as i64
}

/// Start of the tumbling bucket that contains `ts`, aligned to epoch.
///
/// Uses `rem_euclid` so negative timestamps align to the bucket below them
/// rather than toward zero.
fn bucket_start(ts: i64, timespan: i64) -> i64 {
    ts - ts.rem_euclid(timespan)
}

/// Outcome of a window's pre-insert maintenance for a new event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowDecision {
    /// The current window continues; push the event into it.
    Extend,
    /// The window rolled over and the state was cleared; push the event into
    /// the fresh window. Callers must also clear any associated event buffers
    /// so they stay in sync with the state.
    Reset,
    /// The event predates the current window (older than a sliding window's
    /// start, in an earlier tumbling bucket, or in a session that already
    /// closed); do not push it and leave the state untouched.
    Discard,
}

/// Apply a correlation window's pre-insert maintenance for a new event at `ts`,
/// before the event is pushed into `state`.
///
/// - `Sliding` evicts entries older than [`sliding_cutoff`] and discards the
///   event when it is older than that too.
/// - `Tumbling` resets the window when `ts` falls in a *later*
///   boundary-aligned bucket than the newest retained entry, and discards
///   events that fall in an *earlier* bucket (a late arrival must not wipe the
///   active bucket's accumulation).
/// - `Session` resets when `ts` is more than `gap` after the newest entry, or
///   when extending would push the total span past `timespan` (the hard cap).
///   An event before the session start joins it only when it is within `gap`
///   of the start and keeps the span under the cap; otherwise it belongs to a
///   closed session and is discarded.
///
/// Out-of-order arrivals are decided against the group's retained entries,
/// whose newest timestamp never moves backwards. The engine bounds event
/// timestamps by the wall clock before they get here, so no entry is anchored
/// in the future.
pub fn apply_window_open(
    state: &mut WindowState,
    ts: i64,
    timespan_secs: u64,
    window: WindowMode,
    gap_secs: Option<u64>,
) -> WindowDecision {
    let timespan = timespan_secs as i64;
    match window {
        WindowMode::Sliding => {
            let cutoff = sliding_cutoff(state, ts, timespan_secs);
            state.evict(cutoff);
            if ts < cutoff {
                WindowDecision::Discard
            } else {
                WindowDecision::Extend
            }
        }
        WindowMode::Tumbling => {
            if timespan <= 0 {
                return WindowDecision::Extend;
            }
            match state.latest_timestamp() {
                Some(last) if bucket_start(ts, timespan) > bucket_start(last, timespan) => {
                    state.clear();
                    WindowDecision::Reset
                }
                Some(last) if bucket_start(ts, timespan) < bucket_start(last, timespan) => {
                    WindowDecision::Discard
                }
                _ => WindowDecision::Extend,
            }
        }
        WindowMode::Session => {
            // `gap` is required for session windows; fall back to `timespan` if
            // it is somehow absent so the window still has a bound.
            let gap = gap_secs.map(|g| g as i64).unwrap_or(timespan);
            let capped = |span: i64| timespan > 0 && span > timespan;
            match (state.earliest_timestamp(), state.latest_timestamp()) {
                (Some(start), Some(last)) if ts >= last => {
                    if (ts - last) > gap || capped(ts - start) {
                        state.clear();
                        WindowDecision::Reset
                    } else {
                        WindowDecision::Extend
                    }
                }
                (Some(start), Some(last)) if ts < start => {
                    if (start - ts) > gap || capped(last - ts) {
                        WindowDecision::Discard
                    } else {
                        WindowDecision::Extend
                    }
                }
                _ => WindowDecision::Extend,
            }
        }
    }
}

/// Number of distinct rule references, so a rule listed twice in `rules`
/// counts once.
fn count_distinct_rules(rule_refs: &[String]) -> usize {
    rule_refs.iter().collect::<HashSet<_>>().len()
}

/// Number of distinct referenced rules with at least one hit in the window.
fn count_fired_rules(rule_refs: &[String], rule_hits: &HashMap<String, VecDeque<i64>>) -> usize {
    rule_refs
        .iter()
        .filter(|r| rule_hits.get(r.as_str()).is_some_and(|ts| !ts.is_empty()))
        .collect::<HashSet<_>>()
        .len()
}

/// Check if all referenced rules fired in the correct order within the window.
///
/// For `temporal_ordered`, each rule must have at least one hit, and there
/// must exist a sequence of timestamps (one per rule) that is non-decreasing
/// and follows the rule ordering.
///
/// Taking the earliest hit at or after the previous rule's choice is enough:
/// any valid sequence can swap in that earlier hit and stay valid, so the
/// check is one pass over each rule's hits.
pub(super) fn check_temporal_ordered(
    rule_refs: &[String],
    rule_hits: &HashMap<String, VecDeque<i64>>,
) -> bool {
    let mut previous = i64::MIN;
    for rule_ref in rule_refs {
        let earliest = rule_hits
            .get(rule_ref.as_str())
            .and_then(|hits| hits.iter().copied().filter(|&ts| ts >= previous).min());
        match earliest {
            Some(ts) => previous = ts,
            None => return false,
        }
    }
    true
}

/// Evaluate a boolean condition expression against the set of rules that have
/// fired within the temporal window.
///
/// Each `Identifier` in the expression is treated as a rule reference — it's
/// `true` if that rule has at least one hit in `rule_hits`.
pub(super) fn eval_temporal_expr(
    expr: &ConditionExpr,
    rule_hits: &HashMap<String, VecDeque<i64>>,
) -> bool {
    match expr {
        ConditionExpr::Identifier(name) => rule_hits
            .get(name.as_str())
            .is_some_and(|ts| !ts.is_empty()),
        ConditionExpr::And(children) => children.iter().all(|c| eval_temporal_expr(c, rule_hits)),
        ConditionExpr::Or(children) => children.iter().any(|c| eval_temporal_expr(c, rule_hits)),
        ConditionExpr::Not(child) => !eval_temporal_expr(child, rule_hits),
        ConditionExpr::Selector { .. } => {
            // Selectors are not meaningful for temporal condition evaluation
            false
        }
    }
}

/// The window's finite values, in arrival order.
fn finite_values(entries: &VecDeque<(i64, f64)>) -> Vec<f64> {
    entries
        .iter()
        .map(|(_, v)| *v)
        .filter(|v| v.is_finite())
        .collect()
}

/// Value at `percentile` (default 50) across the window's finite values, or
/// `None` when there are none.
fn window_percentile(entries: &VecDeque<(i64, f64)>, percentile: Option<u64>) -> Option<f64> {
    let mut values = finite_values(entries);
    if values.is_empty() {
        return None;
    }
    let rank = percentile.map(|p| p as f64).unwrap_or(50.0);
    Some(percentile_linear_interp(&mut values, rank))
}

/// Median of the window's finite values, averaging the two middle values for
/// an even count, or `None` when there are none.
fn window_median(entries: &VecDeque<(i64, f64)>) -> Option<f64> {
    let mut values = finite_values(entries);
    let n = values.len();
    if n == 0 {
        return None;
    }
    let (below, &mut upper, _) = values.select_nth_unstable_by(n / 2, f64::total_cmp);
    if n.is_multiple_of(2) {
        let lower = below.iter().copied().max_by(f64::total_cmp)?;
        Some((lower + upper) / 2.0)
    } else {
        Some(upper)
    }
}

/// Compute the value at a given percentile rank using linear interpolation.
///
/// Returns 0.0 if `values` is empty. `values` may be in any order and is
/// partially reordered in place, which keeps this O(n) on average instead of
/// a full sort per evaluation.
/// `percentile` is from 0.0 to 100.0.
pub(super) fn percentile_linear_interp(values: &mut [f64], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let n = values.len();
    if n == 1 {
        return values[0];
    }

    // Clamp percentile to [0, 100]
    let p = percentile.clamp(0.0, 100.0) / 100.0;

    // Use the "C = 1" interpolation method (most common in statistics)
    // rank = p * (n - 1)
    let rank = p * (n - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    let fraction = rank - lower as f64;

    let (_, &mut low, above) = values.select_nth_unstable_by(lower.min(n - 1), f64::total_cmp);
    if lower == upper || upper >= n {
        low
    } else {
        // `above` holds every value ordered after `low`, so its minimum is
        // the next value in sorted order.
        let high = above.iter().copied().min_by(f64::total_cmp).unwrap_or(low);
        low + fraction * (high - low)
    }
}
