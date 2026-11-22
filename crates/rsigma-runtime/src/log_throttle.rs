//! Rate limiting for repeated warnings.
//!
//! [`WarnThrottle`] decides when a caller should emit a warning for a
//! recurring condition and how many occurrences that warning covers. It
//! never logs by itself, so each caller keeps its own `tracing` event, level,
//! and fields.

use std::time::{Duration, Instant};

/// Folds repeated occurrences of one condition into at most one warning per
/// interval. The first occurrence warns at once; later occurrences within
/// the interval are counted and reported by the next warning after it.
#[derive(Debug)]
pub(crate) struct WarnThrottle {
    interval: Duration,
    last_warn: Option<Instant>,
    pending: u64,
}

impl WarnThrottle {
    /// Default gap between two warnings for the same condition.
    pub(crate) const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);

    pub(crate) fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_warn: None,
            pending: 0,
        }
    }

    /// Count one occurrence at `now`. Returns `Some(n)` when the caller
    /// should warn now, where `n` counts the occurrences this warning covers,
    /// the current one included. Returns `None` when the warning is deferred.
    pub(crate) fn record(&mut self, now: Instant) -> Option<u64> {
        self.pending += 1;
        if self
            .last_warn
            .is_some_and(|last| now.saturating_duration_since(last) < self.interval)
        {
            return None;
        }
        self.last_warn = Some(now);
        Some(std::mem::take(&mut self.pending))
    }

    /// Return and reset the count of deferred occurrences.
    pub(crate) fn take_pending(&mut self) -> u64 {
        std::mem::take(&mut self.pending)
    }
}

impl Default for WarnThrottle {
    fn default() -> Self {
        Self::new(Self::DEFAULT_INTERVAL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_record_warns_at_once() {
        let mut throttle = WarnThrottle::default();
        assert_eq!(throttle.record(Instant::now()), Some(1));
    }

    #[test]
    fn records_within_interval_are_deferred() {
        let start = Instant::now();
        let mut throttle = WarnThrottle::new(Duration::from_secs(10));
        assert_eq!(throttle.record(start), Some(1));
        assert_eq!(throttle.record(start + Duration::from_secs(1)), None);
        assert_eq!(throttle.record(start + Duration::from_secs(9)), None);
    }

    #[test]
    fn first_record_after_interval_carries_deferred_count() {
        let start = Instant::now();
        let mut throttle = WarnThrottle::new(Duration::from_secs(10));
        assert_eq!(throttle.record(start), Some(1));
        assert_eq!(throttle.record(start + Duration::from_secs(2)), None);
        assert_eq!(throttle.record(start + Duration::from_secs(3)), None);
        assert_eq!(throttle.record(start + Duration::from_secs(10)), Some(3));
        assert_eq!(throttle.record(start + Duration::from_secs(11)), None);
        assert_eq!(throttle.record(start + Duration::from_secs(25)), Some(2));
    }

    #[test]
    fn take_pending_returns_deferred_count_then_zero() {
        let start = Instant::now();
        let mut throttle = WarnThrottle::new(Duration::from_secs(10));
        assert_eq!(throttle.take_pending(), 0);
        throttle.record(start);
        throttle.record(start + Duration::from_secs(1));
        throttle.record(start + Duration::from_secs(2));
        assert_eq!(throttle.take_pending(), 2);
        assert_eq!(throttle.take_pending(), 0);
    }

    #[test]
    fn take_pending_does_not_reset_the_interval() {
        let start = Instant::now();
        let mut throttle = WarnThrottle::new(Duration::from_secs(10));
        throttle.record(start);
        throttle.record(start + Duration::from_secs(1));
        assert_eq!(throttle.take_pending(), 1);
        assert_eq!(throttle.record(start + Duration::from_secs(2)), None);
        assert_eq!(throttle.record(start + Duration::from_secs(10)), Some(2));
    }
}
