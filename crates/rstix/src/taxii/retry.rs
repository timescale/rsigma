//! Exponential backoff retry policy.

use std::time::Duration;

/// Retry policy for transient TAXII transport failures.
#[derive(Clone, Debug, PartialEq)]
pub struct RetryPolicy {
    /// Maximum retry attempts after the initial request.
    pub max_attempts: u32,
    /// Initial backoff delay.
    pub initial_delay: Duration,
    /// Maximum delay before one retry, including jitter and a server
    /// `Retry-After`. A `Retry-After` longer than this ends the retries.
    pub max_delay: Duration,
    /// Multiplier applied after each attempt.
    pub multiplier: f64,
    /// Random jitter factor in `[0, jitter_factor]`.
    pub jitter_factor: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            multiplier: 2.0,
            jitter_factor: 0.1,
        }
    }
}

impl RetryPolicy {
    /// Delay before retry attempt `attempt` (1-based), never above `max_delay`.
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let exp = self
            .multiplier
            .powi(i32::try_from(attempt.saturating_sub(1)).unwrap_or(i32::MAX));
        let base_ms = self.initial_delay.as_millis() as f64 * exp;
        let jittered = if self.jitter_factor > 0.0 {
            let frac = (attempt as f64 * 0.37).fract() * self.jitter_factor;
            base_ms * (1.0 + frac)
        } else {
            base_ms
        };
        let max_ms = self.max_delay.as_millis() as f64;
        if jittered.is_nan() {
            return Duration::ZERO;
        }
        Duration::from_millis(jittered.clamp(0.0, max_ms) as u64).min(self.max_delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_never_exceeds_max_delay() {
        let policy = RetryPolicy {
            max_attempts: u32::MAX,
            initial_delay: Duration::from_secs(10),
            max_delay: Duration::from_secs(30),
            multiplier: 10.0,
            jitter_factor: 1.0,
        };
        for attempt in [1, 2, 3, 30, u32::MAX] {
            assert!(policy.delay_for_attempt(attempt) <= policy.max_delay);
        }
    }

    #[test]
    fn degenerate_multipliers_stay_in_range() {
        for multiplier in [f64::NAN, f64::INFINITY, -2.0, 0.0] {
            let policy = RetryPolicy {
                multiplier,
                ..RetryPolicy::default()
            };
            for attempt in [1, 2, 64] {
                assert!(policy.delay_for_attempt(attempt) <= policy.max_delay);
            }
        }
    }

    #[test]
    fn first_attempt_uses_initial_delay() {
        let policy = RetryPolicy {
            jitter_factor: 0.0,
            ..RetryPolicy::default()
        };
        assert_eq!(policy.delay_for_attempt(1), policy.initial_delay);
        assert_eq!(policy.delay_for_attempt(2), policy.initial_delay * 2);
    }
}
