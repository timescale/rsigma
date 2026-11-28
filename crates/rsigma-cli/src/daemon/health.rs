use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone)]
pub struct HealthState {
    ready: Arc<AtomicBool>,
    /// Set once the input source has stopped on an error. Never cleared, so a
    /// later rule reload cannot report the daemon ready again.
    input_failed: Arc<AtomicBool>,
}

impl HealthState {
    pub fn new() -> Self {
        HealthState {
            ready: Arc::new(AtomicBool::new(false)),
            input_failed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_ready(&self, ready: bool) {
        let previous = self.ready.swap(ready, Ordering::AcqRel);
        if previous != ready {
            tracing::info!(ready, "Readiness state changed");
        }
    }

    /// Record that the input source stopped on an error.
    pub fn set_input_failed(&self) {
        if !self.input_failed.swap(true, Ordering::AcqRel) {
            tracing::info!(
                ready = false,
                "Readiness state changed: the input source failed"
            );
        }
    }

    /// Whether the rules are loaded.
    pub fn rules_loaded(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub fn input_failed(&self) -> bool {
        self.input_failed.load(Ordering::Acquire)
    }

    pub fn is_ready(&self) -> bool {
        self.rules_loaded() && !self.input_failed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_ready_records_transition_correctly() {
        let state = HealthState::new();
        assert!(!state.is_ready());
        state.set_ready(true);
        assert!(state.is_ready());
        // No-op transition: still ready, no panic, no flip.
        state.set_ready(true);
        assert!(state.is_ready());
        state.set_ready(false);
        assert!(!state.is_ready());
    }

    #[test]
    fn a_failed_input_stays_not_ready_across_reloads() {
        let state = HealthState::new();
        state.set_ready(true);
        state.set_input_failed();
        assert!(!state.is_ready());
        assert!(state.rules_loaded());
        state.set_ready(true);
        assert!(
            !state.is_ready(),
            "a reload must not clear the input failure"
        );
    }
}
