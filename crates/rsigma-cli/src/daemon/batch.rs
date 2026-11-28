use rsigma_runtime::{EventSource, RawEvent, StdinReadStatus};

use crate::exit_code;

use super::health::HealthState;
use super::server::{DaemonConfig, StdinMode};

impl DaemonConfig {
    /// Whether this run reads stdin to end of input and exits with the batch
    /// result. Stdin is the only input that ends on its own.
    pub(crate) fn runs_batch(&self) -> bool {
        matches!(self.input.as_str(), "stdin" | "stdin://") && self.stdin_mode == StdinMode::Batch
    }
}

/// Ends a stdin source the way `--stdin-mode` asks.
///
/// At the end of input a stream-mode source is held open, so the daemon keeps
/// running until a shutdown signal instead of exiting. A read error is never
/// held: it marks the daemon not ready and ends the source, so the pipeline
/// drains and the daemon exits with a runtime error.
pub(crate) struct StdinInput<S> {
    source: Option<S>,
    status: StdinReadStatus,
    hold_open: bool,
    health: HealthState,
}

impl<S> StdinInput<S> {
    pub(crate) fn new(
        source: S,
        status: StdinReadStatus,
        mode: StdinMode,
        health: HealthState,
    ) -> Self {
        Self {
            source: Some(source),
            status,
            hold_open: mode == StdinMode::Stream,
            health,
        }
    }
}

impl<S: EventSource> EventSource for StdinInput<S> {
    async fn recv(&mut self) -> Option<RawEvent> {
        if let Some(source) = &mut self.source {
            if let Some(event) = source.recv().await {
                return Some(event);
            }
            self.source = None;
            if self.status.failed() {
                self.health.set_input_failed();
                tracing::error!("Stdin input failed; draining and exiting");
                return None;
            }
            if !self.hold_open {
                return None;
            }
            tracing::info!("Stdin input ended; waiting for a shutdown signal");
        }
        if self.hold_open && !self.status.failed() {
            std::future::pending().await
        } else {
            None
        }
    }
}

/// Refuse to start a stdin run whose stored state cannot be restored. Nothing
/// has been written to the database at this point, so the stored snapshot is
/// left untouched for inspection or for a later `--clear-state` run.
pub(crate) fn exit_unrestorable(store: &'static str, reason: &str) -> ! {
    tracing::error!(
        store,
        reason,
        "Stored state cannot be restored; pass --clear-state to start fresh"
    );
    std::process::exit(exit_code::CONFIG_ERROR);
}

/// Log a pipeline task that did not finish normally, and report whether it
/// failed.
pub(crate) fn task_failed<T>(
    task: &'static str,
    joined: Result<T, tokio::task::JoinError>,
) -> bool {
    match joined {
        Ok(_) => false,
        Err(e) => {
            tracing::error!(task, error = %e, "Daemon task failed");
            true
        }
    }
}

/// Why a stdin batch run did not complete cleanly.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct BatchFailures {
    /// A signal or the API server stopped the run before stdin ended.
    pub interrupted: bool,
    /// The stdin reader stopped on a read error instead of at end of input.
    pub input_read_error: bool,
    /// Entries that reached neither a sink nor the DLQ.
    pub undelivered: u64,
    /// The final state save returned an error.
    pub state_save_failed: bool,
    /// A pipeline task panicked, so events or delivery failures it held were
    /// neither processed nor counted.
    pub task_failed: bool,
}

impl BatchFailures {
    pub(crate) fn is_clean(&self) -> bool {
        !self.interrupted
            && !self.input_read_error
            && self.undelivered == 0
            && !self.state_save_failed
            && !self.task_failed
    }

    pub(crate) fn exit_code(&self) -> i32 {
        if self.is_clean() {
            exit_code::SUCCESS
        } else {
            exit_code::RUNTIME_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rsigma_runtime::AckToken;

    use super::*;

    struct OneEvent(Option<RawEvent>);

    impl EventSource for OneEvent {
        async fn recv(&mut self) -> Option<RawEvent> {
            self.0.take()
        }
    }

    fn one_event() -> OneEvent {
        OneEvent(Some(RawEvent {
            payload: "{}".to_string(),
            ack_token: AckToken::Noop,
            tenant: None,
        }))
    }

    #[tokio::test]
    async fn stream_mode_stays_pending_after_end_of_input() {
        let health = HealthState::new();
        health.set_ready(true);
        let mut source = StdinInput::new(
            one_event(),
            StdinReadStatus::default(),
            StdinMode::Stream,
            health.clone(),
        );
        assert_eq!(source.recv().await.unwrap().payload, "{}");
        let next = tokio::time::timeout(Duration::from_millis(50), source.recv()).await;
        assert!(next.is_err(), "a held source must not report end of input");
        assert!(health.is_ready());
    }

    #[tokio::test]
    async fn batch_mode_ends_at_end_of_input() {
        let mut source = StdinInput::new(
            one_event(),
            StdinReadStatus::default(),
            StdinMode::Batch,
            HealthState::new(),
        );
        assert_eq!(source.recv().await.unwrap().payload, "{}");
        assert!(source.recv().await.is_none());
        assert!(source.recv().await.is_none());
    }

    #[test]
    fn clean_batch_exits_zero() {
        assert_eq!(BatchFailures::default().exit_code(), exit_code::SUCCESS);
    }

    #[test]
    fn each_failure_exits_with_a_runtime_error() {
        let cases = [
            BatchFailures {
                interrupted: true,
                ..BatchFailures::default()
            },
            BatchFailures {
                input_read_error: true,
                ..BatchFailures::default()
            },
            BatchFailures {
                undelivered: 1,
                ..BatchFailures::default()
            },
            BatchFailures {
                state_save_failed: true,
                ..BatchFailures::default()
            },
            BatchFailures {
                task_failed: true,
                ..BatchFailures::default()
            },
        ];
        for failures in cases {
            assert_eq!(failures.exit_code(), exit_code::RUNTIME_ERROR);
        }
    }
}
