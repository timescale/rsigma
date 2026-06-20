//! Live event-tap capture for the daemon.
//!
//! A [`TapRegistry`] holds the set of active capture sessions. The engine hot
//! path ([`LogProcessor::process_batch_with_format`]) loads the registry once
//! per batch through an `ArcSwap` and, while at least one session is active,
//! offers each event to the matching sessions with a non-blocking `try_send`.
//! Delivery never blocks the engine: a full session channel drops the event
//! and bumps a per-session counter, so a slow streaming client can never apply
//! backpressure to detection.
//!
//! This module only captures and fans events out to bounded per-session
//! channels. Redaction, serialization, and HTTP streaming live in the CLI, so
//! the runtime stays free of the hashing and transport dependencies.
//!
//! [`LogProcessor::process_batch_with_format`]: crate::LogProcessor::process_batch_with_format

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use tokio::sync::mpsc;

/// Which point on the decode path a session captures from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapStage {
    /// The raw input line as received, before parsing. Captures every
    /// non-empty line, including lines that fail to parse.
    Raw,
    /// The decoded event the engine evaluated (post-parse, post-event-filter),
    /// serialized to JSON.
    Decoded,
}

/// One captured item handed to a session's streaming task.
#[derive(Debug)]
pub enum TapPayload {
    /// A raw input line (`raw` stage).
    Raw(String),
    /// A decoded event serialized to JSON (`decoded` stage).
    Decoded(Box<serde_json::Value>),
}

/// A single active capture session: a stage filter plus a bounded channel into
/// the streaming task, with capture / drop counters shared with the handle
/// that owns the receiving end.
pub(crate) struct TapSession {
    id: u64,
    pub(crate) stage: TapStage,
    tx: mpsc::Sender<TapPayload>,
    captured: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

impl TapSession {
    /// Offer one payload without ever blocking. On a full or closed channel
    /// the payload is dropped and the drop counter is bumped, so the engine
    /// never waits on a slow consumer.
    pub(crate) fn offer(&self, payload: TapPayload) {
        match self.tx.try_send(payload) {
            Ok(()) => {
                self.captured.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Handle returned to the streaming task on a successful
/// [`TapRegistry::register`]. Owns the receiving end of the session channel
/// and deregisters the session from the registry on drop, so a dropped client
/// connection tears the session down automatically and stops the hot path from
/// offering to a dead session.
pub struct TapSessionHandle {
    id: u64,
    registry: Arc<TapRegistry>,
    /// Receiving end of the session channel; the streaming task drains it.
    pub rx: mpsc::Receiver<TapPayload>,
    /// Events successfully queued for this session (delivered to the channel).
    pub captured: Arc<AtomicU64>,
    /// Events dropped because the session channel was full.
    pub dropped: Arc<AtomicU64>,
}

impl Drop for TapSessionHandle {
    fn drop(&mut self) {
        self.registry.deregister(self.id);
    }
}

/// The set of active capture sessions plus the daemon-wide tap limits.
///
/// Created once at daemon startup when the tap is enabled and installed on the
/// [`LogProcessor`](crate::LogProcessor) through
/// [`set_event_tap`](crate::LogProcessor::set_event_tap). Shared via `Arc`:
/// the engine hot path reads the active-session snapshot, while the CLI
/// session manager registers and deregisters sessions.
pub struct TapRegistry {
    buffer_events: usize,
    max_sessions: usize,
    max_duration: Duration,
    next_id: AtomicU64,
    /// Authoritative session list, guarded for add/remove.
    sessions: Mutex<Vec<Arc<TapSession>>>,
    /// Wait-free snapshot the hot path loads once per batch.
    snapshot: ArcSwap<Vec<Arc<TapSession>>>,
}

impl TapRegistry {
    /// Build an empty registry with the given per-session channel capacity,
    /// concurrent-session cap, and maximum capture window.
    pub fn new(buffer_events: usize, max_sessions: usize, max_duration: Duration) -> Arc<Self> {
        Arc::new(Self {
            buffer_events: buffer_events.max(1),
            max_sessions,
            max_duration,
            next_id: AtomicU64::new(0),
            sessions: Mutex::new(Vec::new()),
            snapshot: ArcSwap::from_pointee(Vec::new()),
        })
    }

    /// Largest capture window the daemon will honor (the `duration` query
    /// param is rejected above this).
    pub fn max_duration(&self) -> Duration {
        self.max_duration
    }

    /// Number of currently-active sessions.
    pub fn active_sessions(&self) -> usize {
        self.snapshot.load().len()
    }

    /// Register a new session for `stage`. Returns `None` when the active
    /// session count is already at the configured cap (the caller maps this to
    /// a `409`).
    pub fn register(self: &Arc<Self>, stage: TapStage) -> Option<TapSessionHandle> {
        let mut sessions = self.sessions.lock();
        if sessions.len() >= self.max_sessions {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(self.buffer_events);
        let captured = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        sessions.push(Arc::new(TapSession {
            id,
            stage,
            tx,
            captured: captured.clone(),
            dropped: dropped.clone(),
        }));
        self.publish(&sessions);
        Some(TapSessionHandle {
            id,
            registry: self.clone(),
            rx,
            captured,
            dropped,
        })
    }

    fn deregister(&self, id: u64) {
        let mut sessions = self.sessions.lock();
        let before = sessions.len();
        sessions.retain(|s| s.id != id);
        if sessions.len() != before {
            self.publish(&sessions);
        }
    }

    fn publish(&self, sessions: &[Arc<TapSession>]) {
        self.snapshot.store(Arc::new(sessions.to_vec()));
    }

    /// Wait-free snapshot of the active sessions for one batch. The hot path
    /// loads this once and reuses it for every line and event in the batch.
    pub(crate) fn sessions_snapshot(&self) -> arc_swap::Guard<Arc<Vec<Arc<TapSession>>>> {
        self.snapshot.load()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_respects_session_cap() {
        let reg = TapRegistry::new(8, 2, Duration::from_secs(30));
        let a = reg.register(TapStage::Decoded);
        let b = reg.register(TapStage::Raw);
        assert!(a.is_some());
        assert!(b.is_some());
        assert_eq!(reg.active_sessions(), 2);
        assert!(reg.register(TapStage::Decoded).is_none(), "third over cap");
    }

    #[tokio::test]
    async fn dropping_handle_deregisters_session() {
        let reg = TapRegistry::new(8, 2, Duration::from_secs(30));
        let handle = reg.register(TapStage::Decoded).expect("registered");
        assert_eq!(reg.active_sessions(), 1);
        drop(handle);
        assert_eq!(reg.active_sessions(), 0);
        // A slot freed up, so a new session registers.
        assert!(reg.register(TapStage::Raw).is_some());
    }

    #[tokio::test]
    async fn offer_delivers_until_full_then_drops() {
        let reg = TapRegistry::new(2, 1, Duration::from_secs(30));
        let handle = reg.register(TapStage::Raw).expect("registered");
        let snapshot = reg.sessions_snapshot();
        let session = &snapshot[0];

        session.offer(TapPayload::Raw("a".into()));
        session.offer(TapPayload::Raw("b".into()));
        // Channel capacity is 2; the third is dropped, not blocked.
        session.offer(TapPayload::Raw("c".into()));

        assert_eq!(handle.captured.load(Ordering::Relaxed), 2);
        assert_eq!(handle.dropped.load(Ordering::Relaxed), 1);
    }
}
