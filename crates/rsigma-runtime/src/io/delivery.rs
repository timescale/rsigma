//! Async delivery layer: one bounded queue and worker task per sink.
//!
//! The daemon fans every result into a [`Dispatcher`], which owns one
//! [`SinkWorker`] per leaf sink. Each worker drains its queue sequentially,
//! batches opportunistically, retries with bounded exponential backoff, and
//! routes terminal failures to the DLQ. Acknowledgments use the lifetime of an
//! [`AckGuard`]: each event's ack tokens fire only once every worker has
//! durably committed (delivered or DLQ-parked) the event, so the at-least-once
//! contract survives fan-out.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use rsigma_eval::ProcessResult;

use crate::error::RuntimeError;
use crate::io::{AckToken, Sink};
use crate::metrics::MetricsHook;

type DeliveryFuture<'a> = Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + 'a>>;

/// A sink the delivery layer can drive: deliver one result, identify itself.
///
/// Implemented for the concrete [`crate::io::Sink`] enum; generic so the worker
/// can be unit-tested against a mock without a test-only enum variant.
pub trait DeliverySink: Send + 'static {
    /// Deliver a single result, returning an error the worker may retry.
    fn deliver<'a>(&'a mut self, result: &'a ProcessResult) -> DeliveryFuture<'a>;
    /// Short, stable label used for structured logs and per-sink metrics.
    fn label(&self) -> &'static str;
}

impl DeliverySink for Sink {
    fn deliver<'a>(&'a mut self, result: &'a ProcessResult) -> DeliveryFuture<'a> {
        self.send(result)
    }
    fn label(&self) -> &'static str {
        self.kind_label()
    }
}

/// Behavior when a worker's bounded queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnFull {
    /// Block the dispatcher until the queue drains. Preserves at-least-once,
    /// but a stalled sink eventually backpressures the whole pipeline.
    Block,
    /// Drop the result and increment a counter. Best-effort (at-most-once),
    /// but never stalls the pipeline.
    Drop,
}

/// Per-sink delivery tuning. Public so the CLI can build it from config.
#[derive(Debug, Clone, Copy)]
pub struct DeliveryConfig {
    /// Bounded queue capacity between the dispatcher and the worker.
    pub queue_depth: usize,
    /// Maximum results drained into one worker batch.
    pub batch_max: usize,
    /// Maximum time a partial batch waits before flushing (reserved for
    /// batch-oriented sinks; the Phase 1 sinks deliver per result).
    pub batch_flush: Duration,
    /// Maximum retries after the first attempt before routing to the DLQ.
    pub retry_max: u32,
    /// Base backoff for the first retry.
    pub backoff_base: Duration,
    /// Backoff ceiling.
    pub backoff_max: Duration,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        DeliveryConfig {
            queue_depth: 1024,
            batch_max: 64,
            batch_flush: Duration::from_millis(50),
            retry_max: 3,
            backoff_base: Duration::from_millis(100),
            backoff_max: Duration::from_secs(5),
        }
    }
}

/// A result that could not be delivered after exhausting retries.
///
/// Emitted to the DLQ channel; the CLI wraps it into its own DLQ record so the
/// runtime stays free of CLI types.
pub struct DeliveryFailure {
    /// The serialized `ProcessResult` that failed to deliver.
    pub serialized: String,
    /// Human-readable failure reason (the last transport error).
    pub error: String,
}

/// Holds an event's ack tokens until every worker has committed it.
///
/// The dispatcher clones one `Arc<AckGuard>` into each worker's queue item.
/// When the last clone drops (all workers committed, or dropped under
/// `OnFull::Drop`), `Drop` forwards the tokens to the ack channel. An
/// un-flushed worker at shutdown still holds its clone, so the tokens never
/// fire and the source redelivers, preserving at-least-once.
struct AckGuard {
    tokens: Mutex<Vec<AckToken>>,
    ack_tx: mpsc::UnboundedSender<AckToken>,
}

impl Drop for AckGuard {
    fn drop(&mut self) {
        let tokens = std::mem::take(&mut *self.tokens.lock());
        for token in tokens {
            // Unbounded and non-blocking: acks are cheap and the number of
            // in-flight guards is bounded by the worker queues. A closed
            // receiver (daemon shutting down) drops the token, which simply
            // means no ack, i.e. the source redelivers.
            let _ = self.ack_tx.send(token);
        }
    }
}

/// One unit of work handed to a worker: a shared result plus the shared ack
/// guard whose lifetime gates the ack.
struct DeliveryItem {
    result: Arc<ProcessResult>,
    _guard: Arc<AckGuard>,
}

/// Handle to a spawned per-sink worker task.
struct SinkWorker {
    tx: mpsc::Sender<DeliveryItem>,
    handle: JoinHandle<()>,
    on_full: OnFull,
    label: &'static str,
    metrics: Arc<dyn MetricsHook>,
}

impl SinkWorker {
    fn spawn<S: DeliverySink>(
        sink: S,
        on_full: OnFull,
        cfg: DeliveryConfig,
        dlq_tx: Option<mpsc::Sender<DeliveryFailure>>,
        metrics: Arc<dyn MetricsHook>,
    ) -> Self {
        let label = sink.label();
        metrics.register_sink(label);
        let (tx, rx) = mpsc::channel(cfg.queue_depth.max(1));
        let worker_metrics = metrics.clone();
        let handle = tokio::spawn(worker_loop(sink, rx, cfg, dlq_tx, worker_metrics, label));
        SinkWorker {
            tx,
            handle,
            on_full,
            label,
            metrics,
        }
    }

    /// Enqueue an item, honoring the full-queue policy. Returns whether the
    /// item was accepted (always true under `Block` unless the worker is gone).
    async fn enqueue(&self, item: DeliveryItem) {
        match self.on_full {
            OnFull::Block => {
                self.metrics.on_sink_queue_depth_change(self.label, 1);
                if self.tx.send(item).await.is_err() {
                    // Worker gone: undo the depth bump. The guard clone in
                    // `item` drops here, contributing to the ack-join.
                    self.metrics.on_sink_queue_depth_change(self.label, -1);
                }
            }
            OnFull::Drop => match self.tx.try_send(item) {
                Ok(()) => self.metrics.on_sink_queue_depth_change(self.label, 1),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Dropped: the item's guard clone drops here, so the ack
                    // still fires (best-effort for this lossy sink).
                    self.metrics.on_sink_dropped(self.label);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            },
        }
    }
}

/// Drives every sink for the daemon output path.
pub struct Dispatcher {
    workers: Vec<SinkWorker>,
    ack_tx: mpsc::UnboundedSender<AckToken>,
}

impl Dispatcher {
    /// Spawn one worker per leaf sink, each with its own full-queue policy.
    /// `sinks` should already be flattened to leaves (see
    /// [`crate::io::Sink::into_leaves`]); `cfg` holds the shared retry/backoff/
    /// batch/queue tuning.
    pub fn spawn<S: DeliverySink>(
        sinks: Vec<(S, OnFull)>,
        cfg: DeliveryConfig,
        dlq_tx: Option<mpsc::Sender<DeliveryFailure>>,
        ack_tx: mpsc::UnboundedSender<AckToken>,
        metrics: Arc<dyn MetricsHook>,
    ) -> Self {
        let workers = sinks
            .into_iter()
            .map(|(sink, on_full)| {
                SinkWorker::spawn(sink, on_full, cfg, dlq_tx.clone(), metrics.clone())
            })
            .collect();
        Dispatcher { workers, ack_tx }
    }

    /// Fan one result and its ack tokens into every worker. Awaits queue space
    /// for `Block` sinks; never blocks for `Drop` sinks.
    pub async fn dispatch(&self, result: ProcessResult, tokens: Vec<AckToken>) {
        if self.workers.is_empty() {
            for token in tokens {
                let _ = self.ack_tx.send(token);
            }
            return;
        }
        let guard = Arc::new(AckGuard {
            tokens: Mutex::new(tokens),
            ack_tx: self.ack_tx.clone(),
        });
        let result = Arc::new(result);
        for worker in &self.workers {
            worker
                .enqueue(DeliveryItem {
                    result: result.clone(),
                    _guard: guard.clone(),
                })
                .await;
        }
    }

    /// Close every worker queue and await drain. The caller bounds this with
    /// the drain timeout; un-drained items stay unacked so the source
    /// redelivers them on restart.
    pub async fn shutdown(self) {
        let mut handles = Vec::with_capacity(self.workers.len());
        for worker in self.workers {
            handles.push(worker.handle);
            // Dropping `worker.tx` (via `worker` going out of scope) closes the
            // queue; the worker drains remaining items, then exits.
        }
        drop(self.ack_tx);
        for handle in handles {
            let _ = handle.await;
        }
    }
}

async fn worker_loop<S: DeliverySink>(
    mut sink: S,
    mut rx: mpsc::Receiver<DeliveryItem>,
    cfg: DeliveryConfig,
    dlq_tx: Option<mpsc::Sender<DeliveryFailure>>,
    metrics: Arc<dyn MetricsHook>,
    label: &'static str,
) {
    while let Some(first) = rx.recv().await {
        let mut batch = Vec::with_capacity(cfg.batch_max.clamp(1, 64));
        batch.push(first);
        while batch.len() < cfg.batch_max {
            match rx.try_recv() {
                Ok(item) => batch.push(item),
                Err(_) => break,
            }
        }
        metrics.on_sink_queue_depth_change(label, -(batch.len() as i64));
        for item in &batch {
            deliver_one(
                &mut sink,
                &item.result,
                &cfg,
                dlq_tx.as_ref(),
                &metrics,
                label,
            )
            .await;
        }
        // Dropping `batch` drops each item's `Arc<AckGuard>` clone, advancing
        // the ack-join.
        drop(batch);
    }
}

async fn deliver_one<S: DeliverySink>(
    sink: &mut S,
    result: &ProcessResult,
    cfg: &DeliveryConfig,
    dlq_tx: Option<&mpsc::Sender<DeliveryFailure>>,
    metrics: &Arc<dyn MetricsHook>,
    label: &'static str,
) {
    let mut attempt: u32 = 0;
    loop {
        match sink.deliver(result).await {
            Ok(()) => return,
            Err(e) => {
                if attempt >= cfg.retry_max {
                    metrics.on_sink_delivery_failed(label);
                    match dlq_tx {
                        Some(dlq) => {
                            let serialized = serde_json::to_string(result).unwrap_or_default();
                            let _ = dlq
                                .send(DeliveryFailure {
                                    serialized,
                                    error: format!("sink delivery failure: {e}"),
                                })
                                .await;
                        }
                        None => {
                            tracing::warn!(
                                sink = label,
                                error = %e,
                                "Sink delivery failed after retries and no DLQ is configured; dropping result",
                            );
                        }
                    }
                    return;
                }
                attempt += 1;
                metrics.on_sink_retry(label);
                let delay = backoff_delay(cfg.backoff_base, cfg.backoff_max, attempt);
                tracing::debug!(sink = label, attempt, error = %e, "Sink delivery retry");
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// Capped exponential backoff. `attempt` is 1 for the first retry.
fn backoff_delay(base: Duration, max: Duration, attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(20);
    let factor: u32 = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
    base.checked_mul(factor).unwrap_or(max).min(max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::metrics::NoopMetrics;

    fn noop_metrics() -> Arc<dyn MetricsHook> {
        Arc::new(NoopMetrics)
    }

    /// One empty `ProcessResult`. The delivery layer treats results opaquely,
    /// so content is irrelevant to the queue/retry/ack mechanics under test.
    fn result() -> ProcessResult {
        Vec::new()
    }

    fn fast_cfg() -> DeliveryConfig {
        DeliveryConfig {
            queue_depth: 64,
            batch_max: 16,
            batch_flush: Duration::from_millis(1),
            retry_max: 5,
            backoff_base: Duration::from_millis(1),
            backoff_max: Duration::from_millis(5),
        }
    }

    /// Configurable mock sink: fail the first `fail_first` deliveries, then
    /// succeed; optionally gate on a notify; record successful deliveries.
    struct MockSink {
        label: &'static str,
        fail_first: Arc<AtomicUsize>,
        always_fail: bool,
        delivered: Arc<AtomicUsize>,
        // A latching gate: deliveries block until the watch value is `true`,
        // after which every delivery (including later ones) proceeds. A plain
        // `Notify` would only wake waiters parked at the instant it fires.
        gate: Option<tokio::sync::watch::Receiver<bool>>,
    }

    impl MockSink {
        fn new(label: &'static str) -> Self {
            MockSink {
                label,
                fail_first: Arc::new(AtomicUsize::new(0)),
                always_fail: false,
                delivered: Arc::new(AtomicUsize::new(0)),
                gate: None,
            }
        }
    }

    impl DeliverySink for MockSink {
        fn deliver<'a>(&'a mut self, _result: &'a ProcessResult) -> DeliveryFuture<'a> {
            let fail_first = self.fail_first.clone();
            let delivered = self.delivered.clone();
            let always_fail = self.always_fail;
            let gate = self.gate.clone();
            Box::pin(async move {
                if let Some(mut rx) = gate {
                    loop {
                        if *rx.borrow() {
                            break;
                        }
                        if rx.changed().await.is_err() {
                            break;
                        }
                    }
                }
                if always_fail {
                    return Err(RuntimeError::Io(std::io::Error::other("mock always fails")));
                }
                if fail_first.load(Ordering::SeqCst) > 0 {
                    fail_first.fetch_sub(1, Ordering::SeqCst);
                    return Err(RuntimeError::Io(std::io::Error::other("mock transient")));
                }
                delivered.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
        fn label(&self) -> &'static str {
            self.label
        }
    }

    #[tokio::test]
    async fn delivers_and_acks_single_sink() {
        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel();
        let sink = MockSink::new("mock");
        let delivered = sink.delivered.clone();
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block)],
            fast_cfg(),
            None,
            ack_tx,
            noop_metrics(),
        );

        for _ in 0..10 {
            dispatcher.dispatch(result(), vec![AckToken::Noop]).await;
        }
        dispatcher.shutdown().await;

        assert_eq!(delivered.load(Ordering::SeqCst), 10);
        let mut acks = 0;
        while ack_rx.try_recv().is_ok() {
            acks += 1;
        }
        assert_eq!(acks, 10, "every dispatched event must be acked");
    }

    #[tokio::test]
    async fn retries_then_succeeds() {
        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel();
        let (dlq_tx, mut dlq_rx) = mpsc::channel(8);
        let sink = MockSink::new("mock");
        sink.fail_first.store(3, Ordering::SeqCst); // < retry_max (5)
        let delivered = sink.delivered.clone();
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block)],
            fast_cfg(),
            Some(dlq_tx),
            ack_tx,
            noop_metrics(),
        );

        dispatcher.dispatch(result(), vec![AckToken::Noop]).await;
        dispatcher.shutdown().await;

        assert_eq!(delivered.load(Ordering::SeqCst), 1, "eventually delivered");
        assert!(ack_rx.try_recv().is_ok(), "acked after success");
        assert!(
            dlq_rx.try_recv().is_err(),
            "no DLQ entry on eventual success"
        );
    }

    #[tokio::test]
    async fn terminal_failure_routes_to_dlq_and_acks() {
        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel();
        let (dlq_tx, mut dlq_rx) = mpsc::channel(8);
        let mut sink = MockSink::new("mock");
        sink.always_fail = true;
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block)],
            fast_cfg(),
            Some(dlq_tx),
            ack_tx,
            noop_metrics(),
        );

        dispatcher.dispatch(result(), vec![AckToken::Noop]).await;
        dispatcher.shutdown().await;

        let failure = dlq_rx.try_recv().expect("terminal failure routed to DLQ");
        assert!(failure.error.contains("sink delivery failure"));
        assert!(
            ack_rx.try_recv().is_ok(),
            "token acked after DLQ parking (matches prior behavior)",
        );
    }

    #[tokio::test]
    async fn ack_join_waits_for_all_sinks() {
        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel();
        let (gate_tx, gate_rx) = tokio::sync::watch::channel(false);
        let fast = MockSink::new("fast");
        let mut slow = MockSink::new("slow");
        slow.gate = Some(gate_rx);

        let dispatcher = Dispatcher::spawn(
            vec![(fast, OnFull::Block), (slow, OnFull::Block)],
            fast_cfg(),
            None,
            ack_tx,
            noop_metrics(),
        );
        dispatcher.dispatch(result(), vec![AckToken::Noop]).await;

        // The fast sink delivered, but the slow sink is gated, so the guard
        // still has a live clone and the ack must not have fired yet.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            ack_rx.try_recv().is_err(),
            "ack must wait for the slow sink"
        );

        gate_tx.send(true).unwrap();
        // Allow the slow worker to complete and drop its guard clone.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            ack_rx.try_recv().is_ok(),
            "ack fires once every sink confirms",
        );
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn drop_on_full_never_blocks_and_still_acks() {
        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel();
        let (gate_tx, gate_rx) = tokio::sync::watch::channel(false);
        let mut sink = MockSink::new("lossy");
        sink.gate = Some(gate_rx);
        let cfg = DeliveryConfig {
            queue_depth: 1,
            ..fast_cfg()
        };
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Drop)],
            cfg,
            None,
            ack_tx,
            noop_metrics(),
        );

        // Dispatch far more than the queue can hold while the sink is gated;
        // dispatch must not block.
        for _ in 0..50 {
            dispatcher.dispatch(result(), vec![AckToken::Noop]).await;
        }
        gate_tx.send(true).unwrap();
        dispatcher.shutdown().await;

        // Every event is acked exactly once whether delivered or dropped.
        let mut acks = 0;
        while ack_rx.try_recv().is_ok() {
            acks += 1;
        }
        assert_eq!(acks, 50, "lossy sink still acks every event (best-effort)");
    }

    #[test]
    fn backoff_is_capped_and_exponential() {
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(5);
        assert_eq!(backoff_delay(base, max, 1), Duration::from_millis(100));
        assert_eq!(backoff_delay(base, max, 2), Duration::from_millis(200));
        assert_eq!(backoff_delay(base, max, 3), Duration::from_millis(400));
        assert_eq!(backoff_delay(base, max, 100), max, "capped at max");
    }
}
