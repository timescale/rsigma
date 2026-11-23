//! Async delivery layer: one bounded queue and worker task per sink.
//!
//! The daemon fans every result into a [`Dispatcher`], which owns one
//! [`SinkWorker`] per leaf sink. Each worker drains its queue sequentially,
//! batches opportunistically, retries with bounded exponential backoff, and
//! routes terminal failures to the DLQ channel. Acknowledgments use the
//! lifetime of an [`AckGuard`]: each event's ack tokens fire only once every
//! worker has finished with the event, either delivering it or handing the
//! failure to the DLQ channel, so the at-least-once contract survives fan-out.
//! The ack does not wait for whoever drains the DLQ channel to persist the
//! failure.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use uuid::Uuid;

use rsigma_eval::ProcessResult;

use crate::error::RuntimeError;
use crate::io::{AckToken, FormattedIncidentEnvelope, IncidentEnvelope, Sink};
use crate::metrics::MetricsHook;

type DeliveryFuture<'a> = Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + 'a>>;
pub(crate) type BatchFuture<'a> =
    Pin<Box<dyn Future<Output = Vec<Result<(), RuntimeError>>> + Send + 'a>>;

/// A sink the delivery layer can drive: deliver one result, identify itself.
///
/// Implemented for the concrete [`crate::io::Sink`] enum; generic so the worker
/// can be unit-tested against a mock without a test-only enum variant.
pub trait DeliverySink: Send + 'static {
    /// Deliver a single result, returning an error the worker may retry.
    ///
    /// `ctx` is minted once per queued item and handed back unchanged on every
    /// retry, so a sink that derives request identity from it (e.g. a signed
    /// webhook) reproduces the same id, timestamp, and signature on a re-send.
    fn deliver<'a>(
        &'a mut self,
        result: &'a ProcessResult,
        ctx: &'a DeliveryContext,
    ) -> DeliveryFuture<'a>;
    /// Make the first delivery attempt for a batch of results, returning one
    /// outcome per attempted item, in item order.
    ///
    /// The worker calls this once for each run of results it drains, then
    /// retries every failed item on its own through [`Self::deliver`] with
    /// the same context. A sink that resumes partial deliveries must keep
    /// what each failed item already delivered, so its retry does not repeat
    /// it. A sink may stop early and return fewer outcomes: the items past
    /// the last outcome count as not attempted, and the worker delivers each
    /// on its own once the failed items before it have settled. The default
    /// delivers the items one at a time and stops at the first failure, so
    /// later items wait for its retries and keep their order.
    fn deliver_batch<'a>(
        &'a mut self,
        items: &'a [(&'a ProcessResult, &'a DeliveryContext)],
    ) -> BatchFuture<'a> {
        Box::pin(async move {
            let mut outcomes = Vec::with_capacity(items.len());
            for (result, ctx) in items {
                let outcome = self.deliver(result, ctx).await;
                let failed = outcome.is_err();
                outcomes.push(outcome);
                if failed {
                    break;
                }
            }
            outcomes
        })
    }
    /// Deliver a single incident line. Defaults to a no-op so mock sinks and
    /// any sink that does not carry incidents need no implementation.
    fn deliver_incident<'a>(
        &'a mut self,
        _incident: &'a IncidentEnvelope,
        _ctx: &'a DeliveryContext,
    ) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }
    /// Deliver an incident with one pre-serialized line per sink format.
    fn deliver_formatted_incident<'a>(
        &'a mut self,
        incident: &'a FormattedIncidentEnvelope,
        ctx: &'a DeliveryContext,
    ) -> DeliveryFuture<'a> {
        self.deliver_incident(incident.native(), ctx)
    }
    /// Short, stable label used for structured logs and per-sink metrics.
    fn label(&self) -> &'static str;
}

impl DeliverySink for Sink {
    fn deliver<'a>(
        &'a mut self,
        result: &'a ProcessResult,
        ctx: &'a DeliveryContext,
    ) -> DeliveryFuture<'a> {
        self.send_with_context(result, ctx)
    }
    fn deliver_batch<'a>(
        &'a mut self,
        items: &'a [(&'a ProcessResult, &'a DeliveryContext)],
    ) -> BatchFuture<'a> {
        self.send_batch_with_context(items)
    }
    fn deliver_incident<'a>(
        &'a mut self,
        incident: &'a IncidentEnvelope,
        _ctx: &'a DeliveryContext,
    ) -> DeliveryFuture<'a> {
        self.send_incident(incident)
    }
    fn deliver_formatted_incident<'a>(
        &'a mut self,
        incident: &'a FormattedIncidentEnvelope,
        _ctx: &'a DeliveryContext,
    ) -> DeliveryFuture<'a> {
        self.send_formatted_incident(incident)
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
    /// How long a partial batch waits for more results before it is
    /// delivered. Zero delivers whatever is queued at once.
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
            batch_flush: Duration::ZERO,
            retry_max: 3,
            backoff_base: Duration::from_millis(100),
            backoff_max: Duration::from_secs(5),
        }
    }
}

/// Per-delivery identity, created once per queued item and reused on every
/// retry attempt.
///
/// The worker creates one of these before the retry loop and hands the same
/// reference to the sink on each attempt. A sink that derives request identity
/// from it (today, a signed webhook) therefore reproduces a byte-identical id,
/// timestamp, and signature when a delivery is retried, which is what lets a
/// receiver dedupe redeliveries and enforce a replay window.
///
/// The id and timestamp are computed lazily on first access: most deliveries go
/// to sinks that never read them (stdout, file, NATS, OTLP), so the worker pays
/// no per-item RNG call or allocation unless a sink actually signs. The first
/// access (the first signing attempt) fixes the value, and every retry reuses
/// the same one.
pub struct DeliveryContext {
    seq: u64,
    inner: OnceLock<ContextData>,
    finding_uids: Vec<String>,
}

struct ContextData {
    id_base: String,
    first_attempt: SystemTime,
}

impl DeliveryContext {
    /// Create a context with nothing computed yet. Cheap; no RNG, no syscall.
    pub fn new() -> Self {
        static NEXT_SEQ: AtomicU64 = AtomicU64::new(0);
        DeliveryContext {
            seq: NEXT_SEQ.fetch_add(1, Ordering::Relaxed),
            inner: OnceLock::new(),
            finding_uids: Vec::new(),
        }
    }

    /// The OCSF `finding_info.uid` for the result at `index` of this delivery.
    ///
    /// Stable for the life of the context. A uid pinned with
    /// [`Self::set_finding_uids`] wins; otherwise the uid derives from
    /// [`Self::id_base`] and `index`.
    pub fn finding_uid(&self, index: usize) -> String {
        match self.finding_uids.get(index).filter(|uid| !uid.is_empty()) {
            Some(uid) => uid.clone(),
            None => format!("{}_{index:04}_0", self.id_base()),
        }
    }

    /// Pin the finding uids of the delivered results, index-aligned with the
    /// dispatched `ProcessResult`.
    ///
    /// The daemon mints uids with [`Self::finding_uid`] before the risk layer
    /// and alert pipeline run, so a result keeps its uid when an earlier
    /// result in the batch is folded or silenced away.
    pub fn set_finding_uids(&mut self, finding_uids: Vec<String>) {
        self.finding_uids = finding_uids;
    }

    /// Process-unique number for this delivery, so a sink can recognize a
    /// retry of the delivery it last attempted.
    pub(crate) fn seq(&self) -> u64 {
        self.seq
    }

    fn data(&self) -> &ContextData {
        self.inner.get_or_init(|| ContextData {
            id_base: format!("msg_{}", Uuid::new_v4().simple()),
            first_attempt: SystemTime::now(),
        })
    }

    /// Stable base id for this delivery (`msg_<uuid>`). A sink may append a
    /// per-result suffix to address individual results within one batch.
    pub fn id_base(&self) -> &str {
        &self.data().id_base
    }

    /// Wall-clock time of the first access (the first delivery attempt that
    /// reads the context); used as the signed timestamp.
    pub fn first_attempt(&self) -> SystemTime {
        self.data().first_attempt
    }
}

impl Default for DeliveryContext {
    fn default() -> Self {
        Self::new()
    }
}

/// A result that could not be delivered after exhausting retries.
///
/// Emitted to the DLQ channel; the CLI wraps it into its own DLQ record so the
/// runtime stays free of CLI types. The event is acked once the failure is
/// queued on the channel, so a receiver that drops or fails to persist it
/// loses the result.
pub struct DeliveryFailure {
    /// The serialized `ProcessResult` that failed to deliver.
    pub serialized: String,
    /// Human-readable failure reason (the last transport error).
    pub error: String,
    /// Tenant of the failed result, when tenancy is enabled.
    pub tenant: Option<rsigma_eval::TenantId>,
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

/// The payload of one unit of work: either a result batch or an incident line.
enum DeliveryPayload {
    Result(Arc<ProcessResult>),
    Incident(Arc<IncidentEnvelope>),
    FormattedIncident(Arc<FormattedIncidentEnvelope>),
}

/// One unit of work handed to a worker: a shared payload plus the shared ack
/// guard whose lifetime gates the ack.
struct DeliveryItem {
    payload: DeliveryPayload,
    context: Arc<DeliveryContext>,
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
    /// Spawn one worker per leaf sink, each with its own full-queue policy and
    /// delivery tuning. `sinks` should already be flattened to leaves (see
    /// [`crate::io::Sink::into_leaves`]); each carries its own
    /// [`DeliveryConfig`] so a sink (e.g. a webhook) can override the global
    /// retry/backoff/queue defaults.
    ///
    /// Terminal failures go to `dlq_tx`. With `None`, or once its receiver is
    /// gone, each one is logged at `warn` and dropped.
    pub fn spawn<S: DeliverySink>(
        sinks: Vec<(S, OnFull, DeliveryConfig)>,
        dlq_tx: Option<mpsc::Sender<DeliveryFailure>>,
        ack_tx: mpsc::UnboundedSender<AckToken>,
        metrics: Arc<dyn MetricsHook>,
    ) -> Self {
        let workers = sinks
            .into_iter()
            .map(|(sink, on_full, cfg)| {
                SinkWorker::spawn(sink, on_full, cfg, dlq_tx.clone(), metrics.clone())
            })
            .collect();
        Dispatcher { workers, ack_tx }
    }

    /// Fan one result and its ack tokens into every worker. Awaits queue space
    /// for `Block` sinks; never blocks for `Drop` sinks.
    pub async fn dispatch(&self, result: ProcessResult, tokens: Vec<AckToken>) {
        self.dispatch_with_context(result, tokens, DeliveryContext::new())
            .await;
    }

    /// [`Self::dispatch`] with a context the caller built, e.g. one whose
    /// finding uids were minted before the alert pipeline ran.
    pub async fn dispatch_with_context(
        &self,
        result: ProcessResult,
        tokens: Vec<AckToken>,
        context: DeliveryContext,
    ) {
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
        let context = Arc::new(context);
        for worker in &self.workers {
            worker
                .enqueue(DeliveryItem {
                    payload: DeliveryPayload::Result(result.clone()),
                    context: context.clone(),
                    _guard: guard.clone(),
                })
                .await;
        }
    }

    /// Fan one incident line into every worker. Incidents are synthetic (no
    /// input event), so they carry no ack tokens.
    pub async fn dispatch_incident(&self, incident: IncidentEnvelope) {
        if self.workers.is_empty() {
            return;
        }
        let guard = Arc::new(AckGuard {
            tokens: Mutex::new(Vec::new()),
            ack_tx: self.ack_tx.clone(),
        });
        let incident = Arc::new(incident);
        let context = Arc::new(DeliveryContext::new());
        for worker in &self.workers {
            worker
                .enqueue(DeliveryItem {
                    payload: DeliveryPayload::Incident(incident.clone()),
                    context: context.clone(),
                    _guard: guard.clone(),
                })
                .await;
        }
    }

    /// Fan one format-keyed incident into every worker.
    pub async fn dispatch_formatted_incident(&self, incident: FormattedIncidentEnvelope) {
        if self.workers.is_empty() {
            return;
        }
        let guard = Arc::new(AckGuard {
            tokens: Mutex::new(Vec::new()),
            ack_tx: self.ack_tx.clone(),
        });
        let incident = Arc::new(incident);
        let context = Arc::new(DeliveryContext::new());
        for worker in &self.workers {
            worker
                .enqueue(DeliveryItem {
                    payload: DeliveryPayload::FormattedIncident(incident.clone()),
                    context: context.clone(),
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
        drain_ready(&mut rx, &mut batch, cfg.batch_max);
        if batch.len() < cfg.batch_max && !cfg.batch_flush.is_zero() {
            let deadline = tokio::time::Instant::now() + cfg.batch_flush;
            while batch.len() < cfg.batch_max {
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Some(item)) => {
                        batch.push(item);
                        drain_ready(&mut rx, &mut batch, cfg.batch_max);
                    }
                    Ok(None) | Err(_) => break,
                }
            }
        }
        metrics.on_sink_queue_depth_change(label, -(batch.len() as i64));
        let mut start = 0;
        while start < batch.len() {
            let target = match &batch[start].payload {
                DeliveryPayload::Result(_) => {
                    let end = batch[start..]
                        .iter()
                        .position(|item| !matches!(item.payload, DeliveryPayload::Result(_)))
                        .map_or(batch.len(), |len| start + len);
                    deliver_results(
                        &mut sink,
                        &batch[start..end],
                        &cfg,
                        dlq_tx.as_ref(),
                        &metrics,
                        label,
                    )
                    .await;
                    start = end;
                    continue;
                }
                DeliveryPayload::Incident(e) => DeliverTarget::Incident(e),
                DeliveryPayload::FormattedIncident(e) => DeliverTarget::FormattedIncident(e),
            };
            deliver_one(
                &mut sink,
                target,
                &batch[start].context,
                &cfg,
                dlq_tx.as_ref(),
                &metrics,
                label,
                None,
            )
            .await;
            start += 1;
        }
        // Dropping `batch` drops each item's `Arc<AckGuard>` clone, advancing
        // the ack-join.
        drop(batch);
    }
}

/// Move the items already queued into `batch`, up to `batch_max`.
fn drain_ready(
    rx: &mut mpsc::Receiver<DeliveryItem>,
    batch: &mut Vec<DeliveryItem>,
    batch_max: usize,
) {
    while batch.len() < batch_max {
        match rx.try_recv() {
            Ok(item) => batch.push(item),
            Err(_) => break,
        }
    }
}

/// Deliver a run of result items with one batched first attempt, then retry
/// each failed item on its own, in order.
async fn deliver_results<S: DeliverySink>(
    sink: &mut S,
    run: &[DeliveryItem],
    cfg: &DeliveryConfig,
    dlq_tx: Option<&mpsc::Sender<DeliveryFailure>>,
    metrics: &Arc<dyn MetricsHook>,
    label: &'static str,
) {
    let items: Vec<(&ProcessResult, &DeliveryContext)> = run
        .iter()
        .filter_map(|item| match &item.payload {
            DeliveryPayload::Result(result) => Some((result.as_ref(), item.context.as_ref())),
            _ => None,
        })
        .collect();
    let mut outcomes = sink.deliver_batch(&items).await.into_iter();
    for (result, ctx) in items {
        // An item without an outcome gets a full attempt of its own.
        let first_failure = match outcomes.next() {
            Some(Ok(())) => continue,
            Some(Err(err)) => Some(err),
            None => None,
        };
        deliver_one(
            sink,
            DeliverTarget::Result(result),
            ctx,
            cfg,
            dlq_tx,
            metrics,
            label,
            first_failure,
        )
        .await;
    }
}

/// What a worker is delivering: a result batch or an incident line.
enum DeliverTarget<'a> {
    Result(&'a ProcessResult),
    Incident(&'a IncidentEnvelope),
    FormattedIncident(&'a FormattedIncidentEnvelope),
}

/// Deliver one item with retries. `first_failure` is the error of a first
/// attempt already made (in a batch); the loop then starts at the retry
/// decision for that error.
#[allow(clippy::too_many_arguments)]
async fn deliver_one<S: DeliverySink>(
    sink: &mut S,
    target: DeliverTarget<'_>,
    ctx: &DeliveryContext,
    cfg: &DeliveryConfig,
    dlq_tx: Option<&mpsc::Sender<DeliveryFailure>>,
    metrics: &Arc<dyn MetricsHook>,
    label: &'static str,
    mut first_failure: Option<RuntimeError>,
) {
    let mut attempt: u32 = 0;
    loop {
        let outcome = match first_failure.take() {
            Some(err) => Err(err),
            None => match target {
                DeliverTarget::Result(r) => sink.deliver(r, ctx).await,
                DeliverTarget::Incident(e) => sink.deliver_incident(e, ctx).await,
                DeliverTarget::FormattedIncident(e) => {
                    sink.deliver_formatted_incident(e, ctx).await
                }
            },
        };
        match outcome {
            Ok(()) => return,
            Err(e) => {
                // A `Permanent` error will not heal on retry (e.g. a 4xx from a
                // misrendered webhook body), so route it to the DLQ immediately
                // rather than burning the retry budget.
                let permanent = matches!(e, RuntimeError::Permanent(_));
                if permanent || attempt >= cfg.retry_max {
                    metrics.on_sink_delivery_failed(label);
                    match dlq_tx {
                        Some(dlq) => {
                            let serialized = match target {
                                DeliverTarget::Result(r) => {
                                    serde_json::to_string(r).unwrap_or_default()
                                }
                                // The native line, so a DLQ replay stays in
                                // the format the rest of the DLQ speaks.
                                DeliverTarget::Incident(e) => e.json.clone(),
                                DeliverTarget::FormattedIncident(e) => e.native().json.clone(),
                            };
                            let tenant = match target {
                                DeliverTarget::Result(r) => {
                                    r.iter().find_map(|result| result.header.tenant_id.clone())
                                }
                                DeliverTarget::Incident(e) => e.tenant.clone(),
                                DeliverTarget::FormattedIncident(e) => e.native().tenant.clone(),
                            };
                            let failure = DeliveryFailure {
                                serialized,
                                error: format!("sink delivery failure: {e}"),
                                tenant,
                            };
                            if dlq.send(failure).await.is_err() {
                                tracing::warn!(
                                    sink = label,
                                    error = %e,
                                    "Sink delivery failed and the DLQ channel is closed; dropping result",
                                );
                            }
                        }
                        None => {
                            tracing::warn!(
                                sink = label,
                                error = %e,
                                "Sink delivery failed and no DLQ is configured; dropping result",
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
        permanent: bool,
        delivered: Arc<AtomicUsize>,
        attempts: Arc<AtomicUsize>,
        // Records the delivery-context id seen on each attempt, to prove the
        // worker reuses one context across retries.
        ctx_ids: Arc<std::sync::Mutex<Vec<String>>>,
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
                permanent: false,
                delivered: Arc::new(AtomicUsize::new(0)),
                attempts: Arc::new(AtomicUsize::new(0)),
                ctx_ids: Arc::new(std::sync::Mutex::new(Vec::new())),
                gate: None,
            }
        }
    }

    impl DeliverySink for MockSink {
        fn deliver<'a>(
            &'a mut self,
            _result: &'a ProcessResult,
            ctx: &'a DeliveryContext,
        ) -> DeliveryFuture<'a> {
            let fail_first = self.fail_first.clone();
            let delivered = self.delivered.clone();
            let attempts = self.attempts.clone();
            let always_fail = self.always_fail;
            let permanent = self.permanent;
            let gate = self.gate.clone();
            let ctx_ids = self.ctx_ids.clone();
            let ctx_id = ctx.id_base().to_string();
            Box::pin(async move {
                ctx_ids.lock().unwrap().push(ctx_id);
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
                attempts.fetch_add(1, Ordering::SeqCst);
                if always_fail {
                    return Err(if permanent {
                        RuntimeError::Permanent("mock permanent".to_string())
                    } else {
                        RuntimeError::Io(std::io::Error::other("mock always fails"))
                    });
                }
                if fail_first.load(Ordering::SeqCst) > 0 {
                    fail_first.fetch_sub(1, Ordering::SeqCst);
                    return Err(RuntimeError::Io(std::io::Error::other("mock transient")));
                }
                delivered.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
        fn deliver_incident<'a>(
            &'a mut self,
            _incident: &'a IncidentEnvelope,
            _ctx: &'a DeliveryContext,
        ) -> DeliveryFuture<'a> {
            let always_fail = self.always_fail;
            let permanent = self.permanent;
            Box::pin(async move {
                if always_fail {
                    Err(if permanent {
                        RuntimeError::Permanent("mock permanent".to_string())
                    } else {
                        RuntimeError::Io(std::io::Error::other("mock always fails"))
                    })
                } else {
                    Ok(())
                }
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
            vec![(sink, OnFull::Block, fast_cfg())],
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
    async fn retry_reuses_the_same_delivery_context() {
        let (ack_tx, _ack_rx) = mpsc::unbounded_channel();
        let sink = MockSink::new("mock");
        sink.fail_first.store(2, Ordering::SeqCst); // two failures, then success
        let ctx_ids = sink.ctx_ids.clone();
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, fast_cfg())],
            None,
            ack_tx,
            noop_metrics(),
        );

        dispatcher.dispatch(result(), vec![AckToken::Noop]).await;
        dispatcher.shutdown().await;

        let ids = ctx_ids.lock().unwrap().clone();
        assert_eq!(
            ids.len(),
            3,
            "two failures then success means three attempts"
        );
        assert!(
            ids.iter().all(|id| *id == ids[0]),
            "the delivery context id must be stable across retries: {ids:?}",
        );
    }

    #[tokio::test]
    async fn fanout_shares_one_delivery_context() {
        let (ack_tx, _ack_rx) = mpsc::unbounded_channel();
        let first = MockSink::new("first");
        let first_ids = first.ctx_ids.clone();
        let second = MockSink::new("second");
        let second_ids = second.ctx_ids.clone();
        let dispatcher = Dispatcher::spawn(
            vec![
                (first, OnFull::Block, fast_cfg()),
                (second, OnFull::Block, fast_cfg()),
            ],
            None,
            ack_tx,
            noop_metrics(),
        );

        dispatcher.dispatch(result(), vec![AckToken::Noop]).await;
        dispatcher.shutdown().await;

        assert_eq!(
            first_ids.lock().unwrap().as_slice(),
            second_ids.lock().unwrap().as_slice(),
            "every sink must derive identity from the same dispatched result",
        );
    }

    #[tokio::test]
    async fn retries_then_succeeds() {
        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel();
        let (dlq_tx, mut dlq_rx) = mpsc::channel(8);
        let sink = MockSink::new("mock");
        sink.fail_first.store(3, Ordering::SeqCst); // < retry_max (5)
        let delivered = sink.delivered.clone();
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, fast_cfg())],
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
            vec![(sink, OnFull::Block, fast_cfg())],
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
    async fn terminal_failure_with_closed_dlq_counts_and_acks() {
        #[derive(Default)]
        struct FailureCounter(AtomicUsize);
        impl MetricsHook for FailureCounter {
            fn on_sink_delivery_failed(&self, _sink: &str) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn on_parse_error(&self) {}
            fn on_events_processed(&self, _: u64) {}
            fn on_detection_matches(&self, _: u64) {}
            fn on_correlation_matches(&self, _: u64) {}
            fn observe_processing_latency(&self, _: f64) {}
            fn on_input_queue_depth_change(&self, _: i64) {}
            fn on_back_pressure(&self) {}
            fn observe_batch_size(&self, _: u64) {}
            fn on_output_queue_depth_change(&self, _: i64) {}
            fn observe_pipeline_latency(&self, _: f64) {}
            fn set_correlation_state_entries(&self, _: u64) {}
        }

        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel();
        let (dlq_tx, dlq_rx) = mpsc::channel(8);
        drop(dlq_rx);
        let counter = Arc::new(FailureCounter::default());
        let mut sink = MockSink::new("mock");
        sink.always_fail = true;
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, fast_cfg())],
            Some(dlq_tx),
            ack_tx,
            counter.clone(),
        );

        dispatcher.dispatch(result(), vec![AckToken::Noop]).await;
        dispatcher.shutdown().await;

        assert_eq!(counter.0.load(Ordering::SeqCst), 1, "failure still counted");
        assert!(
            ack_rx.try_recv().is_ok(),
            "token acked even though the DLQ channel is closed",
        );
    }

    #[tokio::test]
    async fn formatted_incident_failure_routes_native_line_to_dlq() {
        let (ack_tx, _ack_rx) = mpsc::unbounded_channel();
        let (dlq_tx, mut dlq_rx) = mpsc::channel(8);
        let mut sink = MockSink::new("mock");
        sink.always_fail = true;
        sink.permanent = true;
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, fast_cfg())],
            Some(dlq_tx),
            ack_tx,
            noop_metrics(),
        );
        let incident = FormattedIncidentEnvelope::new(IncidentEnvelope::new(
            "{\"incident_id\":\"i-1\"}".to_string(),
            None,
        ))
        .with_line(
            crate::io::SinkFormat::Ocsf,
            "{\"class_uid\":2004}".to_string(),
        );

        dispatcher.dispatch_formatted_incident(incident).await;
        dispatcher.shutdown().await;

        let failure = dlq_rx.try_recv().expect("incident failure routed to DLQ");
        assert_eq!(failure.serialized, "{\"incident_id\":\"i-1\"}");
    }

    #[tokio::test]
    async fn permanent_failure_skips_retries_and_dlqs() {
        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel();
        let (dlq_tx, mut dlq_rx) = mpsc::channel(8);
        let mut sink = MockSink::new("mock");
        sink.always_fail = true;
        sink.permanent = true;
        let attempts = sink.attempts.clone();
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, fast_cfg())],
            Some(dlq_tx),
            ack_tx,
            noop_metrics(),
        );

        dispatcher.dispatch(result(), vec![AckToken::Noop]).await;
        dispatcher.shutdown().await;

        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "a permanent failure must not be retried",
        );
        let failure = dlq_rx.try_recv().expect("permanent failure routed to DLQ");
        assert!(failure.error.contains("permanent delivery failure"));
        assert!(ack_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn ack_join_waits_for_all_sinks() {
        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel();
        let (gate_tx, gate_rx) = tokio::sync::watch::channel(false);
        let fast = MockSink::new("fast");
        let mut slow = MockSink::new("slow");
        slow.gate = Some(gate_rx);

        let dispatcher = Dispatcher::spawn(
            vec![
                (fast, OnFull::Block, fast_cfg()),
                (slow, OnFull::Block, fast_cfg()),
            ],
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
            vec![(sink, OnFull::Drop, cfg)],
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

    /// Records each batched first attempt and each single delivery by
    /// sequence number. The item at `fail_at` fails its batched attempt and
    /// then `retry_failures` retries before it succeeds. With `stop_at_failure`
    /// the batch returns no outcome for the items after it.
    #[derive(Default)]
    struct BatchLog {
        batches: Vec<Vec<u64>>,
        singles: Vec<u64>,
        incidents: usize,
    }

    struct BatchSink {
        log: Arc<std::sync::Mutex<BatchLog>>,
        fail_at: Option<usize>,
        stop_at_failure: bool,
        retry_failures: usize,
        permanent: bool,
        gate: Option<tokio::sync::watch::Receiver<bool>>,
    }

    impl BatchSink {
        fn new() -> Self {
            BatchSink {
                log: Arc::default(),
                fail_at: None,
                stop_at_failure: false,
                retry_failures: 0,
                permanent: false,
                gate: None,
            }
        }

        fn failure(&self) -> RuntimeError {
            if self.permanent {
                RuntimeError::Permanent("mock permanent".to_string())
            } else {
                RuntimeError::Io(std::io::Error::other("mock transient"))
            }
        }
    }

    impl DeliverySink for BatchSink {
        fn deliver<'a>(
            &'a mut self,
            _result: &'a ProcessResult,
            ctx: &'a DeliveryContext,
        ) -> DeliveryFuture<'a> {
            Box::pin(async move {
                if let Some(mut rx) = self.gate.clone() {
                    while !*rx.borrow() {
                        if rx.changed().await.is_err() {
                            break;
                        }
                    }
                }
                self.log.lock().unwrap().singles.push(ctx.seq());
                if self.retry_failures > 0 {
                    self.retry_failures -= 1;
                    return Err(self.failure());
                }
                Ok(())
            })
        }
        fn deliver_batch<'a>(
            &'a mut self,
            items: &'a [(&'a ProcessResult, &'a DeliveryContext)],
        ) -> BatchFuture<'a> {
            Box::pin(async move {
                self.log
                    .lock()
                    .unwrap()
                    .batches
                    .push(items.iter().map(|(_, ctx)| ctx.seq()).collect());
                let attempted = match self.fail_at {
                    Some(at) if self.stop_at_failure => (at + 1).min(items.len()),
                    _ => items.len(),
                };
                (0..attempted)
                    .map(|index| match self.fail_at {
                        Some(at) if at == index => Err(self.failure()),
                        _ => Ok(()),
                    })
                    .collect()
            })
        }
        fn deliver_incident<'a>(
            &'a mut self,
            _incident: &'a IncidentEnvelope,
            _ctx: &'a DeliveryContext,
        ) -> DeliveryFuture<'a> {
            self.log.lock().unwrap().incidents += 1;
            Box::pin(async { Ok(()) })
        }
        fn label(&self) -> &'static str {
            "batch"
        }
    }

    #[derive(Default)]
    struct SinkCounters {
        retries: AtomicUsize,
        failures: AtomicUsize,
    }

    impl MetricsHook for SinkCounters {
        fn on_sink_retry(&self, _sink: &str) {
            self.retries.fetch_add(1, Ordering::SeqCst);
        }
        fn on_sink_delivery_failed(&self, _sink: &str) {
            self.failures.fetch_add(1, Ordering::SeqCst);
        }
        fn on_parse_error(&self) {}
        fn on_events_processed(&self, _: u64) {}
        fn on_detection_matches(&self, _: u64) {}
        fn on_correlation_matches(&self, _: u64) {}
        fn observe_processing_latency(&self, _: f64) {}
        fn on_input_queue_depth_change(&self, _: i64) {}
        fn on_back_pressure(&self) {}
        fn observe_batch_size(&self, _: u64) {}
        fn on_output_queue_depth_change(&self, _: i64) {}
        fn observe_pipeline_latency(&self, _: f64) {}
        fn set_correlation_state_entries(&self, _: u64) {}
    }

    /// Dispatch `count` results with contexts the test can identify.
    async fn dispatch_results(dispatcher: &Dispatcher, count: usize) -> Vec<u64> {
        let mut seqs = Vec::new();
        for _ in 0..count {
            let ctx = DeliveryContext::new();
            seqs.push(ctx.seq());
            dispatcher
                .dispatch_with_context(result(), vec![AckToken::Noop], ctx)
                .await;
        }
        seqs
    }

    #[tokio::test]
    async fn a_failed_batch_item_is_retried_alone() {
        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel();
        let (dlq_tx, mut dlq_rx) = mpsc::channel(8);
        let mut sink = BatchSink::new();
        sink.fail_at = Some(1);
        sink.retry_failures = 1;
        let log = sink.log.clone();
        let counters = Arc::new(SinkCounters::default());
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, fast_cfg())],
            Some(dlq_tx),
            ack_tx,
            counters.clone(),
        );

        let seqs = dispatch_results(&dispatcher, 3).await;
        dispatcher.shutdown().await;

        let log = log.lock().unwrap();
        assert_eq!(
            log.batches,
            std::slice::from_ref(&seqs),
            "one batched first attempt"
        );
        assert_eq!(
            log.singles,
            [seqs[1], seqs[1]],
            "only the failed item is retried, until it succeeds"
        );
        assert_eq!(counters.retries.load(Ordering::SeqCst), 2);
        assert_eq!(counters.failures.load(Ordering::SeqCst), 0);
        assert!(dlq_rx.try_recv().is_err());
        let mut acks = 0;
        while ack_rx.try_recv().is_ok() {
            acks += 1;
        }
        assert_eq!(acks, 3);
    }

    #[tokio::test]
    async fn a_batch_item_that_keeps_failing_goes_to_the_dlq_like_a_single_item() {
        let (ack_tx, _ack_rx) = mpsc::unbounded_channel();
        let (dlq_tx, mut dlq_rx) = mpsc::channel(8);
        let mut sink = BatchSink::new();
        sink.fail_at = Some(1);
        sink.retry_failures = usize::MAX;
        let log = sink.log.clone();
        let counters = Arc::new(SinkCounters::default());
        let cfg = fast_cfg();
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, cfg)],
            Some(dlq_tx),
            ack_tx,
            counters.clone(),
        );

        let seqs = dispatch_results(&dispatcher, 3).await;
        dispatcher.shutdown().await;

        // The batched attempt counts as the first attempt, so the item gets
        // exactly `retry_max` retries, as it would on its own.
        let log = log.lock().unwrap();
        assert_eq!(log.singles, vec![seqs[1]; cfg.retry_max as usize]);
        assert_eq!(
            counters.retries.load(Ordering::SeqCst),
            cfg.retry_max as usize
        );
        assert_eq!(counters.failures.load(Ordering::SeqCst), 1);
        assert!(dlq_rx.try_recv().is_ok());
        assert!(dlq_rx.try_recv().is_err(), "only the failed item is parked");
    }

    #[tokio::test]
    async fn a_permanent_batch_failure_skips_retries() {
        let (ack_tx, _ack_rx) = mpsc::unbounded_channel();
        let (dlq_tx, mut dlq_rx) = mpsc::channel(8);
        let mut sink = BatchSink::new();
        sink.fail_at = Some(0);
        sink.permanent = true;
        let log = sink.log.clone();
        let counters = Arc::new(SinkCounters::default());
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, fast_cfg())],
            Some(dlq_tx),
            ack_tx,
            counters.clone(),
        );

        dispatch_results(&dispatcher, 2).await;
        dispatcher.shutdown().await;

        assert!(log.lock().unwrap().singles.is_empty());
        assert_eq!(counters.retries.load(Ordering::SeqCst), 0);
        assert_eq!(counters.failures.load(Ordering::SeqCst), 1);
        let failure = dlq_rx.try_recv().expect("permanent failure routed to DLQ");
        assert!(failure.error.contains("permanent delivery failure"));
    }

    #[tokio::test]
    async fn batch_acks_wait_for_every_item_to_settle() {
        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel();
        let (gate_tx, gate_rx) = tokio::sync::watch::channel(false);
        let mut sink = BatchSink::new();
        sink.fail_at = Some(1);
        sink.gate = Some(gate_rx);
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, fast_cfg())],
            None,
            ack_tx,
            noop_metrics(),
        );

        dispatch_results(&dispatcher, 3).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            ack_rx.try_recv().is_err(),
            "no item of the batch is acked while one is still retrying"
        );

        gate_tx.send(true).unwrap();
        dispatcher.shutdown().await;
        let mut acks = 0;
        while ack_rx.try_recv().is_ok() {
            acks += 1;
        }
        assert_eq!(acks, 3);
    }

    #[tokio::test]
    async fn incidents_split_result_runs_and_go_one_at_a_time() {
        let (ack_tx, _ack_rx) = mpsc::unbounded_channel();
        let sink = BatchSink::new();
        let log = sink.log.clone();
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, fast_cfg())],
            None,
            ack_tx,
            noop_metrics(),
        );

        let before = dispatch_results(&dispatcher, 2).await;
        dispatcher
            .dispatch_incident(IncidentEnvelope::new("{}".to_string(), None))
            .await;
        dispatcher
            .dispatch_incident(IncidentEnvelope::new("{}".to_string(), None))
            .await;
        let after = dispatch_results(&dispatcher, 1).await;
        dispatcher.shutdown().await;

        let log = log.lock().unwrap();
        assert_eq!(log.batches, [before, after]);
        assert_eq!(log.incidents, 2);
        assert!(log.singles.is_empty());
    }

    #[tokio::test]
    async fn the_default_batch_delivers_each_item() {
        let (ack_tx, _ack_rx) = mpsc::unbounded_channel();
        let sink = MockSink::new("mock");
        sink.fail_first.store(1, Ordering::SeqCst);
        let delivered = sink.delivered.clone();
        let attempts = sink.attempts.clone();
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, fast_cfg())],
            None,
            ack_tx,
            noop_metrics(),
        );

        dispatch_results(&dispatcher, 3).await;
        dispatcher.shutdown().await;

        assert_eq!(delivered.load(Ordering::SeqCst), 3);
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            4,
            "three first attempts and one retry"
        );
    }

    #[tokio::test]
    async fn items_a_batch_did_not_reach_get_their_own_attempt_without_a_retry() {
        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel();
        let mut sink = BatchSink::new();
        sink.fail_at = Some(1);
        sink.stop_at_failure = true;
        let log = sink.log.clone();
        let counters = Arc::new(SinkCounters::default());
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, fast_cfg())],
            None,
            ack_tx,
            counters.clone(),
        );

        let seqs = dispatch_results(&dispatcher, 4).await;
        dispatcher.shutdown().await;

        let log = log.lock().unwrap();
        assert_eq!(log.batches, std::slice::from_ref(&seqs));
        assert_eq!(
            log.singles,
            seqs[1..],
            "the failed item is retried first, then the rest go in order"
        );
        assert_eq!(
            counters.retries.load(Ordering::SeqCst),
            1,
            "only the item that failed counts a retry"
        );
        let mut acks = 0;
        while ack_rx.try_recv().is_ok() {
            acks += 1;
        }
        assert_eq!(acks, 4);
    }

    /// Delivers through the default `deliver_batch`, recording the order of
    /// every attempt. The first attempt of the first item fails.
    struct OrderSink {
        attempts: Arc<std::sync::Mutex<Vec<u64>>>,
        failed_once: bool,
    }

    impl DeliverySink for OrderSink {
        fn deliver<'a>(
            &'a mut self,
            _result: &'a ProcessResult,
            ctx: &'a DeliveryContext,
        ) -> DeliveryFuture<'a> {
            Box::pin(async move {
                self.attempts.lock().unwrap().push(ctx.seq());
                if !self.failed_once {
                    self.failed_once = true;
                    return Err(RuntimeError::Io(std::io::Error::other("mock transient")));
                }
                Ok(())
            })
        }
        fn label(&self) -> &'static str {
            "order"
        }
    }

    #[tokio::test]
    async fn the_default_batch_retries_a_failure_before_the_items_after_it() {
        let (ack_tx, _ack_rx) = mpsc::unbounded_channel();
        let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = OrderSink {
            attempts: attempts.clone(),
            failed_once: false,
        };
        // A flush window long enough that all three land in one batch.
        let cfg = DeliveryConfig {
            batch_flush: Duration::from_millis(100),
            ..fast_cfg()
        };
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, cfg)],
            None,
            ack_tx,
            noop_metrics(),
        );

        let seqs = dispatch_results(&dispatcher, 3).await;
        dispatcher.shutdown().await;

        assert_eq!(
            *attempts.lock().unwrap(),
            [seqs[0], seqs[0], seqs[1], seqs[2]],
            "results reach the sink in order"
        );
    }

    /// Wait until the sink has made `count` batched attempts.
    async fn wait_for_batches(log: &std::sync::Mutex<BatchLog>, count: usize) {
        let started = std::time::Instant::now();
        while log.lock().unwrap().batches.len() < count {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the batch never arrived"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    #[tokio::test]
    async fn without_a_flush_interval_a_lone_item_goes_out_at_once() {
        let (ack_tx, _ack_rx) = mpsc::unbounded_channel();
        let sink = BatchSink::new();
        let log = sink.log.clone();
        let cfg = DeliveryConfig {
            batch_flush: Duration::ZERO,
            ..fast_cfg()
        };
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, cfg)],
            None,
            ack_tx,
            noop_metrics(),
        );

        let started = std::time::Instant::now();
        let seqs = dispatch_results(&dispatcher, 1).await;
        wait_for_batches(&log, 1).await;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(log.lock().unwrap().batches, [seqs]);
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn a_flush_interval_gathers_items_that_arrive_close_together() {
        let (ack_tx, _ack_rx) = mpsc::unbounded_channel();
        let sink = BatchSink::new();
        let log = sink.log.clone();
        let cfg = DeliveryConfig {
            batch_flush: Duration::from_millis(500),
            ..fast_cfg()
        };
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, cfg)],
            None,
            ack_tx,
            noop_metrics(),
        );

        let mut seqs = dispatch_results(&dispatcher, 1).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        seqs.extend(dispatch_results(&dispatcher, 1).await);
        wait_for_batches(&log, 1).await;
        assert_eq!(log.lock().unwrap().batches, [seqs]);
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn a_lone_item_waits_at_most_the_flush_interval() {
        let (ack_tx, _ack_rx) = mpsc::unbounded_channel();
        let sink = BatchSink::new();
        let log = sink.log.clone();
        let flush = Duration::from_millis(100);
        let cfg = DeliveryConfig {
            batch_flush: flush,
            ..fast_cfg()
        };
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, cfg)],
            None,
            ack_tx,
            noop_metrics(),
        );

        let started = std::time::Instant::now();
        dispatch_results(&dispatcher, 1).await;
        wait_for_batches(&log, 1).await;
        let waited = started.elapsed();
        assert!(waited >= flush, "delivered after {waited:?}");
        assert!(
            waited < flush + Duration::from_secs(2),
            "delivered after {waited:?}"
        );
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn a_full_batch_does_not_wait_for_the_flush_interval() {
        let (ack_tx, _ack_rx) = mpsc::unbounded_channel();
        let sink = BatchSink::new();
        let log = sink.log.clone();
        let cfg = DeliveryConfig {
            batch_max: 2,
            batch_flush: Duration::from_secs(30),
            ..fast_cfg()
        };
        let dispatcher = Dispatcher::spawn(
            vec![(sink, OnFull::Block, cfg)],
            None,
            ack_tx,
            noop_metrics(),
        );

        let started = std::time::Instant::now();
        dispatch_results(&dispatcher, 2).await;
        wait_for_batches(&log, 1).await;
        assert!(started.elapsed() < Duration::from_secs(5));
        dispatcher.shutdown().await;
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
