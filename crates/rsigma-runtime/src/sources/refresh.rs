//! Background refresh scheduler for dynamic pipeline sources.
//!
//! Manages per-source refresh loops based on `RefreshPolicy`:
//! - `Interval(duration)`: re-fetches on a timer
//! - `Watch`: uses file system notifications (via `notify`)
//! - `Push`: receives updates from external triggers (NATS)
//! - `OnDemand`: only refreshes when explicitly triggered via API/signal

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

use rsigma_eval::pipeline::sources::{DynamicSource, RefreshPolicy, SourceType};
use tokio::sync::{Notify, Semaphore, mpsc, watch};

use super::{MAX_CONCURRENT_RESOLVES, SourceResolver, catch_resolver_panic};

/// A message requesting source re-resolution.
#[derive(Debug, Clone)]
pub enum RefreshTrigger {
    /// Re-resolve all sources.
    All,
    /// Re-resolve a specific source by ID.
    Single(String),
    /// A NATS push message arrived with pre-parsed data for a specific source.
    #[cfg(feature = "nats")]
    NatsPush {
        source_id: String,
        data: serde_json::Value,
    },
}

/// A refresh request queue that never drops a request.
///
/// Requests for the same source coalesce while they wait, and a request made
/// while that source is resolving runs it once more afterwards, so the latest
/// change is always picked up. Unlike the bounded trigger channel, a request
/// never fails or waits for room.
#[derive(Clone, Default)]
pub struct RefreshRequests {
    inner: Arc<PendingRequests>,
}

#[derive(Default)]
struct PendingRequests {
    pending: Mutex<Pending>,
    notify: Notify,
}

#[derive(Default)]
struct Pending {
    all: bool,
    sources: HashSet<String>,
}

impl RefreshRequests {
    /// Ask for `source_id` to be re-resolved.
    pub fn request_source(&self, source_id: &str) {
        self.inner
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sources
            .insert(source_id.to_string());
        self.inner.notify.notify_one();
    }

    /// Ask for every source to be re-resolved.
    pub fn request_all(&self) {
        self.inner
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .all = true;
        self.inner.notify.notify_one();
    }

    /// Whether any request waits for the scheduler.
    pub fn is_pending(&self) -> bool {
        let pending = self
            .inner
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        pending.all || !pending.sources.is_empty()
    }

    fn take(&self) -> Pending {
        std::mem::take(
            &mut *self
                .inner
                .pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }
}

/// Notification sent when sources have been refreshed.
#[derive(Debug, Clone)]
pub struct RefreshResult {
    /// The latest data of every source refreshed so far (source_id -> value).
    ///
    /// Sources refresh independently, and each refresh replaces only its own
    /// entry, so an entry can be unchanged since the previous notification.
    pub resolved: HashMap<String, serde_json::Value>,
}

/// Manages background refresh tasks for dynamic sources.
///
/// The scheduler spawns per-source tasks based on their refresh policy and
/// sends `RefreshResult` notifications whenever source data changes.
pub struct RefreshScheduler {
    /// Channel for on-demand refresh triggers (from API, SIGHUP, NATS control).
    trigger_tx: mpsc::Sender<RefreshTrigger>,
    /// Receiver for on-demand triggers (consumed by the run loop).
    trigger_rx: Option<mpsc::Receiver<RefreshTrigger>>,
    /// Watch channel sender for notifying consumers of updated source data.
    result_tx: watch::Sender<Option<RefreshResult>>,
    /// Watch channel receiver for consumers.
    result_rx: watch::Receiver<Option<RefreshResult>>,
    /// Lossless, coalescing refresh requests.
    requests: RefreshRequests,
}

impl RefreshScheduler {
    /// Create a new scheduler.
    pub fn new() -> Self {
        let (trigger_tx, trigger_rx) = mpsc::channel(32);
        let (result_tx, result_rx) = watch::channel(None);
        Self {
            trigger_tx,
            trigger_rx: Some(trigger_rx),
            result_tx,
            result_rx,
            requests: RefreshRequests::default(),
        }
    }

    /// Get a handle for refresh requests that are never dropped. Prefer it
    /// over [`trigger_sender`](Self::trigger_sender) where a caller cannot
    /// wait for room in the trigger channel.
    pub fn requests(&self) -> RefreshRequests {
        self.requests.clone()
    }

    /// Get a sender for triggering on-demand resolution.
    pub fn trigger_sender(&self) -> mpsc::Sender<RefreshTrigger> {
        self.trigger_tx.clone()
    }

    /// Get a receiver that is notified when sources are refreshed.
    pub fn result_receiver(&self) -> watch::Receiver<Option<RefreshResult>> {
        self.result_rx.clone()
    }

    /// Start the scheduler for a detached, non-pipeline consumer.
    ///
    /// Returns a [`SourceSubscription`] bundling the spawned coordination task,
    /// a [`watch`] receiver of decoded source payloads, and a trigger sender for
    /// on-demand re-resolution. This is the seam used by consumers that want a
    /// source's decoded payload directly (rather than bound into a pipeline
    /// `${source.*}` namespace): it reuses the same per-source file, HTTP, and
    /// NATS fetch and refresh machinery as the pipeline binder via [`Self::run`],
    /// so that logic is never duplicated.
    pub fn subscribe(
        self,
        sources: Vec<DynamicSource>,
        resolver: Arc<dyn SourceResolver>,
    ) -> SourceSubscription {
        let results = self.result_receiver();
        let trigger = self.trigger_sender();
        let handle = self.run(sources, resolver);
        SourceSubscription {
            handle,
            results,
            trigger,
        }
    }

    /// Start the scheduler background loop.
    ///
    /// Takes ownership of the trigger receiver and spawns per-source interval tasks.
    /// Returns a `JoinHandle` for the main coordination task.
    ///
    /// Each triggered source resolves in its own task, at most
    /// [`MAX_CONCURRENT_RESOLVES`] at a time, and publishes its value on the
    /// watch channel when it finishes, so a slow or hung source does not hold
    /// up the others. A trigger for a source that is still resolving runs it
    /// once more after the current resolve. A panicking resolve is logged and
    /// fails only that refresh.
    pub fn run(
        mut self,
        sources: Vec<DynamicSource>,
        resolver: Arc<dyn SourceResolver>,
    ) -> tokio::task::JoinHandle<()> {
        let trigger_rx = self
            .trigger_rx
            .take()
            .expect("run() can only be called once");

        tokio::spawn(async move {
            Self::run_loop(
                sources,
                resolver,
                trigger_rx,
                self.trigger_tx,
                self.result_tx,
                self.requests,
            )
            .await;
        })
    }

    async fn run_loop(
        sources: Vec<DynamicSource>,
        resolver: Arc<dyn SourceResolver>,
        mut trigger_rx: mpsc::Receiver<RefreshTrigger>,
        trigger_tx: mpsc::Sender<RefreshTrigger>,
        result_tx: watch::Sender<Option<RefreshResult>>,
        requests: RefreshRequests,
    ) {
        // Spawn interval timers
        for source in &sources {
            if let RefreshPolicy::Interval(duration) = &source.refresh {
                let tx = trigger_tx.clone();
                let id = source.id.clone();
                let interval = if *duration < super::MIN_REFRESH_INTERVAL {
                    tracing::warn!(
                        source_id = %id,
                        configured = ?duration,
                        clamped_to = ?super::MIN_REFRESH_INTERVAL,
                        "Refresh interval below minimum, clamping to floor"
                    );
                    super::MIN_REFRESH_INTERVAL
                } else {
                    *duration
                };
                tokio::spawn(async move {
                    let mut timer = tokio::time::interval(interval);
                    timer.tick().await; // skip immediate first tick
                    loop {
                        timer.tick().await;
                        if tx.send(RefreshTrigger::Single(id.clone())).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }

        // Spawn NATS push subscriptions
        #[cfg(feature = "nats")]
        for source in &sources {
            if source.refresh == RefreshPolicy::Push
                && let SourceType::Nats {
                    url,
                    subject,
                    format,
                    extract: extract_expr,
                } = &source.source_type
            {
                let tx = trigger_tx.clone();
                let id = source.id.clone();
                let connect = resolver.nats_connect_config();
                let url = url.clone();
                let subject = subject.clone();
                let format = *format;
                let extract_expr = extract_expr.clone();
                tokio::spawn(async move {
                    if let Err(e) = nats_push_loop(
                        &connect,
                        &url,
                        &subject,
                        format,
                        extract_expr.as_ref(),
                        &id,
                        &tx,
                    )
                    .await
                    {
                        tracing::error!(
                            source_id = %id,
                            error = %e,
                            "NATS push subscription failed"
                        );
                    }
                });
            }
        }

        // Spawn file watchers for Watch policy sources
        for source in &sources {
            if source.refresh == RefreshPolicy::Watch
                && let SourceType::File { path, .. } = &source.source_type
            {
                let tx = trigger_tx.clone();
                let id = source.id.clone();
                let path = path.clone();
                tokio::spawn(async move {
                    file_watch_loop(&path, &id, &tx).await;
                });
            }
        }

        // Main loop: wait for triggers and requests, and start a resolve task
        // per source.
        let in_flight = Arc::new(Mutex::new(HashMap::new()));
        let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_RESOLVES));
        let start = |source: &DynamicSource| {
            SourceRefresh {
                source: source.clone(),
                resolver: resolver.clone(),
                result_tx: result_tx.clone(),
                in_flight: in_flight.clone(),
                permits: permits.clone(),
            }
            .spawn();
        };
        loop {
            let trigger = tokio::select! {
                trigger = trigger_rx.recv() => match trigger {
                    Some(trigger) => trigger,
                    None => break,
                },
                () = requests.inner.notify.notified() => {
                    let pending = requests.take();
                    for source in &sources {
                        if pending.all || pending.sources.contains(&source.id) {
                            start(source);
                        }
                    }
                    continue;
                }
            };
            // Handle NATS push with pre-parsed data (no re-resolution needed)
            #[cfg(feature = "nats")]
            if let RefreshTrigger::NatsPush { source_id, data } = trigger {
                resolver.store_cached(&source_id, data.clone());
                publish(&result_tx, source_id, data);
                continue;
            }

            match &trigger {
                RefreshTrigger::All => sources.iter().for_each(start),
                RefreshTrigger::Single(id) => {
                    sources.iter().filter(|s| s.id == *id).for_each(start)
                }
                #[cfg(feature = "nats")]
                RefreshTrigger::NatsPush { .. } => unreachable!(),
            }
        }
        drop(trigger_tx);
    }
}

/// One source refresh, run in its own task.
struct SourceRefresh {
    source: DynamicSource,
    resolver: Arc<dyn SourceResolver>,
    result_tx: watch::Sender<Option<RefreshResult>>,
    /// Sources resolving now, each with whether another trigger arrived meanwhile.
    in_flight: Arc<Mutex<HashMap<String, bool>>>,
    /// Shared by the sources that fetch over the network or from a process.
    /// A watchlist reads memory and never waits for one, so sources that do
    /// not answer cannot hold up indicator pushes.
    permits: Arc<Semaphore>,
}

impl SourceRefresh {
    fn spawn(self) {
        {
            let mut in_flight = self
                .in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(again) = in_flight.get_mut(&self.source.id) {
                *again = true;
                return;
            }
            in_flight.insert(self.source.id.clone(), false);
        }
        tokio::spawn(self.run());
    }

    async fn run(self) {
        loop {
            self.resolve_once().await;
            let mut in_flight = self
                .in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match in_flight.get_mut(&self.source.id) {
                Some(again) if *again => *again = false,
                _ => {
                    in_flight.remove(&self.source.id);
                    return;
                }
            }
        }
    }

    async fn resolve_once(&self) {
        let source = &self.source;
        let started = std::time::Instant::now();
        let result = {
            let _permit = match source.source_type {
                SourceType::Watchlist { .. } => None,
                _ => Some(self.permits.acquire().await),
            };
            catch_resolver_panic(source, self.resolver.resolve(source)).await
        };
        let duration_ms = started.elapsed().as_millis() as u64;
        match result {
            Ok(value) => {
                tracing::debug!(source_id = %source.id, duration_ms, "Scheduled refresh completed");
                publish(&self.result_tx, source.id.clone(), value.data);
            }
            Err(e) if !source.required => {
                tracing::warn!(
                    source_id = %source.id,
                    error = %e,
                    duration_ms,
                    "Optional source refresh failed, using null"
                );
                publish(&self.result_tx, source.id.clone(), serde_json::Value::Null);
            }
            Err(e) => {
                tracing::warn!(
                    source_id = %source.id,
                    error = %e,
                    duration_ms,
                    "Background source refresh failed",
                );
            }
        }
    }
}

/// Record `data` as the latest value of `source_id` and notify receivers.
fn publish(
    result_tx: &watch::Sender<Option<RefreshResult>>,
    source_id: String,
    data: serde_json::Value,
) {
    result_tx.send_modify(|current| match current {
        Some(result) => {
            result.resolved.insert(source_id, data);
        }
        None => {
            *current = Some(RefreshResult {
                resolved: HashMap::from([(source_id, data)]),
            });
        }
    });
}

impl Default for RefreshScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// A detached source subscription returned by [`RefreshScheduler::subscribe`].
///
/// Bundles the spawned coordination task, a receiver of decoded source payloads
/// (the latest [`RefreshResult`] per refresh), and a trigger sender for
/// on-demand re-resolution and hot-reload. Dropping `handle` does not stop the
/// loop; hold it (or detach it) for the lifetime of the consumer.
pub struct SourceSubscription {
    /// The scheduler coordination task.
    pub handle: tokio::task::JoinHandle<()>,
    /// Latest decoded source payloads, updated on every refresh.
    pub results: watch::Receiver<Option<RefreshResult>>,
    /// Trigger channel for on-demand re-resolution (`All` / `Single`).
    pub trigger: mpsc::Sender<RefreshTrigger>,
}

/// Subscribe to a NATS subject at `url` with the authentication and TLS
/// settings of `connect`, and forward parsed messages as triggers.
#[cfg(feature = "nats")]
async fn nats_push_loop(
    connect: &crate::NatsConnectConfig,
    url: &str,
    subject: &str,
    format: rsigma_eval::pipeline::sources::DataFormat,
    extract_expr: Option<&rsigma_eval::pipeline::sources::ExtractExpr>,
    source_id: &str,
    trigger_tx: &mpsc::Sender<RefreshTrigger>,
) -> Result<(), String> {
    use futures::StreamExt;

    let client = connect
        .connect_to(url)
        .await
        .map_err(|e| format!("NATS connect failed: {e}"))?;

    let mut subscriber = client
        .subscribe(subject.to_string())
        .await
        .map_err(|e| format!("NATS subscribe failed: {e}"))?;

    tracing::info!(
        source_id = %source_id,
        subject = %subject,
        "NATS push subscription active"
    );

    while let Some(msg) = subscriber.next().await {
        let extract_expr = extract_expr.cloned();
        let parsed = super::run_blocking(move || {
            super::nats::parse_nats_message(&msg.payload, format, extract_expr.as_ref())
        })
        .await;
        match parsed {
            Ok(data) => {
                let trigger = RefreshTrigger::NatsPush {
                    source_id: source_id.to_string(),
                    data,
                };
                if trigger_tx.send(trigger).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(
                    source_id = %source_id,
                    error = %e,
                    "Failed to parse NATS push message"
                );
            }
        }
    }

    Ok(())
}

/// The default NATS control subject for triggering source re-resolution.
pub const NATS_CONTROL_SUBJECT: &str = "rsigma.control.resolve";

/// Subscribe to the NATS control subject on the server `connect` names and
/// forward re-resolution triggers.
///
/// Messages with an empty payload trigger re-resolution of all sources.
/// Messages with a non-empty payload are treated as a source ID to re-resolve.
#[cfg(feature = "nats")]
pub async fn nats_control_loop(
    connect: &crate::NatsConnectConfig,
    subject: &str,
    trigger_tx: mpsc::Sender<RefreshTrigger>,
) -> Result<(), String> {
    use futures::StreamExt;

    let client = connect
        .connect()
        .await
        .map_err(|e| format!("NATS control connect failed: {e}"))?;

    let mut subscriber = client
        .subscribe(subject.to_string())
        .await
        .map_err(|e| format!("NATS control subscribe failed: {e}"))?;

    tracing::info!(
        subject = %subject,
        "NATS control subscription active for source re-resolution"
    );

    while let Some(msg) = subscriber.next().await {
        let payload = String::from_utf8_lossy(&msg.payload);
        let payload = payload.trim();

        let trigger = if payload.is_empty() {
            tracing::debug!("NATS control: triggering all sources");
            RefreshTrigger::All
        } else {
            tracing::debug!(source_id = %payload, "NATS control: triggering single source");
            RefreshTrigger::Single(payload.to_string())
        };

        if trigger_tx.send(trigger).await.is_err() {
            tracing::debug!("NATS control loop: trigger channel closed, exiting");
            break;
        }
    }

    Ok(())
}

/// Watch a file for changes and send refresh triggers.
async fn file_watch_loop(
    path: &std::path::Path,
    source_id: &str,
    trigger_tx: &mpsc::Sender<RefreshTrigger>,
) {
    use notify::{Event, EventKind, RecommendedWatcher, Watcher};
    use tokio::sync::mpsc as tokio_mpsc;

    let (notify_tx, mut notify_rx) = tokio_mpsc::channel::<()>(4);

    let _watcher = {
        let tx = notify_tx.clone();
        match RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res
                    && matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_))
                {
                    let _ = tx.try_send(());
                }
            },
            notify::Config::default(),
        ) {
            Ok(mut w) => {
                if let Err(e) = w.watch(path, notify::RecursiveMode::NonRecursive) {
                    tracing::warn!(
                        source_id = %source_id,
                        path = %path.display(),
                        error = %e,
                        "Could not watch source file"
                    );
                    return;
                }
                tracing::info!(
                    source_id = %source_id,
                    path = %path.display(),
                    "Watching source file for changes"
                );
                Some(w)
            }
            Err(e) => {
                tracing::warn!(
                    source_id = %source_id,
                    error = %e,
                    "Could not create file watcher for source"
                );
                return;
            }
        }
    };

    while notify_rx.recv().await.is_some() {
        // Debounce: wait a short period for additional changes
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        // Drain any queued notifications
        while notify_rx.try_recv().is_ok() {}

        if trigger_tx
            .send(RefreshTrigger::Single(source_id.to_string()))
            .await
            .is_err()
        {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::DefaultSourceResolver;
    use rsigma_eval::pipeline::sources::{DataFormat, ErrorPolicy, SourceType};

    fn file_source(id: &str, path: std::path::PathBuf) -> DynamicSource {
        DynamicSource {
            id: id.to_string(),
            source_type: SourceType::File {
                path,
                format: DataFormat::Json,
                extract: None,
                stix: None,
            },
            refresh: RefreshPolicy::OnDemand,
            timeout: None,
            on_error: ErrorPolicy::Fail,
            required: true,
            default: None,
        }
    }

    // A detached consumer subscribes to a single file source and receives its
    // decoded payload on the watch channel after an on-demand trigger, reusing
    // the same fetch machinery as the pipeline binder.
    #[tokio::test]
    async fn subscribe_delivers_decoded_payload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dispositions.json");
        std::fs::write(
            &path,
            r#"{"rules": [{"rule_id": "r1", "verdict": "false_positive"}]}"#,
        )
        .unwrap();

        let scheduler = RefreshScheduler::new();
        let sub = scheduler.subscribe(
            vec![file_source("d", path)],
            Arc::new(DefaultSourceResolver::new()),
        );
        let mut results = sub.results;

        sub.trigger.send(RefreshTrigger::All).await.unwrap();
        results.changed().await.unwrap();

        let payload = results.borrow().clone().expect("a refresh result");
        let data = payload.resolved.get("d").expect("source d resolved");
        assert_eq!(data["rules"][0]["rule_id"], "r1");
        assert_eq!(data["rules"][0]["verdict"], "false_positive");
    }

    fn watchlist_source(id: &str) -> DynamicSource {
        DynamicSource {
            id: id.to_string(),
            source_type: SourceType::Watchlist {
                max_indicators: 1000,
                max_value_length: 64,
                default_ttl: None,
            },
            refresh: RefreshPolicy::OnDemand,
            timeout: None,
            on_error: ErrorPolicy::UseCached,
            required: true,
            default: None,
        }
    }

    fn http_source(id: &str) -> DynamicSource {
        DynamicSource {
            id: id.to_string(),
            source_type: SourceType::Http {
                url: "http://127.0.0.1:9/never".to_string(),
                method: None,
                headers: Default::default(),
                body: None,
                format: DataFormat::Json,
                extract: None,
                stix: None,
                max_body_size: None,
            },
            refresh: RefreshPolicy::OnDemand,
            timeout: None,
            on_error: ErrorPolicy::Fail,
            required: false,
            default: None,
        }
    }

    /// Never answers for `http` sources; resolves watchlists from a registry,
    /// pausing on `gate` while it is set.
    struct HangingResolver {
        inner: DefaultSourceResolver,
        gate: Mutex<Option<Arc<Notify>>>,
        resolves: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SourceResolver for HangingResolver {
        async fn resolve(
            &self,
            source: &DynamicSource,
        ) -> Result<crate::sources::ResolvedValue, crate::sources::SourceError> {
            if matches!(source.source_type, SourceType::Http { .. }) {
                std::future::pending::<()>().await;
            }
            let gate = self.gate.lock().unwrap().clone();
            if let Some(gate) = gate {
                gate.notified().await;
            }
            self.resolves
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.resolve(source).await
        }
    }

    fn hanging(registry: &Arc<WatchlistRegistry>) -> Arc<HangingResolver> {
        Arc::new(HangingResolver {
            inner: DefaultSourceResolver::new().with_watchlists(registry.clone()),
            gate: Mutex::new(None),
            resolves: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    async fn next_value(
        results: &mut watch::Receiver<Option<RefreshResult>>,
        id: &str,
    ) -> serde_json::Value {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                results.changed().await.unwrap();
                if let Some(value) = results
                    .borrow_and_update()
                    .as_ref()
                    .and_then(|r| r.resolved.get(id).cloned())
                {
                    return value;
                }
            }
        })
        .await
        .expect("the watchlist was never re-resolved")
    }

    fn push(registry: &WatchlistRegistry, value: &str) {
        registry
            .add(
                "wl",
                &[WatchlistItem::Bare(value.to_string())],
                None,
                chrono::Utc::now(),
            )
            .unwrap();
        registry.mark_changed("wl", std::time::Instant::now());
    }

    use crate::sources::{WatchlistItem, WatchlistRegistry};

    #[tokio::test]
    async fn sources_that_never_answer_do_not_hold_up_a_watchlist() {
        let mut sources: Vec<DynamicSource> = (0..MAX_CONCURRENT_RESOLVES * 2)
            .map(|i| http_source(&format!("hung-{i}")))
            .collect();
        sources.push(watchlist_source("wl"));
        let registry = Arc::new(WatchlistRegistry::from_sources(&sources));
        let resolver = hanging(&registry);
        let scheduler = RefreshScheduler::new();
        let mut results = scheduler.result_receiver();
        let requests = scheduler.requests();
        let handle = scheduler.run(sources, resolver);

        // Every network source is now stuck, holding every shared permit.
        requests.request_all();
        tokio::task::yield_now().await;
        push(&registry, "198.51.100.7");
        requests.request_source("wl");
        while next_value(&mut results, "wl").await != serde_json::json!(["198.51.100.7"]) {}
        let status = registry.status("wl", std::time::Instant::now()).unwrap();
        assert_eq!(status.applied_revision, status.revision);
        assert_eq!(status.pending_for, None);
        handle.abort();
    }

    #[tokio::test]
    async fn requests_made_while_a_source_resolves_are_not_lost() {
        let sources = vec![watchlist_source("wl")];
        let registry = Arc::new(WatchlistRegistry::from_sources(&sources));
        let resolver = hanging(&registry);
        let gate = Arc::new(Notify::new());
        *resolver.gate.lock().unwrap() = Some(gate.clone());
        let scheduler = RefreshScheduler::new();
        let mut results = scheduler.result_receiver();
        let requests = scheduler.requests();
        let handle = scheduler.run(sources, resolver.clone());

        push(&registry, "a");
        requests.request_source("wl");
        // Far more requests than the trigger channel holds arrive while the
        // first resolve waits; they coalesce into one more resolve.
        for value in 0..100 {
            tokio::task::yield_now().await;
            push(&registry, &format!("b{value}"));
            requests.request_source("wl");
        }
        *resolver.gate.lock().unwrap() = None;
        gate.notify_one();

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let value = next_value(&mut results, "wl").await;
            if value.as_array().is_some_and(|values| values.len() == 101) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "last value: {value}"
            );
        }
        let status = registry.status("wl", std::time::Instant::now()).unwrap();
        assert_eq!(status.applied_revision, 101);
        assert!(
            resolver.resolves.load(std::sync::atomic::Ordering::SeqCst) <= 3,
            "requests coalesce"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn a_cache_first_rebuild_does_not_wait_on_an_optional_source_with_no_value() {
        let sources = vec![http_source("hung"), watchlist_source("wl")];
        let registry = Arc::new(WatchlistRegistry::from_sources(&sources));
        let resolver = hanging(&registry);
        let resolved = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            crate::sources::resolve_all_cache_first(resolver.as_ref(), &sources),
        )
        .await
        .expect("the rebuild must not fetch the optional source")
        .unwrap();
        assert_eq!(resolved["hung"], serde_json::Value::Null);
        assert_eq!(resolved["wl"], serde_json::json!([]));
    }

    #[cfg(feature = "nats")]
    #[tokio::test]
    async fn nats_push_writes_the_cache() {
        let resolver = Arc::new(DefaultSourceResolver::new());
        let scheduler = RefreshScheduler::new();
        let mut results = scheduler.result_receiver();
        let trigger = scheduler.trigger_sender();
        let handle = scheduler.run(Vec::new(), resolver.clone());

        trigger
            .send(RefreshTrigger::NatsPush {
                source_id: "feed".to_string(),
                data: serde_json::json!(["198.51.100.7"]),
            })
            .await
            .unwrap();
        results.changed().await.unwrap();

        assert_eq!(
            resolver.cache().get("feed"),
            Some(serde_json::json!(["198.51.100.7"]))
        );
        handle.abort();
    }
}
