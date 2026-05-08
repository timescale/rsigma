//! Background refresh scheduler for dynamic pipeline sources.
//!
//! Manages per-source refresh loops based on `RefreshPolicy`:
//! - `Interval(duration)`: re-fetches on a timer
//! - `Watch`: uses file system notifications (via `notify`)
//! - `Push`: receives updates from external triggers (NATS)
//! - `OnDemand`: only refreshes when explicitly triggered via API/signal

use std::collections::HashMap;
use std::sync::Arc;

use rsigma_eval::pipeline::sources::{DynamicSource, RefreshPolicy, SourceType};
use tokio::sync::{mpsc, watch};

use super::{SourceResolver, resolve_all};

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

/// Notification sent when sources have been refreshed.
#[derive(Debug, Clone)]
pub struct RefreshResult {
    /// The newly resolved source data (source_id -> value).
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
        }
    }

    /// Get a sender for triggering on-demand resolution.
    pub fn trigger_sender(&self) -> mpsc::Sender<RefreshTrigger> {
        self.trigger_tx.clone()
    }

    /// Get a receiver that is notified when sources are refreshed.
    pub fn result_receiver(&self) -> watch::Receiver<Option<RefreshResult>> {
        self.result_rx.clone()
    }

    /// Start the scheduler background loop.
    ///
    /// Takes ownership of the trigger receiver and spawns per-source interval tasks.
    /// Returns a `JoinHandle` for the main coordination task.
    ///
    /// When a refresh occurs (via interval timer or on-demand trigger), all sources
    /// are re-resolved and the result is published on the watch channel.
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
                let url = url.clone();
                let subject = subject.clone();
                let format = *format;
                let extract_expr = extract_expr.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        nats_push_loop(&url, &subject, format, extract_expr.as_ref(), &id, &tx)
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

        // Main loop: wait for triggers and resolve
        while let Some(trigger) = trigger_rx.recv().await {
            // Handle NATS push with pre-parsed data (no re-resolution needed)
            #[cfg(feature = "nats")]
            if let RefreshTrigger::NatsPush { source_id, data } = trigger {
                let mut resolved = HashMap::new();
                resolved.insert(source_id, data);
                let _ = result_tx.send(Some(RefreshResult { resolved }));
                continue;
            }

            let to_resolve: Vec<&DynamicSource> = match &trigger {
                RefreshTrigger::All => sources.iter().collect(),
                RefreshTrigger::Single(id) => sources.iter().filter(|s| s.id == *id).collect(),
                #[cfg(feature = "nats")]
                RefreshTrigger::NatsPush { .. } => unreachable!(),
            };

            if to_resolve.is_empty() {
                continue;
            }

            match resolve_all(
                resolver.as_ref(),
                &to_resolve.iter().map(|s| (*s).clone()).collect::<Vec<_>>(),
            )
            .await
            {
                Ok(resolved) => {
                    let _ = result_tx.send(Some(RefreshResult { resolved }));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Background source refresh failed");
                }
            }
        }
    }
}

impl Default for RefreshScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Subscribe to a NATS subject and forward parsed messages as triggers.
#[cfg(feature = "nats")]
async fn nats_push_loop(
    url: &str,
    subject: &str,
    format: rsigma_eval::pipeline::sources::DataFormat,
    extract_expr: Option<&rsigma_eval::pipeline::sources::ExtractExpr>,
    source_id: &str,
    trigger_tx: &mpsc::Sender<RefreshTrigger>,
) -> Result<(), String> {
    use futures::StreamExt;

    let client = async_nats::connect(url)
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
        match super::nats::parse_nats_message(&msg.payload, format, extract_expr) {
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

/// Subscribe to the NATS control subject and forward re-resolution triggers.
///
/// Messages with an empty payload trigger re-resolution of all sources.
/// Messages with a non-empty payload are treated as a source ID to re-resolve.
#[cfg(feature = "nats")]
pub async fn nats_control_loop(
    url: &str,
    subject: &str,
    trigger_tx: mpsc::Sender<RefreshTrigger>,
) -> Result<(), String> {
    use futures::StreamExt;

    let client = async_nats::connect(url)
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
