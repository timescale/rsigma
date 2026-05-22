use std::path::Path;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

/// Watches a path for file changes and sends reload signals via a channel.
///
/// In addition to the rules path, optionally watches pipeline file paths.
/// Any YAML change in watched paths triggers a reload signal.
pub fn spawn_file_watcher(
    rules_path: &Path,
    pipeline_paths: &[&Path],
    reload_tx: mpsc::Sender<()>,
) -> Option<RecommendedWatcher> {
    let tx = reload_tx.clone();
    let mut watcher = match RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| match res {
            Ok(event) => {
                if matches!(
                    event.kind,
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                ) {
                    let is_yaml = event.paths.iter().any(|p| {
                        matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml"))
                    });
                    if is_yaml {
                        match tx.try_send(()) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                tracing::debug!(
                                    "Reload channel full, event coalesced into pending reload"
                                );
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                tracing::warn!("Reload channel closed, watcher event dropped");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "File watcher error");
            }
        },
        notify::Config::default(),
    ) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(error = %e, "Could not create file watcher, hot-reload disabled");
            return None;
        }
    };

    if let Err(e) = watcher.watch(rules_path, RecursiveMode::Recursive) {
        tracing::warn!(error = %e, path = %rules_path.display(), "Could not watch rules path");
        return None;
    }

    tracing::info!(path = %rules_path.display(), "Watching rules directory for changes");

    for path in pipeline_paths {
        if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "Could not watch pipeline file"
            );
        } else {
            tracing::info!(path = %path.display(), "Watching pipeline file for changes");
        }
    }

    Some(watcher)
}

/// Set up a SIGHUP handler that sends reload signals and source re-resolution
/// triggers, and (when `daemon-tls` is built in) also re-reads the configured
/// TLS certificate and key from disk and atomically swaps the rustls
/// `ServerConfig` so new handshakes pick up the rotated material without
/// dropping inflight connections.
#[cfg(unix)]
pub async fn sighup_listener(
    reload_tx: mpsc::Sender<()>,
    sources_trigger_tx: Option<mpsc::Sender<rsigma_runtime::sources::refresh::RefreshTrigger>>,
    #[cfg(feature = "daemon-tls")] tls_state: Option<super::tls::TlsState>,
    #[cfg(feature = "daemon-tls")] tls_metrics: std::sync::Arc<super::metrics::Metrics>,
) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sig = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "Could not register SIGHUP handler");
            return;
        }
    };

    loop {
        sig.recv().await;
        tracing::info!("SIGHUP received, triggering reload and source re-resolution");
        let _ = reload_tx.try_send(());
        if let Some(tx) = &sources_trigger_tx {
            let _ = tx.try_send(rsigma_runtime::sources::refresh::RefreshTrigger::All);
        }

        #[cfg(feature = "daemon-tls")]
        if let Some(ref state) = tls_state {
            match state.reload() {
                Ok(new_expiry) => {
                    super::server::update_tls_metrics(&tls_metrics, new_expiry);
                    super::server::warn_if_cert_expiring_soon(new_expiry);
                    tracing::info!(not_after = new_expiry, "TLS certificate hot-reloaded");
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "Failed to reload TLS certificate; keeping previous one active"
                    );
                }
            }
        }
    }
}

#[cfg(not(unix))]
pub async fn sighup_listener(
    _reload_tx: mpsc::Sender<()>,
    _sources_trigger_tx: Option<mpsc::Sender<rsigma_runtime::sources::refresh::RefreshTrigger>>,
    #[cfg(feature = "daemon-tls")] _tls_state: Option<super::tls::TlsState>,
    #[cfg(feature = "daemon-tls")] _tls_metrics: std::sync::Arc<super::metrics::Metrics>,
) {
    std::future::pending::<()>().await;
}
