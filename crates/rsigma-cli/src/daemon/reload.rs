use std::path::Path;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

/// Watches a path for file changes and sends reload signals via a channel.
pub fn spawn_file_watcher(
    rules_path: &Path,
    reload_tx: mpsc::Sender<()>,
) -> Option<RecommendedWatcher> {
    let tx = reload_tx.clone();
    let mut watcher = match RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res
                && matches!(
                    event.kind,
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                )
            {
                let is_yaml = event.paths.iter().any(|p| {
                    matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml"))
                });
                if is_yaml {
                    let _ = tx.try_send(());
                }
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
    Some(watcher)
}

/// Set up a SIGHUP handler that sends reload signals.
#[cfg(unix)]
pub async fn sighup_listener(reload_tx: mpsc::Sender<()>) {
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
        tracing::info!("SIGHUP received, triggering reload");
        let _ = reload_tx.try_send(());
    }
}

#[cfg(not(unix))]
pub async fn sighup_listener(_reload_tx: mpsc::Sender<()>) {
    // No-op on non-Unix platforms
    std::future::pending::<()>().await;
}
