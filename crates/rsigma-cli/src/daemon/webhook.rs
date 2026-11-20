//! Daemon-side loader for webhook config files and directories.
//!
//! Mirrors the `--source` loader: each `--webhook` path is a YAML file with a
//! top-level `webhooks:` block, or a directory whose `*.yml`/`*.yaml` files are
//! loaded alphabetically. All webhooks across all paths are merged and built
//! together so they share one process-level egress-filtered HTTP client.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rsigma_runtime::{BuiltWebhook, MetricsHook, WebhooksFile, build_webhooks, load_webhooks_file};

/// Load, merge, validate, and build every webhook under `paths`.
///
/// Returns a human-readable error string (for direct CLI reporting) on any I/O,
/// parse, duplicate-id, or validation failure.
pub fn load_and_build_webhooks(
    paths: &[PathBuf],
    metrics: Arc<dyn MetricsHook>,
) -> Result<Vec<BuiltWebhook>, String> {
    let merged = load_webhook_paths(paths)?;

    // Duplicate ids would collide on the per-sink and webhook metric labels.
    let mut seen = std::collections::HashSet::new();
    for webhook in &merged.webhooks {
        if !seen.insert(webhook.id.clone()) {
            return Err(format!("duplicate webhook id '{}'", webhook.id));
        }
    }

    build_webhooks(merged, metrics).map_err(|e| e.to_string())
}

/// Load and merge every webhook file named by `paths`, expanding directories.
pub fn load_webhook_paths(paths: &[PathBuf]) -> Result<WebhooksFile, String> {
    let mut merged = WebhooksFile {
        webhooks: Vec::new(),
    };
    for path in paths {
        for file in expand(path)? {
            let parsed = load_webhooks_file(&file).map_err(|e| e.to_string())?;
            merged.webhooks.extend(parsed.webhooks);
        }
    }
    Ok(merged)
}

/// Expand one path into the list of YAML files to load: a directory yields its
/// `*.yml`/`*.yaml` children (sorted); a file yields itself.
fn expand(path: &Path) -> Result<Vec<PathBuf>, String> {
    if path.is_dir() {
        let mut files: Vec<PathBuf> = std::fs::read_dir(path)
            .map_err(|e| format!("failed to read webhook dir '{}': {e}", path.display()))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|ext| ext == "yml" || ext == "yaml")
            })
            .collect();
        files.sort();
        Ok(files)
    } else {
        Ok(vec![path.to_path_buf()])
    }
}
