//! Shared input handling for tools that accept inline content xor a file path.

use std::path::{Path, PathBuf};

use rmcp::ErrorData as McpError;

/// Resolve a tool's `yaml` (inline) xor `path` (on-disk) input into a source
/// string plus a label for diagnostics.
///
/// Exactly one of `yaml` / `path` must be set. `path` is resolved relative to
/// `root` when `root` is set and the path is relative; this lets `mcp serve
/// --rules-dir` scope path-based calls to a rules tree.
pub(crate) fn load_source(
    yaml: Option<&str>,
    path: Option<&str>,
    root: Option<&Path>,
) -> Result<(String, String), McpError> {
    match (yaml, path) {
        (Some(_), Some(_)) => Err(McpError::invalid_params(
            "provide either `yaml` or `path`, not both",
            None,
        )),
        (None, None) => Err(McpError::invalid_params(
            "one of `yaml` or `path` is required",
            None,
        )),
        (Some(text), None) => Ok((text.to_string(), "<inline>".to_string())),
        (None, Some(p)) => {
            let resolved = resolve_path(p, root);
            let text = std::fs::read_to_string(&resolved).map_err(|e| {
                McpError::invalid_params(format!("cannot read '{}': {e}", resolved.display()), None)
            })?;
            Ok((text, resolved.display().to_string()))
        }
    }
}

/// Resolve a possibly-relative tool path against the optional server root.
pub(crate) fn resolve_path(path: &str, root: Option<&Path>) -> PathBuf {
    let p = Path::new(path);
    match root {
        Some(root) if p.is_relative() => root.join(p),
        _ => p.to_path_buf(),
    }
}
