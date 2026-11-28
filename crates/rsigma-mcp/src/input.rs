//! Shared input handling for tools that accept inline content xor a file path.

use std::path::{Component, Path, PathBuf};

use rmcp::ErrorData as McpError;

/// Resolve a tool's `yaml` (inline) xor `path` (on-disk) input into a source
/// string plus a label for diagnostics.
///
/// Exactly one of `yaml` / `path` must be set. `path` is resolved relative to
/// `root` when `root` is set and the path is relative, and must stay inside
/// `root`; this lets `mcp serve --rules-dir` scope path-based calls to a rules
/// tree.
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
            let resolved = resolve_confined_path(p, root)?;
            let text = std::fs::read_to_string(&resolved).map_err(|e| {
                McpError::invalid_params(format!("cannot read '{}': {e}", resolved.display()), None)
            })?;
            Ok((text, resolved.display().to_string()))
        }
    }
}

/// Join a possibly-relative tool path onto the optional server root, without
/// any containment check. Tools must go through [`resolve_confined_path`].
fn resolve_path(path: &str, root: Option<&Path>) -> PathBuf {
    let p = Path::new(path);
    match root {
        Some(root) if p.is_relative() => root.join(p),
        _ => p.to_path_buf(),
    }
}

/// Resolve and canonicalize a path, confining it to `root` when configured.
///
/// Both the root and candidate are canonicalized before containment is checked,
/// so absolute paths and symlink escapes fail closed.
pub(crate) fn resolve_confined_path(path: &str, root: Option<&Path>) -> Result<PathBuf, McpError> {
    let resolved = resolve_path(path, root);
    let Some(root) = root else {
        return Ok(resolved);
    };
    let canonical_root = root.canonicalize().map_err(|error| {
        McpError::invalid_params(
            format!("cannot resolve rules dir '{}': {error}", root.display()),
            None,
        )
    })?;
    let escapes = || {
        McpError::invalid_params(
            format!("path '{path}' escapes the configured --rules-dir"),
            None,
        )
    };
    // A missing file outside the root must fail the same way as an existing
    // one, so callers cannot probe for files outside the root.
    let lexically_inside = lexically_normalize(&resolved)
        .zip(lexically_normalize(root))
        .is_some_and(|(candidate, root)| candidate.starts_with(root));
    let canonical = match resolved.canonicalize() {
        Ok(canonical) => canonical,
        Err(_) if !lexically_inside => return Err(escapes()),
        Err(error) => {
            return Err(McpError::invalid_params(
                format!("cannot read '{}': {error}", resolved.display()),
                None,
            ));
        }
    };
    if !canonical.starts_with(&canonical_root) {
        return Err(escapes());
    }
    Ok(canonical)
}

/// Make `path` absolute and collapse `.` and `..` without touching the
/// filesystem.
fn lexically_normalize(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in std::path::absolute(path).ok()?.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    Some(out)
}

/// Reject a directory tree that contains symlinks when a root is configured.
///
/// The in-process walkers stay inside the root, but sigma-cli walks a
/// delegated tree itself and would follow a link out of it.
pub(crate) fn ensure_no_symlinks(dir: &Path, root: Option<&Path>) -> Result<(), McpError> {
    if root.is_none() {
        return Ok(());
    }
    let unreadable = |path: &Path, error: std::io::Error| {
        McpError::invalid_params(format!("cannot read '{}': {error}", path.display()), None)
    };
    let mut pending = vec![dir.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).map_err(|e| unreadable(&directory, e))? {
            let entry = entry.map_err(|e| unreadable(&directory, e))?;
            let file_type = entry
                .file_type()
                .map_err(|e| unreadable(&entry.path(), e))?;
            if file_type.is_symlink() {
                return Err(McpError::invalid_params(
                    format!(
                        "directory contains a symlink, which is not allowed with --rules-dir: '{}'",
                        entry.path().display()
                    ),
                    None,
                ));
            }
            if file_type.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(())
}
