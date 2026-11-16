//! Directory walking shared by the linter and the ruleset resolver.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Recursively collect `.yml`/`.yaml` file paths under `dir`, in sorted
/// depth-first order, skipping hidden directories and any path matching the
/// exclude set (relative to `base`). Symlink loops are guarded by `visited`.
pub(crate) fn collect_yaml_files(
    dir: &Path,
    base: &Path,
    exclude_set: Option<&globset::GlobSet>,
    files: &mut Vec<PathBuf>,
    visited: &mut HashSet<PathBuf>,
) -> crate::error::Result<()> {
    let canonical = match dir.canonicalize() {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };
    if !visited.insert(canonical) {
        return Ok(());
    }

    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();

        if let Some(gs) = exclude_set
            && let Ok(rel) = path.strip_prefix(base)
            && gs.is_match(rel)
        {
            continue;
        }

        if path.is_dir() {
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with('.'))
            {
                continue;
            }
            collect_yaml_files(&path, base, exclude_set, files, visited)?;
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yml" | "yaml")
        ) {
            files.push(path);
        }
    }
    Ok(())
}
