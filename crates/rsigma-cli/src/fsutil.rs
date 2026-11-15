//! Filesystem helpers shared by commands that rewrite files in place.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Unique suffix for sibling temporary files, so concurrent writes in one
/// process cannot collide on the same name.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Replace `path` atomically: write a sibling temporary file, sync it, copy the
/// target's permissions when it already exists, then rename over the target.
pub(crate) fn atomic_write(path: &Path, contents: &str) -> std::io::Result<()> {
    let target = match fs::canonicalize(path) {
        Ok(target) => target,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => path.to_path_buf(),
        Err(error) => return Err(error),
    };
    let permissions = fs::metadata(&target)
        .ok()
        .map(|metadata| metadata.permissions());
    let dir = target.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    let file_name = target
        .file_name()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
        })?
        .to_string_lossy();
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = dir.join(format!(
        ".{file_name}.rsigma-{}-{counter}.tmp",
        std::process::id()
    ));

    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        if let Some(permissions) = permissions {
            file.set_permissions(permissions)?;
        }
        fs::rename(&temporary, &target)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
