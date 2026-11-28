//! Filesystem helpers shared by commands that rewrite files in place.

use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
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
    replace(&target, contents, permissions)
}

/// Replace the directory entry at `path` atomically without following it: a
/// symlink there is replaced by a regular file and its target is left alone.
/// The parent directory must already exist.
pub(crate) fn write_no_follow(path: &Path, contents: &str) -> std::io::Result<()> {
    let permissions = fs::symlink_metadata(path)
        .ok()
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.permissions());
    replace(path, contents, permissions)
}

/// Write `path`, which must stay inside `root`. The path is refused when it
/// resolves outside `root` (see [`path_within`]), missing parent directories
/// are created, and the file is replaced through the canonical parent without
/// following a symlink at `path` itself.
pub(crate) fn write_confined(path: &Path, contents: &str, root: &Path) -> std::io::Result<()> {
    let outside = || {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("it resolves outside {}", root.display()),
        )
    };
    let Some(real_root) = resolve(root) else {
        return Err(outside());
    };
    if !resolve(path).is_some_and(|real| real.starts_with(&real_root)) {
        return Err(outside());
    }
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    fs::create_dir_all(parent)?;
    let real_parent = fs::canonicalize(parent)?;
    if !real_parent.starts_with(&real_root) {
        return Err(outside());
    }
    write_no_follow(&real_parent.join(name), contents)
}

fn replace(
    target: &Path,
    contents: &str,
    permissions: Option<fs::Permissions>,
) -> std::io::Result<()> {
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
        fs::rename(&temporary, target)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Whether `path` lies inside `dir`. Relative paths resolve against the
/// current directory, as the commands that open them do.
///
/// Each existing component is canonicalized as it is reached, so a symlink
/// (or Windows junction) anywhere along the path is followed, and `..` after
/// a component that does not exist yet folds into its parent, the way the
/// directory will once it is created. On Windows the path is first
/// normalized as Win32 opens it, so trailing dots and spaces, drive-relative
/// forms, and legacy device names such as `NUL` or `COM1` are judged by what
/// they actually name.
pub(crate) fn path_within(path: &Path, dir: &Path) -> bool {
    match (resolve(path), resolve(dir)) {
        (Some(path), Some(dir)) => path.starts_with(dir),
        _ => false,
    }
}

/// The physical location `path` names, as far as the filesystem can tell.
/// `None` when the path cannot be made absolute.
fn resolve(path: &Path) -> Option<PathBuf> {
    let absolute = std::path::absolute(path).ok()?;
    let mut real = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) => real.push(component),
            Component::CurDir => {}
            Component::ParentDir => {
                real.pop();
            }
            Component::RootDir | Component::Normal(_) => {
                real.push(component);
                if let Ok(canonical) = fs::canonicalize(&real) {
                    real = canonical;
                }
            }
        }
    }
    Some(real)
}

/// `path` with `suffix` appended to its final component, such as the
/// `<output>.manifest.json` written next to a conversion output.
pub(crate) fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_within_folds_dot_segments() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir(root.join("sub")).unwrap();
        assert!(path_within(root, root));
        assert!(path_within(&root.join("sub/./x"), root));
        assert!(path_within(&root.join("sub/../x"), root));
        assert!(path_within(&root.join("new/dirs/../x"), root));
        assert!(!path_within(&root.join("sub/../../x"), root));
        assert!(!path_within(&root.join("new/../../x"), root));
        assert!(!path_within(root.parent().unwrap(), root));
    }

    #[test]
    fn path_within_rejects_a_sibling_with_a_shared_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        let sibling = dir.path().join("project-evil");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&sibling).unwrap();
        assert!(!path_within(&sibling.join("x"), &project));
    }

    #[cfg(unix)]
    #[test]
    fn path_within_follows_symlinks_after_a_missing_component() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::os::unix::fs::symlink(outside.path(), root.join("link")).unwrap();
        assert!(!path_within(&root.join("link"), root));
        assert!(!path_within(&root.join("link/new/file"), root));
        assert!(!path_within(&root.join("missing/../link/file"), root));
        assert!(!path_within(&root.join("link/missing/../../escaped"), root));

        fs::create_dir(outside.path().join("sub")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("sub"), root.join("deep")).unwrap();
        assert!(!path_within(&root.join("deep/../x"), root));
    }

    #[cfg(unix)]
    #[test]
    fn path_within_accepts_a_symlink_that_stays_inside() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("alias")).unwrap();
        assert!(path_within(&root.join("alias/file"), root));
        let linked_root = tempfile::tempdir().unwrap();
        let alias_root = linked_root.path().join("alias-root");
        std::os::unix::fs::symlink(root, &alias_root).unwrap();
        assert!(path_within(&root.join("real/file"), &alias_root));
    }

    #[cfg(windows)]
    #[test]
    fn path_within_judges_windows_path_forms() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let text = root.display().to_string();
        assert!(path_within(Path::new(&text.to_uppercase()), root));
        assert!(path_within(
            Path::new(&format!("{}\\NEW\\file.txt", text.to_lowercase())),
            root
        ));
        assert!(path_within(
            Path::new(&format!("{text}/forward/slash")),
            root
        ));
        assert!(path_within(
            Path::new(&format!(r"\\?\{text}\verbatim.txt")),
            root
        ));
        assert!(!path_within(
            Path::new(&format!(r"\\?\{text}\..\verbatim.txt")),
            root
        ));
        assert!(!path_within(
            Path::new(&format!(r"{text}\sub\..\..\x")),
            root
        ));
        assert!(!path_within(Path::new(r"\\.\pipe\rsigma"), root));
        assert!(!path_within(Path::new(r"\rooted\file"), root));
        let other_drive = if text.starts_with(['Z', 'z']) {
            "Y:"
        } else {
            "Z:"
        };
        assert!(!path_within(Path::new(&format!(r"{other_drive}\x")), root));
        assert!(!path_within(Path::new(&format!("{other_drive}x")), root));
    }

    #[test]
    fn write_confined_creates_missing_directories_inside_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/c.txt");
        write_confined(&path, "x", dir.path()).unwrap();
        assert_eq!(fs::read_to_string(path).unwrap(), "x");
    }

    #[test]
    fn write_confined_refuses_a_path_outside_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir(&root).unwrap();
        let error = write_confined(&root.join("../escape/x.txt"), "x", &root).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!dir.path().join("escape").exists());
    }

    #[cfg(unix)]
    #[test]
    fn write_confined_refuses_a_symlinked_parent_and_replaces_a_symlinked_file() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::os::unix::fs::symlink(outside.path(), root.join("link")).unwrap();
        assert!(write_confined(&root.join("link/new/x.txt"), "x", root).is_err());
        assert!(fs::read_dir(outside.path()).unwrap().next().is_none());

        let target = root.join("target.txt");
        fs::write(&target, "kept").unwrap();
        std::os::unix::fs::symlink(&target, root.join("alias.txt")).unwrap();
        write_confined(&root.join("alias.txt"), "new", root).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "kept");
        assert!(
            fs::symlink_metadata(root.join("alias.txt"))
                .unwrap()
                .is_file()
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_no_follow_keeps_permissions_of_a_regular_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.txt");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        write_no_follow(&path, "new").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[test]
    fn with_suffix_appends_to_the_file_name() {
        assert_eq!(
            with_suffix(Path::new("build/q.sql"), ".manifest.json"),
            PathBuf::from("build/q.sql.manifest.json")
        );
    }
}
