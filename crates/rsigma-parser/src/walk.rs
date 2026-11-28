//! Directory walking shared by every loader of rules, pipelines, rulesets,
//! and corpora.
//!
//! [`walk_files`] visits each real directory once, so a symlink (or Windows
//! junction) that points back at an ancestor or at itself cannot loop, and
//! returns each real file once, however many links lead to it. An entry that
//! resolves outside the walk's boundary (the walked directory unless
//! [`WalkOptions::confine_to`] names another) is reported in
//! [`Walk::skipped`] and neither opened nor descended into, unless
//! [`WalkOptions::follow_external_links`] is set.
//!
//! # Example
//!
//! ```rust
//! use rsigma_parser::walk::{WalkOptions, walk_files};
//!
//! let dir = std::env::temp_dir().join(format!("rsigma-walk-doc-{}", std::process::id()));
//! std::fs::create_dir_all(dir.join("nested")).unwrap();
//! std::fs::write(dir.join("nested/rule.yml"), "title: x\n").unwrap();
//! std::fs::write(dir.join("notes.txt"), "not a rule\n").unwrap();
//!
//! let walk = walk_files(&dir, &WalkOptions::default()).unwrap();
//! assert_eq!(walk.files.len(), 1);
//! assert!(walk.files[0].path.ends_with("nested/rule.yml"));
//! assert!(walk.skipped.is_empty());
//! # std::fs::remove_dir_all(&dir).unwrap();
//! ```

use std::collections::HashSet;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, FileType};
use std::io;
use std::path::{Path, PathBuf};

/// A file found by [`walk_files`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkedFile {
    /// The path as reached from the walk root. Use it for display.
    pub path: PathBuf,
    /// The canonical location of the file. Use it to open the file.
    pub real_path: PathBuf,
}

/// Why [`walk_files`] passed over an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipReason {
    /// The entry resolves outside the walk's boundary.
    OutsideRoot,
    /// The entry is a link whose target does not exist or cannot be resolved.
    Unresolvable,
}

/// An entry [`walk_files`] did not open or descend into.
///
/// It names the entry as reached from the walk root and never its target, so
/// reporting it does not disclose anything outside the boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedEntry {
    /// The entry as reached from the walk root.
    pub path: PathBuf,
    /// Why the entry was skipped.
    pub reason: SkipReason,
}

impl fmt::Display for SkippedEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.reason {
            SkipReason::OutsideRoot => write!(
                f,
                "skipped {}: it resolves outside the directory being loaded \
                 (pass --follow-external-links to follow it)",
                self.path.display()
            ),
            SkipReason::Unresolvable => write!(
                f,
                "skipped {}: the link target cannot be resolved",
                self.path.display()
            ),
        }
    }
}

/// The result of [`walk_files`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Walk {
    /// Every accepted file, once per real file, in sorted depth-first order.
    pub files: Vec<WalkedFile>,
    /// Entries that were passed over, in the order they were reached.
    pub skipped: Vec<SkippedEntry>,
}

/// Options for [`walk_files`].
///
/// The default accepts `.yml` and `.yaml` files, descends into every
/// directory (hidden ones included), and stays inside the walked directory.
#[derive(Clone, Copy)]
pub struct WalkOptions<'a> {
    follow_external_links: bool,
    boundary: Option<&'a Path>,
    skip_hidden_dirs: bool,
    skip_hidden_files: bool,
    max_depth: Option<usize>,
    accept: fn(&Path) -> bool,
    pub(crate) exclude: Option<&'a globset::GlobSet>,
}

impl Default for WalkOptions<'_> {
    fn default() -> Self {
        Self {
            follow_external_links: false,
            boundary: None,
            skip_hidden_dirs: false,
            skip_hidden_files: false,
            max_depth: None,
            accept: has_yaml_extension,
            exclude: None,
        }
    }
}

impl fmt::Debug for WalkOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalkOptions")
            .field("follow_external_links", &self.follow_external_links)
            .field("boundary", &self.boundary)
            .field("skip_hidden_dirs", &self.skip_hidden_dirs)
            .field("skip_hidden_files", &self.skip_hidden_files)
            .field("max_depth", &self.max_depth)
            .finish_non_exhaustive()
    }
}

impl<'a> WalkOptions<'a> {
    /// Options with the defaults described on [`WalkOptions`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Follow links that resolve outside the boundary instead of skipping
    /// them. Cycles are still detected and files still load once.
    pub fn follow_external_links(mut self, follow: bool) -> Self {
        self.follow_external_links = follow;
        self
    }

    /// Whether links outside the boundary are followed.
    pub fn follows_external_links(&self) -> bool {
        self.follow_external_links
    }

    /// Use `boundary` instead of the walked directory as the boundary. The
    /// walked directory must itself resolve inside it.
    pub fn confine_to(mut self, boundary: &'a Path) -> Self {
        self.boundary = Some(boundary);
        self
    }

    /// Do not descend into directories whose name starts with `.`.
    pub fn skip_hidden_dirs(mut self, skip: bool) -> Self {
        self.skip_hidden_dirs = skip;
        self
    }

    /// Do not return files whose name starts with `.`.
    pub fn skip_hidden_files(mut self, skip: bool) -> Self {
        self.skip_hidden_files = skip;
        self
    }

    /// Descend at most `depth` directories below the walked one; `0` lists
    /// only the walked directory's own files.
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = Some(depth);
        self
    }

    /// Return the files `accept` holds for, judged by the path as reached
    /// from the walk root. The default is [`has_yaml_extension`].
    pub fn accept(mut self, accept: fn(&Path) -> bool) -> Self {
        self.accept = accept;
        self
    }

    pub(crate) fn exclude(mut self, exclude: Option<&'a globset::GlobSet>) -> Self {
        self.exclude = exclude;
        self
    }
}

/// Whether `path` ends in `.yml` or `.yaml`.
pub fn has_yaml_extension(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yml" | "yaml")
    )
}

/// Accept every file.
pub fn any_file(_: &Path) -> bool {
    true
}

struct Pending {
    path: PathBuf,
    real_parent: PathBuf,
    name: OsString,
    file_type: FileType,
    depth: usize,
}

/// Recursively collect the files under `root` that `options` accepts.
///
/// Fails when `root` cannot be resolved or read, when a directory under it
/// cannot be read, or when `root` itself resolves outside the boundary set
/// with [`WalkOptions::confine_to`] and external links are not followed.
pub fn walk_files(root: &Path, options: &WalkOptions<'_>) -> io::Result<Walk> {
    let real_root = fs::canonicalize(root)?;
    let boundary = match options.boundary {
        Some(boundary) => fs::canonicalize(boundary)?,
        None => real_root.clone(),
    };
    if !options.follow_external_links && !real_root.starts_with(&boundary) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} resolves outside {}",
                root.display(),
                options.boundary.unwrap_or(root).display()
            ),
        ));
    }

    let mut walk = Walk::default();
    let mut visited = HashSet::from([real_root.clone()]);
    let mut seen_files = HashSet::new();
    let mut stack = Vec::new();
    push_children(&mut stack, root, &real_root, 0)?;

    while let Some(entry) = stack.pop() {
        if let Some(exclude) = options.exclude
            && let Ok(relative) = entry.path.strip_prefix(root)
            && exclude.is_match(relative)
        {
            continue;
        }
        let hidden = entry.name.to_string_lossy().starts_with('.');

        let (real, is_dir, is_file) = if entry.file_type.is_symlink() {
            match fs::canonicalize(&entry.path).and_then(|real| {
                let metadata = fs::metadata(&real)?;
                Ok((real, metadata.is_dir(), metadata.is_file()))
            }) {
                Ok(resolved) => resolved,
                Err(_) => {
                    if (options.accept)(&entry.path) {
                        walk.skipped.push(SkippedEntry {
                            path: entry.path,
                            reason: SkipReason::Unresolvable,
                        });
                    }
                    continue;
                }
            }
        } else {
            (
                entry.real_parent.join(&entry.name),
                entry.file_type.is_dir(),
                entry.file_type.is_file(),
            )
        };

        if is_dir {
            if hidden && options.skip_hidden_dirs {
                continue;
            }
            if options.max_depth.is_some_and(|max| entry.depth >= max) {
                continue;
            }
            if !options.follow_external_links && !real.starts_with(&boundary) {
                walk.skipped.push(SkippedEntry {
                    path: entry.path,
                    reason: SkipReason::OutsideRoot,
                });
                continue;
            }
            if !visited.insert(real.clone()) {
                continue;
            }
            push_children(&mut stack, &entry.path, &real, entry.depth + 1)?;
        } else if is_file {
            if (hidden && options.skip_hidden_files) || !(options.accept)(&entry.path) {
                continue;
            }
            if !options.follow_external_links && !real.starts_with(&boundary) {
                walk.skipped.push(SkippedEntry {
                    path: entry.path,
                    reason: SkipReason::OutsideRoot,
                });
                continue;
            }
            if seen_files.insert(real.clone()) {
                walk.files.push(WalkedFile {
                    path: entry.path,
                    real_path: real,
                });
            }
        }
    }
    Ok(walk)
}

/// Queue the entries of `dir` so they pop in sorted order.
fn push_children(
    stack: &mut Vec<Pending>,
    dir: &Path,
    real_dir: &Path,
    depth: usize,
) -> io::Result<()> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(real_dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let name = entry.file_name();
        entries.push(Pending {
            path: dir.join(&name),
            real_parent: real_dir.to_path_buf(),
            name,
            file_type,
            depth,
        });
    }
    entries.sort_by(|a, b| b.name.cmp(&a.name));
    stack.extend(entries);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, "title: t\n").unwrap();
    }

    fn names(walk: &Walk, root: &Path) -> Vec<String> {
        walk.files
            .iter()
            .map(|f| {
                f.path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect()
    }

    #[test]
    fn sorted_depth_first_with_yaml_filter() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("b.yml"));
        write(&dir.path().join("a/z.yaml"));
        write(&dir.path().join("a/y.txt"));
        write(&dir.path().join("c.yml"));
        let walk = walk_files(dir.path(), &WalkOptions::default()).unwrap();
        assert_eq!(names(&walk, dir.path()), ["a/z.yaml", "b.yml", "c.yml"]);
    }

    #[test]
    fn hidden_and_depth_options() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join(".git/x.yml"));
        write(&dir.path().join(".hidden.yml"));
        write(&dir.path().join("sub/deep.yml"));
        write(&dir.path().join("top.yml"));

        let all = walk_files(dir.path(), &WalkOptions::default()).unwrap();
        assert_eq!(
            names(&all, dir.path()),
            [".git/x.yml", ".hidden.yml", "sub/deep.yml", "top.yml"]
        );

        let options = WalkOptions::new()
            .skip_hidden_dirs(true)
            .skip_hidden_files(true);
        let visible = walk_files(dir.path(), &options).unwrap();
        assert_eq!(names(&visible, dir.path()), ["sub/deep.yml", "top.yml"]);

        let flat = walk_files(dir.path(), &WalkOptions::new().max_depth(0)).unwrap();
        assert_eq!(names(&flat, dir.path()), [".hidden.yml", "top.yml"]);
    }

    #[test]
    fn root_outside_boundary_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let inside = dir.path().join("inside");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&inside).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let error = walk_files(&outside, &WalkOptions::new().confine_to(&inside)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            walk_files(
                &outside,
                &WalkOptions::new()
                    .confine_to(&inside)
                    .follow_external_links(true)
            )
            .is_ok()
        );
    }

    #[test]
    fn missing_root_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(walk_files(&dir.path().join("missing"), &WalkOptions::default()).is_err());
    }
}
