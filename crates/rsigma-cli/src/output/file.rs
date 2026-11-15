//! Buffered CLI output files and path identity for those files.
//!
//! A findings or `--output` path is compared after the path is made absolute
//! and `.` / `..` are removed, then after the existing prefix is canonicalized.
//! That treats `./x` and `x` as one file, and treats a path inside a corpus
//! directory as that directory's contents, including a file that does not
//! exist yet.

use std::fs::File;
use std::io::{self, BufWriter};
use std::path::{Component, Path, PathBuf};

/// Buffered destination. A write failure exits with
/// [`crate::exit_code::CONFIG_ERROR`] so a truncated file never looks like a
/// successful run.
pub(crate) struct OutputFile {
    path: PathBuf,
    pub(crate) writer: BufWriter<File>,
}

impl OutputFile {
    pub(crate) fn create(path: PathBuf) -> Self {
        match File::create(&path) {
            Ok(file) => Self {
                path,
                writer: BufWriter::new(file),
            },
            Err(e) => {
                eprintln!("error: cannot create output file '{}': {e}", path.display());
                std::process::exit(crate::exit_code::CONFIG_ERROR);
            }
        }
    }

    pub(crate) fn check(&self, result: io::Result<()>) {
        if let Err(e) = result {
            eprintln!(
                "error: failed to write output file '{}': {e}",
                self.path.display()
            );
            std::process::exit(crate::exit_code::CONFIG_ERROR);
        }
    }
}

/// `true` when both paths name the same file, after `.` / `..` and symlinks.
pub(crate) fn same_output_path(a: &Path, b: &Path) -> bool {
    resolve_output_path(a) == resolve_output_path(b)
}

/// `true` when `file` is a path inside the directory `dir`.
///
/// A file that does not exist yet still counts, so creating it would add a
/// new file to a directory that is about to be walked.
pub(crate) fn output_path_is_inside(file: &Path, dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let file = resolve_output_path(file);
    let dir = resolve_output_path(dir);
    file.starts_with(&dir) && file != dir
}

fn resolve_output_path(path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let lexical = lexical_normalize(&abs);
    if let Ok(canon) = std::fs::canonicalize(&lexical) {
        return canon;
    }
    let mut tail = Vec::new();
    let mut cursor = lexical.as_path();
    while !cursor.as_os_str().is_empty() && !cursor.exists() {
        let Some(name) = cursor.file_name() else {
            break;
        };
        tail.push(name.to_os_string());
        match cursor.parent() {
            Some(parent) if parent != cursor => cursor = parent,
            _ => break,
        }
    }
    let Ok(base) = std::fs::canonicalize(cursor) else {
        return lexical;
    };
    let mut out = base;
    for name in tail.iter().rev() {
        out.push(name);
    }
    out
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push(component);
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_component_names_the_same_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x.ndjson");
        std::fs::write(&file, "keep\n").unwrap();
        let dotted = dir.path().join(".").join("x.ndjson");
        assert!(same_output_path(&file, &dotted));
        let body = std::fs::read_to_string(&file).unwrap();
        assert_eq!(body, "keep\n");
    }

    #[test]
    fn a_missing_file_inside_a_directory_is_inside_that_directory() {
        let dir = tempfile::tempdir().unwrap();
        let corpus = dir.path().join("c");
        std::fs::create_dir(&corpus).unwrap();
        let findings = corpus.join("out.ndjson");
        assert!(output_path_is_inside(&findings, &corpus));
        assert!(!output_path_is_inside(
            &dir.path().join("out.ndjson"),
            &corpus
        ));
        let lookalike = dir.path().join("c-extra").join("out.ndjson");
        assert!(!output_path_is_inside(&lookalike, &corpus));
    }
}
