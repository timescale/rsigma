//! `rsigma rule fmt`: rewrite Sigma rules into the canonical layout.
//!
//! The formatter itself lives in `rsigma-parser`. This command collects files,
//! reports which ones would change, optionally writes them, and keeps the
//! stream contract: stdout carries data (paths, diffs, `--stdout` text) and
//! stderr carries progress, warnings, errors, and the summary.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use clap::Args;
use similar::TextDiff;

use rsigma_parser::{FormatError, format_yaml};

use crate::exit_code::{CONFIG_ERROR, FINDINGS, RULE_ERROR, SUCCESS};
use crate::output::{OutputCtx, Painter};

/// Arguments for `rsigma rule fmt`.
#[derive(Args, Debug)]
pub(crate) struct FmtArgs {
    /// Sigma rule files or directories to format (default: the current directory)
    #[arg(value_name = "PATHS")]
    pub paths: Vec<PathBuf>,

    /// Exit 1 when any file would be reformatted
    #[arg(long)]
    pub check: bool,

    /// Print a unified diff for each file that would change, and exit 1 if any would
    #[arg(long)]
    pub diff: bool,

    /// Rewrite files in place
    #[arg(long)]
    pub write: bool,

    /// Print the formatted text of one file to stdout
    #[arg(long)]
    pub stdout: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Stdout,
    Write,
    Diff,
    Check,
    Report,
}

/// Files found for formatting plus collector errors.
struct Collected {
    files: Vec<PathBuf>,
    errors: usize,
}

pub(crate) fn cmd_fmt(args: FmtArgs, ctx: OutputCtx) -> i32 {
    let mode = match validate(&args) {
        Ok(mode) => mode,
        Err(message) => {
            eprintln!("error: {message}");
            return CONFIG_ERROR;
        }
    };

    if ctx.explicit_format {
        ctx.warn_unsupported("rule fmt", "text output");
    }

    if mode == Mode::Stdout {
        return stdout_mode(&args.paths[0], &ctx);
    }

    if args.paths.len() == 1 && is_stdin(&args.paths[0]) {
        return stdin_mode(mode, &ctx);
    }

    let roots: Vec<PathBuf> = if args.paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        args.paths.clone()
    };
    let implicit_root = args.paths.is_empty();
    let collected = collect(&roots, implicit_root);
    let mut failed = collected.errors;

    let mut changed = 0usize;
    let mut already = 0usize;
    let mut skipped = 0usize;
    let painter = Painter::new(ctx.color);

    for path in &collected.files {
        let display = display_path(path, implicit_root);
        let source = match fs::read_to_string(path) {
            Ok(source) => source,
            Err(error) => {
                eprintln!("error: {display}: {error}");
                failed += 1;
                continue;
            }
        };
        let outcome = match format_yaml(&source) {
            Ok(outcome) => outcome,
            Err(error @ FormatError::NotSigma { .. }) => {
                if ctx.show_progress() {
                    eprintln!("skipped: {display}: {error}");
                }
                skipped += 1;
                continue;
            }
            Err(error) => {
                eprintln!("error: {display}: {error}");
                failed += 1;
                continue;
            }
        };

        if !outcome.changed {
            already += 1;
            continue;
        }

        match mode {
            Mode::Report | Mode::Check => {
                println!("Would reformat: {display}");
                changed += 1;
            }
            Mode::Diff => {
                print_diff(&display, &source, &outcome.formatted, &painter);
                changed += 1;
            }
            Mode::Write => match atomic_write(path, &outcome.formatted) {
                Ok(()) => {
                    if ctx.show_progress() {
                        eprintln!("Reformatted: {display}");
                    }
                    changed += 1;
                }
                Err(error) => {
                    eprintln!("error: {display}: {error}");
                    failed += 1;
                }
            },
            Mode::Stdout => unreachable!("stdout mode returns early"),
        }
    }

    report_summary(&ctx, mode, changed, already, skipped, failed);
    exit_code(mode, changed, failed)
}

/// Validate the flag combination and pick the mode. The conflict pairs are
/// checked in the order the plan documents so the first reported message is
/// deterministic.
fn validate(args: &FmtArgs) -> Result<Mode, String> {
    let conflicts = [
        (args.write, "--write", args.check, "--check"),
        (args.write, "--write", args.diff, "--diff"),
        (args.write, "--write", args.stdout, "--stdout"),
        (args.stdout, "--stdout", args.check, "--check"),
        (args.stdout, "--stdout", args.diff, "--diff"),
    ];
    for (a, a_name, b, b_name) in conflicts {
        if a && b {
            return Err(format!("`{a_name}` cannot be combined with `{b_name}`"));
        }
    }

    let stdin_count = args.paths.iter().filter(|path| is_stdin(path)).count();
    if stdin_count > 1 {
        return Err("`-` can appear only once".to_string());
    }
    if stdin_count == 1 && args.paths.len() > 1 {
        return Err("`-` cannot be combined with file paths".to_string());
    }
    if stdin_count == 1 && args.write {
        return Err("`--write` cannot be used with `-`".to_string());
    }

    if args.stdout {
        if args.paths.len() != 1 {
            return Err("`--stdout` needs exactly one file path".to_string());
        }
        if args.paths[0].is_dir() {
            return Err(format!(
                "`--stdout` needs a file, but `{}` is a directory",
                display_path(&args.paths[0], false)
            ));
        }
        return Ok(Mode::Stdout);
    }
    if args.write {
        return Ok(Mode::Write);
    }
    if args.diff {
        return Ok(Mode::Diff);
    }
    if args.check {
        return Ok(Mode::Check);
    }
    Ok(Mode::Report)
}

/// Print the formatted text of one file. A non-Sigma file is echoed unchanged
/// so editor integrations never blank a buffer.
fn stdout_mode(path: &Path, ctx: &OutputCtx) -> i32 {
    let label = input_label(path);
    let source = match read_source(path) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("error: {label}: {error}");
            return RULE_ERROR;
        }
    };
    match format_yaml(&source) {
        Ok(outcome) => {
            print!("{}", outcome.formatted);
            SUCCESS
        }
        Err(FormatError::NotSigma { .. }) => {
            if ctx.show_progress() {
                eprintln!("skipped: {label}: not a Sigma document");
            }
            print!("{source}");
            SUCCESS
        }
        Err(error) => {
            eprintln!("error: {label}: {error}");
            RULE_ERROR
        }
    }
}

/// Report and diff a single document read from stdin.
fn stdin_mode(mode: Mode, ctx: &OutputCtx) -> i32 {
    let source = match read_source(Path::new("-")) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("error: <stdin>: {error}");
            return RULE_ERROR;
        }
    };
    let mut changed = 0usize;
    let mut already = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    match format_yaml(&source) {
        Ok(outcome) => {
            if !outcome.changed {
                already += 1;
            } else {
                changed += 1;
                match mode {
                    Mode::Report | Mode::Check => println!("Would reformat: <stdin>"),
                    Mode::Diff => print_diff(
                        "<stdin>",
                        &source,
                        &outcome.formatted,
                        &Painter::new(ctx.color),
                    ),
                    Mode::Write | Mode::Stdout => unreachable!("stdin has no write or stdout mode"),
                }
            }
        }
        Err(FormatError::NotSigma { .. }) => {
            if ctx.show_progress() {
                eprintln!("skipped: <stdin>: not a Sigma document");
            }
            skipped += 1;
        }
        Err(error) => {
            eprintln!("error: <stdin>: {error}");
            failed += 1;
        }
    }
    report_summary(ctx, mode, changed, already, skipped, failed);
    exit_code(mode, changed, failed)
}

fn read_source(path: &Path) -> io::Result<String> {
    if is_stdin(path) {
        let mut source = String::new();
        io::stdin().read_to_string(&mut source)?;
        Ok(source)
    } else {
        fs::read_to_string(path)
    }
}

fn is_stdin(path: &Path) -> bool {
    path.as_os_str() == "-"
}

fn input_label(path: &Path) -> String {
    if is_stdin(path) {
        "<stdin>".to_string()
    } else {
        display_path(path, false)
    }
}

fn report_summary(
    ctx: &OutputCtx,
    mode: Mode,
    changed: usize,
    already: usize,
    skipped: usize,
    failed: usize,
) {
    if !ctx.show_stats() {
        return;
    }
    let mut summary = if mode == Mode::Write {
        format!("{changed} reformatted, {already} already formatted, {skipped} skipped")
    } else {
        format!("{changed} would be reformatted, {already} already formatted, {skipped} skipped")
    };
    if failed > 0 {
        summary.push_str(&format!(", {failed} failed"));
    }
    if mode != Mode::Write && changed > 0 {
        summary.push_str(" (run with --write to apply)");
    }
    eprintln!("{summary}");
}

fn exit_code(mode: Mode, changed: usize, failed: usize) -> i32 {
    if failed > 0 {
        RULE_ERROR
    } else if matches!(mode, Mode::Check | Mode::Diff) && changed > 0 {
        FINDINGS
    } else {
        SUCCESS
    }
}

/// Collect files under the given roots. An explicit file argument is accepted
/// whatever its extension; directory walks add `yml`/`yaml` files only.
fn collect(roots: &[PathBuf], implicit_root: bool) -> Collected {
    let mut collected = Collected {
        files: Vec::new(),
        errors: 0,
    };
    let mut seen: HashSet<PathBuf> = HashSet::new();

    for root in roots {
        match fs::metadata(root) {
            Ok(metadata) if metadata.is_file() => {
                add_file(root.clone(), implicit_root, &mut seen, &mut collected);
            }
            Ok(metadata) if metadata.is_dir() => {
                walk_dir(root, implicit_root, &mut seen, &mut collected);
            }
            Ok(_) => {
                // Neither a regular file nor a directory (for example a
                // socket); treat it as an error rather than silently skip it.
                eprintln!("error: {}: not a file or directory", root.display());
                collected.errors += 1;
            }
            Err(error) => {
                eprintln!("error: {}: {error}", root.display());
                collected.errors += 1;
            }
        }
    }
    collected
}

fn add_file(
    path: PathBuf,
    implicit_root: bool,
    seen: &mut HashSet<PathBuf>,
    collected: &mut Collected,
) {
    let key = match fs::canonicalize(&path) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("error: {}: {error}", display_path(&path, implicit_root));
            collected.errors += 1;
            return;
        }
    };
    if seen.insert(key) {
        collected.files.push(path);
    }
}

fn walk_dir(
    dir: &Path,
    implicit_root: bool,
    seen: &mut HashSet<PathBuf>,
    collected: &mut Collected,
) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("error: {}: {error}", dir.display());
            collected.errors += 1;
            return;
        }
    };
    let mut entries: Vec<_> = match entries.collect::<Result<Vec<_>, _>>() {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("error: {}: {error}", dir.display());
            collected.errors += 1;
            return;
        }
    };
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                eprintln!("error: {}: {error}", path.display());
                collected.errors += 1;
                continue;
            }
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            walk_dir(&path, implicit_root, seen, collected);
        } else if file_type.is_file() {
            let extension = path.extension().and_then(|value| value.to_str());
            if matches!(extension, Some("yml") | Some("yaml")) {
                add_file(path, implicit_root, seen, collected);
            }
        }
    }
}

/// Display path: the path as walked, with `/` separators on every platform.
/// Under the implicit `.` root, drop the leading `./` so output reads like the
/// user typed it.
fn display_path(path: &Path, implicit_root: bool) -> String {
    let display = path
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    if implicit_root {
        display.strip_prefix("./").unwrap_or(&display).to_string()
    } else {
        display
    }
}

/// Print a unified diff for one file, colored per line kind.
fn print_diff(path: &str, before: &str, after: &str, painter: &Painter) {
    let diff = TextDiff::from_lines(before, after)
        .unified_diff()
        .context_radius(3)
        .header(&format!("a/{path}"), &format!("b/{path}"))
        .to_string();
    for line in diff.lines() {
        let rendered = if line.starts_with("@@") {
            painter.cyan(line)
        } else if line.starts_with('+') {
            painter.green(line)
        } else if line.starts_with('-') {
            painter.red(line)
        } else {
            line.to_string()
        };
        println!("{rendered}");
    }
}

/// Replace `path` atomically: write a sibling temporary file, sync it, copy the
/// target's permissions, then rename over the target.
fn atomic_write(path: &Path, contents: &str) -> std::io::Result<()> {
    let target = fs::canonicalize(path)?;
    let permissions = fs::metadata(&target)?.permissions();
    let dir = target.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    let file_name = target
        .file_name()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
        })?
        .to_string_lossy();
    let temporary = dir.join(format!(".{file_name}.rsigma-fmt-{}.tmp", process::id()));

    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        file.set_permissions(permissions)?;
        fs::rename(&temporary, &target)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
