//! Integration tests for rsigma rule fmt: modes, flag conflicts, file collection, write safety, and exit codes.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::rsigma;
use predicates::prelude::*;

const UNFORMATTED: &str = "title: Test\nlogsource:\n  category: test\ndetection:\n  selection:\n    Field: value\n  condition: selection\n";

const FORMATTED: &str = "title: Test\nlogsource:\n    category: test\ndetection:\n    selection:\n        Field: value\n    condition: selection\n";

const NON_SIGMA: &str = "name: test\npipeline:\n    - id: one\n";

const MALFORMED: &str = "title: [unclosed\n";

fn write_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, contents).unwrap();
    path
}

fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The CLI prints `/` separators on every platform.
fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn report_lists_unformatted_files_and_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(dir.path(), "rule.yml", UNFORMATTED);
    let output = rsigma()
        .args(["rule", "fmt", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(stdout_of(&output).contains(&format!("Would reformat: {}", slash(&path))));
}

#[test]
fn report_formatted_file_prints_nothing_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "rule.yml", FORMATTED);
    let output = rsigma()
        .args(["rule", "fmt", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(stdout_of(&output).is_empty());
}

#[test]
fn check_exits_one_when_a_file_would_change() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "rule.yml", UNFORMATTED);
    rsigma()
        .args(["rule", "fmt", "--check", dir.path().to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Would reformat:"));
}

#[test]
fn check_exits_zero_when_all_formatted() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "rule.yml", FORMATTED);
    rsigma()
        .args(["rule", "fmt", "--check", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn stdin_is_formatted_with_stdout() {
    let output = rsigma()
        .args(["rule", "fmt", "--stdout", "-"])
        .write_stdin(UNFORMATTED)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(stdout_of(&output), FORMATTED);
}

#[test]
fn stdin_check_exits_one_when_unformatted() {
    rsigma()
        .args(["rule", "fmt", "--check", "-"])
        .write_stdin(UNFORMATTED)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Would reformat: <stdin>"))
        .stderr(predicate::str::contains(
            "(run with --stdout - to print the formatted text)",
        ))
        .stderr(predicate::str::contains("--write").not());
}

#[test]
fn stdin_check_exits_zero_when_formatted() {
    rsigma()
        .args(["rule", "fmt", "--check", "-"])
        .write_stdin(FORMATTED)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn stdin_diff_uses_the_stdin_label() {
    rsigma()
        .args(["rule", "fmt", "--diff", "--color", "never", "-"])
        .write_stdin(UNFORMATTED)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("--- a/<stdin>"));
}

#[test]
fn stdin_non_sigma_is_skipped_with_stdout() {
    let output = rsigma()
        .args(["rule", "fmt", "--stdout", "-"])
        .write_stdin(NON_SIGMA)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(stdout_of(&output), NON_SIGMA);
}

#[test]
fn stdin_with_write_is_a_conflict() {
    rsigma()
        .args(["rule", "fmt", "--write", "-"])
        .write_stdin(UNFORMATTED)
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "`--write` cannot be used with `-`",
        ));
}

#[test]
fn stdin_cannot_be_mixed_with_paths() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "rule.yml", UNFORMATTED);
    rsigma()
        .args(["rule", "fmt", "-", dir.path().to_str().unwrap()])
        .write_stdin(UNFORMATTED)
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "`-` cannot be combined with file paths",
        ));
}

#[test]
fn diff_matches_golden() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "rule.yml", UNFORMATTED);
    let output = rsigma()
        .args([
            "rule",
            "fmt",
            "--diff",
            "--color",
            "never",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = stdout_of(&output).replace(&slash(dir.path()), "<DIR>");
    let golden =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/fmt_diff.txt"))
            .unwrap();
    assert_eq!(stdout, golden);
}

#[test]
fn diff_with_check_is_allowed() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "rule.yml", UNFORMATTED);
    rsigma()
        .args([
            "rule",
            "fmt",
            "--diff",
            "--check",
            "--color",
            "never",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("@@"));
}

#[test]
fn diff_color_always_emits_ansi() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "rule.yml", UNFORMATTED);
    let output = rsigma()
        .args([
            "rule",
            "fmt",
            "--diff",
            "--color",
            "always",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout_of(&output).contains("\u{1b}["));
}

#[test]
fn write_rewrites_then_check_passes() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(dir.path(), "rule.yml", UNFORMATTED);
    rsigma()
        .args(["rule", "fmt", "--write", dir.path().to_str().unwrap()])
        .assert()
        .success();
    assert_eq!(fs::read_to_string(&path).unwrap(), FORMATTED);
    rsigma()
        .args(["rule", "fmt", "--check", dir.path().to_str().unwrap()])
        .assert()
        .success();
}

#[cfg(unix)]
#[test]
fn write_keeps_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = write_file(dir.path(), "rule.yml", UNFORMATTED);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    rsigma()
        .args(["rule", "fmt", "--write", dir.path().to_str().unwrap()])
        .assert()
        .success();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o640);
}

#[test]
fn write_does_not_touch_formatted_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(dir.path(), "rule.yml", FORMATTED);
    let before_modified = fs::metadata(&path).unwrap().modified().unwrap();
    rsigma()
        .args(["rule", "fmt", "--write", dir.path().to_str().unwrap()])
        .assert()
        .success();
    assert_eq!(fs::read_to_string(&path).unwrap(), FORMATTED);
    assert_eq!(
        fs::metadata(&path).unwrap().modified().unwrap(),
        before_modified
    );
}

#[test]
fn write_reports_reformatted_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "rule.yml", UNFORMATTED);
    rsigma()
        .args(["rule", "fmt", "--write", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("Reformatted:"));
}

#[test]
fn stdout_prints_only_formatted_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(dir.path(), "rule.yml", UNFORMATTED);
    let output = rsigma()
        .args(["rule", "fmt", "--stdout", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(stdout_of(&output), FORMATTED);
    assert!(stderr_of(&output).is_empty());
}

#[test]
fn stdout_prints_original_for_non_sigma() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(dir.path(), "pipeline.yml", NON_SIGMA);
    let output = rsigma()
        .args(["rule", "fmt", "--stdout", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(stdout_of(&output), NON_SIGMA);
    assert!(stderr_of(&output).contains("skipped:"));
}

#[test]
fn stdout_rejects_directory_and_multiple_paths() {
    let dir = tempfile::tempdir().unwrap();
    let first = write_file(dir.path(), "a.yml", UNFORMATTED);
    let second = write_file(dir.path(), "b.yml", UNFORMATTED);

    rsigma()
        .args(["rule", "fmt", "--stdout", dir.path().to_str().unwrap()])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(format!(
            "error: `--stdout` needs a file, but `{}` is a directory",
            slash(dir.path())
        )));

    rsigma()
        .args([
            "rule",
            "fmt",
            "--stdout",
            first.to_str().unwrap(),
            second.to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "error: `--stdout` needs exactly one file path",
        ));
}

#[test]
fn conflicting_flags_exit_three() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(dir.path(), "rule.yml", UNFORMATTED);
    let path = path.to_str().unwrap();

    let cases = [
        (
            vec!["--write", "--check", path],
            "error: `--write` cannot be combined with `--check`",
        ),
        (
            vec!["--write", "--diff", path],
            "error: `--write` cannot be combined with `--diff`",
        ),
        (
            vec!["--write", "--stdout", path],
            "error: `--write` cannot be combined with `--stdout`",
        ),
        (
            vec!["--stdout", "--check", path],
            "error: `--stdout` cannot be combined with `--check`",
        ),
        (
            vec!["--stdout", "--diff", path],
            "error: `--stdout` cannot be combined with `--diff`",
        ),
    ];
    for (flags, message) in cases {
        let mut args = vec!["rule", "fmt"];
        args.extend(flags);
        rsigma()
            .args(&args)
            .assert()
            .code(3)
            .stderr(predicate::str::contains(message));
    }
}

#[test]
fn defaults_to_current_directory() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "rule.yml", UNFORMATTED);
    rsigma()
        .args(["rule", "fmt"])
        .current_dir(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Would reformat: rule.yml"));
}

#[test]
fn overlapping_roots_are_deduplicated() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(dir.path(), "rule.yml", UNFORMATTED);
    let output = rsigma()
        .args([
            "rule",
            "fmt",
            dir.path().to_str().unwrap(),
            path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    assert_eq!(stdout.matches("Would reformat:").count(), 1);
}

#[test]
fn files_are_processed_in_sorted_order() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "b.yml", UNFORMATTED);
    write_file(dir.path(), "a.yml", UNFORMATTED);
    let output = rsigma()
        .args(["rule", "fmt", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    let a = stdout.find("a.yml").unwrap();
    let b = stdout.find("b.yml").unwrap();
    assert!(a < b);
}

#[test]
fn hidden_directories_are_skipped() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), ".hidden/rule.yml", UNFORMATTED);
    write_file(dir.path(), "visible.yml", UNFORMATTED);
    let output = rsigma()
        .args(["rule", "fmt", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    assert!(stdout.contains("visible.yml"));
    assert!(!stdout.contains("rule.yml"));
}

#[cfg(unix)]
#[test]
fn symlinks_found_while_walking_are_skipped() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let target = write_file(dir.path(), "real.yml", UNFORMATTED);
    symlink(&target, dir.path().join("link.yml")).unwrap();
    let real_dir = dir.path().join("sub");
    fs::create_dir_all(&real_dir).unwrap();
    write_file(&real_dir, "nested.yml", UNFORMATTED);
    symlink(&real_dir, dir.path().join("linkdir")).unwrap();

    let output = rsigma()
        .args(["rule", "fmt", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    assert!(stdout.contains("real.yml"));
    assert!(stdout.contains("nested.yml"));
    assert!(!stdout.contains("link.yml"));
    assert!(!stdout.contains("linkdir"));
}

#[cfg(unix)]
#[test]
fn explicit_symlink_argument_writes_target() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let target = write_file(dir.path(), "real.yml", UNFORMATTED);
    let link = dir.path().join("link.yml");
    symlink(&target, &link).unwrap();
    rsigma()
        .args(["rule", "fmt", "--write", link.to_str().unwrap()])
        .assert()
        .success();
    assert_eq!(fs::read_to_string(&target).unwrap(), FORMATTED);
}

#[test]
fn missing_path_is_an_error_and_others_still_run() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "rule.yml", UNFORMATTED);
    let missing = dir.path().join("missing");
    let output = rsigma()
        .args([
            "rule",
            "fmt",
            missing.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout_of(&output).contains("Would reformat:"));
    assert!(stderr_of(&output).contains("error:"));
}

#[cfg(unix)]
#[test]
fn unreadable_file_is_an_error() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = write_file(dir.path(), "rule.yml", UNFORMATTED);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read_to_string(&path).is_ok() {
        // Running as root: permissions do not block reads.
        return;
    }
    rsigma()
        .args(["rule", "fmt", dir.path().to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn non_sigma_file_is_skipped_and_quiet_hides_it() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "pipeline.yml", NON_SIGMA);

    rsigma()
        .args(["rule", "fmt", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("skipped:"));

    rsigma()
        .args(["rule", "fmt", "--quiet", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty());
}

#[test]
fn malformed_sigma_is_an_error_and_untouched_by_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(dir.path(), "rule.yml", MALFORMED);
    rsigma()
        .args(["rule", "fmt", "--write", dir.path().to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("error:"));
    assert_eq!(fs::read_to_string(&path).unwrap(), MALFORMED);
}

#[test]
fn error_beats_would_change_in_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "bad.yml", MALFORMED);
    write_file(dir.path(), "rule.yml", UNFORMATTED);
    rsigma()
        .args(["rule", "fmt", "--check", dir.path().to_str().unwrap()])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("Would reformat:"));
}

#[test]
fn quiet_and_no_stats_control_the_summary() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "rule.yml", UNFORMATTED);

    rsigma()
        .args(["rule", "fmt", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("would be reformatted"));

    rsigma()
        .args(["rule", "fmt", "--no-stats", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("would be reformatted").not());

    rsigma()
        .args(["rule", "fmt", "--quiet", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Would reformat:"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn explicit_output_format_warns() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "rule.yml", FORMATTED);
    rsigma()
        .args([
            "rule",
            "fmt",
            "--output-format",
            "json",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("not supported by `rule fmt`"));
}

#[test]
fn explicit_non_yaml_extension_file_is_formatted() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(dir.path(), "rule.txt", UNFORMATTED);
    rsigma()
        .args(["rule", "fmt", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Would reformat:"));
}
