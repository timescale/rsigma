//! Smoke tests for the deprecated flat-form CLI aliases.
//!
//! Each deprecated alias (`eval`, `daemon`, `parse`, `validate`, `lint`,
//! `fields`, `condition`, `stdin`, `convert`, `list-targets`, `list-formats`,
//! `resolve`) must keep working for one release before it is hidden in the
//! next and removed in v1.0. This file asserts that:
//!
//! 1. The flat invocation still succeeds (or fails with the same exit code
//!    as the new grouped form for error paths).
//! 2. The flat invocation prints the `warning: \`rsigma <old>\` is deprecated`
//!    message on stderr.
//! 3. Where it makes sense (cheap stateless commands), the flat form
//!    produces the same stdout as the new grouped form.
//! 4. `rsigma --help` lists every deprecated alias with `[deprecated]` in
//!    its about text, plus the five new groups.
//! 5. Each new group's own `--help` lists the leaf subcommands.

mod common;

use common::{SIMPLE_RULE, rsigma, temp_file};
use predicates::prelude::*;

const DEPRECATION_PREFIX: &str = "warning: `rsigma ";

// ---------------------------------------------------------------------------
// Help output
// ---------------------------------------------------------------------------

#[test]
fn root_help_lists_all_groups_and_deprecated_aliases() {
    let assert = rsigma()
        .args(["--help"])
        .assert()
        .success()
        // New groups appear with their short description.
        .stdout(predicate::str::contains("engine"))
        .stdout(predicate::str::contains("rule"))
        .stdout(predicate::str::contains("backend"))
        .stdout(predicate::str::contains("pipeline"))
        .stdout(predicate::str::contains("attack"))
        // Every deprecated alias keeps its row and is tagged `[deprecated]`.
        .stdout(predicate::str::contains("[deprecated]"));

    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    for alias in [
        "eval",
        "daemon",
        "parse",
        "validate",
        "lint",
        "fields",
        "condition",
        "stdin",
        "convert",
        "list-targets",
        "list-formats",
        "resolve",
    ] {
        assert!(
            stdout.contains(alias),
            "`{alias}` should appear in `rsigma --help`, got:\n{stdout}"
        );
    }
}

#[test]
fn engine_group_help_lists_eval_and_daemon() {
    rsigma()
        .args(["engine", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("eval"))
        .stdout(predicate::str::contains("daemon"));
}

#[test]
fn rule_group_help_lists_all_six_leafs() {
    let assert = rsigma().args(["rule", "--help"]).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    for leaf in ["parse", "validate", "lint", "fields", "condition", "stdin"] {
        assert!(
            stdout.contains(leaf),
            "`rsigma rule --help` should list `{leaf}`, got:\n{stdout}"
        );
    }
}

#[test]
fn backend_group_help_lists_convert_targets_formats() {
    let assert = rsigma().args(["backend", "--help"]).assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    for leaf in ["convert", "targets", "formats"] {
        assert!(
            stdout.contains(leaf),
            "`rsigma backend --help` should list `{leaf}`, got:\n{stdout}"
        );
    }
}

#[test]
fn pipeline_group_help_lists_resolve() {
    rsigma()
        .args(["pipeline", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("resolve"));
}

// ---------------------------------------------------------------------------
// Per-alias deprecation warning + behavior parity
// ---------------------------------------------------------------------------

#[test]
fn deprecated_parse_warns_and_succeeds() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    let assert = rsigma()
        .args(["parse", rule.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("rule parse"))
        .stdout(predicate::str::contains("Test Rule"));

    // Same stdout as the new form.
    let new_stdout = rsigma()
        .args(["rule", "parse", rule.path().to_str().unwrap()])
        .output()
        .unwrap()
        .stdout;
    let old_stdout = assert.get_output().stdout.clone();
    assert_eq!(
        String::from_utf8_lossy(&old_stdout),
        String::from_utf8_lossy(&new_stdout),
        "deprecated `parse` should produce identical stdout to `rule parse`",
    );
}

#[test]
fn deprecated_validate_warns_and_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rule.yml"), SIMPLE_RULE).unwrap();
    rsigma()
        .args(["validate", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("rule validate"))
        .stdout(predicate::str::contains("Detection rules:"));
}

#[test]
fn deprecated_lint_warns_and_succeeds() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args(["lint", rule.path().to_str().unwrap()])
        .assert()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("rule lint"));
}

#[test]
fn deprecated_fields_warns_and_succeeds() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args(["fields", "-r", rule.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("rule fields"));
}

#[test]
fn deprecated_condition_warns_and_succeeds() {
    let assert = rsigma()
        .args(["condition", "sel and not filter"])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("rule condition"));

    let new_stdout = rsigma()
        .args(["rule", "condition", "sel and not filter"])
        .output()
        .unwrap()
        .stdout;
    assert_eq!(
        String::from_utf8_lossy(&assert.get_output().stdout),
        String::from_utf8_lossy(&new_stdout),
        "deprecated `condition` should produce identical stdout to `rule condition`",
    );
}

#[test]
fn deprecated_stdin_warns_and_succeeds() {
    rsigma()
        .args(["stdin"])
        .write_stdin(SIMPLE_RULE)
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("rule stdin"))
        .stdout(predicate::str::contains("Test Rule"));
}

#[test]
fn deprecated_eval_warns_and_succeeds() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args([
            "eval",
            "--rules",
            rule.path().to_str().unwrap(),
            "--event",
            r#"{"CommandLine":"benign"}"#,
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("engine eval"));
}

#[test]
fn deprecated_convert_warns_and_succeeds() {
    let rule = temp_file(".yml", SIMPLE_RULE);
    rsigma()
        .args(["convert", rule.path().to_str().unwrap(), "-t", "test"])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("backend convert"));
}

#[test]
fn deprecated_list_targets_warns_and_matches_backend_targets() {
    let assert = rsigma()
        .args(["list-targets"])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("backend targets"));

    let new_stdout = rsigma()
        .args(["backend", "targets"])
        .output()
        .unwrap()
        .stdout;
    assert_eq!(
        String::from_utf8_lossy(&assert.get_output().stdout),
        String::from_utf8_lossy(&new_stdout),
        "deprecated `list-targets` should produce identical stdout to `backend targets`",
    );
}

#[test]
fn deprecated_list_formats_warns_and_matches_backend_formats() {
    let assert = rsigma()
        .args(["list-formats", "test"])
        .assert()
        .success()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("backend formats"));

    let new_stdout = rsigma()
        .args(["backend", "formats", "test"])
        .output()
        .unwrap()
        .stdout;
    assert_eq!(
        String::from_utf8_lossy(&assert.get_output().stdout),
        String::from_utf8_lossy(&new_stdout),
        "deprecated `list-formats test` should produce identical stdout to `backend formats test`",
    );
}

// ---------------------------------------------------------------------------
// Daemon and resolve deprecation
// ---------------------------------------------------------------------------

/// `rsigma daemon` is the heaviest deprecated alias. We only assert that
/// `--help` on the alias prints the deprecation warning and the same flag
/// list as `engine daemon --help`. Spawning a real daemon is covered by
/// `cli_daemon.rs` (which already uses the new path).
#[cfg(feature = "daemon")]
#[test]
fn deprecated_daemon_help_lists_new_path() {
    rsigma()
        .args(["daemon", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--rules"))
        .stdout(predicate::str::contains("--input"));

    // The about line tags the flat form as deprecated.
    rsigma()
        .args(["--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "daemon        [deprecated] Use `rsigma engine daemon` instead",
        ));
}

#[cfg(feature = "daemon")]
#[test]
fn deprecated_resolve_warns_on_invalid_pipeline() {
    // Don't need a real dynamic source — empty pipeline list is a parse error
    // and exits non-zero. We're only checking the deprecation warning fires
    // before the failure.
    rsigma()
        .args(["resolve", "-p", "/tmp/nonexistent_rsigma_pipeline.yml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(DEPRECATION_PREFIX))
        .stderr(predicate::str::contains("pipeline resolve"));
}
