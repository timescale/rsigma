//! Optional delegation to an external `sigma-cli` for conversion targets that
//! rsigma has no native backend for.
//!
//! This is a light subprocess wrapper, not a port or an embedded interpreter:
//! `rsigma backend convert` hands the original rule files plus a near 1:1
//! flag mapping to `sigma convert` and relays its output. No Python runtime is
//! required unless a delegated target is actually used, so the rsigma binary
//! stays self-contained for everyone converting to a native backend.
//!
//! Discovery uses the `RSIGMA_SIGMA_CLI` environment override when set, falling
//! back to a bare `sigma` resolved on `PATH`. A spawn that fails with
//! [`std::io::ErrorKind::NotFound`] means sigma-cli is not installed, which the
//! caller turns into install guidance rather than a conversion failure.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Environment variable that overrides discovery with an explicit path to the
/// `sigma` executable.
pub(crate) const SIGMA_CLI_ENV: &str = "RSIGMA_SIGMA_CLI";

/// Program name used when the override is unset.
const DEFAULT_PROGRAM: &str = "sigma";

/// A resolved sigma-cli invocation target.
pub(crate) struct SigmaCli {
    program: PathBuf,
    is_override: bool,
}

impl SigmaCli {
    /// Resolve the configured sigma-cli from the current environment.
    pub(crate) fn configured() -> Self {
        let (program, is_override) = resolve_program(std::env::var_os(SIGMA_CLI_ENV));
        Self {
            program,
            is_override,
        }
    }

    /// The executable that will be spawned (override path or bare `sigma`).
    pub(crate) fn program(&self) -> &Path {
        &self.program
    }

    /// Whether the executable came from the `RSIGMA_SIGMA_CLI` override.
    pub(crate) fn is_override(&self) -> bool {
        self.is_override
    }

    /// Run sigma-cli with `args`, capturing stdout, stderr, and the exit status.
    pub(crate) fn run<I, S>(&self, args: I) -> std::io::Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Command::new(&self.program).args(args).output()
    }
}

/// Decide the program name and whether it came from the override.
///
/// An override that is set but empty is treated as unset so an accidental
/// `RSIGMA_SIGMA_CLI=` does not break discovery.
fn resolve_program(env_value: Option<OsString>) -> (PathBuf, bool) {
    match env_value {
        Some(value) if !value.is_empty() => (PathBuf::from(value), true),
        _ => (PathBuf::from(DEFAULT_PROGRAM), false),
    }
}

/// Build the `sigma convert` argument vector from rsigma's convert arguments.
///
/// The mapping is near 1:1; the only transform is rsigma's
/// `-O correlation_method=<m>` option, which becomes sigma-cli's
/// `-c/--correlation-method <m>`. Every other `-O key=value` is forwarded as a
/// sigma-cli `-O/--backend-option`, and pipelines, the no-pipeline and
/// skip-unsupported toggles, the output format, and the rule paths pass through
/// unchanged. `--output` is intentionally not forwarded: rsigma captures
/// sigma-cli's stdout and routes it through its own output handling.
pub(crate) fn build_convert_args(
    target: &str,
    format: &str,
    pipelines: &[PathBuf],
    without_pipeline: bool,
    skip_unsupported: bool,
    backend_options: &[String],
    rules: &[PathBuf],
) -> Vec<OsString> {
    fn os(value: impl AsRef<OsStr>) -> OsString {
        value.as_ref().to_os_string()
    }

    let mut argv: Vec<OsString> = vec![os("convert"), os("-t"), os(target), os("-f"), os(format)];

    for pipeline in pipelines {
        argv.push(os("-p"));
        argv.push(os(pipeline));
    }
    if without_pipeline {
        argv.push(os("--without-pipeline"));
    }
    if skip_unsupported {
        argv.push(os("-s"));
    }

    for option in backend_options {
        match option.split_once('=') {
            Some(("correlation_method", value)) => {
                argv.push(os("-c"));
                argv.push(os(value));
            }
            _ => {
                argv.push(os("-O"));
                argv.push(os(option));
            }
        }
    }

    for rule in rules {
        argv.push(os(rule));
    }

    argv
}

/// Message shown when a target has no native backend and sigma-cli cannot be
/// run, guiding the user to install it (or fix a broken override).
pub(crate) fn install_hint(
    target: &str,
    program: &Path,
    is_override: bool,
    native_targets: &[&str],
) -> String {
    let program = program.display();
    let native = native_targets.join(", ");
    if is_override {
        format!(
            "No native rsigma backend for target '{target}' (native targets: {native}), \
             and the sigma-cli override {SIGMA_CLI_ENV}='{program}' could not be executed.\n\
             Point {SIGMA_CLI_ENV} at a working sigma executable, or unset it to use one on PATH."
        )
    } else {
        format!(
            "No native rsigma backend for target '{target}' (native targets: {native}), \
             and sigma-cli was not found on PATH.\n\
             Install it to convert to '{target}':\n\
             \x20\x20pipx install sigma-cli\n\
             \x20\x20sigma plugin install {target}\n\
             Or set {SIGMA_CLI_ENV} to the path of an existing sigma executable."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_strings(argv: &[OsString]) -> Vec<String> {
        argv.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn resolve_program_prefers_override() {
        let (program, is_override) = resolve_program(Some(OsString::from("/opt/sigma/bin/sigma")));
        assert_eq!(program, PathBuf::from("/opt/sigma/bin/sigma"));
        assert!(is_override);
    }

    #[test]
    fn resolve_program_falls_back_to_path() {
        let (program, is_override) = resolve_program(None);
        assert_eq!(program, PathBuf::from("sigma"));
        assert!(!is_override);
    }

    #[test]
    fn resolve_program_treats_empty_override_as_unset() {
        let (program, is_override) = resolve_program(Some(OsString::new()));
        assert_eq!(program, PathBuf::from("sigma"));
        assert!(!is_override);
    }

    #[test]
    fn build_args_maps_flags_one_to_one() {
        let argv = build_convert_args(
            "splunk",
            "default",
            &[PathBuf::from("ecs.yml"), PathBuf::from("custom.yml")],
            false,
            true,
            &["index=main".to_string()],
            &[PathBuf::from("rule.yml")],
        );
        assert_eq!(
            to_strings(&argv),
            vec![
                "convert",
                "-t",
                "splunk",
                "-f",
                "default",
                "-p",
                "ecs.yml",
                "-p",
                "custom.yml",
                "-s",
                "-O",
                "index=main",
                "rule.yml",
            ]
        );
    }

    #[test]
    fn build_args_special_cases_correlation_method() {
        let argv = build_convert_args(
            "loki",
            "default",
            &[],
            false,
            false,
            &["correlation_method=stats".to_string()],
            &[PathBuf::from("rule.yml")],
        );
        assert_eq!(
            to_strings(&argv),
            vec![
                "convert", "-t", "loki", "-f", "default", "-c", "stats", "rule.yml",
            ]
        );
    }

    #[test]
    fn build_args_adds_without_pipeline_flag() {
        let argv = build_convert_args(
            "loki",
            "ruler",
            &[],
            true,
            false,
            &[],
            &[PathBuf::from("a.yml"), PathBuf::from("b.yml")],
        );
        assert_eq!(
            to_strings(&argv),
            vec![
                "convert",
                "-t",
                "loki",
                "-f",
                "ruler",
                "--without-pipeline",
                "a.yml",
                "b.yml",
            ]
        );
    }

    #[test]
    fn install_hint_mentions_plugin_install_when_not_override() {
        let hint = install_hint("splunk", Path::new("sigma"), false, &["postgres", "lynxdb"]);
        assert!(hint.contains("sigma-cli was not found"));
        assert!(hint.contains("sigma plugin install splunk"));
        assert!(hint.contains("RSIGMA_SIGMA_CLI"));
        assert!(hint.contains("native targets: postgres, lynxdb"));
    }

    #[test]
    fn install_hint_mentions_override_path_when_override() {
        let hint = install_hint("splunk", Path::new("/bad/sigma"), true, &["postgres"]);
        assert!(hint.contains("/bad/sigma"));
        assert!(hint.contains("could not be executed"));
    }
}
