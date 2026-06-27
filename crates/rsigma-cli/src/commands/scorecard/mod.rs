//! `rsigma rule scorecard`: fuse the detection-as-code rule-side outputs into
//! the per-rule keep/tune/retire verdict table a mature detection program
//! reviews on a cadence.
//!
//! It reads JSON the toolkit already emits (the #46 backtest report and the #47
//! coverage report), optionally enriches it with a Prometheus production-volume
//! snapshot and the #70 triage disposition feed, and emits a fused, scored
//! document. No evaluation, no corpus re-reading: it is an offline
//! fusion-and-verdict layer over already-aggregated reports.

mod fuse;
mod inputs;
mod report;
mod verdict;

use std::path::PathBuf;
use std::process;

use clap::parser::ValueSource;
use clap::{ArgMatches, Args};

use crate::config;
use crate::exit_code;
use crate::output::OutputCtx;
use inputs::InputError;
use report::{InputManifest, ReportFormat, Scorecard};
use verdict::{FailOn, Thresholds};

/// Arguments for `rsigma rule scorecard`.
#[derive(Args, Debug)]
pub(crate) struct ScorecardArgs {
    /// Path to a YAML config file. Overrides config-file discovery.
    /// CLI flags still take precedence over config-file values.
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Print the effective config (defaults < file < env) and exit.
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// The backtest JSON report (from `rule backtest --report`).
    /// Required unless supplied via `scorecard.backtest` in the config file.
    #[arg(long = "backtest", value_name = "FILE")]
    pub backtest: Option<PathBuf>,

    /// The coverage JSON report (from `rule coverage --output-format json`).
    /// Required unless supplied via `scorecard.coverage` in the config file.
    #[arg(long = "coverage", value_name = "FILE")]
    pub coverage: Option<PathBuf>,

    /// A Prometheus exposition snapshot file or a `/metrics` URL for production
    /// fire volume (`rsigma_*_matches_by_rule_total`, joined by rule_title).
    #[arg(long = "metrics", value_name = "FILE_OR_URL")]
    pub metrics: Option<String>,

    /// When `--metrics` is a Prometheus query-API base URL, range-query window
    /// (e.g. 7d, 24h) for last-fired and current value.
    #[arg(long = "metrics-window", value_name = "DURATION")]
    pub metrics_window: Option<String>,

    /// The #70 triage disposition feed for the live false-positive ratio and
    /// MTTD/MTTR.
    #[arg(long = "triage", value_name = "FILE")]
    pub triage: Option<PathBuf>,

    /// Exit 1 when any rule's verdict is at or worse than this policy.
    #[arg(long = "fail-on", value_parser = ["none", "tune", "retire"], default_value = config::defaults::SCORECARD_FAIL_ON)]
    pub fail_on: String,

    /// Write the program artifact; `.md`/`.markdown` -> markdown, `.html`/`.htm`
    /// -> HTML.
    #[arg(long = "report", value_name = "PATH")]
    pub report: Option<PathBuf>,

    /// Override the `--report` format (markdown or html) regardless of extension.
    #[arg(long = "report-format", value_parser = ["markdown", "html"])]
    pub report_format: Option<String>,

    /// Keep floor: precision proxy at or above this keeps the rule.
    #[arg(long = "min-precision", default_value_t = config::defaults::SCORECARD_MIN_PRECISION)]
    pub min_precision: f64,

    /// Upper edge of the review band (used in the tune reason).
    #[arg(long = "tune-max-precision", default_value_t = config::defaults::SCORECARD_TUNE_MAX_PRECISION)]
    pub tune_max_precision: f64,

    /// Retire floor: precision proxy below this retires the rule.
    #[arg(long = "retire-max-precision", default_value_t = config::defaults::SCORECARD_RETIRE_MAX_PRECISION)]
    pub retire_max_precision: f64,

    /// Minimum total volume for a keep verdict.
    #[arg(long = "min-volume", default_value_t = config::defaults::SCORECARD_MIN_VOLUME)]
    pub min_volume: u64,

    /// Staleness window in days; a rule that has not fired within it is not kept
    /// (only enforced when last-fired is known via `--metrics-window`).
    #[arg(long = "stale-window", value_name = "DAYS", default_value_t = config::defaults::SCORECARD_STALE_WINDOW_DAYS)]
    pub stale_window: u64,

    /// Live false-positive-ratio ceiling; a rule above it is at best tuned.
    #[arg(long = "max-fp-ratio", default_value_t = config::defaults::SCORECARD_MAX_FP_RATIO)]
    pub max_fp_ratio: f64,
}

/// Overlay the `scorecard` config section (defaults < file < env) onto `args`
/// for any flag the operator did not set explicitly, then handle `--dry-run`.
pub(crate) fn apply_scorecard_config(args: &mut ScorecardArgs, matches: &ArgMatches) {
    let base = config::load_and_merge(args.config.as_deref());
    if args.dry_run {
        config::print_dry_run("scorecard", &base);
        process::exit(exit_code::SUCCESS);
    }
    overlay_scorecard_config(args, matches, base);
}

/// Pure overlay of the resolved `scorecard` section onto `args` (no disk
/// access), split out so it can be unit-tested.
fn overlay_scorecard_config(
    args: &mut ScorecardArgs,
    matches: &ArgMatches,
    base: config::RsigmaConfigPartial,
) {
    let explicit = |id: &str| {
        matches!(
            matches.value_source(id),
            Some(ValueSource::CommandLine | ValueSource::EnvVariable)
        )
    };

    if let Some(sc) = base.scorecard {
        // Inputs with no clap default: `is_none`/`is_empty` means the operator
        // left them off, so the config layer fills them.
        if args.backtest.is_none()
            && let Some(v) = sc.backtest
        {
            args.backtest = Some(v);
        }
        if args.coverage.is_none()
            && let Some(v) = sc.coverage
        {
            args.coverage = Some(v);
        }
        if args.metrics.is_none()
            && let Some(v) = sc.metrics
        {
            args.metrics = Some(v);
        }
        if args.metrics_window.is_none()
            && let Some(v) = sc.metrics_window
        {
            args.metrics_window = Some(v);
        }
        if args.triage.is_none()
            && let Some(v) = sc.triage
        {
            args.triage = Some(v);
        }
        if args.report.is_none()
            && let Some(v) = sc.report
        {
            args.report = Some(v);
        }
        // Flags with clap defaults: fill only when the operator did not set them
        // explicitly on the command line or in the environment.
        if !explicit("fail_on")
            && let Some(v) = sc.fail_on
        {
            args.fail_on = v;
        }
        if !explicit("min_precision")
            && let Some(v) = sc.min_precision
        {
            args.min_precision = v;
        }
        if !explicit("tune_max_precision")
            && let Some(v) = sc.tune_max_precision
        {
            args.tune_max_precision = v;
        }
        if !explicit("retire_max_precision")
            && let Some(v) = sc.retire_max_precision
        {
            args.retire_max_precision = v;
        }
        if !explicit("min_volume")
            && let Some(v) = sc.min_volume
        {
            args.min_volume = v;
        }
        if !explicit("stale_window")
            && let Some(v) = sc.stale_window
        {
            args.stale_window = v;
        }
        if !explicit("max_fp_ratio")
            && let Some(v) = sc.max_fp_ratio
        {
            args.max_fp_ratio = v;
        }
    }
}

/// Run `rule scorecard`. Returns the process exit code: `0` success or under
/// `--fail-on`, `1` verdicts hit `--fail-on`, `2` an input is missing or
/// unfetchable, `3` bad flags or a malformed/version-mismatched report.
pub(crate) fn cmd_scorecard(args: ScorecardArgs, ctx: OutputCtx) -> i32 {
    let Some(backtest_path) = args.backtest.as_deref() else {
        eprintln!(
            "error: no backtest report; set --backtest or scorecard.backtest in the config file"
        );
        return exit_code::CONFIG_ERROR;
    };
    let Some(coverage_path) = args.coverage.as_deref() else {
        eprintln!(
            "error: no coverage report; set --coverage or scorecard.coverage in the config file"
        );
        return exit_code::CONFIG_ERROR;
    };

    let fail_on = match FailOn::parse(&args.fail_on) {
        Some(p) => p,
        None => {
            eprintln!(
                "error: invalid --fail-on '{}' (expected none, tune, retire)",
                args.fail_on
            );
            return exit_code::CONFIG_ERROR;
        }
    };

    // Resolve the report artifact format before doing any loading so a bad
    // `--report`/`--report-format` fails fast with a flag error.
    let report_target = match resolve_report_target(&args) {
        Ok(t) => t,
        Err(code) => return code,
    };

    let backtest = match inputs::load_backtest(backtest_path) {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    let coverage = match inputs::load_coverage(coverage_path) {
        Ok(r) => r,
        Err(e) => return fail(e),
    };

    let metrics = match &args.metrics {
        Some(spec) => match inputs::load_metrics(spec, args.metrics_window.as_deref()) {
            Ok(m) => Some(m),
            Err(e) => return fail(e),
        },
        None => None,
    };
    let triage = match &args.triage {
        Some(path) => match inputs::load_triage(path) {
            Ok(t) => Some(t),
            Err(e) => return fail(e),
        },
        None => None,
    };

    let thresholds = Thresholds {
        min_precision: args.min_precision,
        tune_max_precision: args.tune_max_precision,
        retire_max_precision: args.retire_max_precision,
        min_volume: args.min_volume,
        stale_window_days: args.stale_window,
        max_fp_ratio: args.max_fp_ratio,
    };

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let records = fuse::fuse(
        &backtest,
        &coverage,
        metrics.as_ref(),
        triage.as_ref(),
        &thresholds,
        now_unix,
    );

    let manifest = InputManifest {
        metrics: metrics.is_some(),
        triage: triage.is_some(),
        metrics_window: args.metrics_window.clone(),
    };
    let scorecard = Scorecard::build(records, &coverage, &thresholds, manifest);

    let report_ref = report_target
        .as_ref()
        .map(|(path, format)| (path.as_path(), *format));
    scorecard.render(&ctx, report_ref);

    if scorecard.fails(fail_on) {
        if ctx.show_stats() {
            let n = scorecard
                .records
                .iter()
                .filter(|r| fail_on.triggers(r.verdict))
                .count();
            eprintln!(
                "scorecard: {n} rule(s) at or worse than --fail-on {}",
                fail_on.as_str()
            );
        }
        exit_code::FINDINGS
    } else {
        exit_code::SUCCESS
    }
}

/// Resolve the optional `--report` path to a `(path, format)` pair, dispatching
/// the format from `--report-format` or the path extension. Returns the house
/// `CONFIG_ERROR` when the format cannot be determined or is invalid.
fn resolve_report_target(args: &ScorecardArgs) -> Result<Option<(PathBuf, ReportFormat)>, i32> {
    let Some(path) = args.report.clone() else {
        return Ok(None);
    };
    let format = match &args.report_format {
        Some(spec) => match ReportFormat::parse(spec) {
            Some(f) => f,
            None => {
                eprintln!("error: invalid --report-format '{spec}' (expected markdown or html)");
                return Err(exit_code::CONFIG_ERROR);
            }
        },
        None => match ReportFormat::from_extension(&path) {
            Some(f) => f,
            None => {
                eprintln!(
                    "error: cannot determine report format from {}; use --report-format markdown|html",
                    path.display()
                );
                return Err(exit_code::CONFIG_ERROR);
            }
        },
    };
    Ok(Some((path, format)))
}

/// Map an input failure to its house exit code and emit the message.
fn fail(e: InputError) -> i32 {
    eprintln!("error: {e}");
    match e {
        InputError::Unreadable(_) => exit_code::RULE_ERROR,
        InputError::Malformed(_) => exit_code::CONFIG_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Command, FromArgMatches};

    fn parse(argv: &[&str]) -> (ScorecardArgs, ArgMatches) {
        let cmd = ScorecardArgs::augment_args(Command::new("scorecard"));
        let matches = cmd.get_matches_from(argv);
        let args = ScorecardArgs::from_arg_matches(&matches).expect("valid args");
        (args, matches)
    }

    fn partial(yaml: &str) -> config::RsigmaConfigPartial {
        yaml_serde::from_str(yaml).expect("valid partial")
    }

    #[test]
    fn defaults_match_config_defaults() {
        let (args, _) = parse(&["scorecard", "--backtest", "b", "--coverage", "c"]);
        assert_eq!(
            args.min_precision,
            config::defaults::SCORECARD_MIN_PRECISION
        );
        assert_eq!(args.fail_on, config::defaults::SCORECARD_FAIL_ON);
    }

    #[test]
    fn config_fills_unset_threshold_and_fail_on() {
        let (mut args, matches) = parse(&["scorecard", "--backtest", "b", "--coverage", "c"]);
        let base = partial("scorecard:\n  min_precision: 0.6\n  fail_on: retire\n");
        overlay_scorecard_config(&mut args, &matches, base);
        assert_eq!(args.min_precision, 0.6);
        assert_eq!(args.fail_on, "retire");
    }

    #[test]
    fn cli_flag_beats_config() {
        let (mut args, matches) = parse(&[
            "scorecard",
            "--backtest",
            "b",
            "--coverage",
            "c",
            "--fail-on",
            "tune",
        ]);
        let base = partial("scorecard:\n  fail_on: retire\n");
        overlay_scorecard_config(&mut args, &matches, base);
        assert_eq!(args.fail_on, "tune");
    }

    #[test]
    fn config_fills_unset_metrics_and_triage() {
        let (mut args, matches) = parse(&["scorecard", "--backtest", "b", "--coverage", "c"]);
        let base = partial("scorecard:\n  metrics: /m/metrics.txt\n  triage: /t/triage.json\n");
        overlay_scorecard_config(&mut args, &matches, base);
        assert_eq!(args.metrics.as_deref(), Some("/m/metrics.txt"));
        assert_eq!(
            args.triage.as_deref(),
            Some(std::path::Path::new("/t/triage.json"))
        );
    }

    #[test]
    fn config_fills_unset_backtest_and_coverage() {
        // Neither report is passed on the command line; both come from config.
        let (mut args, matches) = parse(&["scorecard"]);
        let base =
            partial("scorecard:\n  backtest: /r/backtest.json\n  coverage: /r/coverage.json\n");
        overlay_scorecard_config(&mut args, &matches, base);
        assert_eq!(
            args.backtest.as_deref(),
            Some(std::path::Path::new("/r/backtest.json"))
        );
        assert_eq!(
            args.coverage.as_deref(),
            Some(std::path::Path::new("/r/coverage.json"))
        );
    }

    #[test]
    fn cli_report_path_beats_config() {
        let (mut args, matches) = parse(&["scorecard", "--backtest", "cli-bt.json"]);
        let base = partial("scorecard:\n  backtest: /file/bt.json\n  coverage: /file/cov.json\n");
        overlay_scorecard_config(&mut args, &matches, base);
        // The CLI backtest wins; the unset coverage is filled from config.
        assert_eq!(
            args.backtest.as_deref(),
            Some(std::path::Path::new("cli-bt.json"))
        );
        assert_eq!(
            args.coverage.as_deref(),
            Some(std::path::Path::new("/file/cov.json"))
        );
    }
}
