//! `rsigma rule visibility`: turn the shipped field-observability signal into
//! DeTT&CT and ATT&CK Navigator visibility artifacts.
//!
//! The command joins the rule logsource inventory and rule field set (from
//! `--rules`) with the observed field signal (the `engine eval --observe-fields`
//! one-shot JSON, a saved `GET /api/v1/fields` snapshot, stdin, or a live
//! daemon via `--addr`) through a curated, overridable mapping table. It emits
//! a DeTT&CT data-source administration YAML, an optional technique-
//! administration YAML, and a visibility Navigator layer (format 4.5, distinct
//! from `rule coverage`'s detection layer), plus a human report through the
//! global output layer. `--fail-on-blind-spots` is the CI signal for "you
//! wrote rules for data you do not receive."

mod analysis;
mod dettect;
mod mapping;
mod navigator;
mod report;

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process;

use clap::parser::ValueSource;
use clap::{ArgMatches, Args};
use rsigma_eval::RuleFieldSet;
use serde::Deserialize;

use crate::config;
use crate::exit_code;
use crate::output::OutputCtx;
use analysis::{Observed, ObservedField, analyze};
use report::VisibilityReport;

/// The DeTT&CT/Navigator document name stamped into emitted artifacts.
const ARTIFACT_NAME: &str = "rsigma rule visibility";

/// Maximum page the daemon's `/api/v1/fields` endpoint serves; requested so an
/// `--addr` fetch pulls the full partition in one call.
const DAEMON_FIELDS_LIMIT: usize = 1000;

/// Arguments for `rsigma rule visibility`.
#[derive(Args, Debug)]
pub(crate) struct VisibilityArgs {
    /// Path to a YAML config file. Overrides config-file discovery.
    /// CLI flags still take precedence over config-file values.
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Print the effective config (defaults < file < env) and exit.
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Path to a Sigma rule file or directory of rules (repeatable).
    #[arg(short = 'r', long = "rules", value_name = "PATH")]
    pub rules: Vec<PathBuf>,

    /// Observed field report: the `engine eval --observe-fields` JSON, a saved
    /// `GET /api/v1/fields` snapshot, or `-` for stdin. Omit for the
    /// rule-expected baseline (every source unobserved).
    #[arg(long = "observed", value_name = "FILE", conflicts_with = "addr")]
    pub observed: Option<String>,

    /// Fetch the observed snapshot directly from a live daemon
    /// (`GET /api/v1/fields`) as `host:port` or a full URL.
    #[arg(long = "addr", value_name = "DAEMON_ADDR")]
    pub addr: Option<String>,

    /// Logsource/field to ATT&CK data-source mapping table override. A path or
    /// URL reads that table; a bare `--mapping` fetches the curated default
    /// URL. Unset uses the bundled table.
    #[arg(
        long = "mapping",
        value_name = "PATH_OR_URL",
        num_args = 0..=1,
        default_missing_value = "",
    )]
    pub mapping: Option<String>,

    /// Write the DeTT&CT data-source administration YAML to this file.
    #[arg(long = "dettect-data-sources", value_name = "FILE")]
    pub dettect_data_sources: Option<PathBuf>,

    /// Write the DeTT&CT technique-administration YAML to this file.
    #[arg(long = "dettect-techniques", value_name = "FILE")]
    pub dettect_techniques: Option<PathBuf>,

    /// Write the visibility ATT&CK Navigator layer (format 4.5) to this file.
    #[arg(long = "navigator", value_name = "FILE")]
    pub navigator: Option<PathBuf>,

    /// Exit non-zero when a rule-expected data source has no observed telemetry
    /// (every mapped field sits in the broken-coverage `missing` set).
    #[arg(long = "fail-on-blind-spots")]
    pub fail_on_blind_spots: bool,
}

/// Overlay the `visibility` config section (defaults < file < env) onto `args`
/// for any flag the operator did not set explicitly, then handle `--dry-run`.
pub(crate) fn apply_visibility_config(args: &mut VisibilityArgs, matches: &ArgMatches) {
    let base = config::load_and_merge(args.config.as_deref());
    if args.dry_run {
        config::print_dry_run("visibility", &base);
        process::exit(exit_code::SUCCESS);
    }
    overlay_visibility_config(args, matches, base);
}

/// Pure overlay of the resolved `visibility` section onto `args` (no disk
/// access), split out so it can be unit-tested.
fn overlay_visibility_config(
    args: &mut VisibilityArgs,
    matches: &ArgMatches,
    base: config::RsigmaConfigPartial,
) {
    let explicit = |id: &str| {
        matches!(
            matches.value_source(id),
            Some(ValueSource::CommandLine | ValueSource::EnvVariable)
        )
    };

    if let Some(vis) = base.visibility {
        // `--mapping` has no clap default, so `is_none` means the operator
        // left it off; let the config layer fill it.
        if args.mapping.is_none()
            && let Some(v) = vis.mapping
        {
            args.mapping = Some(v);
        }
        if !explicit("fail_on_blind_spots")
            && let Some(v) = vis.fail_on_blind_spots
        {
            args.fail_on_blind_spots = v;
        }
    }
}

/// Run `rule visibility`. Returns the process exit code (0 success, 1 blind
/// spots under `--fail-on-blind-spots`, 2 rule error, 3 config error). Rule
/// errors exit directly via [`crate::load_collection_multi`].
pub(crate) fn cmd_visibility(args: VisibilityArgs, ctx: OutputCtx) -> i32 {
    if args.rules.is_empty() {
        eprintln!("error: no rules path; pass --rules <PATH> (repeatable)");
        return exit_code::CONFIG_ERROR;
    }

    let collection = crate::load_collection_multi(&args.rules);
    let rule_field_set = RuleFieldSet::collect(&collection, &[], true);

    let observed = match resolve_observed(&args) {
        Ok(observed) => observed,
        Err(e) => {
            eprintln!("error: {e}");
            return exit_code::CONFIG_ERROR;
        }
    };

    let mapping = match mapping::resolve(args.mapping.as_deref()) {
        Ok(table) => table,
        Err(e) => {
            eprintln!("error: {e}");
            return exit_code::CONFIG_ERROR;
        }
    };

    // Surface which table is in effect when the operator overrode the bundled
    // default, recording the table's provenance for the report's audit trail.
    if args.mapping.is_some() && ctx.show_progress() {
        let version = mapping.version.as_deref().unwrap_or("unknown");
        eprintln!("Using mapping table version {version}.");
        if let Some(provenance) = &mapping.provenance {
            eprintln!("  {provenance}");
        }
    }

    let analysis = analyze(&collection, &rule_field_set, &observed, &mapping);

    if let Some(path) = &args.dettect_data_sources {
        let admin = dettect::build_data_source_admin(&analysis, ARTIFACT_NAME);
        if let Err(code) = write_yaml(path, &admin, &ctx, "DeTT&CT data-source administration") {
            return code;
        }
    }
    if let Some(path) = &args.dettect_techniques {
        let admin = dettect::build_technique_admin(&analysis, ARTIFACT_NAME);
        if let Err(code) = write_yaml(path, &admin, &ctx, "DeTT&CT technique administration") {
            return code;
        }
    }
    if let Some(path) = &args.navigator {
        let layer = navigator::build_layer(&analysis, ARTIFACT_NAME);
        let json = navigator::to_pretty_json(&layer);
        if let Err(e) = std::fs::write(path, format!("{json}\n")) {
            eprintln!(
                "error: could not write Navigator layer to {}: {e}",
                path.display()
            );
            return exit_code::CONFIG_ERROR;
        }
        if ctx.show_progress() {
            eprintln!("Wrote visibility Navigator layer to {}", path.display());
        }
    }

    let report = VisibilityReport::build(&analysis, args.fail_on_blind_spots);
    report.render(&ctx);
    report.exit_code()
}

/// Serialize `value` as DeTT&CT YAML (with the seed header) and write it.
fn write_yaml<T: serde::Serialize>(
    path: &Path,
    value: &T,
    ctx: &OutputCtx,
    label: &str,
) -> Result<(), i32> {
    let body = match yaml_serde::to_string(value) {
        Ok(yaml) => yaml,
        Err(e) => {
            eprintln!("error: could not serialize {label}: {e}");
            return Err(exit_code::CONFIG_ERROR);
        }
    };
    let content = format!("{}{body}", dettect::SEED_HEADER);
    if let Err(e) = std::fs::write(path, content) {
        eprintln!("error: could not write {label} to {}: {e}", path.display());
        return Err(exit_code::CONFIG_ERROR);
    }
    if ctx.show_progress() {
        eprintln!("Wrote {label} to {}", path.display());
    }
    Ok(())
}

/// Resolve the observed signal: a live daemon (`--addr`), a file or stdin
/// (`--observed`), or the empty baseline.
fn resolve_observed(args: &VisibilityArgs) -> Result<Observed, String> {
    if let Some(addr) = &args.addr {
        let raw = fetch_observed(addr, args.config.as_deref())?;
        return parse_observed(&raw);
    }
    match args.observed.as_deref() {
        Some("-") => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("reading observed report from stdin: {e}"))?;
            parse_observed(&buf)
        }
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("could not read observed report {path}: {e}"))?;
            parse_observed(&raw)
        }
        None => Ok(Observed::default()),
    }
}

/// Fetch `GET /api/v1/fields` from a live daemon, mirroring `engine status`.
fn fetch_observed(addr: &str, config: Option<&Path>) -> Result<String, String> {
    let addr = config::resolve_daemon_addr(Some(addr.to_string()), config);
    let url = config::api_url(
        &addr,
        &format!("/api/v1/fields?limit={DAEMON_FIELDS_LIMIT}"),
    );
    match ureq::get(&url).call() {
        Ok(resp) => resp
            .into_body()
            .read_to_string()
            .map_err(|e| format!("reading response from {url}: {e}")),
        Err(ureq::Error::StatusCode(code)) => Err(format!(
            "{url} returned HTTP {code} (is --observe-fields enabled on the daemon?)"
        )),
        Err(e) => Err(format!(
            "could not reach {url}: {e} (is the daemon running?)"
        )),
    }
}

/// Parse the observed-field JSON into an [`Observed`]. Accepts both the
/// `engine eval --observe-fields` shape (`unknown`/`missing` as arrays) and the
/// daemon `GET /api/v1/fields` shape (paginated `{items, ...}` objects).
fn parse_observed(raw: &str) -> Result<Observed, String> {
    let report: ObservedReport =
        serde_json::from_str(raw).map_err(|e| format!("parsing observed field report: {e}"))?;

    let unknown: Vec<ObservedField> = report
        .unknown
        .map(Partition::into_items)
        .unwrap_or_default()
        .into_iter()
        .map(|u| ObservedField {
            field: u.field,
            count: u.count,
        })
        .collect();

    let missing: BTreeSet<String> = report
        .missing
        .map(Partition::into_items)
        .unwrap_or_default()
        .into_iter()
        .map(|m| m.field)
        .collect();

    Ok(Observed {
        present: true,
        missing,
        unknown,
        events_observed: report.summary.events_observed,
        unique_keys: report.summary.unique_keys_observed,
    })
}

/// Typed mirror of the observed-field JSON. Unknown fields are ignored so a
/// newer producer does not break ingestion.
#[derive(Debug, Deserialize)]
struct ObservedReport {
    #[serde(default)]
    summary: ObservedSummary,
    #[serde(default)]
    unknown: Option<Partition<UnknownEntry>>,
    #[serde(default)]
    missing: Option<Partition<MissingEntry>>,
}

#[derive(Debug, Default, Deserialize)]
struct ObservedSummary {
    #[serde(default)]
    events_observed: u64,
    #[serde(default)]
    unique_keys_observed: usize,
}

/// A partition that is either a bare array (eval report) or a paginated
/// `{items, total, ...}` object (daemon response).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Partition<T> {
    Array(Vec<T>),
    Paged { items: Vec<T> },
}

impl<T> Partition<T> {
    fn into_items(self) -> Vec<T> {
        match self {
            Partition::Array(v) => v,
            Partition::Paged { items } => items,
        }
    }
}

#[derive(Debug, Deserialize)]
struct UnknownEntry {
    field: String,
    #[serde(default)]
    count: u64,
}

#[derive(Debug, Deserialize)]
struct MissingEntry {
    field: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_eval_report_array_shape() {
        let raw = r#"{
            "summary": {"events_observed": 42, "unique_keys_observed": 3},
            "unknown": [{"field": "User", "count": 9}],
            "missing": [{"field": "ProcessGuid", "rule_count": 1, "sources": ["detection"]}]
        }"#;
        let observed = parse_observed(raw).unwrap();
        assert!(observed.present);
        assert_eq!(observed.events_observed, 42);
        assert_eq!(observed.unique_keys, 3);
        assert_eq!(observed.unknown.len(), 1);
        assert_eq!(observed.unknown[0].field, "User");
        assert_eq!(observed.unknown[0].count, 9);
        assert!(observed.missing.contains("ProcessGuid"));
    }

    #[test]
    fn parses_daemon_paginated_shape() {
        let raw = r#"{
            "summary": {"events_observed": 7, "unique_keys_observed": 2},
            "unknown": {"items": [{"field": "src_ip", "count": 4}], "total": 1, "offset": 0, "limit": 100, "next_offset": null},
            "missing": {"items": [{"field": "TargetObject", "rule_count": 2}], "total": 1, "offset": 0, "limit": 100, "next_offset": null}
        }"#;
        let observed = parse_observed(raw).unwrap();
        assert_eq!(observed.events_observed, 7);
        assert_eq!(observed.unknown[0].field, "src_ip");
        assert!(observed.missing.contains("TargetObject"));
    }

    #[test]
    fn empty_report_parses_to_present_but_empty() {
        let observed = parse_observed("{}").unwrap();
        assert!(observed.present);
        assert!(observed.missing.is_empty());
        assert!(observed.unknown.is_empty());
        assert_eq!(observed.events_observed, 0);
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(parse_observed("{not json").is_err());
    }

    fn parse_args(argv: &[&str]) -> (VisibilityArgs, ArgMatches) {
        use clap::{Command, FromArgMatches};
        let cmd = VisibilityArgs::augment_args(Command::new("visibility"));
        let matches = cmd.get_matches_from(argv);
        let args = VisibilityArgs::from_arg_matches(&matches).expect("valid args");
        (args, matches)
    }

    fn partial(yaml: &str) -> config::RsigmaConfigPartial {
        yaml_serde::from_str(yaml).expect("valid partial")
    }

    #[test]
    fn bare_mapping_flag_is_empty_sentinel() {
        let (args, _) = parse_args(&["visibility", "-r", "/r", "--mapping"]);
        assert_eq!(args.mapping.as_deref(), Some(""));
    }

    #[test]
    fn mapping_flag_with_value() {
        let (args, _) = parse_args(&["visibility", "-r", "/r", "--mapping=/local/table.json"]);
        assert_eq!(args.mapping.as_deref(), Some("/local/table.json"));
    }

    #[test]
    fn config_fills_unset_mapping_and_fail_on_blind_spots() {
        let (mut args, matches) = parse_args(&["visibility", "-r", "/r"]);
        let base =
            partial("visibility:\n  mapping: /file/table.json\n  fail_on_blind_spots: true\n");
        overlay_visibility_config(&mut args, &matches, base);
        assert_eq!(args.mapping.as_deref(), Some("/file/table.json"));
        assert!(args.fail_on_blind_spots);
    }

    #[test]
    fn cli_mapping_beats_config() {
        let (mut args, matches) =
            parse_args(&["visibility", "-r", "/r", "--mapping=/cli/table.json"]);
        let base = partial("visibility:\n  mapping: /file/table.json\n");
        overlay_visibility_config(&mut args, &matches, base);
        assert_eq!(args.mapping.as_deref(), Some("/cli/table.json"));
    }
}
