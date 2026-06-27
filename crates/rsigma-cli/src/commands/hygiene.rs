//! `rsigma rule hygiene`: turn the raw signals rsigma already produces into a
//! single rule hygiene and retirement report.
//!
//! It flags, in one report, the candidates a mature detection program reviews
//! on a retirement cadence: never-fired (silence) and noisy rules over a
//! Prometheus window, untagged rules (reusing the shared ATT&CK extractor so
//! this is the same notion of "untagged" `rule coverage` emits), rules with no
//! owner, detection rules with an incomplete ADS document, rules whose
//! referenced fields are never seen in the data, and deprecated/stale rules.
//!
//! Static signals (untagged, owner, ADS, status) need only `--rules`. The
//! silence and noisy signals join per-rule fire counts from a Prometheus
//! snapshot or endpoint (via the shared [`crate::metrics_source`] reader); the
//! broken-coverage signal joins a #55 field-observability snapshot. A
//! repeatable `--fail-on` policy gates CI.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::parser::ValueSource;
use clap::{ArgMatches, Args};
use rsigma_eval::RuleFieldSet;
use rsigma_parser::{AdsDocument, SigmaCollection, Status};
use serde::Serialize;

use crate::config;
use crate::exit_code;
use crate::metrics_source::{self, MetricsData};
use crate::output::{
    DelimitedWriter, OutputCtx, OutputFormat, Tabular, render_json, render_ndjson,
};
use crate::rule_meta;

/// Arguments for `rsigma rule hygiene`.
#[derive(Args, Debug)]
pub(crate) struct HygieneArgs {
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

    /// Prometheus exposition snapshot file or a `/metrics` URL for per-rule fire
    /// volume (`rsigma_*_matches_by_rule_total`, joined by rule_title). Drives
    /// the silence and noisy signals.
    #[arg(long = "metrics", value_name = "FILE_OR_URL")]
    pub metrics: Option<String>,

    /// When `--metrics` is a Prometheus query-API base URL, range-query window
    /// (e.g. 7d, 24h) for a true last-fired timestamp.
    #[arg(long = "metrics-window", value_name = "DURATION")]
    pub metrics_window: Option<String>,

    /// A #55 field-observability JSON snapshot (the `/api/v1/fields` payload or
    /// just its `missing` array). Drives the broken-coverage signal.
    #[arg(long = "fields", value_name = "FILE")]
    pub fields: Option<PathBuf>,

    /// Age past which a never-fired rule is a retirement candidate rather than
    /// merely quiet (duration such as 365d, 12h).
    #[arg(
        long = "silent-threshold",
        value_name = "DURATION",
        default_value = config::defaults::HYGIENE_SILENT_THRESHOLD,
    )]
    pub silent_threshold: String,

    /// Modified-date age past which a rule is flagged stale (duration such as
    /// 365d). Combined with the deprecated/unsupported status check.
    #[arg(
        long = "stale-threshold",
        value_name = "DURATION",
        default_value = config::defaults::HYGIENE_STALE_THRESHOLD,
    )]
    pub stale_threshold: String,

    /// Absolute per-window fire ceiling that overrides the robust outlier test:
    /// a rule firing at least this many times is flagged noisy.
    #[arg(long = "noisy-threshold", value_name = "COUNT")]
    pub noisy_threshold: Option<u64>,

    /// Write the full JSON report to this file, independent of `--output-format`.
    #[arg(long = "report", value_name = "FILE")]
    pub report: Option<PathBuf>,

    /// Findings that fail CI (repeatable): silent, noisy, untagged, no-owner,
    /// incomplete-ads, broken-fields, deprecated, or any.
    #[arg(long = "fail-on", value_name = "CONDITION")]
    pub fail_on: Vec<String>,
}

/// Overlay the `hygiene` config section (defaults < file < env) onto `args`
/// for any flag the operator did not set explicitly, then handle `--dry-run`.
pub(crate) fn apply_hygiene_config(args: &mut HygieneArgs, matches: &ArgMatches) {
    let base = config::load_and_merge(args.config.as_deref());
    if args.dry_run {
        config::print_dry_run("hygiene", &base);
        process::exit(exit_code::SUCCESS);
    }
    overlay_hygiene_config(args, matches, base);
}

/// Pure overlay of the resolved `hygiene` section onto `args` (no disk access),
/// split out so it can be unit-tested.
fn overlay_hygiene_config(
    args: &mut HygieneArgs,
    matches: &ArgMatches,
    base: config::RsigmaConfigPartial,
) {
    let explicit = |id: &str| {
        matches!(
            matches.value_source(id),
            Some(ValueSource::CommandLine | ValueSource::EnvVariable)
        )
    };

    if let Some(h) = base.hygiene {
        // Repeatable inputs with no clap default: an empty vec means the
        // operator left them off, so the config layer fills them.
        if !explicit("rules")
            && args.rules.is_empty()
            && let Some(v) = h.rules
        {
            args.rules = v;
        }
        if args.fail_on.is_empty()
            && let Some(v) = h.fail_on
        {
            args.fail_on = v;
        }
        // Inputs with no clap default: `is_none` means the operator left them off.
        if args.metrics.is_none()
            && let Some(v) = h.metrics
        {
            args.metrics = Some(v);
        }
        if args.metrics_window.is_none()
            && let Some(v) = h.metrics_window
        {
            args.metrics_window = Some(v);
        }
        if args.fields.is_none()
            && let Some(v) = h.fields
        {
            args.fields = Some(v);
        }
        if args.noisy_threshold.is_none()
            && let Some(v) = h.noisy_threshold
        {
            args.noisy_threshold = Some(v);
        }
        // Flags with clap defaults: fill only when not set explicitly.
        if !explicit("silent_threshold")
            && let Some(v) = h.silent_threshold
        {
            args.silent_threshold = v;
        }
        if !explicit("stale_threshold")
            && let Some(v) = h.stale_threshold
        {
            args.stale_threshold = v;
        }
    }
}

// ---------------------------------------------------------------------------
// Signals and fail-on policy
// ---------------------------------------------------------------------------

/// One hygiene signal a rule can trip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Signal {
    Silent,
    Noisy,
    Untagged,
    NoOwner,
    IncompleteAds,
    BrokenFields,
    Deprecated,
}

impl Signal {
    /// Stable wire name, shared by the report, the `--fail-on` policy, and the
    /// table output.
    fn wire(self) -> &'static str {
        match self {
            Signal::Silent => "silent",
            Signal::Noisy => "noisy",
            Signal::Untagged => "untagged",
            Signal::NoOwner => "no-owner",
            Signal::IncompleteAds => "incomplete-ads",
            Signal::BrokenFields => "broken-fields",
            Signal::Deprecated => "deprecated",
        }
    }
}

/// A parsed `--fail-on` condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailOn {
    Signal(Signal),
    Any,
}

impl FailOn {
    fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "silent" => FailOn::Signal(Signal::Silent),
            "noisy" => FailOn::Signal(Signal::Noisy),
            "untagged" => FailOn::Signal(Signal::Untagged),
            "no-owner" => FailOn::Signal(Signal::NoOwner),
            "incomplete-ads" => FailOn::Signal(Signal::IncompleteAds),
            "broken-fields" => FailOn::Signal(Signal::BrokenFields),
            "deprecated" => FailOn::Signal(Signal::Deprecated),
            "any" => FailOn::Any,
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// Report shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct HygieneReport {
    summary: Summary,
    /// Per-rule verdicts for the rules that tripped at least one signal.
    rules: Vec<RuleVerdict>,
    never_fired: Vec<String>,
    noisy: Vec<String>,
    untagged: Vec<String>,
    no_owner: Vec<String>,
    incomplete_ads: Vec<String>,
    broken_coverage: Vec<String>,
    stale_status: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Summary {
    rules_total: usize,
    detection_rules: usize,
    correlation_rules: usize,
    /// Rules that tripped at least one signal.
    flagged: usize,
    metrics_source: bool,
    fields_source: bool,
    never_fired: usize,
    noisy: usize,
    untagged: usize,
    no_owner: usize,
    incomplete_ads: usize,
    broken_coverage: usize,
    stale_status: usize,
}

#[derive(Debug, Clone, Serialize)]
struct RuleVerdict {
    rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    kind: String,
    signals: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fire_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_fired: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    tags: Vec<String>,
}

impl Tabular for RuleVerdict {
    fn headers() -> &'static [&'static str] {
        &[
            "RULE",
            "KIND",
            "SIGNALS",
            "FIRES",
            "LAST_FIRED",
            "OWNER",
            "STATUS",
        ]
    }
    fn row(&self) -> Vec<String> {
        let dash = || "-".to_string();
        vec![
            self.rule.clone(),
            self.kind.clone(),
            self.signals.join(","),
            self.fire_count.map(|c| c.to_string()).unwrap_or_else(dash),
            self.last_fired.clone().unwrap_or_else(dash),
            self.owner.clone().unwrap_or_else(dash),
            self.status.clone().unwrap_or_else(dash),
        ]
    }
}

// ---------------------------------------------------------------------------
// Working per-rule record (pre-noisy)
// ---------------------------------------------------------------------------

struct WorkingRule {
    title: String,
    id: Option<String>,
    kind: &'static str,
    tags: Vec<String>,
    owner: Option<String>,
    status: Option<String>,
    fire_count: Option<u64>,
    last_fired: Option<String>,
    signals: Vec<Signal>,
}

/// Run `rule hygiene`. Returns the process exit code: 0 success or report-only,
/// 1 when a selected `--fail-on` condition matches, 2 on rule load failure (via
/// the loader), 3 on bad flags or an unreadable metrics/fields input.
pub(crate) fn cmd_hygiene(args: HygieneArgs, ctx: OutputCtx) -> i32 {
    if args.rules.is_empty() {
        eprintln!("error: no rules path; pass --rules <PATH> (repeatable)");
        return exit_code::CONFIG_ERROR;
    }

    let Some(silent_secs) = metrics_source::parse_window_secs(&args.silent_threshold) else {
        eprintln!(
            "error: invalid --silent-threshold '{}' (expected e.g. 365d, 12h)",
            args.silent_threshold
        );
        return exit_code::CONFIG_ERROR;
    };
    let Some(stale_secs) = metrics_source::parse_window_secs(&args.stale_threshold) else {
        eprintln!(
            "error: invalid --stale-threshold '{}' (expected e.g. 365d, 12h)",
            args.stale_threshold
        );
        return exit_code::CONFIG_ERROR;
    };

    let fail_on = match parse_fail_on(&args.fail_on) {
        Ok(f) => f,
        Err(bad) => {
            eprintln!(
                "error: invalid --fail-on '{bad}' (expected silent, noisy, untagged, no-owner, \
                 incomplete-ads, broken-fields, deprecated, or any)"
            );
            return exit_code::CONFIG_ERROR;
        }
    };

    let collection = crate::load_collection_multi(&args.rules);

    let metrics = match &args.metrics {
        Some(spec) => match metrics_source::load_metrics(spec, args.metrics_window.as_deref()) {
            Ok(m) => Some(m),
            Err(e) => {
                eprintln!("error: {e}");
                return exit_code::CONFIG_ERROR;
            }
        },
        None => None,
    };

    let missing_fields = match &args.fields {
        Some(path) => match load_missing_fields(path) {
            Ok(set) => Some(set),
            Err(e) => {
                eprintln!("error: {e}");
                return exit_code::CONFIG_ERROR;
            }
        },
        None => None,
    };

    let report = build_report(
        &collection,
        metrics.as_ref(),
        missing_fields.as_ref(),
        silent_secs,
        stale_secs,
        args.noisy_threshold,
        now_unix(),
    );

    if let Some(path) = &args.report
        && let Err(e) = write_report(path, &report)
    {
        eprintln!("error: could not write report to {}: {e}", path.display());
        return exit_code::CONFIG_ERROR;
    }

    render(&report, &ctx);

    exit_code_for(&report, &fail_on, &ctx)
}

/// Parse the repeatable `--fail-on` values, returning the first invalid token.
fn parse_fail_on(values: &[String]) -> Result<Vec<FailOn>, String> {
    values
        .iter()
        .map(|v| FailOn::parse(v).ok_or_else(|| v.clone()))
        .collect()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Report building
// ---------------------------------------------------------------------------

fn build_report(
    collection: &SigmaCollection,
    metrics: Option<&MetricsData>,
    missing_fields: Option<&BTreeSet<String>>,
    silent_secs: i64,
    stale_secs: i64,
    noisy_threshold: Option<u64>,
    now_unix: i64,
) -> HygieneReport {
    let today_days = now_unix.div_euclid(86_400);
    let stale_days = stale_secs / 86_400;

    // Per-rule field sets (title -> fields) for the broken-coverage rollup, only
    // when a field-observability snapshot is supplied. Filters are excluded to
    // match the coverage/untagged universe.
    let title_fields: HashMap<String, BTreeSet<String>> = if missing_fields.is_some() {
        invert_rule_fields(collection)
    } else {
        HashMap::new()
    };

    let mut working: Vec<WorkingRule> = Vec::new();

    for rule in &collection.rules {
        let mut signals = Vec::new();
        if !rule_meta::has_attack_tag(&rule.tags) {
            signals.push(Signal::Untagged);
        }
        let owner = rule_meta::resolve_owner(rule.author.as_deref(), &rule.custom_attributes);
        if owner.is_none() {
            signals.push(Signal::NoOwner);
        }
        if incomplete_ads(rule) {
            signals.push(Signal::IncompleteAds);
        }
        if is_stale(
            rule.status,
            rule.modified.as_deref(),
            rule.date.as_deref(),
            today_days,
            stale_days,
        ) {
            signals.push(Signal::Deprecated);
        }
        if broken_fields(&rule.title, &title_fields, missing_fields) {
            signals.push(Signal::BrokenFields);
        }
        let (fire_count, last_fired) =
            fire_signal(&rule.title, metrics, silent_secs, now_unix, &mut signals);

        working.push(WorkingRule {
            title: rule.title.clone(),
            id: rule.id.clone(),
            kind: "detection",
            tags: rule.tags.clone(),
            owner,
            status: rule.status.map(|s| rule_meta::status_str(s).to_string()),
            fire_count,
            last_fired,
            signals,
        });
    }

    for corr in &collection.correlations {
        let mut signals = Vec::new();
        if !rule_meta::has_attack_tag(&corr.tags) {
            signals.push(Signal::Untagged);
        }
        let owner = rule_meta::resolve_owner(corr.author.as_deref(), &corr.custom_attributes);
        if owner.is_none() {
            signals.push(Signal::NoOwner);
        }
        if is_stale(
            corr.status,
            corr.modified.as_deref(),
            corr.date.as_deref(),
            today_days,
            stale_days,
        ) {
            signals.push(Signal::Deprecated);
        }
        let (fire_count, last_fired) =
            fire_signal(&corr.title, metrics, silent_secs, now_unix, &mut signals);

        working.push(WorkingRule {
            title: corr.title.clone(),
            id: corr.id.clone(),
            kind: "correlation",
            tags: corr.tags.clone(),
            owner,
            status: corr.status.map(|s| rule_meta::status_str(s).to_string()),
            fire_count,
            last_fired,
            signals,
        });
    }

    // Noisy is a distribution outlier, so it needs the full fired-count set.
    if metrics.is_some() {
        let fired: Vec<u64> = working
            .iter()
            .filter_map(|w| w.fire_count)
            .filter(|&c| c > 0)
            .collect();
        let mode = noisy_mode(&fired, noisy_threshold);
        for w in &mut working {
            if let Some(c) = w.fire_count
                && c > 0
                && mode.is_noisy(c)
            {
                w.signals.push(Signal::Noisy);
            }
        }
    }

    assemble(
        collection,
        working,
        metrics.is_some(),
        missing_fields.is_some(),
    )
}

/// Fold the working records into the serializable report (per-signal lists,
/// summary, and the flagged per-rule verdicts).
fn assemble(
    collection: &SigmaCollection,
    working: Vec<WorkingRule>,
    metrics_source_used: bool,
    fields_source_used: bool,
) -> HygieneReport {
    let mut report = HygieneReport {
        summary: Summary {
            rules_total: working.len(),
            detection_rules: collection.rules.len(),
            correlation_rules: collection.correlations.len(),
            flagged: 0,
            metrics_source: metrics_source_used,
            fields_source: fields_source_used,
            never_fired: 0,
            noisy: 0,
            untagged: 0,
            no_owner: 0,
            incomplete_ads: 0,
            broken_coverage: 0,
            stale_status: 0,
        },
        rules: Vec::new(),
        never_fired: Vec::new(),
        noisy: Vec::new(),
        untagged: Vec::new(),
        no_owner: Vec::new(),
        incomplete_ads: Vec::new(),
        broken_coverage: Vec::new(),
        stale_status: Vec::new(),
    };

    for w in working {
        if w.signals.is_empty() {
            continue;
        }
        for &sig in &w.signals {
            let bucket = match sig {
                Signal::Silent => &mut report.never_fired,
                Signal::Noisy => &mut report.noisy,
                Signal::Untagged => &mut report.untagged,
                Signal::NoOwner => &mut report.no_owner,
                Signal::IncompleteAds => &mut report.incomplete_ads,
                Signal::BrokenFields => &mut report.broken_coverage,
                Signal::Deprecated => &mut report.stale_status,
            };
            bucket.push(w.title.clone());
        }
        report.rules.push(RuleVerdict {
            rule: w.title,
            id: w.id,
            kind: w.kind.to_string(),
            signals: w.signals.iter().map(|s| s.wire().to_string()).collect(),
            fire_count: w.fire_count,
            last_fired: w.last_fired,
            owner: w.owner,
            status: w.status,
            tags: w.tags,
        });
    }

    report.summary.flagged = report.rules.len();
    report.summary.never_fired = report.never_fired.len();
    report.summary.noisy = report.noisy.len();
    report.summary.untagged = report.untagged.len();
    report.summary.no_owner = report.no_owner.len();
    report.summary.incomplete_ads = report.incomplete_ads.len();
    report.summary.broken_coverage = report.broken_coverage.len();
    report.summary.stale_status = report.stale_status.len();
    report
}

/// Compute the fire count / last-fired / silence for one rule title against the
/// metrics snapshot, pushing the silent signal when appropriate.
fn fire_signal(
    title: &str,
    metrics: Option<&MetricsData>,
    silent_secs: i64,
    now_unix: i64,
    signals: &mut Vec<Signal>,
) -> (Option<u64>, Option<String>) {
    let Some(m) = metrics else {
        return (None, None);
    };
    let count = m.by_title.get(title).copied().unwrap_or(0);
    let last_fired_ts = m.last_fired.get(title).copied();
    let last_fired = last_fired_ts.map(metrics_source::unix_to_rfc3339);
    // Never-fired by absence, or fired only outside the silence window.
    let silent = count == 0 || last_fired_ts.is_some_and(|ts| now_unix - ts > silent_secs);
    if silent {
        signals.push(Signal::Silent);
    }
    (Some(count), last_fired)
}

/// A detection rule with a `stable` status, no ADS exemption, and at least one
/// missing required ADS section is flagged. This mirrors the shipped ADS
/// presence lint's default bar (enforced on `stable`, default-required
/// sections); finer control stays in the linter.
fn incomplete_ads(rule: &rsigma_parser::SigmaRule) -> bool {
    if rule.status != Some(Status::Stable) || rsigma_parser::ads::is_exempt(rule) {
        return false;
    }
    !AdsDocument::from_rule(rule).missing_required().is_empty()
}

/// Whether a rule is a stale-status retirement candidate: a deprecated or
/// unsupported status, or a `modified`/`date` older than the staleness window.
fn is_stale(
    status: Option<Status>,
    modified: Option<&str>,
    date: Option<&str>,
    today_days: i64,
    stale_days: i64,
) -> bool {
    if status.is_some_and(rule_meta::is_retired_status) {
        return true;
    }
    modified
        .or(date)
        .and_then(rule_meta::parse_rule_date)
        .is_some_and(|rule_days| today_days - rule_days > stale_days)
}

/// Whether a detection rule references only fields that the field-observability
/// snapshot never observed: a non-empty field set entirely inside `missing`.
fn broken_fields(
    title: &str,
    title_fields: &HashMap<String, BTreeSet<String>>,
    missing_fields: Option<&BTreeSet<String>>,
) -> bool {
    let Some(missing) = missing_fields else {
        return false;
    };
    match title_fields.get(title) {
        Some(fields) if !fields.is_empty() => fields.iter().all(|f| missing.contains(f)),
        _ => false,
    }
}

/// Invert the collection's rule field set into `title -> referenced fields`,
/// excluding filter rules (which suppress rather than detect).
fn invert_rule_fields(collection: &SigmaCollection) -> HashMap<String, BTreeSet<String>> {
    let set = RuleFieldSet::collect(collection, &[], false);
    let mut by_title: HashMap<String, BTreeSet<String>> = HashMap::new();
    for (name, origin) in set.iter() {
        for title in &origin.rule_titles {
            by_title
                .entry(title.clone())
                .or_default()
                .insert(name.to_string());
        }
    }
    by_title
}

// ---------------------------------------------------------------------------
// Noisy outlier test (robust median + MAD)
// ---------------------------------------------------------------------------

/// Minimum number of fired rules before the robust outlier test is meaningful.
/// Below this, only an absolute `--noisy-threshold` flags noisy rules.
const MIN_FIRED_FOR_MAD: usize = 3;

enum NoisyMode {
    /// No noisy detection (too few fired rules and no absolute threshold).
    None,
    /// A rule firing at least `0` times is noisy (absolute override).
    Absolute(u64),
    /// A rule firing strictly more than the median-plus-MAD threshold is noisy.
    Mad(f64),
}

impl NoisyMode {
    fn is_noisy(&self, count: u64) -> bool {
        match self {
            NoisyMode::None => false,
            NoisyMode::Absolute(a) => count >= *a,
            NoisyMode::Mad(t) => (count as f64) > *t,
        }
    }
}

/// Pick the noisy classification mode. An absolute `--noisy-threshold` always
/// wins; otherwise a robust median-plus-MAD outlier test over the fired counts
/// (k = 3, the conventional outlier cutoff) is used when enough rules fired.
fn noisy_mode(fired: &[u64], absolute: Option<u64>) -> NoisyMode {
    if let Some(a) = absolute {
        return NoisyMode::Absolute(a.max(1));
    }
    if fired.len() < MIN_FIRED_FOR_MAD {
        return NoisyMode::None;
    }
    let mut values: Vec<f64> = fired.iter().map(|&c| c as f64).collect();
    let med = median(&mut values);
    let mut deviations: Vec<f64> = fired.iter().map(|&c| (c as f64 - med).abs()).collect();
    let mad = median(&mut deviations);
    // 1.4826 scales the MAD to a normal-consistent standard deviation; k = 3 is
    // the conventional outlier cutoff.
    NoisyMode::Mad(med + 3.0 * 1.4826 * mad)
}

/// Median of a slice, sorting it in place. Caller guarantees a non-empty slice.
fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = values.len();
    if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    }
}

// ---------------------------------------------------------------------------
// Field-observability snapshot parsing
// ---------------------------------------------------------------------------

/// Load the set of never-seen field names from a #55 field-observability JSON
/// snapshot. Tolerant of the three shapes the toolkit emits: a top-level
/// `missing` array (the `engine eval` report and `/api/v1/fields/missing`), a
/// top-level `missing.items` array (`/api/v1/fields`), or a bare array. Each
/// entry is either a `{ "field": "...", ... }` object or a plain field string.
fn load_missing_fields(path: &std::path::Path) -> Result<BTreeSet<String>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read fields snapshot {}: {e}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("could not parse fields snapshot {}: {e}", path.display()))?;
    Ok(extract_missing(&value))
}

fn extract_missing(value: &serde_json::Value) -> BTreeSet<String> {
    let array = if let Some(missing) = value.get("missing") {
        if let Some(arr) = missing.as_array() {
            Some(arr)
        } else {
            missing.get("items").and_then(|i| i.as_array())
        }
    } else {
        value.as_array()
    };
    let Some(array) = array else {
        return BTreeSet::new();
    };
    array
        .iter()
        .filter_map(|entry| match entry {
            serde_json::Value::String(s) => Some(s.clone()),
            other => other
                .get("field")
                .and_then(|f| f.as_str())
                .map(str::to_string),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// Resolve the effective output format. An explicit `--output-format` wins;
/// otherwise a TTY gets the human table and a pipe gets NDJSON.
fn effective_format(ctx: &OutputCtx) -> OutputFormat {
    if ctx.explicit_format {
        ctx.format
    } else if ctx.stdout_is_tty {
        OutputFormat::Table
    } else {
        OutputFormat::Ndjson
    }
}

fn render(report: &HygieneReport, ctx: &OutputCtx) {
    match effective_format(ctx) {
        OutputFormat::Json => render_json(report, ctx.pretty_json()),
        OutputFormat::Ndjson => {
            for verdict in &report.rules {
                render_ndjson(verdict);
            }
        }
        OutputFormat::Csv => render_delimited(report, ',', ctx),
        OutputFormat::Tsv => render_delimited(report, '\t', ctx),
        OutputFormat::Table => render_table(report, ctx),
    }
}

fn render_delimited(report: &HygieneReport, sep: char, ctx: &OutputCtx) {
    if ctx.show_stats() {
        emit_summary(report, ctx);
    }
    let mut writer = DelimitedWriter::new(sep, RuleVerdict::headers());
    for verdict in &report.rules {
        writer.push(&verdict.row());
    }
}

fn render_table(report: &HygieneReport, ctx: &OutputCtx) {
    if ctx.show_stats() {
        emit_summary(report, ctx);
    }
    if report.rules.is_empty() {
        if ctx.show_progress() {
            eprintln!("No hygiene findings.");
        }
        return;
    }
    if ctx.show_stats() {
        eprintln!();
    }
    crate::output::render_table(&report.rules);
}

/// Emit the summary and per-signal breakdown to stderr (gated on `show_stats`),
/// keeping stdout reserved for the data rows.
fn emit_summary(report: &HygieneReport, ctx: &OutputCtx) {
    let s = &report.summary;
    let mut sources = Vec::new();
    if s.metrics_source {
        sources.push("metrics");
    }
    if s.fields_source {
        sources.push("fields");
    }
    let sources = if sources.is_empty() {
        "rules only".to_string()
    } else {
        format!("rules + {}", sources.join(" + "))
    };
    eprintln!(
        "Rules: {} ({} detection, {} correlation) | Flagged: {} | Sources: {sources}",
        s.rules_total, s.detection_rules, s.correlation_rules, s.flagged,
    );
    let p = crate::output::Painter::new(ctx.color);
    eprintln!(
        "  {} silent  {} noisy  {} untagged  {} no-owner  {} incomplete-ads  {} broken-fields  {} deprecated",
        p.bold(&s.never_fired.to_string()),
        p.bold(&s.noisy.to_string()),
        p.bold(&s.untagged.to_string()),
        p.bold(&s.no_owner.to_string()),
        p.bold(&s.incomplete_ads.to_string()),
        p.bold(&s.broken_coverage.to_string()),
        p.bold(&s.stale_status.to_string()),
    );
}

fn write_report(path: &std::path::Path, report: &HygieneReport) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(report)
        .unwrap_or_else(|_| "{\"error\":\"serialize\"}".to_string());
    std::fs::write(path, format!("{json}\n"))
}

/// Compute the exit code from the report and the `--fail-on` policy.
fn exit_code_for(report: &HygieneReport, fail_on: &[FailOn], ctx: &OutputCtx) -> i32 {
    let triggered = fail_on.iter().any(|cond| match cond {
        FailOn::Any => !report.rules.is_empty(),
        FailOn::Signal(sig) => !signal_list(report, *sig).is_empty(),
    });
    if triggered {
        if ctx.show_stats() {
            eprintln!("hygiene: --fail-on policy matched at least one rule");
        }
        exit_code::FINDINGS
    } else {
        exit_code::SUCCESS
    }
}

fn signal_list(report: &HygieneReport, sig: Signal) -> &[String] {
    match sig {
        Signal::Silent => &report.never_fired,
        Signal::Noisy => &report.noisy,
        Signal::Untagged => &report.untagged,
        Signal::NoOwner => &report.no_owner,
        Signal::IncompleteAds => &report.incomplete_ads,
        Signal::BrokenFields => &report.broken_coverage,
        Signal::Deprecated => &report.stale_status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Command, FromArgMatches};

    fn collection(yaml: &str) -> SigmaCollection {
        rsigma_parser::parse_sigma_yaml(yaml).expect("parse")
    }

    fn parse(argv: &[&str]) -> (HygieneArgs, ArgMatches) {
        let cmd = HygieneArgs::augment_args(Command::new("hygiene"));
        let matches = cmd.get_matches_from(argv);
        let args = HygieneArgs::from_arg_matches(&matches).expect("valid args");
        (args, matches)
    }

    fn partial(yaml: &str) -> config::RsigmaConfigPartial {
        yaml_serde::from_str(yaml).expect("valid partial")
    }

    #[test]
    fn defaults_match_config_defaults() {
        let (args, _) = parse(&["hygiene", "-r", "/r"]);
        assert_eq!(
            args.silent_threshold,
            config::defaults::HYGIENE_SILENT_THRESHOLD
        );
        assert_eq!(
            args.stale_threshold,
            config::defaults::HYGIENE_STALE_THRESHOLD
        );
    }

    #[test]
    fn config_fills_unset_inputs_and_thresholds() {
        let (mut args, matches) = parse(&["hygiene", "-r", "/r"]);
        let base = partial(
            "hygiene:\n  metrics: /m/metrics.txt\n  silent_threshold: 30d\n  fail_on:\n    - silent\n",
        );
        overlay_hygiene_config(&mut args, &matches, base);
        assert_eq!(args.metrics.as_deref(), Some("/m/metrics.txt"));
        assert_eq!(args.silent_threshold, "30d");
        assert_eq!(args.fail_on, vec!["silent".to_string()]);
    }

    #[test]
    fn cli_threshold_beats_config() {
        let (mut args, matches) = parse(&["hygiene", "-r", "/r", "--silent-threshold", "7d"]);
        let base = partial("hygiene:\n  silent_threshold: 30d\n");
        overlay_hygiene_config(&mut args, &matches, base);
        assert_eq!(args.silent_threshold, "7d");
    }

    #[test]
    fn fail_on_parse_rejects_unknown() {
        assert!(FailOn::parse("silent").is_some());
        assert!(FailOn::parse("any").is_some());
        assert!(FailOn::parse("broken-fields").is_some());
        assert!(FailOn::parse("bogus").is_none());
    }

    #[test]
    fn noisy_mad_flags_high_outlier() {
        let fired = vec![1, 1, 2, 2, 1, 100];
        let mode = noisy_mode(&fired, None);
        assert!(mode.is_noisy(100));
        assert!(!mode.is_noisy(2));
    }

    #[test]
    fn noisy_absolute_overrides_mad() {
        let mode = noisy_mode(&[1, 1, 1], Some(5));
        assert!(mode.is_noisy(5));
        assert!(mode.is_noisy(9));
        assert!(!mode.is_noisy(4));
    }

    #[test]
    fn noisy_needs_enough_fired_without_absolute() {
        // Two fired rules: too few for a robust outlier test.
        let mode = noisy_mode(&[1, 50], None);
        assert!(!mode.is_noisy(50));
    }

    #[test]
    fn extract_missing_accepts_flat_array_items_and_strings() {
        let flat = serde_json::json!({"missing": [{"field": "ProcessGuid"}, {"field": "Foo"}]});
        assert!(extract_missing(&flat).contains("ProcessGuid"));
        let items = serde_json::json!({"missing": {"items": [{"field": "Bar"}], "total": 1}});
        assert!(extract_missing(&items).contains("Bar"));
        let bare = serde_json::json!(["A", "B"]);
        let set = extract_missing(&bare);
        assert!(set.contains("A") && set.contains("B"));
    }

    #[test]
    fn untagged_and_no_owner_static_signals() {
        let col = collection(
            r#"
title: No tags no owner
id: 00000000-0000-0000-0000-000000000001
logsource: {category: test}
detection: {sel: {Image: a}, condition: sel}
"#,
        );
        let report = build_report(&col, None, None, 31_536_000, 31_536_000, None, now_unix());
        assert_eq!(report.untagged, vec!["No tags no owner".to_string()]);
        assert_eq!(report.no_owner, vec!["No tags no owner".to_string()]);
        // No metrics: no silence/noisy.
        assert!(report.never_fired.is_empty());
        assert!(report.noisy.is_empty());
    }

    #[test]
    fn owner_from_author_clears_no_owner() {
        let col = collection(
            r#"
title: Owned
id: 00000000-0000-0000-0000-000000000002
author: Blue Team
tags: [attack.t1059]
logsource: {category: test}
detection: {sel: {Image: a}, condition: sel}
"#,
        );
        let report = build_report(&col, None, None, 31_536_000, 31_536_000, None, now_unix());
        assert!(report.no_owner.is_empty());
        assert!(report.untagged.is_empty());
    }

    #[test]
    fn deprecated_status_flags_stale() {
        let col = collection(
            r#"
title: Old rule
id: 00000000-0000-0000-0000-000000000003
status: deprecated
author: x
tags: [attack.t1059]
logsource: {category: test}
detection: {sel: {Image: a}, condition: sel}
"#,
        );
        let report = build_report(&col, None, None, 31_536_000, 31_536_000, None, now_unix());
        assert_eq!(report.stale_status, vec!["Old rule".to_string()]);
    }

    #[test]
    fn modified_age_flags_stale() {
        let col = collection(
            r#"
title: Ancient
id: 00000000-0000-0000-0000-000000000004
status: stable
author: x
tags: [attack.t1059]
modified: 2000-01-01
logsource: {category: test}
detection: {sel: {Image: a}, condition: sel}
"#,
        );
        // 30-day staleness window; a 2000 modified date is well past it.
        let report = build_report(&col, None, None, 31_536_000, 2_592_000, None, now_unix());
        assert_eq!(report.stale_status, vec!["Ancient".to_string()]);
    }

    #[test]
    fn silence_from_metrics_absence() {
        let col = collection(
            r#"
title: Quiet
id: 00000000-0000-0000-0000-000000000005
author: x
tags: [attack.t1059]
logsource: {category: test}
detection: {sel: {Image: a}, condition: sel}
---
title: Loud
id: 00000000-0000-0000-0000-000000000006
author: x
tags: [attack.t1059]
logsource: {category: test}
detection: {sel: {Image: b}, condition: sel}
"#,
        );
        let mut metrics = MetricsData::default();
        metrics.by_title.insert("Loud".to_string(), 5);
        let report = build_report(
            &col,
            Some(&metrics),
            None,
            31_536_000,
            31_536_000,
            None,
            now_unix(),
        );
        assert_eq!(report.never_fired, vec!["Quiet".to_string()]);
    }

    #[test]
    fn broken_fields_when_all_fields_unseen() {
        let col = collection(
            r#"
title: Tampering
id: 00000000-0000-0000-0000-000000000007
author: x
tags: [attack.t1059]
logsource: {category: test}
detection:
    sel:
        ProcessGuid: "{abc}"
    condition: sel
"#,
        );
        let mut missing = BTreeSet::new();
        missing.insert("ProcessGuid".to_string());
        let report = build_report(
            &col,
            None,
            Some(&missing),
            31_536_000,
            31_536_000,
            None,
            now_unix(),
        );
        assert_eq!(report.broken_coverage, vec!["Tampering".to_string()]);
    }
}
