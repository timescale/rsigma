//! `rsigma rule backtest`: replay an event corpus against a ruleset, diff the
//! per-rule fire counts against declared expectations, and emit a CI-native
//! report.
//!
//! Backtest sits on top of the shared event stream loop (`commands::eval_stream`)
//! so it parses corpus input exactly as `engine eval` does. The difference is
//! the per-result action: instead of rendering each match, backtest accumulates
//! per-rule and per-corpus-file counters, then diffs them against an optional
//! expectations file. Correlation state is reset per corpus file (each file is
//! an independent time slice; carrying window state across files would produce
//! phantom correlations).

mod expectations;
mod report;

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;

use clap::parser::ValueSource;
use clap::{ArgMatches, Args};
use rsigma_eval::{CorrelationConfig, CorrelationEngine, Engine, EvaluationResult, Pipeline};
use rsigma_parser::SigmaCollection;

#[cfg(feature = "evtx")]
use super::eval_stream::stream_evtx_events;
use super::eval_stream::{CorrelationProcessor, DetectionProcessor, EventProcessor, stream_events};
use crate::config;
use crate::exit_code;
use crate::output::OutputCtx;
use expectations::{ResolvedExpectations, UnexpectedPolicy};
use report::{Accumulator, Report, result_key};

/// Arguments for `rsigma rule backtest`.
#[derive(Args, Debug)]
pub(crate) struct BacktestArgs {
    /// Path to a YAML config file. Overrides config-file discovery.
    /// CLI flags still take precedence over config-file values.
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Print the effective config (defaults < file < env) and exit.
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Path to a Sigma rule file or directory of rules.
    /// Required unless supplied via `backtest.rules` in the config file.
    #[arg(short, long)]
    pub rules: Option<PathBuf>,

    /// Event corpus: a file or a directory walked recursively. Repeatable.
    /// Extension dispatch: `.ndjson`/`.jsonl` as NDJSON, `.evtx` via the
    /// feature-gated adapter, everything else through `--input-format`.
    /// Required unless supplied via `backtest.corpus` in the config file.
    #[arg(long = "corpus", value_name = "PATH")]
    pub corpus: Vec<PathBuf>,

    /// Expectations YAML (per-rule fire-count assertions). Without it, backtest
    /// still runs and reports per-rule statistics; it just has nothing to diff.
    #[arg(long = "expectations", value_name = "PATH")]
    pub expectations: Option<PathBuf>,

    /// What an unmatched fire (a rule firing with no covering expectation)
    /// means: `fail`, `warn`, or `ignore`. Overrides the file-level default.
    #[arg(long = "unexpected", value_parser = ["fail", "warn", "ignore"])]
    pub unexpected: Option<String>,

    /// Processing pipeline(s) to apply. Accepts builtin names (ecs_windows,
    /// sysmon) or YAML file paths. Repeatable.
    #[arg(short = 'p', long = "pipeline")]
    pub pipelines: Vec<PathBuf>,

    /// jq filter to extract the event payload from each JSON object.
    #[arg(long = "jq", conflicts_with = "jsonpath")]
    pub jq: Option<String>,

    /// JSONPath (RFC 9535) query to extract the event payload.
    #[arg(long = "jsonpath", conflicts_with = "jq")]
    pub jsonpath: Option<String>,

    /// Input log format for non-NDJSON corpus files.
    /// auto: try JSON, then syslog, then plain (default).
    #[arg(long = "input-format", default_value = "auto")]
    pub input_format: String,

    /// Default timezone offset for RFC 3164 syslog (e.g. +05:00, -08:00).
    #[arg(long = "syslog-tz", default_value = "+00:00")]
    pub syslog_tz: String,

    /// Strip a leading UTF-8 BOM from RFC 5424 syslog messages. On by default.
    #[arg(long = "syslog-strip-bom", default_value_t = true, action = clap::ArgAction::Set)]
    pub syslog_strip_bom: bool,

    /// Write a JUnit XML report (one test case per expectation, plus one per
    /// unexpected-firing rule under the `fail` policy).
    #[arg(long = "junit", value_name = "PATH")]
    pub junit: Option<PathBuf>,

    /// Write the full JSON report to a file regardless of the stdout format.
    #[arg(long = "report", value_name = "PATH")]
    pub report: Option<PathBuf>,
}

/// Overlay the `backtest` config section (defaults < file < env) onto `args`
/// for any flag the operator did not set explicitly, then handle `--dry-run`.
pub(crate) fn apply_backtest_config(args: &mut BacktestArgs, matches: &ArgMatches) {
    let base = config::load_and_merge(args.config.as_deref());
    if args.dry_run {
        config::print_dry_run("backtest", &base);
        process::exit(exit_code::SUCCESS);
    }
    overlay_backtest_config(args, matches, base);
}

/// Pure overlay of the resolved `backtest` section onto `args` (no disk
/// access), split out from [`apply_backtest_config`] so it can be unit-tested.
fn overlay_backtest_config(
    args: &mut BacktestArgs,
    matches: &ArgMatches,
    base: config::RsigmaConfigPartial,
) {
    let explicit = |id: &str| {
        matches!(
            matches.value_source(id),
            Some(ValueSource::CommandLine | ValueSource::EnvVariable)
        )
    };

    if let Some(bt) = base.backtest {
        if !explicit("rules")
            && let Some(v) = bt.rules
        {
            args.rules = Some(v);
        }
        if !explicit("corpus")
            && let Some(v) = bt.corpus
        {
            args.corpus = v;
        }
        if !explicit("expectations")
            && let Some(v) = bt.expectations
        {
            args.expectations = Some(v);
        }
        // `--unexpected` has no clap default, so `is_none` means the operator
        // did not set it on the command line; let the config layer fill it.
        if args.unexpected.is_none()
            && let Some(v) = bt.unexpected
        {
            args.unexpected = Some(v);
        }
        if !explicit("pipelines")
            && let Some(v) = bt.pipelines
        {
            args.pipelines = v;
        }
        if !explicit("input_format")
            && let Some(v) = bt.input_format
        {
            args.input_format = v;
        }
        if !explicit("syslog_tz")
            && let Some(v) = bt.syslog_tz
        {
            args.syslog_tz = v;
        }
        if !explicit("syslog_strip_bom")
            && let Some(v) = bt.syslog_strip_bom
        {
            args.syslog_strip_bom = v;
        }
    }
}

/// Run the backtest. Returns the process exit code (0 pass, 1 findings,
/// 2 rule error, 3 config error). Rule and config errors exit directly.
pub(crate) fn cmd_backtest(args: BacktestArgs, ctx: OutputCtx) -> i32 {
    let Some(rules_path) = args.rules.clone() else {
        eprintln!("error: no rules path; set --rules or backtest.rules in the config file");
        return exit_code::CONFIG_ERROR;
    };
    if args.corpus.is_empty() {
        eprintln!("error: no corpus; set --corpus or backtest.corpus in the config file");
        return exit_code::CONFIG_ERROR;
    }

    // `load_collection` exits with RULE_ERROR if the rules cannot be parsed.
    let collection = crate::load_collection(&rules_path);
    let pipelines = crate::load_pipelines(&args.pipelines);
    let event_filter = crate::build_event_filter(args.jq.clone(), args.jsonpath.clone());

    let resolved = match &args.expectations {
        Some(path) => match expectations::load_and_resolve(path, &collection) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("error: {e}");
                return exit_code::CONFIG_ERROR;
            }
        },
        None => None,
    };

    let policy = match resolve_policy(args.unexpected.as_deref(), resolved.as_ref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return exit_code::CONFIG_ERROR;
        }
    };

    let report = match run(
        &args,
        collection,
        &pipelines,
        &event_filter,
        resolved,
        policy,
    ) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("error: {e}");
            return exit_code::CONFIG_ERROR;
        }
    };

    report.render(&ctx, args.report.as_deref(), args.junit.as_deref());
    report.exit_code()
}

/// Effective unexpected policy: CLI/config flag > expectations-file default >
/// the built-in `warn`.
fn resolve_policy(
    cli_or_config: Option<&str>,
    resolved: Option<&ResolvedExpectations>,
) -> Result<UnexpectedPolicy, String> {
    if let Some(s) = cli_or_config {
        return UnexpectedPolicy::parse(s).ok_or_else(|| {
            format!("invalid unexpected policy '{s}' (expected fail, warn, ignore)")
        });
    }
    if let Some(p) = resolved.and_then(|r| r.file_default_policy) {
        return Ok(p);
    }
    Ok(UnexpectedPolicy::default())
}

/// Walk the corpus, evaluate each file with fresh correlation state, and build
/// the report.
fn run(
    args: &BacktestArgs,
    collection: SigmaCollection,
    pipelines: &[Pipeline],
    event_filter: &crate::EventFilter,
    resolved: Option<ResolvedExpectations>,
    policy: UnexpectedPolicy,
) -> Result<Report, String> {
    let corpus_files = collect_corpus_files(&args.corpus)?;
    if corpus_files.is_empty() {
        eprintln!("warning: no corpus files found under the given --corpus path(s)");
    }

    let has_correlations = !collection.correlations.is_empty();
    let mut acc = Accumulator::new();
    let start = Instant::now();

    // Detection-only rulesets are stateless, so one compiled engine is reused
    // across files. With correlations, the engine is rebuilt per file to reset
    // window state (the engine exposes no in-place state reset).
    let detection_engine =
        (!has_correlations).then(|| build_detection_engine(&collection, pipelines));

    for cf in &corpus_files {
        acc.note_file();
        let events = if has_correlations {
            let mut engine = build_correlation_engine(&collection, pipelines);
            let mut processor = CorrelationProcessor {
                engine: &mut engine,
            };
            stream_corpus_file(cf, &mut processor, event_filter, args, &mut acc)
        } else {
            let engine = detection_engine.as_ref().expect("detection engine built");
            let mut processor = DetectionProcessor { engine };
            stream_corpus_file(cf, &mut processor, event_filter, args, &mut acc)
        };
        acc.add_events(events);
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    Ok(Report::build(
        acc,
        &collection,
        resolved.as_ref(),
        policy,
        duration_ms,
    ))
}

/// Stream a single corpus file through `processor`, recording each fire under
/// the file's relative key. Returns the number of events read.
fn stream_corpus_file<P: EventProcessor>(
    cf: &CorpusFile,
    processor: &mut P,
    event_filter: &crate::EventFilter,
    args: &BacktestArgs,
    acc: &mut Accumulator,
) -> u64 {
    let file_key = cf.key.clone();
    let mut on_result = |m: &EvaluationResult| {
        let key = result_key(m).to_string();
        acc.record(&key, &file_key);
    };

    match cf.kind {
        CorpusKind::Evtx => {
            #[cfg(feature = "evtx")]
            {
                stream_evtx_events(&cf.path, event_filter, None, processor, &mut on_result)
            }
            #[cfg(not(feature = "evtx"))]
            {
                eprintln!(
                    "warning: skipping EVTX corpus file {} (built without the evtx feature)",
                    cf.path.display()
                );
                0
            }
        }
        CorpusKind::Ndjson | CorpusKind::Other => {
            let format = match cf.kind {
                CorpusKind::Ndjson => "json",
                _ => args.input_format.as_str(),
            };
            let file = match File::open(&cf.path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Error opening corpus file '{}': {e}", cf.path.display());
                    return 0;
                }
            };
            stream_events(
                BufReader::new(file),
                event_filter,
                format,
                &args.syslog_tz,
                args.syslog_strip_bom,
                None,
                processor,
                &mut on_result,
            )
        }
    }
}

fn build_detection_engine(collection: &SigmaCollection, pipelines: &[Pipeline]) -> Engine {
    let mut engine = Engine::new();
    for p in pipelines {
        engine.add_pipeline(p.clone());
    }
    if let Err(e) = engine.add_collection(collection) {
        eprintln!("Error compiling rules: {e}");
        process::exit(exit_code::RULE_ERROR);
    }
    engine
}

fn build_correlation_engine(
    collection: &SigmaCollection,
    pipelines: &[Pipeline],
) -> CorrelationEngine {
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    for p in pipelines {
        engine.add_pipeline(p.clone());
    }
    if let Err(e) = engine.add_collection(collection) {
        eprintln!("Error compiling rules: {e}");
        process::exit(exit_code::RULE_ERROR);
    }
    engine
}

// ---------------------------------------------------------------------------
// Corpus traversal
// ---------------------------------------------------------------------------

/// How a corpus file is parsed, decided by its extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CorpusKind {
    /// `.ndjson` / `.jsonl`: forced JSON parsing.
    Ndjson,
    /// `.evtx`: the feature-gated Windows Event Log adapter.
    Evtx,
    /// Anything else: parsed through `--input-format`.
    Other,
}

/// A discovered corpus file plus its report key (path relative to the
/// `--corpus` root, with `/` separators for cross-platform stability).
#[derive(Debug)]
struct CorpusFile {
    key: String,
    path: PathBuf,
    kind: CorpusKind,
}

fn classify(path: &Path) -> CorpusKind {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("ndjson" | "jsonl") => CorpusKind::Ndjson,
        Some("evtx") => CorpusKind::Evtx,
        _ => CorpusKind::Other,
    }
}

/// Resolve the `--corpus` roots into a sorted list of files. A root may be a
/// single file or a directory walked recursively.
fn collect_corpus_files(roots: &[PathBuf]) -> Result<Vec<CorpusFile>, String> {
    let mut out = Vec::new();
    for root in roots {
        if !root.exists() {
            return Err(format!("corpus path not found: {}", root.display()));
        }
        if root.is_file() {
            let key = root
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_else(|| root.to_string_lossy().into_owned());
            out.push(CorpusFile {
                key,
                kind: classify(root),
                path: root.clone(),
            });
        } else if root.is_dir() {
            walk_dir(root, root, &mut out)?;
        }
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(out)
}

fn walk_dir(root: &Path, dir: &Path, out: &mut Vec<CorpusFile>) -> Result<(), String> {
    let read = std::fs::read_dir(dir)
        .map_err(|e| format!("could not read corpus directory {}: {e}", dir.display()))?;
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in read {
        let entry = entry.map_err(|e| {
            format!(
                "could not read corpus directory entry in {}: {e}",
                dir.display()
            )
        })?;
        paths.push(entry.path());
    }
    paths.sort();
    for path in paths {
        if path.is_dir() {
            walk_dir(root, &path, out)?;
        } else if path.is_file() {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let key = rel
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            out.push(CorpusFile {
                key,
                kind: classify(&path),
                path,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Command, FromArgMatches};

    fn parse(argv: &[&str]) -> (BacktestArgs, ArgMatches) {
        let cmd = BacktestArgs::augment_args(Command::new("backtest"));
        let matches = cmd.get_matches_from(argv);
        let args = BacktestArgs::from_arg_matches(&matches).expect("valid args");
        (args, matches)
    }

    fn partial(yaml: &str) -> config::RsigmaConfigPartial {
        yaml_serde::from_str(yaml).expect("valid partial")
    }

    #[test]
    fn cli_flag_beats_config_file() {
        let (mut args, matches) = parse(&["backtest", "--rules", "/cli/rules"]);
        let base = partial("backtest:\n  rules: /file/rules\n  unexpected: fail\n");
        overlay_backtest_config(&mut args, &matches, base);
        assert_eq!(args.rules.as_deref(), Some(Path::new("/cli/rules")));
        // The config fills the unset unexpected policy.
        assert_eq!(args.unexpected.as_deref(), Some("fail"));
    }

    #[test]
    fn config_fills_unset_corpus() {
        let (mut args, matches) = parse(&["backtest", "--rules", "/r"]);
        let base = partial("backtest:\n  corpus:\n    - /file/corpus\n");
        overlay_backtest_config(&mut args, &matches, base);
        assert_eq!(args.corpus, vec![PathBuf::from("/file/corpus")]);
    }

    #[test]
    fn cli_unexpected_beats_config() {
        let (mut args, matches) = parse(&["backtest", "--rules", "/r", "--unexpected", "ignore"]);
        let base = partial("backtest:\n  unexpected: fail\n");
        overlay_backtest_config(&mut args, &matches, base);
        assert_eq!(args.unexpected.as_deref(), Some("ignore"));
    }

    #[test]
    fn policy_precedence_cli_over_file_default() {
        let r = ResolvedExpectations {
            file_default_policy: Some(UnexpectedPolicy::Fail),
            expectations: Vec::new(),
        };
        assert_eq!(
            resolve_policy(Some("ignore"), Some(&r)).unwrap(),
            UnexpectedPolicy::Ignore
        );
        // No CLI/config flag falls back to the file default.
        assert_eq!(
            resolve_policy(None, Some(&r)).unwrap(),
            UnexpectedPolicy::Fail
        );
        // No file default falls back to warn.
        assert_eq!(resolve_policy(None, None).unwrap(), UnexpectedPolicy::Warn);
    }

    #[test]
    fn classify_by_extension() {
        assert_eq!(classify(Path::new("a.ndjson")), CorpusKind::Ndjson);
        assert_eq!(classify(Path::new("a.jsonl")), CorpusKind::Ndjson);
        assert_eq!(classify(Path::new("a.evtx")), CorpusKind::Evtx);
        assert_eq!(classify(Path::new("a.log")), CorpusKind::Other);
        assert_eq!(classify(Path::new("noext")), CorpusKind::Other);
    }

    #[test]
    fn corpus_walk_is_sorted_and_relative() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b.ndjson"), "{}").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub").join("a.ndjson"), "{}").unwrap();

        let files = collect_corpus_files(&[dir.path().to_path_buf()]).unwrap();
        let keys: Vec<&str> = files.iter().map(|f| f.key.as_str()).collect();
        assert_eq!(keys, vec!["b.ndjson", "sub/a.ndjson"]);
    }

    #[test]
    fn missing_corpus_path_is_error() {
        let err = collect_corpus_files(&[PathBuf::from("/no/such/corpus/path")]).unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }
}
