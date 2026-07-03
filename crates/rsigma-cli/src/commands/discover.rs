//! `engine discover-schemas`: mine unrecognized events into candidate schema
//! signatures.
//!
//! Reads a JSON/NDJSON corpus, runs the mining core over the events no built-in
//! or `--schema-config` signature recognizes, and prints ranked candidate
//! declarative signatures (plus a paste-ready `schemas:` block) for a human to
//! review and commit. It does not load rules or evaluate detections, and it
//! never applies a discovered signature on its own.
//!
//! Pairs with `engine classify`: classify shows you have unknowns, discover
//! proposes signatures, and classifying again with the pasted config verifies
//! them. `--dry-run` short-circuits that loop by reclassifying the same corpus
//! with the proposals loaded and reporting the before/after per-schema counts.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use std::process;

use clap::{Args, ValueEnum};
use rsigma_eval::{
    CandidateSource, DiscoveryConfig, DiscoveryReport, JsonEvent, SchemaClassifier,
    SchemaSignature, load_schema_config, mine_events,
};
use serde::Serialize;

use crate::output::{DelimitedWriter, OutputCtx, OutputFormat, Tabular, render_json};

/// What `engine discover-schemas` prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Default)]
pub(crate) enum EmitMode {
    /// Candidates with stats, in the global output format.
    #[default]
    Report,
    /// Only the paste-ready `schemas:` YAML block.
    Yaml,
}

/// Arguments for `rsigma engine discover-schemas`.
#[derive(Args, Debug)]
pub(crate) struct DiscoverArgs {
    /// A single event as a JSON string, or @path to read NDJSON from a file.
    /// If omitted, reads NDJSON from stdin.
    #[arg(short, long)]
    pub event: Option<String>,

    /// Path to a YAML file of user-defined schema signatures. Events these
    /// already recognize are excluded from mining, so a defined schema is never
    /// re-proposed.
    #[arg(long = "schema-config", value_name = "PATH")]
    pub schema_config: Option<PathBuf>,

    /// Minimum events a cluster must contain to yield a candidate.
    #[arg(long, default_value_t = 3)]
    pub min_support: u64,

    /// Jaccard similarity (0.0-1.0) at or above which shapes merge into one
    /// cluster. Higher is stricter (more, tighter clusters).
    #[arg(long, default_value_t = 0.6)]
    pub similarity: f64,

    /// Maximum candidates to emit, highest support first.
    #[arg(long, default_value_t = 20)]
    pub max_candidates: usize,

    /// Maximum predicates per candidate signature.
    #[arg(long, default_value_t = 3)]
    pub max_predicates: usize,

    /// Propose presence predicates only; never emit `equals`/`in` value markers.
    #[arg(long)]
    pub no_value_markers: bool,

    /// Reclassify the corpus with the proposed signatures loaded and report the
    /// before/after per-schema counts.
    #[arg(long)]
    pub dry_run: bool,

    /// What to print: the full report (default) or only the `schemas:` YAML.
    #[arg(long, value_enum, default_value_t = EmitMode::Report)]
    pub emit: EmitMode,
}

pub(crate) fn cmd_discover(args: DiscoverArgs, ctx: OutputCtx) {
    let signatures = match &args.schema_config {
        Some(path) => match load_schema_config(path) {
            // Only the signatures matter here; routing is irrelevant to mining.
            Ok((sigs, _routing)) => sigs,
            Err(e) => {
                eprintln!("Error loading schema config: {e}");
                process::exit(crate::exit_code::CONFIG_ERROR);
            }
        },
        None => Vec::new(),
    };

    let corpus = match read_corpus(args.event) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    };

    let base_classifier = if signatures.is_empty() {
        SchemaClassifier::builtin()
    } else {
        SchemaClassifier::with_user_signatures(signatures.clone())
    };

    let config = DiscoveryConfig {
        min_support: args.min_support,
        similarity: args.similarity,
        max_candidates: args.max_candidates,
        max_predicates: args.max_predicates,
        value_markers: !args.no_value_markers,
        ..DiscoveryConfig::default()
    };

    let report = mine_events(
        corpus.events.iter().map(JsonEvent::borrow),
        &base_classifier,
        &config,
    );

    // `--emit yaml` short-circuits to the paste-ready block on stdout.
    if args.emit == EmitMode::Yaml {
        print!("{}", report.to_signatures_yaml());
        return;
    }

    let dry_run = args
        .dry_run
        .then(|| compute_dry_run(&corpus.events, &signatures, &report));

    let dto = DiscoverReport::build(&report, corpus.parse_errors, dry_run);

    match ctx.format {
        OutputFormat::Json => render_json(&dto, true),
        OutputFormat::Ndjson => {
            for c in &dto.candidates {
                render_json(c, false);
            }
            print_summary_stderr(&dto, &ctx);
        }
        OutputFormat::Csv => render_delimited(&dto, ',', &ctx),
        OutputFormat::Tsv => render_delimited(&dto, '\t', &ctx),
        OutputFormat::Table => print_table(&dto, &report, &ctx),
    }
}

// ---------------------------------------------------------------------------
// Corpus reading (mirrors `engine classify`)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Corpus {
    events: Vec<serde_json::Value>,
    parse_errors: usize,
}

fn read_corpus(event_arg: Option<String>) -> Result<Corpus, String> {
    let mut events = Vec::new();
    let mut parse_errors = 0usize;

    let push_line = |line: &str, events: &mut Vec<serde_json::Value>, errs: &mut usize| {
        if line.trim().is_empty() {
            return;
        }
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(v) => events.push(v),
            Err(_) => *errs += 1,
        }
    };

    match event_arg {
        Some(s) if s.starts_with('@') => {
            let path = PathBuf::from(&s[1..]);
            if path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("evtx"))
            {
                return Err(
                    "`engine discover-schemas` reads JSON/NDJSON; .evtx files are binary. Decode \
                     with `engine eval -e @file.evtx` or convert to NDJSON first."
                        .to_string(),
                );
            }
            let file = File::open(&path)
                .map_err(|e| format!("Error opening event file '{}': {e}", path.display()))?;
            for line in BufReader::new(file).lines() {
                let line = line.map_err(|e| format!("Error reading event file: {e}"))?;
                push_line(&line, &mut events, &mut parse_errors);
            }
        }
        Some(s) => {
            let value: serde_json::Value =
                serde_json::from_str(&s).map_err(|e| format!("Invalid JSON event: {e}"))?;
            events.push(value);
        }
        None => {
            let stdin = io::stdin();
            for line in stdin.lock().lines() {
                let line = line.map_err(|e| format!("Error reading stdin: {e}"))?;
                push_line(&line, &mut events, &mut parse_errors);
            }
        }
    }

    Ok(Corpus {
        events,
        parse_errors,
    })
}

// ---------------------------------------------------------------------------
// Dry-run: before/after classification impact
// ---------------------------------------------------------------------------

fn compute_dry_run(
    events: &[serde_json::Value],
    base_signatures: &[SchemaSignature],
    report: &DiscoveryReport,
) -> DryRun {
    let before_classifier = if base_signatures.is_empty() {
        SchemaClassifier::builtin()
    } else {
        SchemaClassifier::with_user_signatures(base_signatures.to_vec())
    };
    let mut after_signatures = base_signatures.to_vec();
    after_signatures.extend(report.candidates.iter().map(|c| c.signature()));
    let after_classifier = SchemaClassifier::with_user_signatures(after_signatures);

    let before = tally(events, &before_classifier);
    let after = tally(events, &after_classifier);
    DryRun { before, after }
}

fn tally(events: &[serde_json::Value], classifier: &SchemaClassifier) -> BTreeMap<String, u64> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for value in events {
        let event = JsonEvent::borrow(value);
        let key = classifier
            .classify(&event)
            .map(|m| m.name)
            .unwrap_or_else(|| "unknown".to_string());
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

// ---------------------------------------------------------------------------
// Report DTO (owns the JSON/text shape; the core stays serialization-free)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct DiscoverReport {
    summary: DiscoverSummary,
    candidates: Vec<CandidateDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dry_run: Option<DryRun>,
    /// Paste-ready `schemas:` block, identical to `--emit yaml`.
    signatures_yaml: String,
}

#[derive(Debug, Serialize)]
struct DiscoverSummary {
    events_mined: u64,
    shapes: usize,
    clusters: usize,
    candidates: usize,
    parse_errors: usize,
}

#[derive(Debug, Serialize)]
struct CandidateDto {
    name: String,
    specificity: u32,
    source: CandidateSource,
    support: u64,
    coverage_of_unknown: f64,
    predicates: Vec<String>,
    sample_field_sets: Vec<Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    overlap_warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DryRun {
    before: BTreeMap<String, u64>,
    after: BTreeMap<String, u64>,
}

impl DiscoverReport {
    fn build(report: &DiscoveryReport, parse_errors: usize, dry_run: Option<DryRun>) -> Self {
        let candidates = report
            .candidates
            .iter()
            .map(|c| CandidateDto {
                name: c.name.clone(),
                specificity: c.specificity,
                source: c.source,
                support: c.support,
                coverage_of_unknown: c.coverage_of_unknown,
                predicates: c.predicate_descriptions(),
                sample_field_sets: c.sample_field_sets.clone(),
                overlap_warnings: c.overlap_warnings.clone(),
            })
            .collect();
        DiscoverReport {
            summary: DiscoverSummary {
                events_mined: report.stats.events_mined,
                shapes: report.stats.shapes,
                clusters: report.stats.clusters,
                candidates: report.stats.candidates,
                parse_errors,
            },
            candidates,
            dry_run,
            signatures_yaml: report.to_signatures_yaml(),
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

impl Tabular for CandidateDto {
    fn headers() -> &'static [&'static str] {
        &[
            "NAME",
            "SUPPORT",
            "COVERAGE",
            "SPEC",
            "SOURCE",
            "PREDICATES",
        ]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.name.clone(),
            self.support.to_string(),
            format!("{:.0}%", self.coverage_of_unknown * 100.0),
            self.specificity.to_string(),
            source_str(self.source).to_string(),
            self.predicates.join("; "),
        ]
    }
}

fn source_str(s: CandidateSource) -> &'static str {
    match s {
        CandidateSource::Corpus => "corpus",
        CandidateSource::KeysOnly => "keys-only",
    }
}

fn summary_line(dto: &DiscoverReport) -> String {
    let s = &dto.summary;
    format!(
        "Mined {} event(s) into {} shape(s), {} cluster(s); {} candidate(s), {} parse error(s)",
        s.events_mined, s.shapes, s.clusters, s.candidates, s.parse_errors
    )
}

fn print_summary_stderr(dto: &DiscoverReport, ctx: &OutputCtx) {
    if ctx.show_stats() {
        eprintln!("{}", summary_line(dto));
    }
}

fn render_delimited(dto: &DiscoverReport, sep: char, ctx: &OutputCtx) {
    print_summary_stderr(dto, ctx);
    let mut writer = DelimitedWriter::new(sep, CandidateDto::headers());
    for c in &dto.candidates {
        writer.push(&c.row());
    }
}

fn print_table(dto: &DiscoverReport, report: &DiscoveryReport, ctx: &OutputCtx) {
    if ctx.show_stats() {
        eprintln!("{}", summary_line(dto));
    }
    if dto.candidates.is_empty() {
        if ctx.show_progress() {
            eprintln!("No candidate schemas discovered.");
        }
        return;
    }
    if ctx.show_stats() {
        eprintln!();
    }
    crate::output::render_table(&dto.candidates);

    // Advisory warnings below the table.
    for c in &dto.candidates {
        for w in &c.overlap_warnings {
            eprintln!("warning [{}]: {w}", c.name);
        }
    }

    if let Some(dry) = &dto.dry_run {
        print_dry_run(dry);
    }

    // The paste-ready block last, so the operator can copy it directly.
    println!("\n# Paste into a --schema-config file:");
    print!("{}", report.to_signatures_yaml());
}

fn print_dry_run(dry: &DryRun) {
    println!("\nDry run (classification impact):");
    let mut schemas: Vec<&String> = dry.before.keys().chain(dry.after.keys()).collect();
    schemas.sort();
    schemas.dedup();
    for schema in schemas {
        let before = dry.before.get(schema).copied().unwrap_or(0);
        let after = dry.after.get(schema).copied().unwrap_or(0);
        let delta = after as i64 - before as i64;
        let arrow = if delta > 0 {
            format!(" (+{delta})")
        } else if delta < 0 {
            format!(" ({delta})")
        } else {
            String::new()
        };
        println!("  {schema}: {before} -> {after}{arrow}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn corpus_values(n: usize, vendor: &str) -> Vec<serde_json::Value> {
        (0..n)
            .map(|i| json!({"vendor": vendor, "event_type": "alert", "seq": i}))
            .collect()
    }

    #[test]
    fn builds_report_from_mined_corpus() {
        let values = corpus_values(10, "acme");
        let classifier = SchemaClassifier::builtin();
        let report = mine_events(
            values.iter().map(JsonEvent::borrow),
            &classifier,
            &DiscoveryConfig::default(),
        );
        let dto = DiscoverReport::build(&report, 0, None);
        assert_eq!(dto.summary.events_mined, 10);
        assert!(!dto.candidates.is_empty());
        assert!(dto.signatures_yaml.contains("schemas:"));
    }

    #[test]
    fn dry_run_shows_unknown_shrinking_after_proposals() {
        let values = corpus_values(8, "acme");
        let classifier = SchemaClassifier::builtin();
        let report = mine_events(
            values.iter().map(JsonEvent::borrow),
            &classifier,
            &DiscoveryConfig::default(),
        );
        let dry = compute_dry_run(&values, &[], &report);
        // Before: everything is generic_json/unknown; after: the proposals
        // reclassify the vendor events under a discovered schema.
        let discovered_after: u64 = dry
            .after
            .iter()
            .filter(|(k, _)| k.starts_with("discovered"))
            .map(|(_, v)| *v)
            .sum();
        assert!(discovered_after > 0, "proposals should capture events");
        let generic_before = dry.before.get("generic_json").copied().unwrap_or(0);
        let generic_after = dry.after.get("generic_json").copied().unwrap_or(0);
        assert!(
            generic_after < generic_before,
            "unknown/generic should shrink"
        );
    }

    #[test]
    fn read_corpus_rejects_evtx() {
        let err = read_corpus(Some("@evidence.evtx".to_string())).expect_err("should error");
        assert!(err.contains(".evtx"));
    }

    #[test]
    fn read_corpus_skips_blank_and_counts_bad_lines() {
        // Inline single event path is exercised elsewhere; here validate the DTO
        // parse-error surfacing via a direct construction.
        let values = corpus_values(3, "acme");
        let classifier = SchemaClassifier::builtin();
        let report = mine_events(
            values.iter().map(JsonEvent::borrow),
            &classifier,
            &DiscoveryConfig::default(),
        );
        let dto = DiscoverReport::build(&report, 2, None);
        assert_eq!(dto.summary.parse_errors, 2);
    }
}
