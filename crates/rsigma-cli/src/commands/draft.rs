//! `rule draft`: draft a Sigma detection rule from exemplar events.
//!
//! Reads exemplar events (the malicious or noteworthy ones), optionally
//! contrasted against a `--baseline` corpus of normal traffic, and prints a
//! complete paste-ready draft rule: fields classified and ranked, volatile
//! fields dropped, value forms and modifiers inferred, logsource inferred from
//! the built-in schema classifier, and the result verified end-to-end (the
//! draft is parsed, compiled, and must match every exemplar; baseline hits are
//! reported as the estimated false-positive rate).
//!
//! The draft uses the exemplars' native field names, so evaluate it without a
//! mapping pipeline. The human owns the metadata: title, description, tags,
//! and level are placeholders to edit before committing.

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use std::process;

use clap::{Args, ValueEnum};
use rsigma_eval::{DraftConfig, DraftReport, JsonEvent, draft_rule};
use serde::Serialize;

use crate::output::{DelimitedWriter, OutputCtx, OutputFormat, Tabular, render_json};

/// What `rule draft` prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Default)]
pub(crate) enum EmitMode {
    /// Only the paste-ready rule YAML (field report on stderr with stats).
    #[default]
    Yaml,
    /// The full analysis (fields, scores, verification) in the global output
    /// format, with the rule YAML embedded.
    Report,
}

/// Arguments for `rsigma rule draft`.
#[derive(Args, Debug)]
pub(crate) struct DraftArgs {
    /// Exemplar events: a single event as a JSON string, or @path to read
    /// NDJSON (or .evtx with the evtx feature) from a file. If omitted, reads
    /// NDJSON from stdin.
    #[arg(short, long)]
    pub event: Option<String>,

    /// Baseline corpus of normal traffic (@path to NDJSON, or .evtx with the
    /// evtx feature). Used to score fields by rarity and to estimate the
    /// draft's false-positive rate.
    #[arg(long, value_name = "@PATH")]
    pub baseline: Option<String>,

    /// Maximum fields in the drafted selection.
    #[arg(long, default_value_t = 4)]
    pub max_fields: usize,

    /// Fraction (0.0-1.0) of exemplars a field must appear in to be a
    /// candidate.
    #[arg(long, default_value_t = 1.0)]
    pub min_prevalence: f64,

    /// Force this field into the selection (repeatable).
    #[arg(long = "include-field", value_name = "FIELD")]
    pub include_fields: Vec<String>,

    /// Never consider this field (repeatable).
    #[arg(long = "exclude-field", value_name = "FIELD")]
    pub exclude_fields: Vec<String>,

    /// Logsource category override (wins over inference).
    #[arg(long)]
    pub logsource_category: Option<String>,

    /// Logsource product override (wins over inference).
    #[arg(long)]
    pub logsource_product: Option<String>,

    /// Logsource service override (wins over inference).
    #[arg(long)]
    pub logsource_service: Option<String>,

    /// Rule title (derived from the dominant marker when omitted).
    #[arg(long)]
    pub title: Option<String>,

    /// Keep the baseline for contrastive scoring but skip the final baseline
    /// evaluation pass (no hit count/rate in the report).
    #[arg(long)]
    pub skip_baseline_eval: bool,

    /// What to print: the paste-ready rule YAML (default) or the full report.
    #[arg(long, value_enum, default_value_t = EmitMode::Yaml)]
    pub emit: EmitMode,
}

pub(crate) fn cmd_draft(args: DraftArgs, ctx: OutputCtx) {
    let exemplars = match read_events(args.event.as_deref(), "exemplar") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    };
    let baseline = match &args.baseline {
        Some(spec) => {
            if !spec.starts_with('@') {
                eprintln!("--baseline expects @path to an NDJSON file");
                process::exit(crate::exit_code::CONFIG_ERROR);
            }
            match read_events(Some(spec.as_str()), "baseline") {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{e}");
                    process::exit(crate::exit_code::RULE_ERROR);
                }
            }
        }
        None => Corpus::default(),
    };

    // Unparseable input lines are skipped, but a draft mined from a partial
    // corpus is misleading, so say so loudly regardless of the emit mode.
    if exemplars.parse_errors > 0 {
        eprintln!(
            "warning: {} exemplar line(s) failed to parse as JSON and were skipped",
            exemplars.parse_errors
        );
    }
    if baseline.parse_errors > 0 {
        eprintln!(
            "warning: {} baseline line(s) failed to parse as JSON and were skipped",
            baseline.parse_errors
        );
    }

    let config = DraftConfig {
        max_fields: args.max_fields,
        min_prevalence: args.min_prevalence,
        include_fields: args.include_fields,
        exclude_fields: args.exclude_fields,
        title: args.title,
        rule_id: Some(new_uuid_v4()),
        logsource_category: args.logsource_category,
        logsource_product: args.logsource_product,
        logsource_service: args.logsource_service,
        evaluate_baseline: !args.skip_baseline_eval,
        ..DraftConfig::default()
    };

    let exemplar_events: Vec<JsonEvent<'_>> =
        exemplars.events.iter().map(JsonEvent::borrow).collect();
    let baseline_events: Vec<JsonEvent<'_>> =
        baseline.events.iter().map(JsonEvent::borrow).collect();

    let report = match draft_rule(&exemplar_events, &baseline_events, &config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error drafting rule: {e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    };

    let dto = DraftDto::build(&report, exemplars.parse_errors + baseline.parse_errors);

    match args.emit {
        EmitMode::Yaml => {
            print!("{}", report.rule_yaml);
            if ctx.show_stats() {
                eprintln!();
                eprintln!("{}", summary_line(&dto));
                for f in &dto.fields {
                    eprintln!(
                        "  {} {}: {} [{}]{}",
                        if f.selected { "*" } else { " " },
                        f.field,
                        f.values.join(", "),
                        f.stability,
                        f.baseline_prevalence
                            .map(|p| format!(" baseline {:.1}%", p * 100.0))
                            .unwrap_or_default(),
                    );
                }
                for w in &dto.warnings {
                    eprintln!("warning: {w}");
                }
            }
        }
        EmitMode::Report => match ctx.format {
            OutputFormat::Json => render_json(&dto, true),
            OutputFormat::Ndjson => {
                for f in &dto.fields {
                    render_json(f, false);
                }
                print_summary_stderr(&dto, &ctx);
            }
            OutputFormat::Csv => render_delimited(&dto, ',', &ctx),
            OutputFormat::Tsv => render_delimited(&dto, '\t', &ctx),
            OutputFormat::Table => print_table(&dto, &report, &ctx),
        },
    }
}

// ---------------------------------------------------------------------------
// UUIDv4 (kept out of rsigma-eval so the core stays deterministic)
// ---------------------------------------------------------------------------

/// A random version-4 UUID for the draft's `id`.
fn new_uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ---------------------------------------------------------------------------
// Event reading (mirrors `engine eval` input handling, including EVTX)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Corpus {
    events: Vec<serde_json::Value>,
    parse_errors: usize,
}

fn read_events(event_arg: Option<&str>, label: &str) -> Result<Corpus, String> {
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
            if !path.exists() {
                return Err(format!("{label} file not found: {}", path.display()));
            }
            if path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("evtx"))
            {
                #[cfg(feature = "evtx")]
                {
                    read_evtx(&path, &mut events)?;
                }
                #[cfg(not(feature = "evtx"))]
                {
                    return Err(format!(
                        "'{}' is an EVTX file but this build lacks the evtx feature; \
                         rebuild with --features evtx or convert to NDJSON first.",
                        path.display()
                    ));
                }
            } else {
                let file = File::open(&path)
                    .map_err(|e| format!("Error opening {label} file '{}': {e}", path.display()))?;
                for line in BufReader::new(file).lines() {
                    let line = line.map_err(|e| format!("Error reading {label} file: {e}"))?;
                    push_line(&line, &mut events, &mut parse_errors);
                }
            }
        }
        Some(s) => {
            let value: serde_json::Value =
                serde_json::from_str(s).map_err(|e| format!("Invalid JSON {label} event: {e}"))?;
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

#[cfg(feature = "evtx")]
fn read_evtx(path: &std::path::Path, events: &mut Vec<serde_json::Value>) -> Result<(), String> {
    let mut reader = rsigma_runtime::EvtxFileReader::open(path)
        .map_err(|e| format!("Error opening EVTX file '{}': {e}", path.display()))?;
    for record in reader.records() {
        match record {
            Ok(v) => events.push(v),
            Err(e) => eprintln!("Error reading EVTX record: {e}"),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Report DTO
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct DraftDto {
    summary: DraftSummary,
    rule_yaml: String,
    fields: Vec<FieldDto>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DraftSummary {
    exemplar_total: usize,
    exemplar_matched: usize,
    baseline_total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline_hits: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline_hit_rate: Option<f64>,
    parse_errors: usize,
}

#[derive(Debug, Serialize)]
struct FieldDto {
    field: String,
    selected: bool,
    score: f64,
    stability: String,
    modifier: String,
    values: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline_prevalence: Option<f64>,
}

impl DraftDto {
    fn build(report: &DraftReport, parse_errors: usize) -> Self {
        DraftDto {
            summary: DraftSummary {
                exemplar_total: report.exemplar_total,
                exemplar_matched: report.exemplar_matched,
                baseline_total: report.baseline_total,
                baseline_hits: report.baseline_hits,
                baseline_hit_rate: report.baseline_hit_rate,
                parse_errors,
            },
            rule_yaml: report.rule_yaml.clone(),
            fields: report
                .fields
                .iter()
                .map(|f| FieldDto {
                    field: f.field.clone(),
                    selected: f.selected,
                    score: f.score,
                    stability: f.stability.to_string(),
                    modifier: f.modifier.clone(),
                    values: f.values.clone(),
                    baseline_prevalence: f.baseline_prevalence,
                })
                .collect(),
            warnings: report.warnings.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

impl Tabular for FieldDto {
    fn headers() -> &'static [&'static str] {
        &[
            "SELECTED",
            "FIELD",
            "SCORE",
            "STABILITY",
            "MODIFIER",
            "VALUES",
            "BASELINE",
        ]
    }
    fn row(&self) -> Vec<String> {
        vec![
            if self.selected { "*" } else { "" }.to_string(),
            self.field.clone(),
            format!("{:.2}", self.score),
            self.stability.clone(),
            self.modifier.clone(),
            self.values.join(", "),
            self.baseline_prevalence
                .map(|p| format!("{:.1}%", p * 100.0))
                .unwrap_or_default(),
        ]
    }
}

fn summary_line(dto: &DraftDto) -> String {
    let s = &dto.summary;
    let baseline = match (s.baseline_hits, s.baseline_hit_rate) {
        (Some(hits), Some(rate)) => format!(
            ", {hits}/{} baseline events ({:.1}%)",
            s.baseline_total,
            rate * 100.0
        ),
        _ if s.baseline_total > 0 => {
            format!(", baseline of {} events (not evaluated)", s.baseline_total)
        }
        _ => String::new(),
    };
    format!(
        "Drafted from {} exemplar(s); matches {}/{} exemplars{}{}",
        s.exemplar_total,
        s.exemplar_matched,
        s.exemplar_total,
        baseline,
        if s.parse_errors > 0 {
            format!(", {} parse error(s)", s.parse_errors)
        } else {
            String::new()
        }
    )
}

fn print_summary_stderr(dto: &DraftDto, ctx: &OutputCtx) {
    if ctx.show_stats() {
        eprintln!("{}", summary_line(dto));
    }
}

fn render_delimited(dto: &DraftDto, sep: char, ctx: &OutputCtx) {
    print_summary_stderr(dto, ctx);
    let mut writer = DelimitedWriter::new(sep, FieldDto::headers());
    for f in &dto.fields {
        writer.push(&f.row());
    }
}

fn print_table(dto: &DraftDto, report: &DraftReport, ctx: &OutputCtx) {
    if ctx.show_stats() {
        eprintln!("{}", summary_line(dto));
        eprintln!();
    }
    crate::output::render_table(&dto.fields);

    for w in &dto.warnings {
        eprintln!("warning: {w}");
    }

    // The paste-ready rule last, so the operator can copy it directly.
    println!("\n# Draft rule (edit the TODO placeholders before committing):");
    print!("{}", report.rule_yaml);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn uuid_v4_shape() {
        let id = new_uuid_v4();
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[14], b'4');
    }

    #[test]
    fn dto_carries_verification_and_warnings() {
        let values: Vec<serde_json::Value> = (0..3)
            .map(|_| json!({"vendor": "acme", "action": "alert"}))
            .collect();
        let events: Vec<JsonEvent<'_>> = values.iter().map(JsonEvent::borrow).collect();
        let config = DraftConfig {
            rule_id: Some("00000000-0000-4000-8000-000000000000".to_string()),
            date: Some("2026-07-03".to_string()),
            ..DraftConfig::default()
        };
        let report = draft_rule(&events, &[], &config).unwrap();
        let dto = DraftDto::build(&report, 1);
        assert_eq!(dto.summary.exemplar_matched, 3);
        assert_eq!(dto.summary.parse_errors, 1);
        assert!(dto.rule_yaml.contains("title:"));
        assert!(dto.fields.iter().any(|f| f.selected));
    }

    #[test]
    fn read_events_inline_and_missing_file() {
        let corpus = read_events(Some(r#"{"a": 1}"#), "exemplar").unwrap();
        assert_eq!(corpus.events.len(), 1);
        let err = read_events(Some("@/nonexistent/x.ndjson"), "exemplar").unwrap_err();
        assert!(err.contains("not found"));
    }
}
