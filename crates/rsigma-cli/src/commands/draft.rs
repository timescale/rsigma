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
use std::path::{Path, PathBuf};
use std::process;

use clap::{Args, ValueEnum};
use rsigma_eval::rule_draft::correlation::{
    CorrelationDraftConfig, CorrelationDraftReport, CorrelationDraftType, GroupedExemplar,
    SourceLocation, TimedEvent, draft_correlation,
};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Default)]
pub(crate) enum CorrelationTypeArg {
    #[default]
    Auto,
    Temporal,
    #[value(name = "temporal_ordered")]
    TemporalOrdered,
}

impl From<CorrelationTypeArg> for CorrelationDraftType {
    fn from(value: CorrelationTypeArg) -> Self {
        match value {
            CorrelationTypeArg::Auto => Self::Auto,
            CorrelationTypeArg::Temporal => Self::Temporal,
            CorrelationTypeArg::TemporalOrdered => Self::TemporalOrdered,
        }
    }
}

/// Arguments for `rsigma rule draft`.
#[derive(Args, Debug)]
pub(crate) struct DraftArgs {
    /// Exemplar events: a single event as a JSON string, or @path to read
    /// NDJSON (or .evtx with the evtx feature) from a file. If omitted, reads
    /// NDJSON from stdin.
    #[arg(short, long)]
    pub event: Option<String>,

    /// Grouped, timed exemplars from an envelope NDJSON file or directory.
    #[arg(long, value_name = "@PATH")]
    pub groups: Option<String>,

    /// Grouped negative examples that the drafted correlation must not match.
    #[arg(long, value_name = "@PATH")]
    pub negative: Option<String>,

    /// Correlation grouping field (repeatable for an explicit composite key).
    #[arg(long = "group-by", value_name = "FIELD")]
    pub group_by: Vec<String>,

    /// Correlation ordering behavior.
    #[arg(long, value_enum, default_value_t = CorrelationTypeArg::Auto)]
    pub correlation_type: CorrelationTypeArg,

    /// Minimum number of positive groups.
    #[arg(long, default_value_t = 3)]
    pub min_groups: usize,

    /// Margin applied to the maximum observed group span.
    #[arg(long, default_value_t = 1.5)]
    pub window_margin: f64,

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
    if args.groups.is_some() {
        cmd_correlation_draft(args, ctx);
        return;
    }
    if args.negative.is_some() || !args.group_by.is_empty() {
        eprintln!("--negative and --group-by require --groups");
        process::exit(crate::exit_code::CONFIG_ERROR);
    }
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
            if ctx.explicit_format {
                ctx.warn_unsupported("rule draft", "Sigma YAML");
            }
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

fn cmd_correlation_draft(args: DraftArgs, ctx: OutputCtx) {
    if args.event.is_some() {
        eprintln!("--event cannot be combined with --groups");
        process::exit(crate::exit_code::CONFIG_ERROR);
    }
    let groups = match read_grouped(args.groups.as_deref().unwrap(), "group") {
        Ok(groups) => groups,
        Err(error) => {
            eprintln!("{error}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    };
    let negatives = match args.negative.as_deref() {
        Some(spec) => match read_grouped(spec, "negative group") {
            Ok(groups) => groups,
            Err(error) => {
                eprintln!("{error}");
                process::exit(crate::exit_code::RULE_ERROR);
            }
        },
        None => Vec::new(),
    };
    let baseline = match args.baseline.as_deref() {
        Some(spec) if spec.starts_with('@') => match read_events(Some(spec), "baseline") {
            Ok(corpus) => {
                if corpus.parse_errors > 0 {
                    eprintln!(
                        "warning: {} baseline line(s) failed to parse as JSON and were skipped",
                        corpus.parse_errors
                    );
                }
                corpus.events
            }
            Err(error) => {
                eprintln!("{error}");
                process::exit(crate::exit_code::RULE_ERROR);
            }
        },
        Some(_) => {
            eprintln!("--baseline expects @path to an NDJSON file");
            process::exit(crate::exit_code::CONFIG_ERROR);
        }
        None => Vec::new(),
    };
    let detection = DraftConfig {
        max_fields: args.max_fields,
        min_prevalence: args.min_prevalence,
        include_fields: args.include_fields,
        exclude_fields: args.exclude_fields,
        title: args.title.clone(),
        logsource_category: args.logsource_category,
        logsource_product: args.logsource_product,
        logsource_service: args.logsource_service,
        evaluate_baseline: false,
        ..DraftConfig::default()
    };
    let config = CorrelationDraftConfig {
        min_groups: args.min_groups,
        window_margin: args.window_margin,
        correlation_type: args.correlation_type.into(),
        group_by: args.group_by,
        title: args.title,
        correlation_id: Some(new_uuid_v4()),
        slot_ids: (0..64).map(|_| new_uuid_v4()).collect(),
        detection,
        ..CorrelationDraftConfig::default()
    };
    let report = match draft_correlation(&groups, &negatives, &baseline, &config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("Error drafting correlation: {error}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    };
    match args.emit {
        EmitMode::Yaml => {
            if ctx.explicit_format {
                ctx.warn_unsupported("rule draft --groups", "Sigma YAML");
            }
            print!("{}", report.rule_yaml);
            if ctx.show_stats() {
                print_correlation_summary(&report);
            }
        }
        EmitMode::Report => match ctx.format {
            OutputFormat::Json => render_json(&report, true),
            OutputFormat::Ndjson => render_json(&report, false),
            OutputFormat::Table | OutputFormat::Csv | OutputFormat::Tsv => {
                print_correlation_summary(&report);
                print!("{}", report.rule_yaml);
            }
        },
    }
}

fn print_correlation_summary(report: &CorrelationDraftReport) {
    eprintln!(
        "Drafted {} correlation with {} slots, group-by {}, timespan {}",
        report.correlation_type,
        report.slots.len(),
        report.group_by.join(", "),
        report.timespan
    );
    for slot in &report.slots {
        eprintln!(
            "  {}: {} events, fields {}",
            slot.name,
            slot.support,
            slot.selected_fields.join(", ")
        );
    }
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
}

// ---------------------------------------------------------------------------
// UUIDv4 (kept out of rsigma-eval so the core stays deterministic)
// ---------------------------------------------------------------------------

/// A random version-4 UUID for the draft's `id`.
fn new_uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn read_grouped(spec: &str, label: &str) -> Result<Vec<GroupedExemplar>, String> {
    let Some(raw_path) = spec.strip_prefix('@') else {
        return Err(format!(
            "--{label}s expects @path to an NDJSON file or directory"
        ));
    };
    let path = PathBuf::from(raw_path);
    if !path.exists() {
        return Err(format!("{label} path not found: {}", path.display()));
    }
    if path.is_dir() {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&path)
            .map_err(|error| format!("Error reading {}: {error}", path.display()))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.is_file())
            .collect();
        files.sort();
        let mut groups = Vec::with_capacity(files.len());
        for file in files {
            let id = file
                .file_stem()
                .and_then(|stem| stem.to_str())
                .ok_or_else(|| format!("Invalid group filename: {}", file.display()))?
                .to_string();
            let mut parsed = read_grouped_file(&file, Some(&id))?;
            groups.append(&mut parsed);
        }
        Ok(groups)
    } else {
        read_grouped_file(&path, None)
    }
}

fn read_grouped_file(
    path: &Path,
    directory_group: Option<&str>,
) -> Result<Vec<GroupedExemplar>, String> {
    let file =
        File::open(path).map_err(|error| format!("Error opening '{}': {error}", path.display()))?;
    let mut groups: std::collections::BTreeMap<String, Vec<TimedEvent>> =
        std::collections::BTreeMap::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line_number = index + 1;
        let line = line.map_err(|error| format!("Error reading '{}': {error}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(&line)
            .map_err(|error| format!("{}:{line_number}: invalid JSON: {error}", path.display()))?;
        let object = value.as_object().ok_or_else(|| {
            format!(
                "{}:{line_number}: grouped envelope must be a JSON object",
                path.display()
            )
        })?;
        let group = match directory_group {
            Some(group) => {
                if object.contains_key("group") {
                    return Err(format!(
                        "{}:{line_number}: 'group' is not allowed in directory input; the filename stem is the group id",
                        path.display()
                    ));
                }
                group.to_string()
            }
            None => object
                .get("group")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "{}:{line_number}: grouped envelope requires string 'group'",
                        path.display()
                    )
                })?
                .to_string(),
        };
        let timestamp = optional_string(object, "timestamp", path, line_number)?;
        let offset = optional_string(object, "offset", path, line_number)?;
        let event = object
            .get("event")
            .filter(|event| event.is_object())
            .cloned()
            .ok_or_else(|| {
                format!(
                    "{}:{line_number}: grouped envelope requires object 'event'",
                    path.display()
                )
            })?;
        groups.entry(group).or_default().push(TimedEvent {
            timestamp,
            offset,
            event,
            source: SourceLocation {
                file: Some(path.display().to_string()),
                line: Some(line_number),
            },
        });
    }
    Ok(groups
        .into_iter()
        .map(|(id, events)| GroupedExemplar { id, events })
        .collect())
}

fn optional_string(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &Path,
    line: usize,
) -> Result<Option<String>, String> {
    match object.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(|value| Some(value.to_string()))
            .ok_or_else(|| format!("{}:{line}: '{key}' must be a string", path.display())),
    }
}

// ---------------------------------------------------------------------------
// Event reading (mirrors `engine eval` input handling, including EVTX)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub(super) struct Corpus {
    pub(super) events: Vec<serde_json::Value>,
    pub(super) parse_errors: usize,
}

pub(super) fn read_events(event_arg: Option<&str>, label: &str) -> Result<Corpus, String> {
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
                    read_evtx(&path, &mut events, &mut parse_errors)?;
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
fn read_evtx(
    path: &std::path::Path,
    events: &mut Vec<serde_json::Value>,
    parse_errors: &mut usize,
) -> Result<(), String> {
    let mut reader = rsigma_runtime::EvtxFileReader::open(path)
        .map_err(|e| format!("Error opening EVTX file '{}': {e}", path.display()))?;
    for record in reader.records() {
        match record {
            Ok(v) => events.push(v),
            Err(e) => {
                *parse_errors += 1;
                eprintln!("Error reading EVTX record: {e}");
            }
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
