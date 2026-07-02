//! `engine classify`: report which schema rsigma assigns to each event.
//!
//! A diagnostic for tuning schema signatures: it reads JSON (or NDJSON) events
//! and prints, per event, the recognized schema (or `unknown`), plus a summary
//! of per-schema counts. It does not load rules or evaluate detections.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use std::process;

use clap::Args;
use rsigma_eval::{
    JsonEvent, RouteDecision, RoutingConfig, RoutingPlan, SchemaClassifier, SchemaExplanation,
    load_schema_config, validate_schema_config,
};
use serde::Serialize;

use crate::output::{DelimitedWriter, OutputCtx, OutputFormat, Tabular, render_json};

/// Arguments for `rsigma engine classify`.
#[derive(Args, Debug)]
pub(crate) struct ClassifyArgs {
    /// A single event as a JSON string, or @path to read NDJSON from a file.
    /// If omitted, reads NDJSON from stdin.
    #[arg(short, long)]
    pub event: Option<String>,

    /// Path to a YAML file of user-defined schema signatures (and optional
    /// `routing:` bindings), merged over the built-ins.
    #[arg(long = "schema-config", value_name = "PATH")]
    pub schema_config: Option<PathBuf>,

    /// Show, per event, why it classified as it did: the matched signature's
    /// per-predicate pass/fail, or for an unknown event the closest near-miss.
    #[arg(long)]
    pub explain: bool,

    /// Validate the `--schema-config` (unreachable signatures, unknown or
    /// duplicate routing bindings, unresolvable pipeline paths) and exit. Does
    /// not read events.
    #[arg(long)]
    pub check: bool,
}

pub(crate) fn cmd_classify(args: ClassifyArgs, ctx: OutputCtx) {
    // Load signatures and any routing section from the schema config.
    let (signatures, routing) = match &args.schema_config {
        Some(path) => match load_schema_config(path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error loading schema config: {e}");
                process::exit(crate::exit_code::CONFIG_ERROR);
            }
        },
        None => (Vec::new(), None),
    };

    if args.check {
        run_check(&signatures, routing.as_ref());
        return;
    }

    let classifier = if signatures.is_empty() {
        SchemaClassifier::builtin()
    } else {
        SchemaClassifier::with_user_signatures(signatures)
    };
    let plan = routing.map(|r| RoutingPlan::from_config(&r));

    let report = match build_report(&classifier, plan.as_ref(), args.explain, args.event) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    };

    match ctx.format {
        OutputFormat::Json => render_json(&report, true),
        OutputFormat::Ndjson => {
            for rec in &report.events {
                render_json(rec, false);
            }
            print_summary_stderr(&report, &ctx);
        }
        OutputFormat::Csv => render_delimited(&report, ',', &ctx),
        OutputFormat::Tsv => render_delimited(&report, '\t', &ctx),
        OutputFormat::Table => print_table(&report, &ctx),
    }
}

/// Validate a schema config and exit: 0 when clean, `CONFIG_ERROR` otherwise.
fn run_check(signatures: &[rsigma_eval::SchemaSignature], routing: Option<&RoutingConfig>) {
    let mut findings = validate_schema_config(signatures, routing);
    // Pipeline path resolvability: the CLI owns pipeline resolution, so it
    // checks path-like binding pipelines here (built-in names are assumed
    // valid and resolved at load time).
    if let Some(routing) = routing {
        for binding in &routing.bindings {
            for pipeline in &binding.pipelines {
                let looks_like_path = pipeline.contains(std::path::MAIN_SEPARATOR)
                    || pipeline.ends_with(".yml")
                    || pipeline.ends_with(".yaml");
                if looks_like_path && !std::path::Path::new(pipeline).exists() {
                    findings.push(format!(
                        "binding '{}' references pipeline file '{}' which does not exist",
                        binding.schema, pipeline
                    ));
                }
            }
        }
    }

    if findings.is_empty() {
        println!("Schema config OK: no issues found.");
        return;
    }
    eprintln!("Schema config has {} issue(s):", findings.len());
    for finding in &findings {
        eprintln!("  - {finding}");
    }
    process::exit(crate::exit_code::CONFIG_ERROR);
}

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ClassifyReport {
    summary: ClassifySummary,
    events: Vec<ClassifyRecord>,
}

#[derive(Debug, Serialize)]
struct ClassifySummary {
    /// Events successfully parsed and classified (excludes parse errors).
    total_events: usize,
    /// Events that matched a schema signature.
    classified: usize,
    /// Events that matched no signature.
    unknown: usize,
    /// Lines that were not valid JSON.
    parse_errors: usize,
    /// Per-schema counts for recognized schemas (excludes `unknown`).
    by_schema: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
struct ClassifyRecord {
    index: usize,
    /// `None` means the event matched no signature ("unknown").
    schema: Option<String>,
    specificity: Option<u32>,
    /// Present with `--explain`: why the event classified as it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    explanation: Option<SchemaExplanation>,
    /// Present when the config carries a `routing:` section: where this event
    /// would route.
    #[serde(skip_serializing_if = "Option::is_none")]
    route: Option<RouteInfo>,
}

/// Where an event would route under the config's `routing:` bindings.
#[derive(Debug, Serialize)]
struct RouteInfo {
    /// `evaluate`, `drop`, or `error`.
    action: &'static str,
    /// The pipeline-set the event evaluates against (empty means the
    /// Sigma-native default set). Absent for drop/error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pipelines: Option<Vec<String>>,
    /// True when the event matched no schema and fell through to the default.
    unknown: bool,
}

// ---------------------------------------------------------------------------
// Report building
// ---------------------------------------------------------------------------

struct Accumulator<'a> {
    events: Vec<ClassifyRecord>,
    by_schema: BTreeMap<String, usize>,
    classified: usize,
    unknown: usize,
    parse_errors: usize,
    index: usize,
    explain: bool,
    plan: Option<&'a RoutingPlan>,
}

impl<'a> Accumulator<'a> {
    fn new(explain: bool, plan: Option<&'a RoutingPlan>) -> Self {
        Accumulator {
            events: Vec::new(),
            by_schema: BTreeMap::new(),
            classified: 0,
            unknown: 0,
            parse_errors: 0,
            index: 0,
            explain,
            plan,
        }
    }

    fn classify_value(&mut self, classifier: &SchemaClassifier, value: &serde_json::Value) {
        let event = JsonEvent::borrow(value);
        let matched = classifier.classify(&event);
        match &matched {
            Some(m) => {
                self.classified += 1;
                *self.by_schema.entry(m.name.clone()).or_insert(0) += 1;
            }
            None => self.unknown += 1,
        }
        let explanation = self.explain.then(|| classifier.explain(&event));
        let route = self.plan.map(|plan| {
            let schema = matched.as_ref().map(|m| m.name.as_str());
            match plan.decide(schema) {
                RouteDecision::Evaluate { set, unknown } => RouteInfo {
                    action: "evaluate",
                    pipelines: plan.pipeline_sets().get(set).cloned(),
                    unknown,
                },
                RouteDecision::Drop => RouteInfo {
                    action: "drop",
                    pipelines: None,
                    unknown: true,
                },
                RouteDecision::Error => RouteInfo {
                    action: "error",
                    pipelines: None,
                    unknown: true,
                },
            }
        });
        self.events.push(ClassifyRecord {
            index: self.index,
            schema: matched.as_ref().map(|m| m.name.clone()),
            specificity: matched.as_ref().map(|m| m.specificity),
            explanation,
            route,
        });
        self.index += 1;
    }

    fn classify_line(&mut self, classifier: &SchemaClassifier, line: &str) {
        if line.trim().is_empty() {
            return;
        }
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(value) => self.classify_value(classifier, &value),
            Err(_) => self.parse_errors += 1,
        }
    }

    fn into_report(self) -> ClassifyReport {
        ClassifyReport {
            summary: ClassifySummary {
                total_events: self.classified + self.unknown,
                classified: self.classified,
                unknown: self.unknown,
                parse_errors: self.parse_errors,
                by_schema: self.by_schema,
            },
            events: self.events,
        }
    }
}

fn build_report(
    classifier: &SchemaClassifier,
    plan: Option<&RoutingPlan>,
    explain: bool,
    event_arg: Option<String>,
) -> Result<ClassifyReport, String> {
    let mut acc = Accumulator::new(explain, plan);

    match event_arg {
        Some(s) if s.starts_with('@') => {
            let path = PathBuf::from(&s[1..]);
            if path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("evtx"))
            {
                return Err(
                    "`engine classify` reads JSON/NDJSON; .evtx files are binary. Decode with \
                     `engine eval -e @file.evtx` or convert to NDJSON first."
                        .to_string(),
                );
            }
            let file = File::open(&path)
                .map_err(|e| format!("Error opening event file '{}': {e}", path.display()))?;
            for line in BufReader::new(file).lines() {
                let line = line.map_err(|e| format!("Error reading event file: {e}"))?;
                acc.classify_line(classifier, &line);
            }
        }
        Some(s) => {
            // Inline `-e` is a single JSON event.
            let value: serde_json::Value =
                serde_json::from_str(&s).map_err(|e| format!("Invalid JSON event: {e}"))?;
            acc.classify_value(classifier, &value);
        }
        None => {
            let stdin = io::stdin();
            for line in stdin.lock().lines() {
                let line = line.map_err(|e| format!("Error reading stdin: {e}"))?;
                acc.classify_line(classifier, &line);
            }
        }
    }

    Ok(acc.into_report())
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

impl Tabular for ClassifyRecord {
    fn headers() -> &'static [&'static str] {
        &["#", "SCHEMA", "SPECIFICITY"]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.index.to_string(),
            self.schema.clone().unwrap_or_else(|| "unknown".to_string()),
            self.specificity
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ]
    }
}

fn summary_line(report: &ClassifyReport) -> String {
    let s = &report.summary;
    let breakdown = if s.by_schema.is_empty() {
        String::new()
    } else {
        let parts: Vec<String> = s
            .by_schema
            .iter()
            .map(|(name, count)| format!("{name}={count}"))
            .collect();
        format!(" | {}", parts.join(", "))
    };
    format!(
        "Events: {} classified, {} unknown, {} parse errors{breakdown}",
        s.classified, s.unknown, s.parse_errors,
    )
}

fn print_summary_stderr(report: &ClassifyReport, ctx: &OutputCtx) {
    if ctx.show_stats() {
        eprintln!("{}", summary_line(report));
    }
}

fn render_delimited(report: &ClassifyReport, sep: char, ctx: &OutputCtx) {
    print_summary_stderr(report, ctx);
    let mut writer = DelimitedWriter::new(sep, ClassifyRecord::headers());
    for rec in &report.events {
        writer.push(&rec.row());
    }
}

fn print_table(report: &ClassifyReport, ctx: &OutputCtx) {
    if ctx.show_stats() {
        eprintln!("{}", summary_line(report));
    }
    if report.events.is_empty() {
        if ctx.show_progress() {
            eprintln!("No events to classify.");
        }
        return;
    }
    if ctx.show_stats() {
        eprintln!();
    }
    crate::output::render_table(&report.events);
    print_detail_section(report);
}

/// Print the per-event `--explain` and routing dry-run detail below the table,
/// when either is present. Structured formats carry this in the record itself.
fn print_detail_section(report: &ClassifyReport) {
    let any = report
        .events
        .iter()
        .any(|r| r.explanation.is_some() || r.route.is_some());
    if !any {
        return;
    }
    println!();
    for rec in &report.events {
        if rec.explanation.is_none() && rec.route.is_none() {
            continue;
        }
        let schema = rec.schema.as_deref().unwrap_or("unknown");
        println!("#{} {schema}", rec.index);
        if let Some(route) = &rec.route {
            let suffix = if route.unknown {
                " (unknown -> default)"
            } else {
                ""
            };
            match &route.pipelines {
                Some(ps) if !ps.is_empty() => {
                    println!("    route: {} -> [{}]{suffix}", route.action, ps.join(", "));
                }
                Some(_) => {
                    println!(
                        "    route: {} -> default (Sigma-native){suffix}",
                        route.action
                    );
                }
                None => println!("    route: {}", route.action),
            }
        }
        if let Some(ex) = &rec.explanation
            && let Some(sig) = &ex.signature
        {
            let label = if ex.matched.is_some() {
                "matched"
            } else {
                "near-miss"
            };
            println!(
                "    {label}: {} (specificity {})",
                sig.name, sig.specificity
            );
            for p in &sig.predicates {
                let mark = if p.matched { "PASS" } else { "FAIL" };
                println!("      [{mark}] {}", p.predicate);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_for(event: &str) -> ClassifyReport {
        build_report(
            &SchemaClassifier::builtin(),
            None,
            false,
            Some(event.to_string()),
        )
        .expect("report")
    }

    #[test]
    fn classifies_inline_ecs_event() {
        let report = report_for(r#"{"ecs.version": "8.11.0", "process.command_line": "whoami"}"#);
        assert_eq!(report.summary.total_events, 1);
        assert_eq!(report.summary.classified, 1);
        assert_eq!(report.summary.unknown, 0);
        assert_eq!(report.events[0].schema.as_deref(), Some("ecs"));
        assert_eq!(report.events[0].specificity, Some(100));
        assert_eq!(report.summary.by_schema.get("ecs"), Some(&1));
    }

    #[test]
    fn empty_object_is_unknown() {
        let report = report_for("{}");
        assert_eq!(report.summary.unknown, 1);
        assert_eq!(report.summary.classified, 0);
        assert_eq!(report.events[0].schema, None);
        assert!(report.summary.by_schema.is_empty());
    }

    #[test]
    fn invalid_inline_json_is_an_error() {
        let err = build_report(
            &SchemaClassifier::builtin(),
            None,
            false,
            Some("not json".to_string()),
        )
        .expect_err("should error");
        assert!(err.contains("Invalid JSON event"));
    }

    #[test]
    fn counts_accumulate_across_lines() {
        let mut acc = Accumulator::new(false, None);
        let classifier = SchemaClassifier::builtin();
        acc.classify_line(&classifier, r#"{"ecs.version": "8.0.0"}"#);
        acc.classify_line(
            &classifier,
            r#"{"EventID": 1, "ProcessGuid": "{x}", "Image": "a"}"#,
        );
        acc.classify_line(&classifier, r#"{"random": "blob"}"#);
        acc.classify_line(&classifier, ""); // blank line skipped
        acc.classify_line(&classifier, "{bad json");
        let report = acc.into_report();
        assert_eq!(report.summary.total_events, 3);
        assert_eq!(report.summary.classified, 3);
        assert_eq!(report.summary.parse_errors, 1);
        assert_eq!(report.summary.by_schema.get("ecs"), Some(&1));
        assert_eq!(report.summary.by_schema.get("sysmon"), Some(&1));
        assert_eq!(report.summary.by_schema.get("generic_json"), Some(&1));
    }

    #[test]
    fn evtx_path_is_rejected_with_guidance() {
        let err = build_report(
            &SchemaClassifier::builtin(),
            None,
            false,
            Some("@security.evtx".to_string()),
        )
        .expect_err("should error");
        assert!(err.contains(".evtx"));
    }
}
