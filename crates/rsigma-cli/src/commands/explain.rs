//! `rsigma engine explain`: explain why a rule did or did not match an event.
//!
//! Wraps [`rsigma_eval::explain_rule`] with rule/pipeline/event loading and a
//! human tree renderer plus machine-readable JSON. It consumes event data, so
//! it lives under `engine` (the `rule` group stays static); see the plan note
//! on placement.

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;

use clap::Args;

use rsigma_eval::{
    ConditionTrace, DetectionTrace, ItemTrace, JsonEvent, MatchReason, RuleExplanation,
    SelectionBranch, apply_pipelines, compile_rule, explain_rule,
};

use crate::output::{DelimitedWriter, OutputCtx, OutputFormat, Painter, Tabular, render_json};

#[derive(Args, Debug)]
pub(crate) struct ExplainArgs {
    /// Sigma rule file(s) or director(ies) to explain. Repeatable.
    #[arg(short = 'r', long = "rules", value_name = "PATH", num_args = 1.., required = true)]
    pub rules: Vec<PathBuf>,

    /// The event to explain against: inline JSON, `@path` to a JSON file, or
    /// `-` (or omitted) to read a single JSON object from stdin.
    #[arg(short, long, value_name = "JSON|@FILE|-")]
    pub event: Option<String>,

    /// Processing pipeline(s) to apply before evaluation. Accepts builtin
    /// names (ecs_windows, sysmon) or YAML file paths. Repeatable.
    #[arg(short = 'p', long = "pipeline", value_name = "PATH|NAME")]
    pub pipeline: Vec<PathBuf>,

    /// Only explain the rule with this id (falling back to an exact title).
    #[arg(long = "rule-id", value_name = "ID")]
    pub rule_id: Option<String>,

    /// Print the pipeline transformation summary before each trace (human
    /// output). Has no effect without `-p/--pipeline`.
    #[arg(long = "show-pipeline")]
    pub show_pipeline: bool,
}

pub(crate) fn cmd_explain(args: ExplainArgs, ctx: OutputCtx) {
    let event_value = match load_event(args.event.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            process::exit(crate::exit_code::CONFIG_ERROR);
        }
    };

    let pipelines = crate::load_pipelines(&args.pipeline);
    let collection = crate::load_collection_multi(&args.rules);

    let mut rules: Vec<&rsigma_parser::SigmaRule> = collection.rules.iter().collect();
    if let Some(id) = &args.rule_id {
        rules.retain(|r| r.id.as_deref() == Some(id.as_str()) || r.title == *id);
        if rules.is_empty() {
            eprintln!("No rule matched --rule-id {id:?}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
    if rules.is_empty() {
        eprintln!("No rules found in the given path(s)");
        process::exit(crate::exit_code::RULE_ERROR);
    }

    let event = JsonEvent::borrow(&event_value);
    let show_pipeline = args.show_pipeline && !pipelines.is_empty();
    let mut explanations: Vec<RuleExplanation> = Vec::with_capacity(rules.len());
    let mut diffs: Vec<super::pipeline_diff::RuleDiff> = Vec::new();
    for rule in rules {
        if show_pipeline {
            match super::pipeline_diff::diff_rule(rule, &pipelines) {
                Ok(d) => diffs.push(d),
                Err(e) => {
                    eprintln!("Pipeline error for rule {:?}: {e}", rule.title);
                    process::exit(crate::exit_code::RULE_ERROR);
                }
            }
        }
        let mut owned = rule.clone();
        if !pipelines.is_empty()
            && let Err(e) = apply_pipelines(&pipelines, &mut owned)
        {
            eprintln!("Pipeline error for rule {:?}: {e}", owned.title);
            process::exit(crate::exit_code::RULE_ERROR);
        }
        let compiled = match compile_rule(&owned) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Compile error for rule {:?}: {e}", owned.title);
                process::exit(crate::exit_code::RULE_ERROR);
            }
        };
        explanations.push(explain_rule(&compiled, &event));
    }

    let summaries = if show_pipeline {
        Some(diffs.as_slice())
    } else {
        None
    };
    render(&explanations, summaries, &ctx);
}

/// Read the single event to explain from the inline argument, a `@file`, or
/// stdin. The payload must be a single JSON value.
fn load_event(arg: Option<&str>) -> Result<serde_json::Value, String> {
    let text = match arg {
        None | Some("-") => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("failed to read event from stdin: {e}"))?;
            buf
        }
        Some(s) if s.starts_with('@') => {
            let path = &s[1..];
            fs::read_to_string(path)
                .map_err(|e| format!("failed to read event file {path:?}: {e}"))?
        }
        Some(s) => s.to_string(),
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("no event provided (pass --event or pipe a JSON object)".to_string());
    }
    serde_json::from_str(trimmed).map_err(|e| format!("invalid JSON event: {e}"))
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render(
    explanations: &[RuleExplanation],
    summaries: Option<&[super::pipeline_diff::RuleDiff]>,
    ctx: &OutputCtx,
) {
    // Human tree is the default; an explicit machine format overrides it.
    let effective = if ctx.explicit_format {
        ctx.format
    } else {
        OutputFormat::Table
    };
    match effective {
        OutputFormat::Json => render_json(&explanations, ctx.pretty_json()),
        OutputFormat::Ndjson => {
            for e in explanations {
                render_json(e, false);
            }
        }
        OutputFormat::Csv => render_delimited(explanations, ','),
        OutputFormat::Tsv => render_delimited(explanations, '\t'),
        OutputFormat::Table => render_human(explanations, summaries, ctx),
    }
}

fn render_human(
    explanations: &[RuleExplanation],
    summaries: Option<&[super::pipeline_diff::RuleDiff]>,
    ctx: &OutputCtx,
) {
    let p = Painter::new(ctx.color);
    for (i, exp) in explanations.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let verdict = if exp.matched {
            p.green_bold("MATCH")
        } else {
            p.red_bold("NO MATCH")
        };
        let id = exp
            .rule_id
            .as_deref()
            .map(|id| format!(" ({id})"))
            .unwrap_or_default();
        println!("{}{}: {verdict}", p.bold(&exp.rule_title), p.dim(&id));
        if let Some(diffs) = summaries
            && let Some(d) = diffs.get(i)
        {
            super::pipeline_diff::print_applied(d, &p);
        }
        for (ci, cond) in exp.conditions.iter().enumerate() {
            if exp.conditions.len() > 1 {
                println!("  condition {}:", ci + 1);
                render_condition(cond, 2, &p);
            } else {
                render_condition(cond, 1, &p);
            }
        }
    }
}

fn marker(p: &Painter, matched: bool) -> String {
    if matched {
        p.green("PASS")
    } else {
        p.red("FAIL")
    }
}

fn indent(level: usize) -> String {
    "  ".repeat(level)
}

fn render_condition(cond: &ConditionTrace, level: usize, p: &Painter) {
    let pad = indent(level);
    match cond {
        ConditionTrace::Selection {
            name,
            matched,
            detection,
        } => {
            println!("{pad}{} {}", marker(p, *matched), p.bold(name));
            render_detection(detection, level + 1, p);
        }
        ConditionTrace::And { matched, children } => {
            println!("{pad}{} all of:", marker(p, *matched));
            for c in children {
                render_condition(c, level + 1, p);
            }
        }
        ConditionTrace::Or { matched, children } => {
            println!("{pad}{} any of:", marker(p, *matched));
            for c in children {
                render_condition(c, level + 1, p);
            }
        }
        ConditionTrace::Not { matched, child } => {
            println!("{pad}{} not:", marker(p, *matched));
            render_condition(child, level + 1, p);
        }
        ConditionTrace::Quantified {
            quantifier,
            matched,
            need,
            got,
            branches,
        } => {
            println!(
                "{pad}{} {quantifier} of ({got}/{need} matched):",
                marker(p, *matched)
            );
            for b in branches {
                render_branch(b, level + 1, p);
            }
        }
    }
}

fn render_branch(b: &SelectionBranch, level: usize, p: &Painter) {
    println!(
        "{}{} {}",
        indent(level),
        marker(p, b.matched),
        p.bold(&b.name)
    );
    render_detection(&b.detection, level + 1, p);
}

fn render_detection(det: &DetectionTrace, level: usize, p: &Painter) {
    let pad = indent(level);
    match det {
        DetectionTrace::AllOf { items, .. } => {
            for item in items {
                render_item(item, level, p);
            }
        }
        DetectionTrace::AnyOf { matched, branches } => {
            println!("{pad}{} any of:", marker(p, *matched));
            for b in branches {
                render_detection(b, level + 1, p);
            }
        }
        DetectionTrace::And { matched, branches } => {
            println!("{pad}{} all of:", marker(p, *matched));
            for b in branches {
                render_detection(b, level + 1, p);
            }
        }
        DetectionTrace::Keywords { item, .. } => render_item(item, level, p),
        DetectionTrace::Other { kind, matched } => {
            println!("{pad}{} {kind}", marker(p, *matched));
        }
    }
}

fn render_item(item: &ItemTrace, level: usize, p: &Painter) {
    let pad = indent(level);
    let field = item.field.as_deref().unwrap_or("keyword");
    let kind = matcher_kind_str(item);
    let pattern = item
        .pattern
        .as_deref()
        .map(|s| format!(" {s:?}"))
        .unwrap_or_default();
    let reason = format!(" ({})", reason_str(item.reason));
    let actual = match &item.actual {
        Some(v) if !item.matched => format!("  actual={}", truncate(&compact_json(v), 80)),
        _ => String::new(),
    };
    println!(
        "{pad}{} {}|{}{}{}{}",
        marker(p, item.matched),
        field,
        kind,
        pattern,
        actual,
        p.dim(&reason),
    );
}

fn matcher_kind_str(item: &ItemTrace) -> String {
    serde_json::to_value(item.matcher)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "?".to_string())
}

fn reason_str(reason: MatchReason) -> &'static str {
    match reason {
        MatchReason::Matched => "matched",
        MatchReason::FieldAbsent => "field absent",
        MatchReason::ValueMismatch => "value mismatch",
        MatchReason::CaseMismatch => "case mismatch",
        MatchReason::Existence => "existence check failed",
        MatchReason::NoKeywordMatch => "no keyword match",
    }
}

fn compact_json(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

// ---------------------------------------------------------------------------
// Delimited (csv/tsv) flat-leaf renderer
// ---------------------------------------------------------------------------

struct LeafRow {
    rule: String,
    result: String,
    selection: String,
    field: String,
    matcher: String,
    reason: String,
    actual: String,
}

impl Tabular for LeafRow {
    fn headers() -> &'static [&'static str] {
        &[
            "RULE",
            "RESULT",
            "SELECTION",
            "FIELD",
            "MATCHER",
            "REASON",
            "ACTUAL",
        ]
    }
    fn row(&self) -> Vec<String> {
        vec![
            self.rule.clone(),
            self.result.clone(),
            self.selection.clone(),
            self.field.clone(),
            self.matcher.clone(),
            self.reason.clone(),
            self.actual.clone(),
        ]
    }
}

fn render_delimited(explanations: &[RuleExplanation], sep: char) {
    let mut writer = DelimitedWriter::new(sep, LeafRow::headers());
    let mut rows = Vec::new();
    for exp in explanations {
        for cond in &exp.conditions {
            collect_condition_leaves(&exp.rule_title, cond, &mut rows);
        }
    }
    for r in &rows {
        writer.push(&r.row());
    }
}

fn collect_condition_leaves(rule: &str, cond: &ConditionTrace, out: &mut Vec<LeafRow>) {
    match cond {
        ConditionTrace::Selection {
            name, detection, ..
        } => collect_detection_leaves(rule, name, detection, out),
        ConditionTrace::And { children, .. } | ConditionTrace::Or { children, .. } => {
            for c in children {
                collect_condition_leaves(rule, c, out);
            }
        }
        ConditionTrace::Not { child, .. } => {
            collect_condition_leaves(rule, child, out);
        }
        ConditionTrace::Quantified { branches, .. } => {
            for b in branches {
                collect_detection_leaves(rule, &b.name, &b.detection, out);
            }
        }
    }
}

fn collect_detection_leaves(
    rule: &str,
    selection: &str,
    det: &DetectionTrace,
    out: &mut Vec<LeafRow>,
) {
    match det {
        DetectionTrace::AllOf { items, .. } => {
            for item in items {
                out.push(leaf_row(rule, selection, item));
            }
        }
        DetectionTrace::AnyOf { branches, .. } | DetectionTrace::And { branches, .. } => {
            for b in branches {
                collect_detection_leaves(rule, selection, b, out);
            }
        }
        DetectionTrace::Keywords { item, .. } => out.push(leaf_row(rule, selection, item)),
        DetectionTrace::Other { kind, matched } => out.push(LeafRow {
            rule: rule.to_string(),
            result: result_str(*matched),
            selection: selection.to_string(),
            field: kind.clone(),
            matcher: String::new(),
            reason: String::new(),
            actual: String::new(),
        }),
    }
}

fn leaf_row(rule: &str, selection: &str, item: &ItemTrace) -> LeafRow {
    LeafRow {
        rule: rule.to_string(),
        result: result_str(item.matched),
        selection: selection.to_string(),
        field: item.field.clone().unwrap_or_else(|| "keyword".to_string()),
        matcher: matcher_kind_str(item),
        reason: reason_str(item.reason).to_string(),
        actual: item.actual.as_ref().map(compact_json).unwrap_or_default(),
    }
}

fn result_str(matched: bool) -> String {
    if matched { "PASS" } else { "FAIL" }.to_string()
}
