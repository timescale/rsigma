//! `rsigma ruleset show`: the documents a ruleset resolves to and why.

use std::process;

use serde::Serialize;
use serde_json::json;

use rsigma_parser::ruleset::{Decision, DocumentKind, ResolvedRuleset, RuleEntry};
use rsigma_parser::{emit_correlation_yaml, emit_filter_yaml, emit_rule_yaml};

use crate::exit_code;
use crate::output::{OutputCtx, OutputFormat, Tabular, render_json, render_report};
use crate::ruleset::resolve_named;

#[derive(Debug, Serialize)]
struct ShowRow {
    kind: String,
    decision: String,
    id: String,
    title: String,
    origin: String,
    reason: String,
    overlays: String,
}

impl Tabular for ShowRow {
    fn headers() -> &'static [&'static str] {
        &[
            "KIND", "DECISION", "ID", "TITLE", "ORIGIN", "REASON", "OVERLAYS",
        ]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.kind.clone(),
            self.decision.clone(),
            self.id.clone(),
            self.title.clone(),
            self.origin.clone(),
            self.reason.clone(),
            self.overlays.clone(),
        ]
    }
}

#[derive(Debug, Serialize)]
struct Counts {
    detection: usize,
    correlation: usize,
    filter: usize,
    candidates: usize,
}

fn decision_label(decision: &Decision) -> String {
    match decision {
        Decision::Included { selector } => match selector {
            Some(index) => format!("included:{index}"),
            None => "included".to_string(),
        },
        Decision::Excluded { selector } => format!("excluded:{selector}"),
        Decision::PulledIn { by } => format!("pulled_in:{by}"),
        Decision::Dropped { reason } => format!("dropped:{reason}"),
        Decision::FilterKept => "filter_kept".to_string(),
        Decision::FilterOrphaned => "filter_orphaned".to_string(),
        Decision::NotSelected => "not_selected".to_string(),
        other => other.as_str().to_string(),
    }
}

fn decision_reason(decision: &Decision) -> String {
    match decision {
        Decision::Included {
            selector: Some(index),
        } => {
            format!("matched include selector {index}")
        }
        Decision::Included { selector: None } => "admitted without an include selector".to_string(),
        Decision::Excluded { selector } => format!("rejected by exclude selector {selector}"),
        Decision::PulledIn { by } => format!("pulled in as a dependency of {by}"),
        Decision::Dropped { reason } => reason.clone(),
        Decision::FilterKept => "filter retained because its target is kept".to_string(),
        Decision::FilterOrphaned => "filter dropped because its target is not kept".to_string(),
        Decision::NotSelected => "not matched by any include selector".to_string(),
        other => other.as_str().to_string(),
    }
}

fn origin_label(entry: &RuleEntry) -> String {
    format!(
        "s{}:{}#{}",
        entry.origin.source,
        entry.origin.file.display(),
        entry.origin.ordinal
    )
}

fn is_kept(decision: &Decision) -> bool {
    matches!(
        decision,
        Decision::Included { .. } | Decision::PulledIn { .. } | Decision::FilterKept
    )
}

/// The entry with `id` (or name), preferring a kept one: a forked rule shares
/// its id with the excluded vendor copy.
fn find_entry<'a>(resolved: &'a ResolvedRuleset, id: &str) -> Option<&'a RuleEntry> {
    let mut matching = resolved.entries.iter().filter(|entry| {
        entry
            .id
            .as_deref()
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(id))
            || entry.name.as_deref() == Some(id)
    });
    let first = matching.next()?;
    if is_kept(&first.decision) {
        return Some(first);
    }
    Some(
        matching
            .find(|entry| is_kept(&entry.decision))
            .unwrap_or(first),
    )
}

fn document_yaml(resolved: &ResolvedRuleset, entry: &RuleEntry) -> Option<String> {
    let id = entry.id.as_deref()?;
    match entry.kind {
        DocumentKind::Detection => resolved
            .collection
            .rules
            .iter()
            .find(|rule| rule.id.as_deref() == Some(id))
            .map(emit_rule_yaml),
        DocumentKind::Correlation => resolved
            .collection
            .correlations
            .iter()
            .find(|rule| rule.id.as_deref() == Some(id))
            .map(emit_correlation_yaml),
        DocumentKind::Filter => resolved
            .collection
            .filters
            .iter()
            .find(|rule| rule.id.as_deref() == Some(id))
            .map(emit_filter_yaml),
    }
}

fn render_detail(resolved: &ResolvedRuleset, entry: &RuleEntry, ctx: &OutputCtx) {
    let overlays: Vec<serde_json::Value> = entry
        .overlays
        .iter()
        .map(|overlay| {
            json!({
                "origin": overlay.origin.to_string(),
                "set": overlay.set,
                "appended": overlay.appended,
            })
        })
        .collect();

    if matches!(ctx.format, OutputFormat::Json | OutputFormat::Ndjson) {
        let envelope = json!({
            "ruleset": resolved.name,
            "document": {
                "kind": entry.kind.as_str(),
                "id": entry.id,
                "name": entry.name,
                "title": entry.title,
                "decision": decision_label(&entry.decision),
                "reason": decision_reason(&entry.decision),
                "origin": origin_label(entry),
                "overlays": overlays,
            },
        });
        render_json(&envelope, ctx.pretty_json());
        return;
    }

    println!("ruleset: {}", resolved.name);
    println!("kind: {}", entry.kind.as_str());
    println!("id: {}", entry.id.as_deref().unwrap_or("-"));
    println!("name: {}", entry.name.as_deref().unwrap_or("-"));
    println!("title: {}", entry.title);
    println!("decision: {}", decision_label(&entry.decision));
    println!("reason: {}", decision_reason(&entry.decision));
    println!("origin: {}", origin_label(entry));
    if entry.overlays.is_empty() {
        println!("overlays: none");
    } else {
        println!("overlays:");
        for overlay in &entry.overlays {
            println!("  {}", overlay.origin);
            if !overlay.set.is_empty() {
                println!("    set: {}", overlay.set.join(", "));
            }
            if !overlay.appended.is_empty() {
                println!("    append: {}", overlay.appended.join(", "));
            }
        }
    }
}

pub(crate) fn cmd_show(args: super::ShowArgs, ctx: OutputCtx) {
    let resolved = resolve_named(&args.name, args.config.as_deref(), &ctx);

    if let Some(id) = &args.id {
        let Some(entry) = find_entry(&resolved, id) else {
            eprintln!(
                "error: no document with id '{id}' in ruleset '{}'",
                resolved.name
            );
            process::exit(exit_code::CONFIG_ERROR);
        };
        if args.yaml {
            let Some(yaml) = document_yaml(&resolved, entry) else {
                eprintln!(
                    "error: document '{}' is not kept in ruleset '{}'",
                    id, resolved.name
                );
                process::exit(exit_code::CONFIG_ERROR);
            };
            print!("{yaml}");
            return;
        }
        render_detail(&resolved, entry, &ctx);
        return;
    }

    let counts = Counts {
        detection: resolved.collection.rules.len(),
        correlation: resolved.collection.correlations.len(),
        filter: resolved.collection.filters.len(),
        candidates: resolved.entries.len(),
    };

    let rows: Vec<ShowRow> = resolved
        .entries
        .iter()
        .filter(|entry| args.all || is_kept(&entry.decision))
        .map(|entry| ShowRow {
            kind: entry.kind.as_str().to_string(),
            decision: decision_label(&entry.decision),
            id: entry.id.clone().unwrap_or_else(|| "-".to_string()),
            title: entry.title.clone(),
            origin: origin_label(entry),
            reason: decision_reason(&entry.decision),
            overlays: if entry.overlays.is_empty() {
                "-".to_string()
            } else {
                entry
                    .overlays
                    .iter()
                    .map(|overlay| overlay.origin.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            },
        })
        .collect();

    let envelope = json!({
        "ruleset": resolved.name,
        "counts": counts,
        "entries": &rows,
    });
    render_report(&ctx, &envelope, &rows);
}
