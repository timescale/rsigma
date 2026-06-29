//! `rsigma pipeline diff`: show how processing pipelines rewrite a rule.
//!
//! A rule can work in isolation yet silently fail through an ECS/CIM pipeline
//! because a field was renamed or an `AllOf` was expanded into an `AnyOf` of
//! alternatives. Static tooling never shows the post-transform rule that
//! actually runs. This command serializes the rule AST before and after
//! [`apply_pipelines_with_state`], diffs the two, and lists the applied
//! transformation ids.

use std::path::PathBuf;
use std::process;

use clap::Args;
use serde::Serialize;
use similar::TextDiff;

use rsigma_eval::{Pipeline, apply_pipelines_with_state};
use rsigma_parser::SigmaRule;

use crate::output::{OutputCtx, OutputFormat, Painter, render_json};

#[derive(Args, Debug)]
pub(crate) struct PipelineDiffArgs {
    /// Sigma rule file(s) or director(ies) to diff. Repeatable.
    #[arg(short = 'r', long = "rules", value_name = "PATH", num_args = 1.., required = true)]
    pub rules: Vec<PathBuf>,

    /// Processing pipeline(s) to apply. Accepts builtin names (ecs_windows,
    /// sysmon) or YAML file paths. Repeatable, applied in priority order.
    #[arg(short = 'p', long = "pipeline", value_name = "PATH|NAME", num_args = 1.., required = true)]
    pub pipeline: Vec<PathBuf>,

    /// Only diff the rule with this id (falling back to an exact title).
    #[arg(long = "rule-id", value_name = "ID")]
    pub rule_id: Option<String>,
}

/// The before/after projection of one rule through a pipeline set.
#[derive(Debug, Serialize)]
pub(crate) struct RuleDiff {
    pub rule_title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Whether the pipeline changed the rule AST.
    pub changed: bool,
    /// Ids of the transformations that fired (only transformations with an
    /// `id:` are recorded by the pipeline engine).
    pub applied_items: Vec<String>,
    /// The rule AST before transformation.
    pub before: serde_json::Value,
    /// The rule AST after transformation.
    pub after: serde_json::Value,
}

/// Clone `rule`, apply `pipelines`, and report the before/after AST plus the
/// applied transformation ids.
pub(crate) fn diff_rule(rule: &SigmaRule, pipelines: &[Pipeline]) -> Result<RuleDiff, String> {
    let before = serde_json::to_value(rule).map_err(|e| e.to_string())?;
    let mut after_rule = rule.clone();
    let state =
        apply_pipelines_with_state(pipelines, &mut after_rule).map_err(|e| e.to_string())?;
    let after = serde_json::to_value(&after_rule).map_err(|e| e.to_string())?;
    let mut applied_items: Vec<String> = state.applied_items.into_iter().collect();
    applied_items.sort();
    Ok(RuleDiff {
        rule_title: rule.title.clone(),
        rule_id: rule.id.clone(),
        changed: before != after,
        applied_items,
        before,
        after,
    })
}

pub(crate) fn cmd_pipeline_diff(args: PipelineDiffArgs, ctx: OutputCtx) {
    let pipelines = crate::load_pipelines(&args.pipeline);
    let collection = crate::load_collection_multi(&args.rules);

    let mut rules: Vec<&SigmaRule> = collection.rules.iter().collect();
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

    let mut diffs = Vec::with_capacity(rules.len());
    for rule in rules {
        match diff_rule(rule, &pipelines) {
            Ok(d) => diffs.push(d),
            Err(e) => {
                eprintln!("Pipeline error for rule {:?}: {e}", rule.title);
                process::exit(crate::exit_code::RULE_ERROR);
            }
        }
    }

    let effective = if ctx.explicit_format {
        ctx.format
    } else {
        OutputFormat::Table
    };
    match effective {
        OutputFormat::Json => render_json(&diffs, ctx.pretty_json()),
        OutputFormat::Ndjson => {
            for d in &diffs {
                render_json(d, false);
            }
        }
        // The diff is structural, not tabular; csv/tsv fall back to the human
        // unified diff rather than emitting a misleading flat table.
        _ => render_human(&diffs, &ctx),
    }
}

fn render_human(diffs: &[RuleDiff], ctx: &OutputCtx) {
    let p = Painter::new(ctx.color);
    for (i, d) in diffs.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let id = d
            .rule_id
            .as_deref()
            .map(|id| format!(" ({id})"))
            .unwrap_or_default();
        println!("{}{}", p.bold(&d.rule_title), p.dim(&id));
        print_applied(d, &p);
        if d.changed {
            print_unified_diff(&d.before, &d.after, &p);
        } else {
            println!("  {}", p.dim("(no change)"));
        }
    }
}

/// Print the "transformations applied" summary line. Shared by `pipeline diff`
/// and `engine explain --show-pipeline`.
pub(crate) fn print_applied(d: &RuleDiff, p: &Painter) {
    if d.applied_items.is_empty() {
        // Transformations without an `id:` are not tracked, so a real change
        // can still occur with an empty list; say so rather than implying none.
        let note = if d.changed {
            "transformations applied (no ids recorded)"
        } else {
            "no transformations applied"
        };
        println!("  {}", p.dim(note));
    } else {
        println!(
            "  {} {}",
            p.dim("transformations applied:"),
            d.applied_items.join(", ")
        );
    }
}

fn print_unified_diff(before: &serde_json::Value, after: &serde_json::Value, p: &Painter) {
    let before_s = serde_json::to_string_pretty(before).unwrap_or_default();
    let after_s = serde_json::to_string_pretty(after).unwrap_or_default();
    let diff = TextDiff::from_lines(&before_s, &after_s);
    let unified = diff
        .unified_diff()
        .context_radius(2)
        .header("before", "after")
        .to_string();
    for line in unified.lines() {
        let painted = if line.starts_with("@@") {
            p.cyan(line)
        } else if line.starts_with('+') {
            p.green(line)
        } else if line.starts_with('-') {
            p.red(line)
        } else {
            line.to_string()
        };
        println!("  {painted}");
    }
}
