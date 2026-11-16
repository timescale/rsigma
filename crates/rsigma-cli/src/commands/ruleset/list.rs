//! `rsigma ruleset list`: resolution status for every declared ruleset.

use std::process;

use serde::Serialize;
use serde_json::json;

use rsigma_parser::ruleset::{ResolveOptions, resolve_ruleset};

use crate::config;
use crate::exit_code;
use crate::output::{OutputCtx, Tabular, render_report};
use crate::ruleset::{load_specs, ruleset_pipelines};

#[derive(Debug, Serialize)]
struct RulesetRow {
    name: String,
    sources: String,
    detection: usize,
    correlation: usize,
    filter: usize,
    overlays: usize,
    pipelines: String,
    status: String,
    error: String,
}

impl Tabular for RulesetRow {
    fn headers() -> &'static [&'static str] {
        &[
            "NAME",
            "SOURCES",
            "DETECTION",
            "CORRELATION",
            "FILTER",
            "OVERLAYS",
            "PIPELINES",
            "STATUS",
            "ERROR",
        ]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.name.clone(),
            self.sources.clone(),
            self.detection.to_string(),
            self.correlation.to_string(),
            self.filter.to_string(),
            self.overlays.to_string(),
            self.pipelines.clone(),
            self.status.clone(),
            self.error.clone(),
        ]
    }
}

pub(crate) fn cmd_list(args: super::ListArgs, ctx: OutputCtx) {
    let config = args.config.as_deref();
    let specs = load_specs(config);
    if specs.is_empty() {
        let files = config::discover(config);
        if files.is_empty() {
            eprintln!(
                "No rulesets defined. Add a `rulesets:` section to rsigma.yaml or another configuration file."
            );
        } else {
            eprintln!(
                "No rulesets defined. Add a `rulesets:` section to one of: {}",
                files
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        return;
    }

    let mut rows = Vec::with_capacity(specs.len());
    let mut failed = false;
    for (name, spec) in &specs {
        let sources = spec
            .sources
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(",");
        let pipelines = ruleset_pipelines(spec)
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(",");

        match resolve_ruleset(name, spec, &ResolveOptions::default()) {
            Ok(resolved) => {
                if !ctx.quiet {
                    for warning in &resolved.warnings {
                        eprintln!("warning: {warning}");
                    }
                }
                rows.push(RulesetRow {
                    name: name.clone(),
                    sources,
                    detection: resolved.collection.rules.len(),
                    correlation: resolved.collection.correlations.len(),
                    filter: resolved.collection.filters.len(),
                    overlays: spec.overlays.len(),
                    pipelines,
                    status: "ok".to_string(),
                    error: match resolved.collection.error_count() {
                        0 => String::new(),
                        count => format!("{count} source parse error(s)"),
                    },
                });
            }
            Err(error) => {
                failed = true;
                rows.push(RulesetRow {
                    name: name.clone(),
                    sources,
                    detection: 0,
                    correlation: 0,
                    filter: 0,
                    overlays: spec.overlays.len(),
                    pipelines,
                    status: "error".to_string(),
                    error: error.to_string(),
                });
            }
        }
    }

    let envelope = json!({ "rulesets": &rows });
    render_report(&ctx, &envelope, &rows);

    if failed {
        process::exit(exit_code::CONFIG_ERROR);
    }
}
