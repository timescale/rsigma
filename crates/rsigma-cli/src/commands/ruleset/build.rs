//! `rsigma ruleset build`: materialize a resolved ruleset with a lockfile.

use std::process;

use serde::Serialize;
use serde_json::json;

use crate::exit_code::{CONFIG_ERROR, FINDINGS, RULE_ERROR};
use crate::output::{OutputCtx, Tabular, render_report};
use crate::ruleset::build::{
    check_output, ensure_unique, plan_output, portable_path, write_output,
};
use crate::ruleset::{load_named, resolve_or_exit};

#[derive(Debug, Serialize)]
struct SummaryRow {
    metric: String,
    value: String,
}

impl Tabular for SummaryRow {
    fn headers() -> &'static [&'static str] {
        &["METRIC", "VALUE"]
    }

    fn row(&self) -> Vec<String> {
        vec![self.metric.clone(), self.value.clone()]
    }
}

#[derive(Debug, Serialize)]
struct DriftRow {
    path: String,
}

impl Tabular for DriftRow {
    fn headers() -> &'static [&'static str] {
        &["PATH"]
    }

    fn row(&self) -> Vec<String> {
        vec![self.path.clone()]
    }
}

pub(crate) fn cmd_build(args: super::BuildArgs, ctx: OutputCtx) {
    let (name, spec) = load_named(&args.name, args.config.as_deref());
    let resolved = resolve_or_exit(&name, &spec, &ctx);

    let errors = resolved.collection.error_count();
    if errors > 0 {
        for diagnostic in resolved.collection.errors() {
            match &diagnostic.path {
                Some(path) => eprintln!("{}: {}", path.display(), diagnostic.message),
                None => eprintln!("{}", diagnostic.message),
            }
        }
        eprintln!("error: ruleset '{name}' has {errors} parse error(s); refusing to build");
        process::exit(RULE_ERROR);
    }

    if let Err(error) = ensure_unique(&resolved) {
        eprintln!("error: ruleset '{name}': {error}");
        process::exit(CONFIG_ERROR);
    }

    let output = args
        .output
        .clone()
        .or_else(|| spec.output.clone())
        .unwrap_or_else(|| {
            eprintln!(
                "error: ruleset '{name}' has no output directory; pass -o <DIR> or set output in the ruleset spec"
            );
            process::exit(CONFIG_ERROR);
        });

    let (plan, lock) = plan_output(&resolved, &spec);

    if args.check {
        let drifted = check_output(&output, &plan, &lock);
        if drifted.is_empty() {
            eprintln!("No drift in {}", output.display());
            return;
        }
        let rows: Vec<DriftRow> = drifted
            .iter()
            .map(|path| DriftRow {
                path: portable_path(path),
            })
            .collect();
        let envelope = json!({
            "ruleset": name,
            "output": output.display().to_string(),
            "drifted": &rows,
        });
        render_report(&ctx, &envelope, &rows);
        process::exit(FINDINGS);
    }

    let summary = match write_output(&output, &plan, &lock, args.force) {
        Ok(summary) => summary,
        Err(error) => {
            eprintln!("error: {error}");
            process::exit(CONFIG_ERROR);
        }
    };

    let rows = vec![
        SummaryRow {
            metric: "written".to_string(),
            value: summary.written.to_string(),
        },
        SummaryRow {
            metric: "unchanged".to_string(),
            value: summary.unchanged.to_string(),
        },
        SummaryRow {
            metric: "removed".to_string(),
            value: summary.removed.to_string(),
        },
        SummaryRow {
            metric: "documents".to_string(),
            value: summary.documents.to_string(),
        },
    ];
    let envelope = json!({
        "ruleset": name,
        "output": output.display().to_string(),
        "written": summary.written,
        "unchanged": summary.unchanged,
        "removed": summary.removed,
        "documents": summary.documents,
    });
    render_report(&ctx, &envelope, &rows);
}
