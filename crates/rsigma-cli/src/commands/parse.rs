use std::io::{self, Read};
use std::path::PathBuf;
use std::process;

use clap::Args;
use rsigma_parser::{parse_sigma_file, parse_sigma_yaml};

use crate::output::{OutputCtx, render_json};

/// Arguments for `rsigma rule parse` (and the deprecated `rsigma parse`).
#[derive(Args, Debug)]
pub(crate) struct ParseArgs {
    /// Path to a Sigma YAML file
    pub path: PathBuf,

    /// Pretty-print JSON output (default; pass `--no-pretty` for compact).
    ///
    /// Forced on when `--output-format json` is set on a TTY. Mostly here
    /// for backwards compatibility -- new code should rely on
    /// `--output-format`.
    #[arg(short, long, default_value_t = true)]
    pub pretty: bool,
}

/// Arguments for `rsigma rule condition` (and the deprecated `rsigma condition`).
#[derive(Args, Debug)]
pub(crate) struct ConditionArgs {
    /// The condition expression to parse
    pub expr: String,
}

/// Arguments for `rsigma rule stdin` (and the deprecated `rsigma stdin`).
#[derive(Args, Debug)]
pub(crate) struct StdinArgs {
    /// Pretty-print JSON output (default; pass `--no-pretty` for compact).
    #[arg(short, long, default_value_t = true)]
    pub pretty: bool,
}

pub(crate) fn cmd_parse(args: ParseArgs, ctx: OutputCtx) {
    let ParseArgs { path, pretty } = args;
    match parse_sigma_file(&path) {
        Ok(collection) => {
            crate::print_warnings(&collection.errors);
            render_json(&collection, effective_pretty(ctx, pretty));
        }
        Err(e) => {
            eprintln!("Error parsing {}: {e}", path.display());
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
}

pub(crate) fn cmd_condition(args: ConditionArgs, ctx: OutputCtx) {
    let ConditionArgs { expr } = args;
    match rsigma_parser::parse_condition(&expr) {
        // `--pretty` is implied for condition output; the AST is small and
        // human-friendly is the default. `--output-format ndjson` overrides
        // to compact via [`effective_pretty`].
        Ok(ast) => render_json(&ast, effective_pretty(ctx, true)),
        Err(e) => {
            eprintln!("Condition parse error: {e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
}

pub(crate) fn cmd_stdin(args: StdinArgs, ctx: OutputCtx) {
    let StdinArgs { pretty } = args;
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        eprintln!("Error reading stdin: {e}");
        process::exit(crate::exit_code::RULE_ERROR);
    }

    match parse_sigma_yaml(&input) {
        Ok(collection) => {
            crate::print_warnings(&collection.errors);
            render_json(&collection, effective_pretty(ctx, pretty));
        }
        Err(e) => {
            eprintln!("Parse error: {e}");
            process::exit(crate::exit_code::RULE_ERROR);
        }
    }
}

/// Resolve the effective JSON pretty-print decision for `parse` / `stdin` /
/// `condition`. `--output-format ndjson` always wins (compact); otherwise we
/// fall back to the per-command `--pretty` flag, which defaults to `true`.
fn effective_pretty(ctx: OutputCtx, flag: bool) -> bool {
    use crate::output::OutputFormat;
    match ctx.format {
        OutputFormat::Ndjson => false,
        OutputFormat::Json => flag || ctx.pretty_json(),
        // Table/CSV/TSV do not apply to parser output -- fall back to JSON
        // with the same `--pretty` semantics.
        _ => flag,
    }
}
